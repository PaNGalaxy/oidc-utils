#!/usr/bin/env python

# based on https://developers.onelogin.com/authentication/tools/linux-ssh-pam-module

'''
PAM module for authenticating users via a OIDC token
'''
import base64
import json
import jwt
import os
import requests
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate

logging.basicConfig(filename='/tmp/oidc.log', encoding='utf-8', level=logging.DEBUG)


def logit(data):
    logging.debug(str(data))


def pam_sm_setcred(pamh, _flags, _argv):
    '''
    Default
    '''
    return pamh.PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, _flags, _argv):
    '''
    Default
    '''
    return pamh.PAM_SUCCESS


def pam_sm_open_session(pamh, _flags, _argv):
    '''
    Default
    '''
    return pamh.PAM_SUCCESS


def pam_sm_close_session(pamh, _flags, _argv):
    '''
    Default
    '''
    return pamh.PAM_SUCCESS


def pam_sm_chauthtok(pamh, _flags, _argv):
    '''
    Default
    '''
    return pamh.PAM_SUCCESS


def pam_sm_authenticate(pamh, _flags, _argv):
    '''
    Authenticates a user via an OIDC token
    '''   

    # build access token

    use_first_pass = 'use_first_pass' in _argv
    # get user&token
    try:
        user = pamh.get_user(None)
        if user is None:
            return pamh.PAM_USER_UNKNOWN
        if use_first_pass:
            access_token = pamh.authtok
            if access_token is None:
                logit('empty access_token token with use_first_pass')
                return pamh.PAM_AUTH_ERR
        else:
            access_token = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, 'Passcode or token: ')).resp
        if len(access_token) < 20:
            pamh.authtok = access_token
            return pamh.PAM_AUTH_ERR

        next_token_part = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, 'Next: ')).resp
        while (next_token_part != 'token_end') and (next_token_part != ''):
            access_token = access_token + next_token_part
            next_token_part = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, 'Next: ')).resp
        if access_token is None:
            logit('empty access_token token')
            return pamh.PAM_AUTH_ERR
    except pamh.exception as error:
        return error.pam_result

    return verify_token_jwt(pamh, user, access_token)
       

def verify_token_jwt(pamh, user, access_token):
    config = load_config()
    try:
        # Obtain appropriate cert from JWK URI
        jwks_url = config['jwks_url']
        
        key_set = requests.get(jwks_url, timeout=5)

        encoded_header, rest = access_token.split('.', 1)
        headerobj = json.loads(base64.b64decode(encoded_header+ '==').decode('utf8'))
        key_id = headerobj['kid']
        for key in key_set.json()['keys']:
            if key['kid'] == key_id:
                x5c = key['x5c'][0]
                break
        else:
            raise jwt.DecodeError('Cannot find kid ' + key_id)

        cert = load_der_x509_certificate(base64.b64decode(x5c), default_backend())
        # Decode token (exp date is checked automatically)
        decoded_token = jwt.decode(
                access_token,
                key=cert.public_key(),
                algorithms=['RS256'],
                options={'exp': True, 'verify_aud': False}
            )
        # Check if correct user
        if decoded_token['preferred_username'].split('@',1)[0] != user:
            logit('SSH user does not match token user: %s (ssh) !=v %s (token)' % (user,
                    decoded_token['preferred_username']))
            return pamh.PAM_AUTH_ERR

        # Check if two factor authenticated
        if config['check_2fa']:
            if 'mfa' not in decoded_token['amr']:
                logit('missing 2fa in token: %s ' % access_token)
                return pamh.PAM_AUTH_ERR
    except Exception as error:
        logit('Error verifying jwt token %s, error: %s' % (access_token, error))
        return pamh.PAM_AUTH_ERR
        
    logit('Login successful for user %s, token %s' % (user, access_token))
    return pamh.PAM_SUCCESS

def load_config():
    config_dpath = os.path.dirname(os.path.realpath(__file__))
    config_fpath = os.path.join(config_dpath, 'oidc-pam.json')
    config_fd = open(config_fpath, 'r')
    config = config_fd.read()
    config_fd.close()
    config = json.loads(config)
    return config
