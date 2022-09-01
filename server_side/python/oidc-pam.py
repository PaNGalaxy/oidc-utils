#!/usr/bin/env python

# based on https://developers.onelogin.com/authentication/tools/linux-ssh-pam-module

'''
PAM module for authenticating users via a OIDC token
'''
import json
import jwt
import os
import sys
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
    logit("setcred")
    return pamh.PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, _flags, _argv):
    '''
    Default
    '''
    logit("acct mgmt")
    return pamh.PAM_SUCCESS


def pam_sm_open_session(pamh, _flags, _argv):
    '''
    Default
    '''
    logit("open session")
    return pamh.PAM_SUCCESS


def pam_sm_close_session(pamh, _flags, _argv):
    '''
    Default
    '''
    logit("close session")
    return pamh.PAM_SUCCESS


def pam_sm_chauthtok(pamh, _flags, _argv):
    '''
    Default
    '''
    logit("chauthtok")
    return pamh.PAM_SUCCESS


def pam_sm_authenticate(pamh, _flags, _argv):
    '''
    Authenticates a user via an OIDC token
    '''    
    logit("trying")
    
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

    if (os.environ['PAM_OIDC_VERFIFICATION_TYPE'] == "jwks_url"):
        return verify_token_jwt(pamh, user, access_token)
    else:    
        return verify_token_introspection(pamh, user, access_token)

def verify_token_jwt(pamh, user, access_token):
    config = load_config_jwt(pamh)
    try:
        # Obtain appropriate cert from JWK URI
        jwks_url = config['jwks_uri']
        key_set = requests.get(jwks_url, timeout=5)

        encoded_header, rest = access_token.split('.', 1)
        headerobj = json.loads(base64.b64_decode(encoded_header).decode('utf8'))

        key_id = headerobj['kid']
        for key in key_set.json()['keys']:
            if key['kid'] == key_id:
                x5c = key['x5c'][0]
                break
        else:
            raise jwt.DecodeError(f'Cannot find kid={kid}')

        cert = load_der_x509_certificate(base64.b64decode(x5c), default_backend())

        # Decode token (exp date is checked automatically)
        decoded_token = jwt.decode(
                access_token,
                key=certificate.public_key(),
                algorithms=['RS256'],
                audience=self.setting('KEY')
            )

        # Check if correct user
        if decoded_token['preferred_username'] != user:
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

def verify_token_introspection(pamh, user, access_token):
    logit('Attempting token verification through instrosepction URL.')
    config = load_config_introspection(pamh)
    try:
        url = config['introspection_url']
        logit(access_token)
        data = {'token': access_token.strip(), 'client_id': config['client_id'],
                'client_secret': config['client_secret']}
        response = requests.post(url, data=data, timeout=5)
        if response.status_code != requests.status_codes.codes.ok:
            logit('Error checking introspecting token, server returned %d %s' % response.status_code, response.text)
            return pamh.PAM_AUTH_ERR
        token_info = response.json()
        if 'active' not in token_info or token_info['active'] != True:
            logit('Error checking introspecting token, token %s invalid, server response: %s' % (
                access_token, response.text))
            return pamh.PAM_AUTH_ERR
        if 'preferred_username' not in token_info or token_info['preferred_username'] != user:
            logit('wrong user name in token: %s, expected %s' % (access_token, user))
            return pamh.PAM_AUTH_ERR
        if config['check_2fa']:
            if 'session_attribute' not in token_info or token_info['session_attribute'] != '2fa':
                logit('missing 2fa in token: %s ' % access_token)
                return pamh.PAM_AUTH_ERR
    except Exception as error:
        logit('Error introspecting token %s, error: %s' % (access_token, error))
        return pamh.PAM_AUTH_ERR

    logit('Login successful for user %s, token %s' % (user, access_token))
    return pamh.PAM_SUCCESS

def load_config(pamh):
    # Load config file 
    config_dpath = os.path.dirname(os.path.realpath(__file__))
    config_fpath = os.path.join(config_dpath, 'oidc-pam.json')
    config_fd = open(config_fpath, 'r')
    config = config_fd.read()
    config_fd.close()
    config = json.loads(config)
    return config

def load_config_jwt(pamh):   
    try:
        config = load_config(pamh)
        return next((config_item for config_item in config if config_item['verification_type'] == "jwks_url"))
    except Exception as error:
        logit('Error loading configuration for jwt verification: %s' % error)\
        return pamh.PAM_AUTH_ERR

def load_config_introspection(pamh):
    try:
        config = load_config(pamh)
        return next((config_item for config_item in config if config_item['verification_type'] == "introspection_url"))
    except Exception as error:
        logit('Error loading configuration for introspection verification: %s' % error)\
        return pamh.PAM_AUTH_ERR