#!/usr/bin/env python

# based on https://developers.onelogin.com/authentication/tools/linux-ssh-pam-module

'''
PAM module for authenticating users via a OIDC token
'''
import json
import os
import sys
import requests
import logging

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
    # Load config file and build access token
    try:
        config_dpath = os.path.dirname(os.path.realpath(__file__))
        config_fpath = os.path.join(config_dpath, 'oidc-pam.json')
        config_fd = open(config_fpath, 'r')
        config = config_fd.read()
        config_fd.close()
        config = json.loads(config)
    except Exception as error:
        logit('Error loading configuration: %s' % error)
        return pamh.PAM_AUTH_ERR

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
