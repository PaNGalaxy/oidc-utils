#!/usr/bin/env python

# based on https://developers.onelogin.com/authentication/tools/linux-ssh-pam-module

'''
PAM module for authenticating users via a onelogin email/username and OTP
'''
import json
import os
import sys
import syslog
import time
import requests

def logit(data):
    '''
    Logs data to stderr and syslog
    Args:
        data (*): Data to log
    Returns: None
    '''
    data_str = str(data)
    sys.stderr.write('%s\n' % data_str)
    syslog.syslog(syslog.LOG_ERR, data_str)

class UniformTimer:
    '''
    This class is used to make sections of code run in a uniform time.
    '''
    def __init__(self, base_duration_secs):
        '''
        Constructor (doesn't start timing)
        Args:
            base_duration_secs (float): Default timer value
        '''
        self.base_duration_secs = base_duration_secs
        self.timer = 0
 
    def start(self, duration_secs=None):
        '''
        Start timer (non-blocking)
        Args:
            duration_secs (float|None): Override the default timer value
                                        with this value (optional).
        '''
        if duration_secs is None:
            duration_secs = self.base_duration_secs
        self.timer = time.time() + duration_secs
 
    def finish(self):
        '''
        Waits for timer to expire (blocking)
        Args:
            None
        '''
        time.sleep(max(0, self.timer - time.time()))

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
    Authenticates a user via onelogin email/username and OTP
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

    # get user&token
    try:
        user = pamh.get_user(None)
        if user is None:
            return pamh.PAM_USER_UNKNOWN
        access_token = pamh.authtok
#        if len(access_token)<20: #cannot be token, should be wrong password
#            return pamh.PAM_AUTH_ERR
        if len(access_token)>5:
            next_token_part = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF,'Next: ')).resp
            while (next_token_part != 'token_end') and (next_token_part!=''):
                access_token = access_token + next_token_part                 
                next_token_part = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF,'Next: ')).resp
        if access_token is None:
            logit('empty access_token token')
            return pamh.PAM_AUTH_ERR
    except pamh.exception as error:
        return error.pam_result

    # check user same as in token
    uniform_timer = UniformTimer(config['request_duration_secs'])
    try:
        uniform_timer.start()
        url = config['introspection_url']
        logit(access_token)
        data = {'token': access_token.strip(),'client_id': config['client_id'], 'client_secret':config['client_secret']}
        response = requests.post(url, data = data)
        if response.status_code != requests.status_codes.codes.ok:
            logit('Error checking introspecting token, server returned %d %s' % response.status_code, response.text)
            return pamh.PAM_AUTH_ERR
        token_info=response.json()
        if token_info['active']!= True:
            logit('Error checking introspecting token, token %s invalid, server response: %s' %(access_token, response.text))
            return pamh.PAM_AUTH_ERR            
        logit(response.json())
        uniform_timer.finish()
    except Exception as error:
        logit('Error introspecting token %s, error: %s' % (access_token,error))
        return pamh.PAM_AUTH_ERR

    return pamh.PAM_SUCCESS