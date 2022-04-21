import requests
import paramiko
import socket       #This method requires that we create our own socket

token=''
hostname = 'localhost'
username = 'test'
MAX_LENGTH = 511

#idea from https://stackoverflow.com/questions/43903875/python-paramiko-client-multifactor-authentication

def interaction_handler(title, instructions, prompt_list):
    global token
    resp = []
    for pr in prompt_list:
        if pr[0].strip() == "Password:":
            if len(token) > MAX_LENGTH:
                resp.append(token[0:MAX_LENGTH])
                token = token[MAX_LENGTH:]
        elif pr[0].strip() == "Next:":
            if len(token) == 0:
                resp.append('token_end')
            elif len(token) > MAX_LENGTH:
                resp.append(token[0:MAX_LENGTH])
                token = token[MAX_LENGTH:]
            else:
                resp.append(token)
                token=''
    return tuple(resp)

try:
        url = 'http://host.docker.internal:8080/realms/NDIP/protocol/openid-connect/token'
        data = {
            'username': 'gtest',
            'password':'1234',
            'grant_type':'password',
            'client_id': 'ndip',
            'client_secret':'ZLrwMJePHNqDbHzZOLwdQrHjaByI4mhK'
         }
        response = requests.post(url, data = data)
        response.raise_for_status()
        token=response.json()['access_token']
except Exception as e:
    print(e)  


try:

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((hostname, 2222))

    ts = paramiko.Transport(sock)
    ts.start_client(timeout=10)
    ts.auth_interactive(username, interaction_handler)
    chan = ts.open_session(timeout=10)
    chan.exec_command("whoami")
    response = chan.recv(1024).decode("utf-8").strip()
    print(response) 


except Exception as e:
    print(e)

