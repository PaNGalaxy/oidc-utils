import paramiko
import socket
import argparse

parser = argparse.ArgumentParser(description="Example connecting to the ssh server useing OIDC token")
parser.add_argument("username", type=str, help="Username for authentication.")
parser.add_argument("token", type=str, help="Token for authentication.")
parser.add_argument("hostname", type=str, help="Hostname of the server.")
parser.add_argument("port", type=int, help="Port number of the server.")
args = parser.parse_args()

username = args.username
token = args.token
hostname = args.hostname
port = args.port

MAX_LENGTH = 511


# idea from https://stackoverflow.com/questions/43903875/python-paramiko-client-multifactor-authentication

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
                token = ''
    return tuple(resp)


try:

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((hostname, port))
    ts = paramiko.Transport(sock)
    ts.window_size = 3 * 1024 * 1024
    ts.start_client(timeout=10)
    print("client started")
    ts.auth_interactive(username, interaction_handler)
    print("auth_interactive")
    chan = ts.open_session(timeout=10)
    print("session opened")
    chan.exec_command("whoami")
    response = chan.recv(1024).decode("utf-8").strip()
    print(response)


except Exception as e:
    print(e)
