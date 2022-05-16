import os
import json

def nested_set(dic, keys, value):
    for key in keys[:-1]:
        dic = dic.setdefault(key, {})
    dic[keys[-1]] = value

def json_set_values(input,output,vals):
    with open(input) as f:
        doc = json.load(f)
    for val in vals:
        nested_set(doc,val['path'],val['value'])

    with open(output, 'w') as f:
        json.dump(doc, f,indent=4)


def str2bool(v):
  return v.lower() in ("yes", "true", "t", "1")


dict = []
if 'KEYCLOAK_URL' in os.environ:
    dict.append({'path': ['introspection_url'], 'value': os.environ['KEYCLOAK_URL']+'/protocol/openid-connect/token/introspect'})
if 'KEYCLOAK_CLIENT_SECRET' in os.environ:
    dict.append({'path': ['client_secret'], 'value': os.environ['KEYCLOAK_CLIENT_SECRET']})
if 'KEYCLOAK_CLIENT_ID' in os.environ:
    dict.append({'path': ['client_id'], 'value': os.environ['KEYCLOAK_CLIENT_ID']})
if 'OIDC_CHECK_2FA' in os.environ:
    dict.append({'path': ['check_2fa'], 'value': str2bool(os.environ['OIDC_CHECK_2FA'])})


json_set_values('oidc-pam.json','/etc/security/oidc/oidc-pam.json', dict)
