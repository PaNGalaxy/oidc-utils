
#2FA

##links
https://goteleport.com/blog/ssh-2fa-tutorial/
https://github.com/google/google-authenticator-libpam

##getting secrets/link to a QR code for Google Authenticator
```
docker run --entrypoint="" ubuntu_sshd_2fa cat /home/test/auth_secrets
```

#PAM module in Python

https://developers.onelogin.com/authentication/tools/linux-ssh-pam-module

#keycloak

get token

```curl -d 'client_id=ndip' -d 'client_secret=ZLrwMJePHNqDbHzZOLwdQrHjaByI4mhK'  -d 'username=gtest' -d 'password=1234' -d 'grant_type=password' 'http://localhost:8080/realms/NDIP/protocol/openid-connect/token'```


refresh token

```curl -X POST -d 'client_id=ndip' -d 'client_secret=ZLrwMJePHNqDbHzZOLwdQrHjaByI4mhK' -d 'grant_type=refresh_token' -d refresh_token=$rtoken http://localhost:8080/realms/NDIP/protocol/openid-connect/token```

introspect token

curl -d token=$token -d 'client_id=ndip'  -d 'client_secret=ZLrwMJePHNqDbHzZOLwdQrHjaByI4mhK'  http://localhost:8080/realms/NDIP/protocol/openid-connect/token/introspect
