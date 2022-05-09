#!/bin/bash

su test

if [ ! -e "/home/test/auth_secrets" ]; then
  bash -c "google-authenticator -t -d -f -W -u" > /home/test/auth_secrets
fi


su root

cd /tmp/oidc
python2 /tmp/oidc/update_oidc_config.py

/usr/sbin/sshd -D