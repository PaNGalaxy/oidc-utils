#!/bin/bash
set -e

chown test: -R /home/test

if [ ! -e "/home/test/auth_secrets" ]; then
  su test bash -c "google-authenticator -t -d -f -W -u -C" > /home/test/auth_secrets
fi

cd /tmp/oidc
python2 /tmp/oidc/update_oidc_config.py

/usr/sbin/sshd -D