#!/bin/bash
set -e

mkdir -p -m=700 /home/test/auth
chmod 700 /home/test/auth
chown test: -R /home/test

if [ ! -e "/home/test/auth/.google_authenticator" ]; then
  su test bash -c "google-authenticator -t -d -f -W -u -s /home/test/auth/.google_authenticator" > /home/test/auth/auth_secrets
fi

cd /tmp/oidc
python3 /tmp/oidc/update_oidc_config.py

/usr/sbin/sshd -D