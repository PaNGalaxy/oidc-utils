#!/bin/bash
set -e

chown $TEST_USER: -R /home/$TEST_USER

cd /tmp/oidc
python3 /tmp/oidc/update_oidc_config.py

/usr/sbin/sshd -D