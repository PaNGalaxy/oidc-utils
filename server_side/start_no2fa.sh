#!/bin/bash
set -e

chown test: -R /home/test

cd /tmp/oidc
python3 /tmp/oidc/update_oidc_config.py

/usr/sbin/sshd -D