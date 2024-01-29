#!/bin/bash
set -e

chown $TEST_USER: -R /home/$TEST_USER

/usr/sbin/sshd -D