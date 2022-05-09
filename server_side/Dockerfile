FROM ubuntu:latest AS no2fa

RUN apt-get update && apt-get install -y ssh libpam-python  curl python2 sudo
RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py && python2 get-pip.py 
RUN pip2 config set global.target /lib/python2.7 && pip2 install requests

RUN useradd test
RUN mkhomedir_helper test
RUN echo test:123 | chpasswd
RUN mkdir /run/sshd

COPY oidc-pam.py  /etc/security/oidc/oidc-pam.py
COPY sshd /etc/pam.d/
COPY sshd_pam.conf /etc/ssh/sshd_config.d/
COPY docker-entrypoint.sh  /tmp/oidc/
COPY update_oidc_config.py  /tmp/oidc/
COPY oidc-pam.json  /tmp/oidc/
RUN chmod 777 /tmp/oidc/docker-entrypoint.sh


EXPOSE 22


ENTRYPOINT /tmp/oidc/docker-entrypoint.sh


#2FA

FROM no2fa AS with2fa

RUN apt-get install -y libpam-google-authenticator
COPY sshd_2fa /etc/pam.d/sshd

USER root
