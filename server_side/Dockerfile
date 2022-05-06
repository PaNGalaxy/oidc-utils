FROM ubuntu:latest AS no2fa

RUN apt-get update && apt-get install -y ssh libpam-python  curl python2
RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py && python2 get-pip.py 
RUN pip2 config set global.target /lib/python2.7 && pip2 install requests

RUN useradd test
RUN mkhomedir_helper test
RUN echo test:123 | chpasswd
RUN mkdir /run/sshd

COPY oidc-pam.py  /etc/securuty/oidc/oidc-pam.py
COPY oidc-pam.json  /etc/securuty/oidc/oidc-pam.json
COPY sshd /etc/pam.d/
COPY sshd_pam.conf /etc/ssh/sshd_config.d/

EXPOSE 22
ENTRYPOINT /usr/sbin/sshd -D


#2FA

FROM no2fa AS with2fa

RUN apt-get install -y libpam-google-authenticator 
COPY sshd_2fa /etc/pam.d/sshd


USER test
RUN google-authenticator -t -d -f -W -u > /home/test/auth_secrets

USER root
