FROM ubuntu:22.04 AS package

RUN apt-get update && apt-get install -y cmake libpam0g-dev libcurl4-openssl-dev

COPY c  /src/c

WORKDIR /src/c
RUN bash ./build.sh



FROM ubuntu:22.04 AS no2fa

RUN useradd test
RUN mkhomedir_helper test
RUN echo test:123 | chpasswd
RUN mkdir /run/sshd /etc/security/oidc

RUN apt-get update && apt-get install -y curl python3 ssh


COPY --from=package /src/c/build/*.deb  /

RUN dpkg -i /oidc-pam-0.1.0-Linux.deb

COPY c/sshd /etc/pam.d/
COPY sshd_pam.conf /etc/ssh/sshd_config.d/
COPY start_no2fa.sh  /tmp/oidc/
COPY update_oidc_config.py  /tmp/oidc/
COPY oidc-pam.json  /tmp/oidc/


EXPOSE 22

RUN chmod 777 /tmp/oidc/start_no2fa.sh
CMD /tmp/oidc/start_no2fa.sh


#2FA

FROM no2fa AS with2fa

RUN apt-get install -y libpam-google-authenticator
COPY c/sshd_2fa /etc/pam.d/sshd

ENV OIDC_CHECK_2FA=1

COPY start_2fa.sh  /tmp/oidc/
RUN chmod 777 /tmp/oidc/start_2fa.sh

CMD /tmp/oidc/start_2fa.sh


USER root


