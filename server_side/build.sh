docker build --target no2fa -t ubuntu_sshd -f dockerfiles/Dockerfile .
docker build --target with2fa -t ubuntu_sshd_2fa -f dockerfiles/Dockerfile  .