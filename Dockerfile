FROM ubuntu:focal
WORKDIR /opt
COPY validatingwebhook .
CMD ["./validatingwebhook", "--tls-cert", "/etc/opt/tls.crt", "--tls-key", "/etc/opt/tls.key"]