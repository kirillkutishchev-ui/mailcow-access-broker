FROM nginx:1.27-alpine

RUN apk add --no-cache openssl \
    && mkdir -p /etc/nginx/tls \
    && openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
       -keyout /etc/nginx/tls/local.key \
       -out /etc/nginx/tls/local.crt \
       -subj "/CN=mail.mailcow.test" \
       -addext "subjectAltName=DNS:mail.mailcow.test"

COPY default.conf /etc/nginx/conf.d/default.conf

