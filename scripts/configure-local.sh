#!/bin/sh
set -eu

MAILCOW_DIR="${1:-/opt/mailcow-lab/mailcow-dockerized}"
CONF="$MAILCOW_DIR/mailcow.conf"

if [ ! -f "$CONF" ]; then
  echo "mailcow.conf not found: $CONF" >&2
  exit 1
fi

set -a
. "$CONF"
set +a

NETWORK="$(docker inspect "$(cd "$MAILCOW_DIR" && docker compose ps -q nginx-mailcow)" --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}')"
BROKER_SECRET="$(openssl rand -hex 32)"

umask 077
cat > .env <<EOF
PUBLIC_BASE_URL=https://mail.mailcow.test:9443
MAILCOW_BASE_URL=https://mail.mailcow.test:9443
MAILCOW_ADMIN_USERNAME=admin
TRUSTED_ADMIN_CIDRS=172.16.0.0/12
TRUSTED_PROXY_CIDRS=172.16.0.0/12
MAILCOW_NETWORK=$NETWORK
MAILCOW_DB_HOST=mysql-mailcow
MAILCOW_DB_PORT=3306
MAILCOW_DB_NAME=$DBNAME
MAILCOW_DB_USER=$DBUSER
MAILCOW_DB_PASSWORD=$DBPASS
MAILCOW_REDIS_HOST=redis-mailcow
MAILCOW_REDIS_PORT=6379
MAILCOW_REDIS_PASSWORD=$REDISPASS
MAILCOW_SESSION_COOKIE=MCSESSID
MAILCOW_SESSION_PREFIX=PHPREDIS_SESSION:
MAILCOW_SESSION_TTL=10800
BROKER_SECRET=$BROKER_SECRET
AUDIT_RETENTION_DAYS=90
BROKER_BIND=127.0.0.1
BROKER_PORT=8095
LOCAL_HTTPS_BIND=0.0.0.0
LOCAL_HTTPS_PORT=9443
EOF
chmod 600 .env
echo "Created $(pwd)/.env for local testing"

