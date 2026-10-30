#!/bin/sh
set -eu

MAILCOW_DIR="${1:-/opt/mailcow-lab/mailcow-dockerized}"
cd "$MAILCOW_DIR"

echo '=== SSO REFERENCES ==='
grep -RInE 'sogo-sso\.pass|SOGoPasswordChangeEnabled|WOHttpAllowHost|x-webobjects-remote-user' \
  docker-compose.yml data/conf/sogo data/conf/dovecot data/Dockerfiles 2>/dev/null | head -n 180 || true

echo '=== SECRET FILE HASHES ==='
for container in \
  mailcowdockerized-php-fpm-mailcow-1 \
  mailcowdockerized-dovecot-mailcow-1 \
  mailcowdockerized-sogo-mailcow-1 \
  mailcowdockerized-nginx-mailcow-1
do
  printf '%s ' "$container"
  docker exec "$container" sh -lc '
    found=0
    for file in \
      /etc/sogo-sso/sogo-sso.pass \
      /etc/sogo/sieve.creds \
      /etc/dovecot/sogo-sso.pass
    do
      if [ -f "$file" ]; then
        found=1
        printf "%s:" "$file"
        sha256sum "$file" | cut -d" " -f1
      fi
    done
    if [ "$found" -eq 0 ]; then printf "no-known-secret-file\n"; fi
  '
done

