#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
test -f .env

for name in MAILCOW_DB_PASSWORD MAILCOW_REDIS_PASSWORD BROKER_SECRET; do
  value="$(sed -n "s/^${name}=//p" .env)"
  if [ -z "$value" ]; then
    echo "missing local value: $name" >&2
    exit 1
  fi
  matches="$(find . \
    -path './.git' -prune -o \
    -name '.env' -prune -o \
    -type f -print0 | xargs -0 grep -lF -- "$value" || true)"
  if [ -n "$matches" ]; then
    echo "secret leaked from $name into tracked candidate files:" >&2
    echo "$matches" >&2
    exit 1
  fi
done

echo 'secret_scan=PASS'

