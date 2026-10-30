#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -k -sS \
  --resolve mail.mailcow.test:9443:127.0.0.1 \
  -A 'MCAB-Debug/1' \
  -c "$TMP/cookies" \
  -o /dev/null \
  https://mail.mailcow.test:9443/admin

sid="$(awk '$6=="MCSESSID" {print $7}' "$TMP/cookies")"
test "${#sid}" -eq 64

docker compose cp tests/inspect-session.php broker:/tmp/inspect-session.php >/dev/null
docker compose exec -T broker php /tmp/inspect-session.php "$sid"

echo '=== DASHBOARD HEADERS ==='
curl -k -sS \
  --resolve mail.mailcow.test:9443:127.0.0.1 \
  -A 'MCAB-Debug/1' \
  -b "$TMP/cookies" \
  -D "$TMP/headers" \
  -o /dev/null \
  https://mail.mailcow.test:9443/admin/dashboard
sed -E 's/(MCSESSID=)[^;]+/\1<redacted>/g' "$TMP/headers" | head -n 30

