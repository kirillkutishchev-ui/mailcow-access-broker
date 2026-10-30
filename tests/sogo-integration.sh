#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
BASE='https://mail.mailcow.test:9443'
RESOLVE='mail.mailcow.test:9443:127.0.0.1'
AUTH_BASE="${AUTH_BASE:-$BASE}"
AUTH_RESOLVE="${AUTH_RESOLVE:-$RESOLVE}"
MAILBOX="${1:-user@demo.mailcow.test}"
UA='MCAB-SOGo-Test/1'
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -k -sS --resolve "$RESOLVE" -A "$UA" \
  -c "$TMP/cookies" -b "$TMP/cookies" -o /dev/null "$BASE/admin"

curl -k -sS --resolve "$AUTH_RESOLVE" -A "$UA" \
  -c "$TMP/cookies" -b "$TMP/cookies" -D "$TMP/auth.headers" -o /dev/null \
  "$AUTH_BASE/sogo-auth.php?login=$MAILBOX"

echo '=== SOGO AUTH REDIRECT ==='
grep -Ei '^(HTTP/|location:)' "$TMP/auth.headers" || true

code="$(curl -k -sS --resolve "$AUTH_RESOLVE" -A "$UA" \
  -c "$TMP/cookies" -b "$TMP/cookies" -o "$TMP/sogo.body" -w '%{http_code}' \
  "$AUTH_BASE/SOGo/so/")"
echo "sogo_code=$code"
test "$code" = 302

final_code="$(curl -k -sS -L --max-redirs 10 --resolve "$AUTH_RESOLVE" -A "$UA" \
  -c "$TMP/cookies" -b "$TMP/cookies" -o "$TMP/sogo-final.body" -w '%{http_code}' \
  "$AUTH_BASE/SOGo/so/")"
echo "sogo_final_code=$final_code"
test "$final_code" = 200

sid="$(awk '$6=="MCSESSID" {print $7}' "$TMP/cookies")"
test "${#sid}" -eq 64

echo '=== INTERNAL AUTH DIRECT ==='
docker exec mailcowdockerized-nginx-mailcow-1 curl -sS -D - -o /dev/null \
  -H "Cookie: MCSESSID=$sid" \
  -H "User-Agent: $UA" \
  -H 'X-Original-URI: /SOGo/so/' \
  http://127.0.0.1:65510/sogo-auth \
  | grep -Ei '^(HTTP/|X-User:|X-Auth-Type:)' || true

echo '=== SOGO BACKEND DIRECT ==='
docker cp tests/check-sogo-backend.sh mailcowdockerized-nginx-mailcow-1:/tmp/check-sogo-backend.sh >/dev/null
docker exec mailcowdockerized-nginx-mailcow-1 chmod 0700 /tmp/check-sogo-backend.sh
docker exec mailcowdockerized-nginx-mailcow-1 /tmp/check-sogo-backend.sh "$sid" "$UA"

docker compose cp tests/inspect-session.php broker:/tmp/inspect-session.php >/dev/null
docker compose exec -T broker php /tmp/inspect-session.php "$sid"

echo 'sogo_integration=PASS'

