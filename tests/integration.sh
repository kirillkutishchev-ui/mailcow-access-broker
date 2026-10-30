#!/bin/sh
set -eu

BASE="${BASE_URL:-https://mail.mailcow.test:9443}"
RESOLVE_HOST="${RESOLVE_HOST:-mail.mailcow.test:9443:127.0.0.1}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl_base() {
  curl -k -sS --resolve "$RESOLVE_HOST" "$@"
}

echo '=== NATIVE SESSION ==='
curl_base \
  -A 'MCAB-Integration-Test/1' \
  -c "$TMP/mailcow.cookies" \
  -b "$TMP/mailcow.cookies" \
  -L --max-redirs 4 \
  -o "$TMP/admin.html" \
  -w 'code=%{http_code} final=%{url_effective}\n' \
  "$BASE/admin"

if grep -q 'name="login_user"' "$TMP/admin.html"; then
  echo 'admin_session=FAILED_login_form'
  exit 1
fi
echo 'admin_session=OK'

echo '=== IP DENY ==='
code="$(curl -sS -H 'X-Forwarded-For: 203.0.113.50' -o /dev/null -w '%{http_code}' http://127.0.0.1:8095/admin)"
echo "untrusted_admin=$code"
test "$code" = 404
code="$(curl -sS -H 'X-Forwarded-For: 203.0.113.50' -o /dev/null -w '%{http_code}' http://127.0.0.1:8095/access-links/)"
echo "untrusted_management=$code"
test "$code" = 404

echo '=== MANAGEMENT CSRF ==='
curl_base -c "$TMP/broker.cookies" -b "$TMP/broker.cookies" "$BASE/access-links/" -o "$TMP/manage.html"
csrf="$(sed -n 's/.*name="csrf" value="\([a-f0-9]*\)".*/\1/p' "$TMP/manage.html" | head -n1)"
test "${#csrf}" -eq 64
echo 'csrf=OK'

echo '=== CREATE LINK ==='
curl_base \
  -c "$TMP/broker.cookies" -b "$TMP/broker.cookies" \
  -X POST \
  -d "csrf=$csrf" \
  -d 'action=create' \
  -d 'name=integration-test' \
  -d 'kind=admin' \
  -d 'mailbox=' \
  -o /dev/null \
  -w 'create=%{http_code}\n' \
  "$BASE/access-links/"

curl_base -c "$TMP/broker.cookies" -b "$TMP/broker.cookies" "$BASE/access-links/" -o "$TMP/created.html"
link="$(grep -oE 'https://mail\.mailcow\.test:9443/access/[A-Za-z0-9_-]{43}' "$TMP/created.html" | head -n1)"
test -n "$link"
echo 'link_created=OK token_not_printed'

echo '=== USE LINK ==='
code="$(curl_base -A 'MCAB-Link-Test/1' -c "$TMP/link.cookies" -b "$TMP/link.cookies" -o /dev/null -w '%{http_code}' "$link")"
echo "link_use=$code"
test "$code" = 303

id="$(docker compose exec -T broker php -r '$p=new PDO("sqlite:/var/lib/mailcow-access/broker.sqlite3"); echo $p->query("SELECT id FROM links WHERE name=\"integration-test\" ORDER BY id DESC LIMIT 1")->fetchColumn();')"
csrf="$(sed -n 's/.*name="csrf" value="\([a-f0-9]*\)".*/\1/p' "$TMP/created.html" | head -n1)"
curl_base \
  -c "$TMP/broker.cookies" -b "$TMP/broker.cookies" \
  -X POST \
  -d "csrf=$csrf" \
  -d 'action=revoke' \
  -d "id=$id" \
  -o /dev/null \
  "$BASE/access-links/"

code="$(curl_base -o /dev/null -w '%{http_code}' "$link")"
echo "revoked_link=$code"
test "$code" = 404
echo 'integration=PASS'

