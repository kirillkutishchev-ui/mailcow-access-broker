#!/bin/sh
set -eu

SID="${1:?session id required}"
UA="${2:-MCAB-SOGo-Test/1}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -sS -D "$TMP/auth.headers" -o /dev/null \
  -H "Cookie: MCSESSID=$SID" \
  -H "User-Agent: $UA" \
  -H 'X-Original-URI: /SOGo/so/' \
  http://127.0.0.1:65510/sogo-auth

user="$(sed -n 's/^X-User: *//Ip' "$TMP/auth.headers" | tr -d '\r' | head -n1)"
auth="$(sed -n 's/^X-Auth: *//Ip' "$TMP/auth.headers" | tr -d '\r' | head -n1)"
type="$(sed -n 's/^X-Auth-Type: *//Ip' "$TMP/auth.headers" | tr -d '\r' | head -n1)"

test -n "$user"
test -n "$auth"
test -n "$type"

code="$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "x-webobjects-remote-user: $user" \
  -H "Authorization: $auth" \
  -H "x-webobjects-auth-type: $type" \
  -H 'Host: mail.mailcow.test:9443' \
  -H 'x-webobjects-server-protocol: HTTP/1.0' \
  -H 'x-webobjects-remote-host: 172.22.1.1' \
  -H 'x-webobjects-server-name: mail.mailcow.test' \
  -H 'x-webobjects-server-url: https://mail.mailcow.test:9443' \
  -H 'x-webobjects-server-port: 8444' \
  http://172.22.1.248:20000/SOGo/so/)"

echo "direct_sogo_backend=$code"

