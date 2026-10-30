#!/bin/sh
set -eu

install -d -o www-data -g www-data -m 0700 /var/lib/mailcow-access
exec "$@"

