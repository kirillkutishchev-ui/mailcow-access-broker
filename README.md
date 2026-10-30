# Mailcow Access Broker

An isolated access layer for an existing Mailcow installation. It does not patch
Mailcow source code or store administrator/mailbox passwords.

## Features

- trusted-IP login into the existing Mailcow superadmin account;
- reusable, non-expiring, revocable admin links;
- reusable mailbox links that preselect an active mailbox but still require its password;
- the generic mailbox login page is blocked; the mailbox identity is taken only from the link;
- management UI at `/access-links/`, available only from trusted admin IP ranges;
- 90-day application audit log (label, IP, time, result, mailbox, creator/revoker);
- native Mailcow `MCSESSID` sessions in the existing Redis;
- only token SHA-256 hashes are stored; raw links are displayed once;
- invalid/revoked tokens and unauthorized `/admin` requests return `404`.

## Security boundary

The broker uses read-only queries against Mailcow MariaDB to validate the configured
superadmin and mailbox status. Its only write into Mailcow infrastructure is a normal,
short-lived PHP session in Redis. Link metadata and audit records live in a separate
SQLite volume.

Mailcow's own one-click mailbox access is used. Set `ALLOW_ADMIN_EMAIL_LOGIN=y` in
`mailcow.conf` and recreate the affected Mailcow containers. Never store the Mailcow
admin password in this project.

## Local lab

Run from WSL:

```sh
cd /mnt/c/Users/Вале/Documents/Codex/mailcow-access-broker
chmod +x scripts/configure-local.sh
./scripts/configure-local.sh /opt/mailcow-lab/mailcow-dockerized
docker compose --profile local up -d --build
docker compose --profile local ps
```

Open `https://mail.mailcow.test:9443/admin` for trusted-IP auto-login and
`https://mail.mailcow.test:9443/access-links/` to manage links.

The local gateway and local DNS/WSL workarounds are test-only. Production uses the
existing system Nginx and `nginx/mailcow-access.conf.example`.

## Production invariants

- keep this project in a separate repository and directory (for example `/opt/mailcow-access`);
- do not commit `.env`, tokens, SQLite data, certificates, Mailcow secrets, or WSL DNS changes;
- bind broker HTTP only to `127.0.0.1`;
- use `TRUSTED_ADMIN_CIDRS=95.32.153.147/32`;
- set `MAILCOW_ADMIN_USERNAME=plusvibeadmin2007`;
- preserve Mailcow volumes, database, accounts, TLS files and local Postfix changes;
- never run `docker compose down -v`, volume prune, or a destructive Git reset.

