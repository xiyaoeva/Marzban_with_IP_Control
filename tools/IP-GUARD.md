# Marzban IP Guard Usage Guide

This guide explains how to run `tools/ip_guard.py` as an external tool for Marzban.

## Scope

- Designed as an external component under `tools/`
- Does not replace Marzban core services
- Uses Marzban API for user status changes when credentials are provided

## Architecture

- Node side: read local access logs and write observations to control-plane DB
- Control side: evaluate policy, disable/recover users, and provide web console

## Requirements

- Python environment with dependencies used by `ip_guard.py`
- Marzban database in MySQL/MariaDB format (`mysql+pymysql://...`)
- Access to Marzban `.env` on control host (default path: `/opt/marzban/.env`)

Note: current implementation supports MySQL URL format only.

## 1) Initialize on Control Host

```bash
cd /opt/marzban
source venv/bin/activate
python tools/ip_guard.py --env-file /opt/marzban/.env init-db
```

This creates policy/state/whitelist/log/offset tables if missing.

## 2) Run Collector on Each Node

Use a DB URL with minimum required permissions.

```bash
export SQLALCHEMY_DATABASE_URL='mysql+pymysql://<DB_USER>:<DB_PASS>@<DB_HOST>:3306/<DB_NAME>'

python /opt/marzban-node/tools/ip_guard.py \
  --sqlalchemy-database-url "$SQLALCHEMY_DATABASE_URL" \
  collect-loop \
  --log-paths /var/lib/marzban-node/access.log \
  --source node-$(hostname) \
  --interval-seconds 60
```

## 3) Run Enforcer + Web on Control Host

```bash
cd /opt/marzban
source venv/bin/activate
python tools/ip_guard.py \
  --env-file /opt/marzban/.env \
  all-control \
  --web-host 127.0.0.1 \
  --web-port 8010 \
  --web-api-key '<YOUR_WEB_API_KEY>'
```

Optional explicit API credentials:

```bash
python tools/ip_guard.py \
  --env-file /opt/marzban/.env \
  --marzban-api-base http://127.0.0.1:8000/api \
  --marzban-admin-username <ADMIN_USER> \
  --marzban-admin-password '<ADMIN_PASS>' \
  all-control \
  --web-host 127.0.0.1 \
  --web-port 8010 \
  --web-api-key '<YOUR_WEB_API_KEY>'
```

## 4) Common Commands

Initialize DB:

```bash
python tools/ip_guard.py --env-file /opt/marzban/.env init-db
```

Collect once (node):

```bash
python tools/ip_guard.py \
  --sqlalchemy-database-url "$SQLALCHEMY_DATABASE_URL" \
  collect-once \
  --log-paths /var/lib/marzban-node/access.log \
  --source node-test
```

Enforce once (control):

```bash
python tools/ip_guard.py --env-file /opt/marzban/.env enforce-once
```

Enforce loop (control):

```bash
python tools/ip_guard.py --env-file /opt/marzban/.env enforce-loop
```

Manual restore:

```bash
python tools/ip_guard.py --env-file /opt/marzban/.env manual-restore --username <USERNAME>
```

Web only:

```bash
python tools/ip_guard.py --env-file /opt/marzban/.env serve --web-host 127.0.0.1 --web-port 8010 --web-api-key '<YOUR_WEB_API_KEY>'
```

## 5) Optional systemd Units

Control unit (`/etc/systemd/system/marzban-ip-guard-control.service`):

```ini
[Unit]
Description=Marzban IP Guard Control (enforcer + web)
After=network-online.target marzban.service
Wants=network-online.target

[Service]
Type=simple
User=<SERVICE_USER>
WorkingDirectory=/opt/marzban
ExecStart=/opt/marzban/venv/bin/python /opt/marzban/tools/ip_guard.py --env-file /opt/marzban/.env all-control --web-host 127.0.0.1 --web-port 8010 --web-api-key <YOUR_WEB_API_KEY>
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Node collector unit (`/etc/systemd/system/marzban-ip-guard-collector.service`):

```ini
[Unit]
Description=Marzban IP Guard Collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/marzban
Environment=SQLALCHEMY_DATABASE_URL=mysql+pymysql://<DB_USER>:<DB_PASS>@<DB_HOST>:3306/<DB_NAME>
ExecStart=/opt/marzban/venv/bin/python /opt/marzban/tools/ip_guard.py --sqlalchemy-database-url ${SQLALCHEMY_DATABASE_URL} collect-loop --log-paths /var/lib/marzban-node/access.log --source node-%H --interval-seconds 60
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## 6) Uninstall

Safe uninstall:

```bash
python tools/ip_guard_uninstall.py --env-file /opt/marzban/.env
```

Drop guard tables too:

```bash
python tools/ip_guard_uninstall.py --env-file /opt/marzban/.env --drop-guard-tables --drop-observations --yes
```

## API Endpoints Used

When API credentials are available, IP Guard uses:

- `POST /api/admin/token`
- `PUT /api/user/{username}`

