# Linux Deployment Guide

This guide deploys `probablyDNS` on a Linux server behind `systemd` and optional `nginx`.

## Overview

Recommended production shape:

1. Run the FastAPI app on `127.0.0.1:8000`
2. Put `nginx` in front of it
3. Terminate TLS at `nginx`
4. Add reverse-proxy rate limiting
5. Use a single app worker if you want the built-in in-memory limiter to be exact

## Prerequisites

- Ubuntu/Debian-like Linux server
- Python 3.11+
- `git`
- `nginx` if exposing publicly
- Outbound network access for:
  - UDP/53
  - TCP/80
  - TCP/443

## 1. Copy The Project

Example target path:

```bash
sudo mkdir -p /opt/probablyDNS
sudo chown "$USER":"$USER" /opt/probablyDNS
cd /opt/probablyDNS
git clone <your-repo-url> .
```

## 2. Create The Virtual Environment

```bash
cd /opt/probablyDNS
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## 3. Test The App Manually

```bash
cd /opt/probablyDNS
source .venv/bin/activate
uvicorn dns_analyzer.webapp:app --host 127.0.0.1 --port 8000
```

From the server:

```bash
curl -I http://127.0.0.1:8000/
```

## 4. Configure Environment Variables

Optional rate-limit overrides:

```bash
export PROBABLYDNS_RATE_LIMIT_REQUESTS=10
export PROBABLYDNS_RATE_LIMIT_WINDOW_SECONDS=60
```

For `systemd`, put them in the service file instead of relying on shell exports.

## 5. Create A systemd Service

Create `/etc/systemd/system/probablydns.service`:

```ini
[Unit]
Description=probablyDNS web application
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/probablyDNS
Environment=PROBABLYDNS_RATE_LIMIT_REQUESTS=10
Environment=PROBABLYDNS_RATE_LIMIT_WINDOW_SECONDS=60
ExecStart=/opt/probablyDNS/.venv/bin/python -m uvicorn dns_analyzer.webapp:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Then enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable probablydns
sudo systemctl start probablydns
sudo systemctl status probablydns
```

Logs:

```bash
journalctl -u probablydns -f
```

## 6. Add nginx

Install:

```bash
sudo apt update
sudo apt install -y nginx
```

Example server block:

```nginx
server {
    listen 80;
    server_name your-domain.example;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable it:

```bash
sudo ln -s /etc/nginx/sites-available/probablydns /etc/nginx/sites-enabled/probablydns
sudo nginx -t
sudo systemctl reload nginx
```

## 7. Add Reverse-Proxy Rate Limiting

The app already limits expensive scan routes to `10` requests per minute per IP, but for public traffic you should also rate-limit in `nginx`.

Example:

```nginx
limit_req_zone $binary_remote_addr zone=probablydns_scan:10m rate=10r/m;

server {
    listen 80;
    server_name your-domain.example;

    location ~ ^/(analyze|report/) {
        limit_req zone=probablydns_scan burst=5 nodelay;
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Notes:

- App-level limiter is in-memory and per process
- If you run multiple Uvicorn workers, limits are no longer globally exact
- Use one app worker plus `nginx` rate limiting for predictable public behavior

## 8. Add TLS

If your server is public, use Let’s Encrypt:

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.example
```

## 9. Validate The Deployment

From another machine:

```bash
curl -I https://your-domain.example/
curl "https://your-domain.example/analyze?domain=example.com"
```

Check:

- `200` for the UI
- `429` after repeated API abuse
- `X-Forwarded-For` reaches the app through `nginx`

## 10. Maintenance

Restart:

```bash
sudo systemctl restart probablydns
```

Stop:

```bash
sudo systemctl stop probablydns
```

Follow logs:

```bash
journalctl -u probablydns -f
```

## Cleanup

Project cleanup examples:

```bash
find /opt/probablyDNS -type d -name __pycache__ -prune -exec rm -rf {} +
find /opt/probablyDNS -type f -name ".dns_history.json" -delete
```
