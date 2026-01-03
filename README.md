# probablyDNS

`probablyDNS` is a DNS diagnostic tool with a Python CLI and a FastAPI web UI. It is built for debugging real DNS failures: broken delegation, resolver drift, DNSSEC problems, propagation issues, HTTP reachability mismatches, and infrastructure surprises.

## What It Does

- Traces delegation from root to authoritative nameservers
- Compares results across public resolvers
- Collects common DNS records and timing data
- Checks DNSSEC status and deeper validation signals
- Runs reachability and HTTP checks for resolved targets
- Produces a web dashboard and JSON output from the same backend logic

## Requirements

- Python 3.11+
- Public outbound access for:
  - UDP/53
  - TCP/80
  - TCP/443

## Install

From the repo root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt
```

## Run The Web App

Linux/macOS:

```bash
source .venv/bin/activate
uvicorn dns_analyzer.webapp:app --host 127.0.0.1 --port 8000
```

Windows:

```powershell
.\run_webapp.ps1
```

Then open `http://127.0.0.1:8000`.

## Run The CLI

Examples:

```bash
python -m dns_analyzer.cli example.com
python -m dns_analyzer.cli example.com --full-report
python -m dns_analyzer.cli example.com --subdomains --whois
python -m dns_analyzer.cli example.com --full-report --json
python -m dns_analyzer.cli example.com --map
```

Useful flags:

- `--full-report`
- `--json`
- `--markdown`
- `--subdomains`
- `--whois`
- `--history`
- `--split-dns`
- `--cdn`
- `--ptr`
- `--wildcard`
- `--graph`
- `--map`

## Rate Limiting

The FastAPI app includes a built-in in-memory rate limiter for expensive scan endpoints:

- Limit: `10` requests per `60` seconds per client IP
- Paths:
  - `/analyze`
  - `/analyze/full`
  - `/report/json`
  - `/report/markdown`

Environment overrides:

```bash
export PROBABLYDNS_RATE_LIMIT_REQUESTS=10
export PROBABLYDNS_RATE_LIMIT_WINDOW_SECONDS=60
```

Important:

- This limiter is process-local
- If you run multiple workers, each worker keeps its own counter
- For public deployment, also add reverse-proxy rate limiting

## Documentation

- [deployment.md](deployment.md): Linux server deployment and hardening
- [features.md](features.md): Current feature and behavior reference
- [prompt.md](prompt.md): Original project brief and scope
- Source code: [https://github.com/rajangohil99/probablyDNS](https://github.com/rajangohil99/probablyDNS)
