from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import asyncio
import json
import os
import time
from collections import defaultdict, deque

from dns_analyzer.cli import collect_all_data

# Load fun facts
facts_path = os.path.join(os.path.dirname(__file__), 'dns-facts.json')
try:
    with open(facts_path, 'r', encoding='utf-8') as f:
        dns_facts_payload = json.load(f)
except Exception:
    dns_facts_payload = {"dns_facts": []}

app = FastAPI(title="DNS Analyzer", description="Professional DNS diagnostic tool API.")

NO_CACHE_HEADERS = {
    "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}

RATE_LIMIT_REQUESTS = int(os.getenv("PROBABLYDNS_RATE_LIMIT_REQUESTS", "10"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("PROBABLYDNS_RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_PATHS = {"/analyze", "/analyze/full", "/report/json", "/report/markdown"}
rate_limit_lock = asyncio.Lock()
rate_limit_buckets: dict[str, deque[float]] = defaultdict(deque)

class AnalyzeRequest(BaseModel):
    domain: str


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"

@app.middleware("http")
async def disable_cache(request: Request, call_next):
    if request.url.path in RATE_LIMIT_PATHS:
        client_ip = get_client_ip(request)
        now = time.time()

        async with rate_limit_lock:
            bucket = rate_limit_buckets[client_ip]
            cutoff = now - RATE_LIMIT_WINDOW_SECONDS
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= RATE_LIMIT_REQUESTS:
                retry_after = max(1, int(RATE_LIMIT_WINDOW_SECONDS - (now - bucket[0])))
                response = JSONResponse(
                    status_code=429,
                    content={"detail": f"Rate limit exceeded. Try again in {retry_after} seconds."},
                    headers={"Retry-After": str(retry_after)},
                )
                for header, value in NO_CACHE_HEADERS.items():
                    response.headers[header] = value
                response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_REQUESTS)
                response.headers["X-RateLimit-Remaining"] = "0"
                response.headers["X-RateLimit-Reset"] = str(retry_after)
                return response

            bucket.append(now)

    response = await call_next(request)
    for header, value in NO_CACHE_HEADERS.items():
        response.headers[header] = value

    if request.url.path in RATE_LIMIT_PATHS:
        client_ip = get_client_ip(request)
        async with rate_limit_lock:
            bucket = rate_limit_buckets[client_ip]
            response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_REQUESTS)
            response.headers["X-RateLimit-Remaining"] = str(max(0, RATE_LIMIT_REQUESTS - len(bucket)))
            if bucket:
                reset_in = max(0, int(RATE_LIMIT_WINDOW_SECONDS - (time.time() - bucket[0])))
                response.headers["X-RateLimit-Reset"] = str(reset_in)

    return response

@app.get("/", response_class=HTMLResponse)
@app.get("/", response_class=HTMLResponse)
async def get_index():
    facts_js = json.dumps(dns_facts_payload)
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>probablyDNS | DNS diagnostics for resolver issues, DNSSEC failures, and broken delegation</title>
        <meta name="description" content="probablyDNS is a brutally honest DNS diagnostic tool for finding resolver issues, DNSSEC failures, misconfigurations, broken delegation, and infrastructure problems." />
        <meta name="keywords" content="DNS diagnostics, DNSSEC, resolver issues, DNS troubleshooting, propagation checker, delegation trace" />
        <meta property="og:title" content="probablyDNS" />
        <meta property="og:description" content="A brutally honest DNS diagnostic tool that exposes misconfigurations, resolver issues, DNSSEC failures, and infrastructure problems." />
        <meta property="og:type" content="website" />
        <meta name="twitter:card" content="summary_large_image" />
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #0d0d12;
                --bg-elevated: #13131a;
                --card-bg: #16161f;
                --panel: #1c1c27;
                --panel-hover: #222230;
                --text: #f0f0f5;
                --text-secondary: #a0a0b0;
                --muted: #6b6b7a;
                --border: rgba(255,255,255,0.08);
                --border-strong: rgba(255,255,255,0.12);
                --primary: #f0f0f5;
                --accent: #22c55e;
                --accent-glow: rgba(34,197,94,0.15);
                --info: #3b82f6;
                --info-glow: rgba(59,130,246,0.15);
                --danger: #ef4444;
                --danger-glow: rgba(239,68,68,0.15);
                --success: #22c55e;
                --success-glow: rgba(34,197,94,0.15);
                --warning: #eab308;
                --warning-glow: rgba(234,179,8,0.15);
                --terminal: #0a0a0f;
                --shadow: 0 25px 50px -12px rgba(0,0,0,0.5);
                --shadow-lg: 0 35px 60px -15px rgba(0,0,0,0.6);
                --font-mono: 'JetBrains Mono', 'SF Mono', 'Fira Code', 'Consolas', monospace;
                --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            }
            * { box-sizing: border-box; }
            body {
                font-family: var(--font-sans);
                background: var(--bg);
                background-image: 
                    radial-gradient(ellipse 80% 50% at 50% -20%, rgba(34,197,94,0.08), transparent),
                    linear-gradient(to right, rgba(255,255,255,0.02) 1px, transparent 1px),
                    linear-gradient(to bottom, rgba(255,255,255,0.02) 1px, transparent 1px);
                background-size: 100% 100%, 32px 32px, 32px 32px;
                color: var(--text);
                padding: 0;
                margin: 0;
                min-height: 100vh;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }
            .container { max-width: 1400px; margin: 0 auto; }
            h1 { 
                color: var(--text); 
                font-size: clamp(3rem, 7vw, 5rem); 
                text-align: center; 
                margin: 0; 
                letter-spacing: -0.03em;
                font-weight: 700;
                background: linear-gradient(to bottom, #fff, #a0a0b0);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            .site-header {
                position: sticky;
                top: 0;
                z-index: 50;
                border-bottom: 1px solid var(--border);
                background: rgba(13,13,18,0.85);
                backdrop-filter: blur(16px) saturate(180%);
                -webkit-backdrop-filter: blur(16px) saturate(180%);
            }
            .site-header-inner {
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 1.5rem;
                height: 64px;
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 1rem;
            }
            .site-brand {
                display: inline-flex;
                align-items: center;
                gap: 0.75rem;
                text-decoration: none;
                color: inherit;
                transition: opacity 0.2s ease;
            }
            .site-brand:hover { opacity: 0.8; }
            .site-brand-icon {
                width: 36px;
                height: 36px;
                border-radius: 10px;
                background: linear-gradient(135deg, var(--panel) 0%, var(--card-bg) 100%);
                border: 1px solid var(--border-strong);
                display: inline-flex;
                align-items: center;
                justify-content: center;
                color: var(--accent);
                font-family: var(--font-mono);
                font-size: 0.9rem;
                font-weight: 700;
                box-shadow: 0 2px 8px rgba(0,0,0,0.3);
            }
            .site-name { 
                font-family: var(--font-mono); 
                font-size: 1.05rem; 
                font-weight: 600; 
                color: var(--text);
                letter-spacing: -0.02em;
            }
            .site-nav { display: inline-flex; align-items: center; gap: 2rem; }
            .site-nav a { 
                color: var(--muted); 
                text-decoration: none; 
                font-family: var(--font-mono); 
                font-size: 0.85rem;
                font-weight: 500;
                transition: color 0.2s ease;
                letter-spacing: -0.01em;
            }
            .site-nav a:hover { color: var(--text); }
            
            .page-shell { max-width: 1200px; margin: 0 auto; padding: 2rem 1.5rem 3rem 1.5rem; }
            .landing-shell { max-width: 880px; margin: 2rem auto 3rem auto; padding: 0 1.5rem; }
            .landing-shell.hidden { display: none; }
            .status-pill {
                display: inline-flex;
                align-items: center;
                gap: 0.6rem;
                padding: 0.5rem 1rem;
                border-radius: 100px;
                background: var(--panel);
                border: 1px solid var(--border-strong);
                color: var(--text-secondary);
                font-size: 0.8rem;
                font-family: var(--font-mono);
                font-weight: 500;
                letter-spacing: -0.01em;
            }
            .status-dot {
                width: 8px;
                height: 8px;
                border-radius: 100%;
                background: var(--accent);
                box-shadow: 0 0 12px var(--accent), 0 0 4px var(--accent);
                animation: pulse 2s ease-in-out infinite;
            }
            .hero-main { text-align: center; margin-bottom: 2.5rem; }
            .tagline { 
                margin: 1.25rem 0 0 0; 
                color: var(--text-secondary); 
                font-size: 1.15rem; 
                line-height: 1.75; 
                max-width: 600px; 
                margin-inline: auto;
                font-weight: 400;
            }
            .terminal-frame {
                border-radius: 16px;
                border: 1px solid var(--border-strong);
                background: var(--card-bg);
                overflow: hidden;
                box-shadow: var(--shadow-lg);
            }
            .terminal-header {
                display: flex;
                align-items: center;
                gap: 0.5rem;
                padding: 1rem 1.25rem;
                background: var(--terminal);
                border-bottom: 1px solid var(--border);
            }
            .terminal-lights { display: flex; align-items: center; gap: 0.5rem; }
            .terminal-lights span { 
                width: 12px; 
                height: 12px; 
                border-radius: 100%; 
                display: inline-block;
                opacity: 0.9;
            }
            .light-red { background: #ff5f57; }
            .light-yellow { background: #febc2e; }
            .light-green { background: #28c840; }
            .terminal-label { 
                font-size: 0.75rem; 
                color: var(--muted); 
                font-family: var(--font-mono); 
                margin-left: 0.75rem;
                font-weight: 500;
            }
            .terminal-body { padding: 1.5rem 1.5rem 1.75rem 1.5rem; background: var(--terminal); }
            .search-box { display: flex; align-items: center; gap: 1rem; }
            .prompt { 
                display: flex; 
                align-items: center; 
                gap: 0.5rem; 
                color: var(--accent); 
                font-family: var(--font-mono); 
                font-size: 1rem; 
                flex-shrink: 0;
            }
            .prompt strong { font-weight: 600; color: var(--text-secondary); }
            .landing-shell input[type="text"] {
                flex: 1;
                min-width: 0;
                background: transparent;
                border: none;
                outline: none;
                color: var(--text);
                font-family: var(--font-mono);
                font-size: 1rem;
                caret-color: var(--accent);
            }
            .landing-shell input[type="text"]::placeholder { color: var(--muted); }
            .landing-shell button {
                padding: 0.85rem 1.5rem;
                background: var(--accent);
                color: #0a0a0f;
                border: none;
                border-radius: 10px;
                cursor: pointer;
                font-family: var(--font-mono);
                font-size: 0.9rem;
                font-weight: 600;
                flex-shrink: 0;
                transition: all 0.2s ease;
                box-shadow: 0 0 20px var(--accent-glow);
            }
            .landing-shell button:hover { 
                transform: translateY(-1px);
                box-shadow: 0 0 30px var(--accent-glow), 0 4px 12px rgba(0,0,0,0.3);
            }
            .terminal-hint {
                display: flex;
                justify-content: center;
                align-items: center;
                gap: 0.5rem;
                color: var(--muted);
                font-size: 0.8rem;
                margin-top: 1rem;
                font-family: var(--font-mono);
            }
            .terminal-hint kbd {
                padding: 0.25rem 0.5rem;
                border-radius: 6px;
                border: 1px solid var(--border-strong);
                background: var(--panel);
                font-family: var(--font-mono);
                color: var(--text);
                font-size: 0.75rem;
            }
            .example-row {
                display: flex;
                flex-wrap: wrap;
                justify-content: center;
                align-items: center;
                gap: 0.75rem;
                margin-top: 0.75rem;
                color: var(--muted);
                font-size: 0.85rem;
                font-family: var(--font-mono);
            }
            .example-chip {
                padding: 0;
                border: none;
                background: transparent;
                color: var(--text);
                font-family: var(--font-mono);
                font-size: 0.8rem;
                cursor: pointer;
                transition: all 0.2s ease;
                text-decoration: none;
            }
            .example-chip:hover { 
                color: var(--accent);
            }
            .feature-grid { 
                max-width: 1000px; 
                margin: 2.5rem auto 0 auto; 
                display: grid; 
                grid-template-columns: repeat(4, minmax(0, 1fr)); 
                gap: 1rem;
            }
            .feature-card { 
                padding: 1.25rem; 
                border-radius: 14px; 
                background: var(--card-bg); 
                border: 1px solid var(--border); 
                transition: all 0.25s ease;
            }
            .feature-card:hover { 
                background: var(--panel); 
                border-color: var(--border-strong);
                transform: translateY(-2px);
            }
            .feature-icon { 
                font-size: 0.9rem; 
                margin-bottom: 0.85rem; 
                color: var(--accent);
                font-family: var(--font-mono);
                font-weight: 700;
            }
            .feature-card h3 { 
                margin: 0 0 0.5rem 0; 
                color: var(--text); 
                font-size: 0.9rem; 
                font-family: var(--font-mono);
                font-weight: 600;
            }
            .feature-card p { 
                margin: 0; 
                color: var(--text-secondary); 
                line-height: 1.6; 
                font-size: 0.8rem;
            }
            
            .scan-shell { display: none; max-width: 800px; margin: 4rem auto 0 auto; text-align: center; padding: 0 1.5rem; }
            .scan-shell.visible { display: block; }
            .scan-domain { 
                font-size: 2.75rem; 
                font-weight: 700; 
                font-family: var(--font-mono); 
                margin: 1.5rem 0 2.5rem 0;
                background: linear-gradient(to bottom, #fff, #a0a0b0);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            .scan-terminal { 
                border-radius: 16px; 
                border: 1px solid var(--border-strong); 
                background: var(--card-bg); 
                overflow: hidden; 
                text-align: left;
                box-shadow: var(--shadow-lg);
            }
            .scan-terminal-body { padding: 1.75rem 2rem; background: var(--terminal); }
            .scan-step { 
                display: flex; 
                align-items: center; 
                gap: 1rem; 
                padding: 0.65rem 0; 
                font-family: var(--font-mono); 
                font-size: 0.9rem; 
                color: var(--muted);
                transition: color 0.2s ease;
            }
            .scan-step.done { color: var(--accent); }
            .scan-step.active { color: var(--text); }
            .scan-icon { width: 18px; text-align: center; color: inherit; }
            .scan-done { 
                margin-left: auto; 
                color: var(--muted); 
                font-size: 0.8rem;
                opacity: 0.7;
            }
            .scan-status { 
                margin-top: 2.5rem; 
                color: var(--text-secondary); 
                font-family: var(--font-mono);
                font-size: 0.85rem;
            }
            
            .results-grid { 
                display: grid; 
                grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); 
                gap: 1.5rem; 
                display: none; 
                max-width: 1200px; 
                margin: 0 auto;
            }
            .results-grid.visible { display: grid; }
            
            .card { 
                background: var(--card-bg); 
                border-radius: 14px; 
                padding: 1.5rem; 
                border: 1px solid var(--border); 
                box-shadow: 0 4px 20px rgba(0,0,0,0.2);
                transition: border-color 0.2s ease;
            }
            .card:hover { border-color: var(--border-strong); }
            .card h3 { 
                margin-top: 0; 
                color: var(--text); 
                border-bottom: 1px solid var(--border); 
                padding-bottom: 0.85rem; 
                margin-bottom: 1.25rem; 
                font-family: var(--font-mono); 
                font-size: 0.95rem;
                font-weight: 600;
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }
            .card-full { grid-column: 1 / -1; }
            .result-topbar { 
                display: flex; 
                flex-wrap: wrap; 
                align-items: flex-start; 
                justify-content: space-between; 
                gap: 1.5rem; 
                margin-bottom: 2rem;
                padding: 1.5rem;
                background: var(--panel);
                border-radius: 14px;
                border: 1px solid var(--border);
            }
            .result-domain { 
                font-size: 2.5rem; 
                font-weight: 700; 
                font-family: var(--font-mono); 
                margin: 0; 
                line-height: 1;
                background: linear-gradient(to bottom, #fff, #c0c0d0);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            .result-meta { 
                color: var(--muted); 
                font-family: var(--font-mono); 
                font-size: 0.8rem; 
                margin-top: 0.75rem;
            }
            .result-action { 
                padding: 1rem 1.5rem; 
                background: var(--card-bg); 
                color: var(--text); 
                border: 1px solid var(--border-strong); 
                border-radius: 10px; 
                font-family: var(--font-mono); 
                font-size: 0.85rem;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.2s ease;
            }
            .result-action:hover {
                background: var(--panel-hover);
                border-color: var(--accent);
            }
            .status-badge { 
                display: inline-flex; 
                align-items: center; 
                gap: 0.5rem; 
                padding: 0.5rem 1rem; 
                border-radius: 100px; 
                font-family: var(--font-mono); 
                font-size: 0.85rem;
                font-weight: 600;
                border: 1px solid currentColor;
            }
            .status-badge.success { 
                color: var(--success); 
                background: var(--success-glow);
                box-shadow: 0 0 20px var(--success-glow);
            }
            .status-badge.warning { 
                color: var(--warning); 
                background: var(--warning-glow);
                box-shadow: 0 0 20px var(--warning-glow);
            }
            .status-badge.danger { 
                color: var(--danger); 
                background: var(--danger-glow);
                box-shadow: 0 0 20px var(--danger-glow);
            }
            .diagnosis-card { 
                border-left: 4px solid var(--accent); 
                padding: 1.75rem 2rem;
                background: linear-gradient(90deg, var(--accent-glow) 0%, transparent 50%);
            }
            .diagnosis-label { 
                display: flex; 
                align-items: center; 
                gap: 0.85rem; 
                color: var(--text-secondary); 
                font-family: var(--font-mono); 
                font-size: 0.85rem; 
                margin-bottom: 1.25rem; 
                text-transform: uppercase; 
                letter-spacing: 0.08em;
                font-weight: 600;
            }
            .diagnosis-icon { 
                width: 40px; 
                height: 32px; 
                display: inline-flex; 
                align-items: center; 
                justify-content: center; 
                border: 1px solid var(--border-strong); 
                border-radius: 8px; 
                background: var(--panel); 
                color: var(--accent);
                font-family: var(--font-mono);
                font-size: 0.9rem;
            }
            .diagnosis-text { font-size: 1rem; line-height: 1.75; color: var(--text); }
            .notes-card h3 { margin-bottom: 0; }
            .notes-list { margin: 0; padding: 0; list-style: none; }
            .notes-list li { 
                display: flex; 
                gap: 1rem; 
                align-items: flex-start; 
                padding: 1rem 0; 
                border-top: 1px solid var(--border);
            }
            .notes-list li:first-child { border-top: none; }
            .notes-index { 
                width: 26px; 
                height: 26px; 
                border-radius: 8px; 
                background: var(--panel); 
                border: 1px solid var(--border-strong); 
                display: inline-flex; 
                align-items: center; 
                justify-content: center; 
                color: var(--text-secondary); 
                font-family: var(--font-mono); 
                font-size: 0.75rem; 
                flex-shrink: 0;
                font-weight: 600;
            }
            
            pre { 
                background: var(--terminal); 
                padding: 1.25rem; 
                border-radius: 10px; 
                overflow-x: auto; 
                color: var(--accent); 
                margin: 0; 
                font-family: var(--font-mono);
                font-size: 0.85rem;
                border: 1px solid var(--border);
            }
            .badge { 
                padding: 0.3rem 0.7rem; 
                border-radius: 100px; 
                font-size: 0.75rem; 
                font-weight: 600; 
                margin-left: 0.5rem; 
                display: inline-block; 
                font-family: var(--font-mono);
            }
            .badge.success { background: var(--success-glow); color: var(--success); }
            .badge.danger { background: var(--danger-glow); color: var(--danger); }
            .badge.warning { background: var(--warning-glow); color: var(--warning); }
            
            .kv-pair { 
                display: flex; 
                justify-content: space-between; 
                align-items: center;
                margin-bottom: 0.6rem; 
                border-bottom: 1px solid var(--border); 
                padding-bottom: 0.6rem;
            }
            .kv-key { color: var(--text-secondary); font-size: 0.85rem; }
            
            .prog-container { 
                width: 100%; 
                background: var(--panel); 
                border-radius: 6px; 
                overflow: hidden; 
                height: 8px; 
                margin: 6px 0 14px 0;
            }
            .prog-bar { 
                height: 100%; 
                background: linear-gradient(90deg, var(--accent) 0%, #16a34a 100%);
                border-radius: 6px;
                transition: width 0.3s ease;
            }
            .prog-bar.slow { background: linear-gradient(90deg, var(--danger) 0%, #dc2626 100%); }
            
            .scroll-box { 
                max-height: 300px; 
                overflow-y: auto; 
                padding-right: 12px;
            }
            .scroll-box::-webkit-scrollbar { width: 6px; }
            .scroll-box::-webkit-scrollbar-track { background: var(--panel); border-radius: 3px; }
            .scroll-box::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 3px; }
            .scroll-box::-webkit-scrollbar-thumb:hover { background: var(--muted); }
            
            @keyframes pulse {
                0%, 100% { 
                    box-shadow: 0 0 12px var(--accent), 0 0 4px var(--accent);
                    opacity: 1;
                }
                50% { 
                    box-shadow: 0 0 20px var(--accent), 0 0 8px var(--accent);
                    opacity: 0.8;
                }
            }
            
            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(10px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            .animate-fade-in { animation: fadeInUp 0.4s ease-out forwards; }
            
            @media (max-width: 900px) {
                .site-header-inner { 
                    height: auto; 
                    padding: 1rem 1.5rem; 
                    flex-direction: column; 
                    align-items: flex-start;
                    gap: 0.75rem;
                }
                .page-shell { padding-top: 1.5rem; }
                .landing-shell { margin-top: 4rem; }
                .search-box { flex-direction: column; align-items: stretch; gap: 1rem; }
                .prompt { width: 100%; }
                .landing-shell button { width: 100%; }
                .feature-grid { grid-template-columns: 1fr 1fr; margin-top: 3rem; gap: 0.75rem; }
                .scan-shell { margin-top: 4rem; }
                .result-domain { font-size: 2rem; }
                .results-grid { grid-template-columns: 1fr; }
            }
            @media (max-width: 640px) {
                h1 { font-size: 2.5rem; }
                .feature-grid { grid-template-columns: 1fr; }
                .result-topbar { flex-direction: column; }
                .result-action { width: 100%; text-align: center; }
            }
        </style>
    </head>
    <body>
        <header class="site-header">
            <div class="site-header-inner">
                <a href="/" class="site-brand">
                    <span class="site-brand-icon">&gt;_</span>
                    <span class="site-name">probablyDNS</span>
                </a>
                <nav class="site-nav">
                    <a href="/">scan</a>
                    <a href="https://github.com/rajangohil99/probablyDNS" target="_blank" rel="noopener noreferrer">source</a>
                </nav>
            </div>
        </header>
        <div class="page-shell">
        <div class="container">
            <div class="landing-shell" id="landing-shell">
                <div class="hero-main">
                    <div class="status-pill"><span class="status-dot"></span><span>DNS Diagnostics Console</span></div>
                    <h1>probablyDNS</h1>
                    <p class="tagline">Debug DNS like you debug code. Trace delegation chains, compare resolvers, validate DNSSEC.</p>
                </div>
                <form onsubmit="runAnalysis(); return false;">
                    <div class="terminal-frame">
                        <div class="terminal-header">
                            <div class="terminal-lights">
                                <span class="light-red"></span>
                                <span class="light-yellow"></span>
                                <span class="light-green"></span>
                            </div>
                            <span class="terminal-label">terminal</span>
                        </div>
                        <div class="terminal-body">
                            <div class="search-box">
                                <div class="prompt"><span>$</span><strong>probablyDNS</strong></div>
                                <input type="text" id="domain" placeholder="enter domain..." value="google.com" onkeydown="if(event.key==='Enter') runAnalysis()" />
                                <button type="submit">Run Audit</button>
                            </div>
                        </div>
                    </div>
                    <div class="terminal-hint"><kbd>Enter</kbd><span>to run</span></div>
                </form>
                <div class="example-row">
                    <span>Try:</span>
                    <span class="example-chip" role="button" tabindex="0" onclick="setExampleDomain('google.com')" onkeydown="if(event.key==='Enter' || event.key===' ') setExampleDomain('google.com')">google.com</span>
                    <span class="example-chip" role="button" tabindex="0" onclick="setExampleDomain('cloudflare.com')" onkeydown="if(event.key==='Enter' || event.key===' ') setExampleDomain('cloudflare.com')">cloudflare.com</span>
                    <span class="example-chip" role="button" tabindex="0" onclick="setExampleDomain('github.com')" onkeydown="if(event.key==='Enter' || event.key===' ') setExampleDomain('github.com')">github.com</span>
                </div>
                <div class="feature-grid" id="features">
                    <div class="feature-card">
                        <div class="feature-icon">::</div>
                        <h3>Delegation Chain</h3>
                        <p>Trace root to authoritative nameservers and spot broken links quickly.</p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">==</div>
                        <h3>Resolver Comparison</h3>
                        <p>Compare Google, Cloudflare, Quad9, and other resolvers for drift.</p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">##</div>
                        <h3>DNSSEC Validation</h3>
                        <p>Verify signatures and surface expired, missing, or broken key chains.</p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">@@</div>
                        <h3>Infrastructure Signals</h3>
                        <p>Review latency, nameserver spread, HTTP reachability, and raw DNS output.</p>
                    </div>
                </div>
            </div>
            <div class="scan-shell" id="scan-shell">
                <div class="status-pill"><span class="status-dot" style="background:var(--info); box-shadow: 0 0 12px var(--info), 0 0 4px var(--info);"></span><span>Scanning</span></div>
                <div class="scan-domain" id="scan-domain">google.com</div>
                <div class="scan-terminal">
                    <div class="terminal-header">
                        <div class="terminal-lights">
                            <span class="light-red"></span>
                            <span class="light-yellow"></span>
                            <span class="light-green"></span>
                        </div>
                        <span class="terminal-label">dns-audit</span>
                    </div>
                    <div class="scan-terminal-body" id="scan-steps"></div>
                </div>
                <div class="scan-status" id="scan-status">Step 1 of 5</div>
            </div>
            <div id="fun-fact-container" style="display:none; margin: 2rem auto 3rem auto; max-width: 680px; padding: 1.75rem 2rem; background: var(--card-bg); border-radius: 14px; border-left: 4px solid var(--accent); box-shadow: var(--shadow-lg); border: 1px solid var(--border);">
                <div style="font-weight: 600; color: var(--accent); margin-bottom: 1rem; text-align: center; letter-spacing: 0.08em; text-transform: uppercase; font-size: 0.75rem; font-family: var(--font-mono);">Did you know?</div>
                <div id="fun-fact-title" style="font-size: 1.2rem; color: var(--text); margin-bottom: 1rem; text-align: center; font-weight: 600; line-height: 1.4; font-family: var(--font-mono);"></div>
                <div id="fun-fact-desc" style="font-size: 0.95rem; color: var(--text-secondary); line-height: 1.7; text-align: center; margin-bottom: 0.5rem;"></div>
                <div id="fun-fact-extras" style="background: var(--panel); padding: 1rem; border-radius: 10px; margin-top: 1.5rem; display: none; border: 1px solid var(--border);"></div>
            </div>
            <div class="results-grid" id="results"></div>
        </div>
        </div>

        <script>
            const dnsFacts = {{FACTS_JSON}};
            const scanSteps = [
                'Resolving authoritative servers...',
                'Tracing delegation chain...',
                'Comparing public resolvers...',
                'Validating DNSSEC...',
                'Inspecting infrastructure signals...'
            ];

            function focusDomainInput() {
                const domainInput = document.getElementById('domain');
                if (!domainInput) return;
                requestAnimationFrame(() => {
                    domainInput.focus();
                    const valueLength = domainInput.value.length;
                    domainInput.setSelectionRange(valueLength, valueLength);
                });
            }

            function setExampleDomain(domain) {
                const domainInput = document.getElementById('domain');
                domainInput.value = domain;
                focusDomainInput();
            }

            window.addEventListener('DOMContentLoaded', focusDomainInput);

            function renderScanSteps(currentStep, isComplete = false) {
                const stepsHtml = scanSteps.map((step, index) => {
                    const done = index < currentStep || isComplete;
                    const active = index === currentStep && !isComplete;
                    const classes = done ? 'scan-step done' : (active ? 'scan-step active' : 'scan-step');
                    const icon = done ? '&#10003;' : (active ? '&#9711;' : '&#9675;');
                    const doneLabel = done ? '<span class="scan-done">done</span>' : '';
                    return `<div class="${classes}"><span class="scan-icon">${icon}</span><span>${step}</span>${doneLabel}</div>`;
                }).join('');
                document.getElementById('scan-steps').innerHTML = stepsHtml;
                document.getElementById('scan-status').innerText = isComplete ? 'Scan complete. Loading results...' : `Step ${Math.min(currentStep + 1, scanSteps.length)} of ${scanSteps.length}`;
            }

            async function runAnalysis() {
                const domain = document.getElementById('domain').value.trim();
                if (!domain) return;

                document.getElementById('landing-shell').classList.add('hidden');
                document.getElementById('scan-shell').classList.add('visible');
                document.getElementById('scan-domain').innerText = domain;
                const factContainer = document.getElementById('fun-fact-container');
                factContainer.style.display = 'block';
                
                if (dnsFacts && dnsFacts.dns_facts && dnsFacts.dns_facts.length > 0) {
                    const factsArray = dnsFacts.dns_facts;
                    const randomFact = factsArray[Math.floor(Math.random() * factsArray.length)];
                    document.getElementById('fun-fact-title').innerText = randomFact.title || '';
                    document.getElementById('fun-fact-desc').innerText = randomFact.description || '';
                    
                    let extrasHtml = '';
                    for (const [key, value] of Object.entries(randomFact)) {
                        if (['id', 'title', 'description'].includes(key)) continue;
                        
                        let displayKey = key.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
                        let displayVal = Array.isArray(value) ? value.join(', ') : (typeof value === 'object' ? JSON.stringify(value) : value);
                        
                        extrasHtml += `<div style="display: flex; justify-content: space-between; margin-bottom: 0.6rem; border-bottom: 1px solid var(--border); padding-bottom: 0.6rem;">
                            <span style="color: var(--text-secondary); font-size: 0.85rem; font-weight: 600;">${displayKey}</span>
                            <span style="color: var(--text); font-size: 0.85rem; font-family: var(--font-mono); text-align: right; max-width: 60%;">${displayVal}</span>
                        </div>`;
                    }
                    
                    const extrasDiv = document.getElementById('fun-fact-extras');
                    if(extrasHtml) {
                        extrasDiv.innerHTML = extrasHtml;
                        extrasDiv.style.display = 'block';
                    } else {
                        extrasDiv.style.display = 'none';
                    }
                }

                document.getElementById('results').classList.remove('visible');
                document.getElementById('results').innerHTML = '';
                let currentStep = 0;
                renderScanSteps(currentStep);
                const interval = setInterval(() => {
                    currentStep = Math.min(currentStep + 1, scanSteps.length - 1);
                    renderScanSteps(currentStep);
                }, 900);
                
                try {
                    const res = await fetch('/analyze/full?domain=' + encodeURIComponent(domain));
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.detail);
                    
                    let html = '';
                    const issueCount = data.diagnosis?.total_issues || 0;
                    const statusLabel = issueCount === 0 ? 'Healthy' : (issueCount <= 2 ? 'Warning' : 'Broken');
                    const statusClass = issueCount === 0 ? 'success' : (issueCount <= 2 ? 'warning' : 'danger');

                    html += `<div class="result-topbar card-full">
                        <div>
                            <div style="display:flex; align-items:center; gap:0.75rem; flex-wrap:wrap;">
                                <h2 class="result-domain">${domain}</h2>
                                <span class="status-badge ${statusClass}">${statusLabel}</span>
                            </div>
                            <div class="result-meta">Scanned ${new Date().toLocaleString()}</div>
                        </div>
                        <button type="button" class="result-action" onclick="runAnalysis()">Re-scan</button>
                    </div>`;
                    
                    // Service Connectivity Macro Box
                    let connHtml = '<div class="card card-full" style="border-left: 4px solid var(--info);"><h3>Network Connectivity Diagnostics</h3><div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--muted); margin-top:-0.5rem; margin-bottom:1rem;">ping -c 4 ${domain} &amp;&amp; curl -I https://${domain}</div><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">Diagnoses if the target domain is actively responding, and checks if your DNS matches the rest of the world or if you are being actively blocked.</div><div style="display: flex; flex-wrap: wrap; gap: 1rem;">';
                    
                    if (data.provider_dns) {
                        let ok = !data.provider_dns.differs;
                        let provIps = data.provider_dns.results?.['Provider DNS (ns1.provider)']?.join(', ') || 'NXDOMAIN';
                        let pubIps = data.provider_dns.results?.['Google DNS (8.8.8.8)']?.join(', ') || 'NXDOMAIN';
                        connHtml += `<div style="flex:1; min-width: 260px; background:var(--panel); border:1px solid var(--border); padding:1rem; border-radius:10px;"><div class="kv-pair"><span class="kv-key">Provider DNS vs Public</span>
                        ${ok ? '<span class="badge success">MATCH</span>' : '<span class="badge warning">DIFFERS</span>'}</div>
                        <div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom: 0.75rem;">${data.provider_dns.conclusion}</div>
                        <div style="font-size:0.8rem; font-family:var(--font-mono); color:var(--info);">Prov: ${provIps}</div>
                        <div style="font-size:0.8rem; font-family:var(--font-mono); color:var(--text);">Pub:  ${pubIps}</div></div>`;
                    }
                    if (data.dns_filtering) {
                        let fk = !data.dns_filtering.is_filtered;
                        let filterResp = data.dns_filtering.response?.join(', ') || 'No Response';
                        connHtml += `<div style="flex:1; min-width: 260px; background:var(--panel); border:1px solid var(--border); padding:1rem; border-radius:10px;"><div class="kv-pair"><span class="kv-key">DNS Filtering / Sinkhole</span>
                        ${fk ? '<span class="badge success">CLEAN</span>' : '<span class="badge danger">BLOCKED</span>'}</div>
                        <div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom: 0.75rem;">${data.dns_filtering.conclusion}</div>
                        <div style="font-size:0.8rem; font-family:var(--font-mono); color:var(--info);">Resolved IP Yield:</div>
                        <div style="font-size:0.8rem; font-family:var(--font-mono); color:var(--text);">${filterResp}</div></div>`;
                    }
                    if (data.reachability && data.reachability.status !== 'error') {
                        let rk = data.reachability.is_reachable;
                        let reachIp = data.reachability.ip || 'Unknown IP';
                        connHtml += `<div style="flex:1; min-width: 260px; background:var(--panel); border:1px solid var(--border); padding:1rem; border-radius:10px;"><div class="kv-pair"><span class="kv-key">App Reachability</span>
                        ${rk ? '<span class="badge success">OK</span>' : '<span class="badge danger">TIMEOUT</span>'}</div>
                        <div style="font-size:0.85rem; font-family:var(--font-mono); margin-bottom:0.75rem; color:var(--text);">Target: ${reachIp}</div>
                        <div style="font-size:0.8rem; color:var(--text-secondary);">Ping: <span style="font-weight:600; color:${data.reachability.ping === 'successful' ? 'var(--success)' : 'var(--danger)'}">${data.reachability.ping}</span></div>
                        <div style="font-size:0.8rem; color:var(--text-secondary);">TCP 80: <span style="font-weight:600; color:${data.reachability.tcp_80 === 'open' ? 'var(--success)' : 'var(--danger)'}">${data.reachability.tcp_80}</span></div>
                        <div style="font-size:0.8rem; color:var(--text-secondary);">TCP 443: <span style="font-weight:600; color:${data.reachability.tcp_443 === 'open' ? 'var(--success)' : 'var(--danger)'}">${data.reachability.tcp_443}</span></div></div>`;
                    }
                    if (data.http_test) {
                        let hk = data.http_test.status_code === 200;
                        let errStr = data.http_test.possible_cause || data.http_test.message;
                        connHtml += `<div style="flex:1; min-width: 260px; background:var(--panel); border:1px solid var(--border); padding:1rem; border-radius:10px;"><div class="kv-pair"><span class="kv-key">Website HTTP Status</span>
                        ${hk ? '<span class="badge success">200 OK</span>' : `<span class="badge danger">HTTP ${data.http_test.status_code}</span>`}</div>
                        <div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom: 0.75rem;">${errStr}</div>
                        <div style="font-size:0.8rem; color:var(--info);">Server ID: <span style="font-weight:600; color:var(--text);">${data.http_test.server || 'Unknown Container'}</span></div>
                        <div style="font-size:0.8rem; color:var(--info);">TLS Handshake: <span style="font-weight:600; color:var(--text);">${data.http_test.tls_handshake || 'Unknown'}</span></div></div>`;
                    }
                    if (data.vpn_reputation && data.vpn_reputation.status !== 'error') {
                        let vk = !data.vpn_reputation.is_vpn;
                        let cause = data.vpn_reputation.possible_cause || 'Good IP Reputation';
                        connHtml += `<div style="flex:1; min-width: 260px; background:var(--panel); border:1px solid var(--border); padding:1rem; border-radius:10px;"><div class="kv-pair"><span class="kv-key">Local VPN/Exit IP Check</span>
                        ${vk ? '<span class="badge success">CLEAN</span>' : '<span class="badge danger">FLAGGED</span>'}</div>
                        <div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom: 0.75rem;">${cause}</div>
                        <div style="font-size:0.8rem; color:var(--info); font-family:var(--font-mono);">Detected Egress IP: <span style="color:var(--text)">${data.vpn_reputation.ip}</span></div>
                        <div style="font-size:0.8rem; color:var(--info);">ASN: <span style="color:var(--text)">${data.vpn_reputation.asn} - ${data.vpn_reputation.organization}</span></div></div>`;
                    }
                    connHtml += '</div></div>';
                    html += connHtml;

                    // Multi-Resolver Consistency (Global Propagation)
                    if (data.multi_resolver) {
                        let mr = data.multi_resolver;
                        html += `<div class="card card-full"><h3>Global Multi-Resolver Consistency (Propagation)</h3><div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--muted); margin-top:-0.5rem; margin-bottom:1rem;">dig A ${domain} @1.1.1.1 +short &amp;&amp; dig A ${domain} @8.8.8.8 +short &amp;&amp; dig A ${domain} @9.9.9.9 +short</div><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">Checks major DNS operators globally to ensure everyone is being sent to the exact same server IP. If these mismatch, the website recently migrated servers or is experiencing a propagation delay.</div>
                        <div style="display:flex; flex-wrap:wrap; gap:1rem;">`;
                        Object.keys(mr.resolvers).forEach(resName => {
                            let rv = mr.resolvers[resName];
                            html += `<div style="flex:1; min-width:200px; padding:1rem; background:var(--panel); border-radius:10px; border:1px solid var(--border);">
                                <div style="font-weight:600; color:var(--info); font-size:1rem; border-bottom:1px solid var(--border); padding-bottom:0.5rem; margin-bottom:0.75rem; font-family:var(--font-mono);">${resName}</div>`;
                            if (rv.error) {
                                html += `<span class="badge danger">ERROR</span> <span style="font-size:0.85rem">${rv.error}</span>`;
                            } else if (rv.records && rv.records.length > 0) {
                                rv.records.forEach(a => { html += `<div style="font-family:var(--font-mono); font-size:0.9rem; color:var(--text);">${a}</div>`; });
                                html += `<div style="font-size:0.8rem; color:var(--muted); margin-top:0.75rem;">TTL: ${rv.ttl}</div>`;
                            } else {
                                html += `<span style="color:var(--muted);">No Answers</span>`;
                            }
                            html += `</div>`;
                        });
                        html += `</div>
                        <div style="margin-top:1.25rem; text-align:right;">
                            ${!mr.inconsistent ? '<span class="badge success" style="font-size:0.9rem; padding:0.5rem 1rem;">All Key Resolvers Match Globally</span>' : '<span class="badge danger" style="font-size:0.9rem; padding:0.5rem 1rem;">Propagation or Split-Horizon Mismatch Detected</span>'}
                        </div>
                        </div>`;
                    }

                    // Resolution Path Timing Graph
                    if (data.resolve_path && Array.isArray(data.resolve_path)) {
                        html += `<div class="card card-full"><h3>Recursive Trace Timing (Latency bottleneck monitor)</h3><div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--muted); margin-top:-0.5rem; margin-bottom:1rem;">dig +trace ${domain}</div><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">Calculates the exact network latency bottleneck for the entire global DNS lookup chain from the Root nodes down into the final target Authority node. Multiple root providers used.</div><div style="display:flex; flex-wrap:wrap; gap:1rem;">`;
                        
                        data.resolve_path.forEach(r => {
                            html += `<div style="flex:1; min-width:300px; padding:1.25rem; background:var(--panel); border-radius:10px; border:1px solid var(--border);">
                                <div style="font-weight:600; color:var(--info); font-size:1rem; border-bottom:1px solid var(--border); padding-bottom:0.5rem; margin-bottom:0.75rem; font-family:var(--font-mono);">Vantage Point: ${r.provider_name}</div>
                                <div style="font-size:0.8rem; color:var(--muted); margin-bottom:1rem; font-family:var(--font-mono);">Root Server IP: ${r.root_ip}</div>`;
                            
                            const renderP = (lbl, ms) => {
                                if(ms < 0) return '';
                                let cls = ms > 100 ? 'slow' : '';
                                return `<div><div style="display:flex; justify-content:space-between; font-size:0.85rem; margin-top:0.75rem; color:var(--text-secondary);"><span>${lbl}</span><span style="font-weight:600; color:var(--info); font-family:var(--font-mono);">${ms} ms</span></div>
                                <div class="prog-container"><div class="prog-bar ${cls}" style="width: ${Math.min((ms/150)*100, 100)}%"></div></div></div>`;
                            };
                            html += renderP('Root server trace', r.root_latency_ms);
                            html += renderP(`TLD node trace (.${r.tld_name})`, r.tld_latency_ms);
                            html += renderP('Authoritative resolution limit', r.auth_latency_ms);
                            
                            html += `<div style="margin-top:1.25rem; border-top:1px solid var(--border); padding-top:0.75rem;"><strong style="color:var(--text-secondary);">Final IP Yield:</strong></div>`;
                            r.final_answer.forEach(f => {
                                html += `<div style="font-family:var(--font-mono); font-size:1rem; color:var(--text);">${domain} &rarr; <span style="color:var(--accent)">${f}</span></div>`;
                            });
                            
                            html += `<div style="margin-top:1rem; font-size:0.9rem; font-weight:600; text-align:right; background:var(--card-bg); padding:0.75rem; border-radius:8px; border:1px solid var(--border);">Total Accumulative Time: <span style="color:var(--success); font-family:var(--font-mono);">${r.total_resolution_time_ms} ms</span></div>`;
                            r.warnings.forEach(w => {
                                html += `<div class="badge danger" style="margin-left:0; margin-top:0.75rem; width:100%; text-align:center;">${w}</div>`;
                            });
                            html += `</div>`;
                        });
                        html += `</div></div>`;
                    }

                    // Final Diagnosis
                    const leadFinding = data.diagnosis.summary && data.diagnosis.summary.length ? data.diagnosis.summary[0] : null;
                    let diagHtml = '<div class="card card-full diagnosis-card">';
                    diagHtml += `<div class="diagnosis-label"><span class="diagnosis-icon">&gt;_</span><span>Diagnosis</span></div>`;
                    if (leadFinding) {
                        const message = leadFinding.issue === 'None detected.'
                            ? `DNS configuration for ${domain} appears properly configured. ${leadFinding.cause}`
                            : `${leadFinding.issue} ${leadFinding.cause ? leadFinding.cause : ''}`.trim();
                        diagHtml += `<div class="diagnosis-text">${message}</div>`;
                    }
                    diagHtml += '</div>';
                    html += diagHtml;

                    if (data.diagnosis.summary && data.diagnosis.summary.length > 0) {
                        let notesHtml = `<div class="card card-full notes-card"><h3>Operator Notes</h3><ul class="notes-list">`;
                        data.diagnosis.summary.forEach((item, index) => {
                            if (item.issue === 'None detected.') {
                                notesHtml += `<li><span class="notes-index">${index + 1}</span><span>${item.cause}</span></li>`;
                            } else {
                                const note = [item.issue, item.action].filter(Boolean).join(' ');
                                notesHtml += `<li><span class="notes-index">${index + 1}</span><span>${note}</span></li>`;
                            }
                        });
                        notesHtml += `</ul></div>`;
                        html += notesHtml;
                    }




                    // WHOIS
                    if (data.whois) {
                        let w = data.whois;
                        html += `<div class="card"><h3>WHOIS & Domain Age</h3><div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--muted); margin-top:-0.5rem; margin-bottom:1rem;">whois ${domain}</div><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">Shows who officially registered the domain and when it expires. If a target is offline, check if they forgot to pay for their domain renewal!</div>
                        <div class="kv-pair"><span class="kv-key">Registrar</span><span style="font-weight:600; color:var(--text); text-align:right;">${w.registrar}</span></div>
                        <div class="kv-pair"><span class="kv-key">Creation Date</span><span style="color:var(--text);">${w.creation_date}</span></div>
                        <div class="kv-pair"><span class="kv-key">Expiration Date</span><span style="color:var(--text);">${w.expiration_date}</span></div>
                        <div class="kv-pair"><span class="kv-key">Days to Expiry</span><span style="color:var(--text);">${w.days_to_expiry} days</span></div>
                        ${w.expiry_warning ? `<div class="badge danger" style="margin-top:1rem; display:block; text-align:center;">CRITICAL: Domain Expiring Soon!</div>` : '<div class="badge success" style="margin-top:1rem; display:block; text-align:center;">Renewal Status Healthy</div>'}
                        </div>`;
                    }



                    // Deep DNSSEC
                    if (data.deep_dnssec) {
                        const d = data.deep_dnssec;
                        html += `<div class="card"><h3>DNSSEC Cryptographic Validation</h3><div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--muted); margin-top:-0.5rem; margin-bottom:1rem;">delv @8.8.8.8 +dnssec ${domain}</div><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">DNSSEC acts like a digital signature to guarantee a hacker didn't fake your DNS query. If validation fails, traffic might be actively hijacked.</div>
                        <div class="kv-pair"><span class="kv-key">Root Node</span><span style="color:var(--text);">${d.root_signed ? 'SIGNED':'UNSIGNED'}</span></div>
                        <div class="kv-pair"><span class="kv-key">TLD Node (.${d.tld})</span><span style="color:var(--text);">${d.tld_signed ? 'SIGNED':'UNSIGNED'}</span></div>
                        <div class="kv-pair"><span class="kv-key">Domain (${domain})</span><span style="color:var(--text);">${d.domain_signed ? 'SIGNED':'UNSIGNED'}</span></div>
                        
                        <div style="margin-top:1.5rem; text-align:center;">
                            <strong style="color:var(--text-secondary);">Validation Result:</strong><br>
                            <div style="margin-top:0.75rem;">
                                ${d.status === 'SUCCESS' ? '<span class="badge success" style="font-size:0.9rem; padding: 0.5rem 1rem;">CRYPTO VERIFIED</span>' : 
                                  d.status === 'DNSSEC not enabled' ? '<span class="badge" style="background:var(--panel); color:var(--text-secondary); font-size:0.9rem; padding: 0.5rem 1rem; border:1px solid var(--border);">NOT ENABLED</span>' :
                                '<span class="badge danger" style="font-size:0.9rem; padding: 0.5rem 1rem;">VALIDATION FAILED</span>'}
                            </div>
                        </div>
                        ${d.reason ? `<div style="margin-top:1rem; text-align:center; color:${d.status === 'DNSSEC not enabled' ? 'var(--muted)' : 'var(--danger)'}; font-size:0.85rem;">${d.reason}</div>` : ''}
                        ${d.impact ? `<div style="margin-top:0.5rem; text-align:center; color:var(--muted); font-size:0.8rem;">[Impact] ${d.impact}</div>` : ''}
                        </div>`;
                    }

                    // Infrastructure Fingerprint
                    if (data.infra_fingerprint) {
                        const fp = data.infra_fingerprint;
                        html += `<div class="card"><h3>Infrastructure Signatures</h3><div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--muted); margin-top:-0.5rem; margin-bottom:1rem;">dig +short NS ${domain} | xargs -I {} dig +short @{} ${domain}</div><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">Attempts to detect which enterprise vendors the target relies on to host their underlying networking logic.</div>
                        <div class="kv-pair"><span class="kv-key">Nameserver Platform</span><span style="font-weight:600; color:var(--text);">${fp.nameserver_provider}</span></div>
                        <div class="kv-pair"><span class="kv-key">Hosting Pipeline</span><span style="font-weight:600; color:var(--text);">${fp.hosting_provider}</span></div>
                        <div class="kv-pair"><span class="kv-key">Email Exchanger</span><span style="font-weight:600; color:var(--text);">${fp.email_provider}</span></div>
                        <div class="kv-pair"><span class="kv-key">CDN / WAF</span><span style="font-weight:600; color:var(--text);">${fp.cdn_provider}</span></div>
                        </div>`;
                    }
                    
                    // Network Ownership (ASN Ledger)
                    if (data.asn_lookup && data.asn_lookup.results && data.asn_lookup.results.length > 0) {
                        html += `<div class="card"><h3>Endpoint Network Ownership (ASN)</h3><div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--muted); margin-top:-0.5rem; margin-bottom:1rem;">whois -h whois.cymru.com " -v [IP_ADDRESS]"</div><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">Queries the BGP global routing table to find the official physical corporation that physically owns the hosting IP space.</div><div class="scroll-box">`;
                        data.asn_lookup.results.forEach(net => {
                            html += `<div style="margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.75rem;">
                                <div style="font-family: var(--font-mono); font-size:1rem; font-weight: 600; color: var(--text)">${net.ip}</div>
                                <div style="font-size: 0.9rem; color: var(--text-secondary); margin-top:0.4rem;">ASN: <span style="color:var(--info)">${net.asn}</span></div>
                                <div style="font-size: 0.9rem; color: var(--text-secondary);">Org: <span style="font-weight:600; color:var(--text);">${net.organization}</span></div>
                                <div style="font-size: 0.8rem; color: var(--muted); margin-top:0.3rem;">Country: ${net.country}</div>
                            </div>`;
                        });
                        html += `</div></div>`;
                    }

                    // Subdomains
                    if (data.subdomains && data.subdomains.length > 0) {
                        html += `<div class="card"><h3>Discovered Subdomains</h3><div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--muted); margin-top:-0.5rem; margin-bottom:1rem;">nmap -sV --script dns-brute ${domain}</div><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">Attempts to map out hidden development, corporate, or API backend nodes running underneath the main network.</div><div class="scroll-box">`;
                        data.subdomains.forEach(sub => {
                            let link = "https://" + sub.subdomain;
                            html += `<div style="margin-bottom: 0.75rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem;">
                                <div style="font-family:var(--font-mono); font-size:0.95rem;"><a href="${link}" target="_blank" style="color:var(--info); text-decoration:none; transition: color 0.2s;" onmouseover="this.style.color='var(--accent)'" onmouseout="this.style.color='var(--info)'">${sub.subdomain}</a></div>
                                <div style="color:var(--muted); font-size:0.8rem; font-family:var(--font-mono); margin-top:0.3rem;">&rarr; ${sub.ips.join(', ')}</div>
                            </div>`;
                        });
                        html += `</div></div>`;
                    }

                    // Reverse DNS (PTR)
                    if (data.reverse_dns && data.reverse_dns.results) {
                        let rev = data.reverse_dns;
                        html += `<div class="card"><h3>Reverse DNS (PTR) Consistency</h3><div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--muted); margin-top:-0.5rem; margin-bottom:1rem;">dig +short -x [IP_ADDRESS]</div><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">Queries the literal IP address in reverse to see if it mathematically resolves back to the original domain name. Crucial for proper Email delivery.</div><div class="scroll-box">`;
                        rev.results.forEach(r => {
                            html += `<div style="margin-bottom: 0.75rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem;">
                                <div style="font-family:var(--font-mono); font-weight:600; font-size:0.95rem; color:var(--text);">${r.ip}</div>
                                <div style="font-size:0.9rem; color:var(--info); font-family:var(--font-mono); margin-top:0.3rem;">PTR: ${r.ptr_records?.join(', ') || 'None Provided'}</div>
                                <div style="font-size:0.8rem; margin-top:0.4rem; color:var(--text-secondary)">Forward Match Binding: ${r.forward_match ? '<span class="badge success">TRUE</span>' : '<span class="badge danger">FALSE</span>'}</div>
                            </div>`;
                        });
                        html += `</div></div>`;
                    }

                    // Wildcard & CDN Macros (Card removed per user request)

                    // Resolution Path block intentionally deleted (Moved above Final Diagnosis)
                    // VPN and Internal DNS Diagnostics
                    if (data.vpn_ext) {
                        const ve = data.vpn_ext;
                        
                        // 1. DNS Leak
                        if (ve.leak) {
                           let l = ve.leak;
                           let bdg = l.status === 'warning' ? 'danger' : 'success';
                           let badge_text = l.status === 'warning' ? 'LEAK DETECTED' : 'CLEAN';
                           html += `<div class="card"><h3>DNS Leak Test</h3><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">Detects if your system is leaking DNS queries to external public resolvers instead of your secure VPN tunnel.</div>
                           <div class="kv-pair"><span class="kv-key">Resolver IP</span><span style="font-family:var(--font-mono); color:var(--text);">${l.resolver_ip}</span></div>
                           <div class="kv-pair"><span class="kv-key">ASN / ISP</span><span style="color:var(--text);">${l.asn} (${l.organization})</span></div>
                           <div class="kv-pair"><span class="kv-key">Status</span><span class="badge ${bdg}">${badge_text}</span></div>
                           ${l.warning ? `<div class="badge danger" style="margin-left:0; margin-top:0.75rem; width:100%; text-align:center;">${l.warning}</div>` : ''}
                           </div>`;
                        }

                        // 2. DNS Filtering / Sinkhole
                        if (ve.filter) {
                           let f = ve.filter;
                           let bdg = f.status === 'warning' ? 'danger' : 'success';
                           let badge_text = f.status === 'warning' ? 'FILTERED' : 'CLEAN';
                           html += `<div class="card"><h3>DNS Filtering / Sinkhole Detection</h3><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">Checks if public resolvers are actively censoring or sinkholing this domain compared to its authoritative zone.</div>
                           <div class="kv-pair"><span class="kv-key">Expected IP</span><span style="font-family:var(--font-mono); color:var(--text);">${f.expected_ip}</span></div>
                           <div class="kv-pair"><span class="kv-key">Returned IP</span><span style="font-family:var(--font-mono); color:var(--text);">${f.returned_ip}</span></div>
                           <div class="kv-pair"><span class="kv-key">Status</span><span class="badge ${bdg}">${badge_text}</span></div>
                           <div style="font-size:0.85rem; color:var(--info); margin-top:0.75rem;">${f.result}</div>
                           </div>`;
                        }
                        
                        // 3. DNS Hijacking
                        if (ve.hijack) {
                           let h = ve.hijack;
                           let bdg = h.status === 'safe' ? 'success' : (h.status === 'error' ? 'warning' : 'danger');
                           let badge_text = h.status === 'safe' ? 'CLEAN' : (h.status === 'error' ? 'ERROR' : 'HIJACKED');
                           html += `<div class="card"><h3>DNS Hijacking Detection</h3><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">Probes the network for transparent DNS proxies forcibly intercepting outbound UDP/53 traffic.</div>
                           <div class="kv-pair"><span class="kv-key">Query target</span><span style="font-family:var(--font-mono); color:var(--text);">${h.query_sent_to}</span></div>
                           <div class="kv-pair"><span class="kv-key">Responded by</span><span style="font-family:var(--font-mono); color:var(--text);">${h.response_received_from}</span></div>
                           <div class="kv-pair"><span class="kv-key">Status</span><span class="badge ${bdg}">${badge_text}</span></div>
                           <div style="font-size:0.85rem; color:var(--warning); margin-top:0.75rem;">${h.result}</div>
                           </div>`;
                        }
                        
                        // 4. Resolver Capabilities
                        if (ve.capabilities) {
                           let c = ve.capabilities;
                           html += `<div class="card"><h3>Resolver Capabilities</h3><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">Tests the underlying protocol options supported by your outbound DNS infrastructure.</div>
                           <div class="kv-pair"><span class="kv-key">Target Resolver</span><span style="font-family:var(--font-mono); color:var(--text);">${c.resolver}</span></div>
                           <div class="kv-pair"><span class="kv-key">Recursion</span><span>${c.recursion === 'enabled' ? '<span class="badge success">ENABLED</span>' : '<span class="badge danger">DISABLED</span>'}</span></div>
                           <div class="kv-pair"><span class="kv-key">DNSSEC Validation</span><span>${c.dnssec_validation === 'supported' ? '<span class="badge success">SUPPORTED</span>' : '<span class="badge warning">UNSUPPORTED</span>'}</span></div>
                           <div class="kv-pair"><span class="kv-key">EDNS Support</span><span>${c.edns === 'supported' ? '<span class="badge success">YES</span>' : '<span class="badge danger">NO</span>'}</span></div>
                           <div class="kv-pair"><span class="kv-key">Max UDP Payload</span><span style="font-family:var(--font-mono); color:var(--text);">${c.max_udp_size} bytes</span></div>
                           </div>`;
                        }

                        // 5. Resolver Benchmark
                        if (ve.benchmark && ve.benchmark.benchmark) {
                            html += `<div class="card card-full"><h3>Public Resolver Performance Benchmark</h3><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">Races standard DNS operators globally to find the fastest response times from your exact network vantage point.</div><div style="display:flex; flex-wrap:wrap; gap:1rem;">`;
                            ve.benchmark.benchmark.forEach((b, idx) => {
                                let timeColor = b.latency.includes("Timeout") ? "var(--danger)" : "var(--success)";
                                if(idx === 0 && !b.latency.includes("Timeout")) timeColor = "var(--accent)"; // fastest
                                html += `<div style="flex:1; background:var(--panel); padding:1.25rem; border-radius:10px; min-width:200px; text-align:center; border: 1px solid var(--border);">
                                <div style="color:var(--text); font-weight:600; margin-bottom:0.75rem; font-family:var(--font-mono);">${b.name}</div>
                                <div style="font-size:1.5rem; font-weight:700; color:${timeColor}; font-family:var(--font-mono);">${b.latency}</div>
                                </div>`;
                            });
                            html += `</div></div>`;
                        }
                    }

                    // DNS Map Tree
                    if (data.map && data.map.text_map) {
                        html += `<div class="card card-full"><h3>Full Graphical Dependency Map</h3><div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--muted); margin-top:-0.5rem; margin-bottom:1rem;">dnsenum ${domain}</div><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">A raw diagnostic system topology tree explicitly mapping out exactly how everything correlates to each other underneath the surface.</div>
                        <pre>${data.map.text_map}</pre>
                        </div>`;
                    }

                    // Resolver Comparison Tables module (Detailed Record Types)
                    if (data.resolver_compare) {
                        data.resolver_compare.forEach(rc => {
                            let srcHtml = `<div class="card card-full"><h3>DNS Source Comparison: <span style="color:var(--accent);">${rc.record_type} Record</span></h3><div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--muted); margin-top:-0.5rem; margin-bottom:1rem;">dig ${rc.record_type} ${domain} @[RESOLVER_IP]</div><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">Granular matrix explicitly polling the top public resolvers for differing TTLs (Time-To-Live drop caches) or conflicting route answers.</div>`;
                            srcHtml += `<table style="width:100%; text-align:left; border-collapse: collapse; margin-bottom: 1rem;">
                                <thead>
                                    <tr style="border-bottom: 1px solid var(--border); color: var(--info);">
                                        <th style="padding: 0.75rem; font-weight:600;">Resolver</th>
                                        <th style="padding: 0.75rem; font-weight:600;">Answers</th>
                                        <th style="padding: 0.75rem; font-weight:600;">TTL</th>
                                        <th style="padding: 0.75rem; font-weight:600;">Query Time</th>
                                    </tr>
                                </thead>
                                <tbody>`;
                            rc.results.forEach(res => {
                                let ans = (res.answers && res.answers.length > 0) ? res.answers.join('<br>') : '<span style="color:var(--muted)">None / NXDOMAIN</span>';
                                srcHtml += `<tr style="border-bottom: 1px solid var(--border);">
                                    <td style="padding: 0.75rem;"><strong style="color:var(--text);">${res.resolver}</strong><br><span style="font-size:0.75rem; color:var(--muted)">${res.server}</span></td>
                                    <td style="padding: 0.75rem; font-family:var(--font-mono); font-size:0.9rem; color:var(--text);">${ans}</td>
                                    <td style="padding: 0.75rem; font-size:0.85rem; color:var(--text-secondary);">${res.ttl}</td>
                                    <td style="padding: 0.75rem; font-size:0.85rem; color:var(--text-secondary);">${res.latency_ms} ms</td>
                                </tr>`;
                            });
                            srcHtml += `</tbody></table>
                            <div style="background:var(--panel); border-left:4px solid var(--accent); padding:1rem 1.25rem; border-radius:8px;">
                                <h4 style="margin:0 0 0.5rem 0; color:var(--text); font-family:var(--font-mono); font-size:0.9rem;">Resolver Analysis</h4>
                                <div style="font-size:0.9rem; color:var(--text-secondary);">${rc.analysis}</div>
                                ${rc.possible_cause ? `<div style="margin-top:0.5rem; font-size:0.85rem; color:var(--warning);"><strong>Possible cause:</strong> ${rc.possible_cause}</div>` : ''}
                            </div>
                            </div>`;
                            html += srcHtml;
                        });
                    }

                    // Dig Results (Moved to absolute Bottom)
                    if (data.dig && data.dig.queries) {
                        html += `<div class="card card-full"><h3>Raw Terminal Simulation Sandbox (Dig Records)</h3><div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--muted); margin-top:-0.5rem; margin-bottom:1rem;">dig ${domain} ANY</div><div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem;">Direct low-level UNIX console output strings for advanced manual sysadmin investigation if GUI widgets aren't explicit enough.</div><div>`;
                        data.dig.queries.forEach(q => {
                            if(q.status === 'success' && q.answers && q.answers.length > 0) {
                                html += `<div style="margin-bottom: 1.25rem; background:var(--terminal); padding:1.25rem; border-radius:10px; border-left:4px solid var(--info); border:1px solid var(--border);">
                                    <div style="font-family:var(--font-mono); font-size:0.9rem; color:var(--accent); margin-bottom:0.75rem;">> dig ${domain} ${q.type}</div>
                                    <div style="font-weight:600; color:var(--text); font-size:0.95rem; margin-bottom:0.5rem; font-family:var(--font-mono);">;; ANSWER SECTION:</div>`;
                                q.answers.forEach(a => {
                                    html += `<div style="font-family:var(--font-mono); font-size:0.9rem; padding:2px 0; color:var(--text);">${domain}.    ${q.ttl}    IN    ${q.type}    ${a}</div>`;
                                });
                                html += `<div style="font-family:var(--font-mono); font-size:0.8rem; color:var(--muted); margin-top:1rem;">;; Query time: ${q.query_time_ms} msec</div>
                                </div>`;
                            }
                        });
                        html += `</div></div>`;
                    }

                    document.getElementById('results').innerHTML = html;
                    document.getElementById('results').classList.add('visible');
                    renderScanSteps(scanSteps.length - 1, true);
                } catch (err) {
                    clearInterval(interval);
                    document.getElementById('results').innerHTML = `<div class="card card-full"><p class="error" style="color:var(--danger)">Error: ${err.message}</p></div>`;
                    document.getElementById('results').classList.add('visible');
                } finally {
                    clearInterval(interval);
                    document.getElementById('fun-fact-container').style.display = 'none';
                    setTimeout(() => {
                        document.getElementById('scan-shell').classList.remove('visible');
                    }, 500);
                }
            }
        </script>
    </body>
    </html>
    """
    html_content = html_content.replace("{{FACTS_JSON}}", facts_js)
    return HTMLResponse(content=html_content, headers=NO_CACHE_HEADERS)

@app.get("/analyze/full")
async def analyze_domain_full(domain: str):
    try:
        results = await collect_all_data(
            domain,
            run_subdomains=True,
            run_whois=True,
            run_history=True,
            run_split=True,
            run_cdn=True,
            run_ptr=True,
            run_wildcard=True,
            run_graph=True,
            run_map=True,
            run_infra=True,
            run_deep_audit=True
        )
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analyze")
async def analyze_domain(domain: str):
    try:
        results = await collect_all_data(domain)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/report/json")
async def report_json(domain: str):
    return await analyze_domain_full(domain)
    
@app.get("/report/markdown")
async def report_markdown(domain: str):
    return "See JSON output"

