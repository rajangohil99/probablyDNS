import asyncio
import urllib.request
import urllib.error
import ssl
from typing import Dict, Any

def sync_http_check(domain: str) -> Dict[str, Any]:
    url = f"https://{domain}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=3.0) as response:
            server = response.headers.get('Server', 'unknown')
            return {
                "status_code": response.getcode(),
                "server": server,
                "tls_handshake": "successful",
                "message": "reachable",
                "possible_cause": None
            }
    except urllib.error.HTTPError as e:
        server = e.headers.get('Server', 'unknown')
        return {
            "status_code": e.code,
            "server": server,
            "tls_handshake": "successful",
            "message": "Blocked or Forbidden" if e.code in (403, 429) else f"HTTP Error {e.code}",
            "possible_cause": "CDN blocking VPN or IP range." if e.code in (403, 429) else None
        }
    except Exception as e:
        return {
            "status_code": 0,
            "server": "unknown",
            "tls_handshake": "failed",
            "message": str(e)[:50],
            "possible_cause": "Network routing issue or TLS failure."
        }

async def check_http(domain: str) -> Dict[str, Any]:
    """Test HTTP website resolution to spot VPN CDN blocking natively"""
    return await asyncio.to_thread(sync_http_check, domain)
