import asyncio
import urllib.request
from typing import Dict, Any
from dns_analyzer.asn_lookup import lookup_asn

async def check_vpn_reputation() -> Dict[str, Any]:
    """Identify if the executing system runs on a known VPN/Cloud ASN that triggers web blocks."""
    try:
        req = urllib.request.Request("https://api.ipify.org")
        ip = (await asyncio.to_thread(urllib.request.urlopen, req, timeout=3.0)).read().decode('utf-8')
        
        asn_data = await lookup_asn(ip)
        
        org = asn_data.get("organization", "").lower()
        is_vpn = any(k in org for k in ["vpn", "proxy", "hosting", "cloud", "digitalocean", "linode", "amazon", "google", "microsoft", "ovh", "hetzner"])
        
        return {
            "status": "success",
            "ip": ip,
            "asn": asn_data.get("asn", "Unknown"),
            "organization": asn_data.get("organization", "Unknown"),
            "reputation": "flagged as VPN/Hosting network" if is_vpn else "clean",
            "is_vpn": is_vpn,
            "possible_cause": "Website may block traffic from VPN ranges." if is_vpn else None
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}
