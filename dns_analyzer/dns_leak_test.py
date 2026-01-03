import asyncio
import dns.asyncresolver
import dns.message
import dns.asyncquery
import dns.rdatatype
from typing import Dict, Any

async def get_asn_info(ip: str) -> Dict[str, str]:
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = ['8.8.8.8']
        parts = ip.split('.')
        parts.reverse()
        arpa = '.'.join(parts) + '.origin.asn.cymru.com'
        answers = await resolver.resolve(arpa, 'TXT')
        if answers:
            txt = answers[0].to_text().strip('"')
            parts = txt.split('|')
            asn = parts[0].strip()
            return {"asn": f"AS{asn}", "org": "Unknown/Cymru (Need IPWhois for granular Org)"}
    except Exception:
        pass
    return {"asn": "Unknown", "org": "Unknown"}

async def run_dns_leak_test() -> Dict[str, Any]:
    try:
        # o-o.myaddr.l.google.com TXT returns the resolver IP that reached Google
        resolver = dns.asyncresolver.Resolver()
        answers = await resolver.resolve('o-o.myaddr.l.google.com', 'TXT')
        resolver_ip = answers[0].to_text().strip('"')
        
        asn_info = await get_asn_info(resolver_ip)
        
        warning = ""
        # Very basic heuristic: if it's a known massive public resolver, might be a leak if user expects VPN
        if asn_info["asn"] in ["AS15169", "AS13335"]:  # Google, Cloudflare
            warning = "System is using a public resolver instead of the configured VPN DNS."
            
        return {
            "resolver_ip": resolver_ip,
            "asn": asn_info["asn"],
            "organization": asn_info["org"],
            "warning": warning,
            "status": "warning" if warning else "safe"
        }
    except Exception as e:
        return {
            "resolver_ip": "Unknown",
            "asn": "Unknown",
            "organization": "Unknown",
            "warning": f"Could not determine leak status: {str(e)}",
            "status": "error"
        }
