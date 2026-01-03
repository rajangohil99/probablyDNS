import asyncio
from typing import Dict, Any, List
import ipaddress
from dns_analyzer.resolver import async_query

async def lookup_asn(ip: str) -> Dict[str, Any]:
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            rev_ip = ".".join(reversed(ip.split(".")))
            query = f"{rev_ip}.origin.asn.cymru.com"
        else:
            nibbles = ip_obj.exploded.replace(":", "")
            rev_ip = ".".join(reversed(nibbles))
            query = f"{rev_ip}.origin6.asn.cymru.com"
            
        res = await async_query(query, 'TXT')
        if res:
            txt = res[0].to_text().strip('"')
            parts = [p.strip() for p in txt.split("|")]
            asn = f"AS{parts[0]}" if parts[0] else "Unknown"
            cc = parts[2] if len(parts) > 2 else "Unknown"
            
            org = "Unknown"
            if parts[0]:
                as_res = await async_query(f"AS{parts[0]}.asn.cymru.com", 'TXT')
                if as_res:
                    as_txt = as_res[0].to_text().strip('"')
                    as_parts = [p.strip() for p in as_txt.split("|")]
                    if len(as_parts) > 4:
                        org = as_parts[4]
                        
            return {
                "ip": ip,
                "asn": asn,
                "organization": org,
                "country": cc
            }
    except Exception:
        pass
        
    return {
        "ip": ip,
        "asn": "Unknown",
        "organization": "Unknown",
        "country": "Unknown"
    }

async def detect_network_ownership(ips: List[str]) -> Dict[str, Any]:
    tasks = [lookup_asn(ip) for ip in ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    valid = []
    for r in results:
        if isinstance(r, dict):
            valid.append(r)
            
    return {"results": valid}
