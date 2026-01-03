import asyncio
from typing import Dict, Any, List
from dns_analyzer.resolver import async_query

async def detect_split_dns(domain: str, auth_ns: List[str]) -> Dict[str, Any]:
    if not auth_ns:
        return {"status": "error", "message": "No authoritative nameservers provided."}
        
    auth_ns_ip_res = await async_query(auth_ns[0], 'A')
    if not auth_ns_ip_res:
        return {"status": "error", "message": "Could not resolve authoritative nameserver IP."}
        
    auth_ip = auth_ns_ip_res[0].to_text()
    
    # Query Google
    public_res = await async_query(domain, 'A', ["8.8.8.8"])
    # Query Auth
    auth_res = await async_query(domain, 'A', [auth_ip])
    
    public_ips = sorted([r.to_text() for r in public_res]) if public_res else []
    auth_ips = sorted([r.to_text() for r in auth_res]) if auth_res else []
    
    is_split = public_ips != auth_ips and len(public_ips) > 0 and len(auth_ips) > 0
    
    return {
        "is_split": is_split,
        "public_ips": public_ips,
        "auth_ips": auth_ips,
        "auth_ns_used": auth_ns[0]
    }
