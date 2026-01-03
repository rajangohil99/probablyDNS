import asyncio
from typing import Dict, Any, List
from dns_analyzer.resolver import async_query

async def detect_split_dns_extended(domain: str, auth_ns: List[str], provider_ns: List[str] = None) -> Dict[str, Any]:
    """Advanced recursive vs authoritative bindings checks."""
    if not provider_ns:
        provider_ns = ["9.9.9.9"] # fallback mock provider for generic tests
        
    auth_answers = []
    if auth_ns:
        a_ip_res = await async_query(auth_ns[0], 'A')
        if a_ip_res:
            auth_ip = a_ip_res[0].to_text()
            res = await async_query(domain, 'A', [auth_ip])
            auth_answers = sorted([r.to_text() for r in res]) if res else []
            
    prov_res = await async_query(domain, 'A', provider_ns)
    prov_answers = sorted([r.to_text() for r in prov_res]) if prov_res else []
    
    pub_res = await async_query(domain, 'A', ["1.1.1.1"])
    pub_answers = sorted([r.to_text() for r in pub_res]) if pub_res else []
    
    is_split = (auth_answers != pub_answers) or (prov_answers != pub_answers)
    
    return {
        "is_split": is_split,
        "authoritative": auth_answers,
        "provider": prov_answers,
        "public": pub_answers
    }
