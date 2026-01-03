import asyncio
import dns.reversename
from typing import Dict, Any, List
from dns_analyzer.resolver import async_query

async def validate_ptr(ip: str) -> Dict[str, Any]:
    try:
        rev_name = dns.reversename.from_address(ip)
        res = await async_query(rev_name.to_text(), 'PTR')
        
        if not res:
            return {"ip": ip, "ptr": None, "forward_match": False}
            
        ptr_domain = res[0].to_text().rstrip('.')
        
        # Forward check
        forward_res = await async_query(ptr_domain, 'A')
        forward_ips = [r.to_text() for r in forward_res] if forward_res else []
        
        match = ip in forward_ips
        return {"ip": ip, "ptr": ptr_domain, "forward_match": match}
    except Exception:
        return {"ip": ip, "ptr": None, "forward_match": False}

async def check_reverse_dns(ips: List[str]) -> Dict[str, Any]:
    tasks = [validate_ptr(ip) for ip in ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    valid_results = [r for r in results if isinstance(r, dict)]
    return {"results": valid_results}
