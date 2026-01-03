import asyncio
from typing import Dict, List, Any
from dns_analyzer.resolver import async_query

PUBLIC_RESOLVERS = {
    "Cloudflare": ["1.1.1.1"],
    "Google": ["8.8.8.8"],
    "Quad9": ["9.9.9.9"],
    "OpenDNS": ["208.67.222.222"]
}

RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']

async def check_multi_resolvers(domain: str) -> Dict[str, Any]:
    """
    Query public resolvers in parallel and check for consistency.
    """
    results = {}
    inconsistent = False
    
    # We will primarily check 'A' records for consistency as an example,
    # but could be expanded to all types.
    tasks = {
        name: async_query(domain, 'A', ips) 
        for name, ips in PUBLIC_RESOLVERS.items()
    }
    
    responses = await asyncio.gather(*tasks.values(), return_exceptions=True)
    
    response_map = {}
    all_answers_set = set()
    
    for name, response in zip(tasks.keys(), responses):
        if not response or isinstance(response, Exception):
            response_map[name] = {"status": "failed", "records": [], "ttl": None}
            continue
            
        records = sorted([rdata.to_text() for rdata in response])
        ttl = response.rrset.ttl if response.rrset else None
        
        response_map[name] = {
            "status": "success",
            "records": records,
            "ttl": ttl
        }
        all_answers_set.add(tuple(records))
        
    if len(all_answers_set) > 1:
        inconsistent = True
        
    return {
        "resolvers": response_map,
        "inconsistent": inconsistent,
        "message": "inconsistent DNS answers detected." if inconsistent else "All resolvers returned consistent answers."
    }
