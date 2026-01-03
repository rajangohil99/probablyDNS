import asyncio
from typing import Dict, List, Optional
from dns_analyzer.resolver import async_query

RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CAA', 'SOA']

async def get_all_records(domain: str, nameservers: Optional[List[str]] = None, timeout: float = 5.0) -> Dict[str, List[str]]:
    """
    Fetch all common DNS records concurrently.
    """
    results = {r_type: [] for r_type in RECORD_TYPES}
    
    tasks = {r_type: async_query(domain, r_type, nameservers, timeout) for r_type in RECORD_TYPES}
    
    # Run all queries concurrently
    responses = await asyncio.gather(*tasks.values(), return_exceptions=True)
    
    for r_type, response in zip(tasks.keys(), responses):
        if not response or isinstance(response, Exception):
            continue
        try:
            results[r_type] = [rdata.to_text() for rdata in response]
        except Exception:
            pass
            
    return results
