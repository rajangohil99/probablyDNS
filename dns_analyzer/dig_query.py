import asyncio
import time
import dns.asyncresolver
from typing import Dict, Any, List

RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CAA']

async def single_dig(domain: str, record_type: str) -> Dict[str, Any]:
    resolver = dns.asyncresolver.Resolver()
    start = time.time()
    try:
        answers = await resolver.resolve(domain, record_type)
        latency = int((time.time() - start) * 1000)
        return {
            "type": record_type,
            "answers": [r.to_text() for r in answers],
            "ttl": answers.rrset.ttl if answers.rrset else 0,
            "query_time_ms": latency,
            "status": "success"
        }
    except Exception as e:
        latency = int((time.time() - start) * 1000)
        return {
            "type": record_type,
            "answers": [],
            "ttl": 0,
            "query_time_ms": latency,
            "status": "error",
            "error": str(e)
        }

async def run_dig_queries(domain: str) -> Dict[str, Any]:
    tasks = [single_dig(domain, rtype) for rtype in RECORD_TYPES]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    valid_results = [r for r in results if isinstance(r, dict)]
    return {"queries": valid_results}
