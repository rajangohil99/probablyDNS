import asyncio
import random
import string
from typing import Dict, Any
from dns_analyzer.resolver import async_query

async def detect_wildcard(domain: str) -> Dict[str, Any]:
    random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    target = f"{random_sub}.{domain}"
    
    res = await async_query(target, 'A')
    
    if res:
        return {
            "has_wildcard": True,
            "test_domain": target,
            "resolved_ips": [r.to_text() for r in res]
        }
    return {"has_wildcard": False}
