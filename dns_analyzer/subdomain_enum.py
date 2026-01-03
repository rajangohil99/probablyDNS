import asyncio
from typing import Dict, Any
from dns_analyzer.resolver import async_query

WORDLIST = [
    "www", "mail", "dev", "api", "vpn", "staging", "test", "webmail",
    "ftp", "ns1", "ns2", "smtp", "pop", "imap", "blog", "shop", "admin",
    "portal", "app", "cdn", "secure"
]

async def check_subdomain(subdomain: str, domain: str) -> Dict[str, str]:
    target = f"{subdomain}.{domain}"
    res = await async_query(target, 'A')
    if res:
        return {"subdomain": target, "ip": res[0].to_text()}
    res_cname = await async_query(target, 'CNAME')
    if res_cname:
        return {"subdomain": target, "cname": res_cname[0].to_text()}
    return {}

async def discover_subdomains(domain: str) -> Dict[str, Any]:
    tasks = [check_subdomain(word, domain) for word in WORDLIST]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    discovered = []
    for r in results:
        if isinstance(r, dict) and r:
            discovered.append(r)
            
    return {
        "discovered": discovered,
        "count": len(discovered)
    }
