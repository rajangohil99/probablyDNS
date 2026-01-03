import asyncio
import time
import dns.message
import dns.asyncquery
import dns.name
import dns.rdatatype
from typing import Dict, Any

async def ping_dns(target: str, nameserver: str, qtype: str = 'A') -> int:
    try:
        req = dns.message.make_query(target, dns.rdatatype.from_text(qtype))
        start = time.time()
        await dns.asyncquery.udp(req, nameserver, timeout=3.0)
        return int((time.time() - start) * 1000)
    except Exception:
        return -1

async def measure_query_path(domain: str, auth_ns: list) -> Dict[str, Any]:
    root_ip = "198.41.0.4"
    tld_name = domain.split('.')[-1]
    
    root_latency = await ping_dns(domain, root_ip, 'A')
    
    tld_latency = -1
    import dns.resolver
    try:
        ans = dns.resolver.resolve(tld_name, 'NS')
        if ans:
            tld_ns = ans[0].target.to_text()
            tld_ip = (dns.resolver.resolve(tld_ns, 'A'))[0].to_text()
            tld_latency = await ping_dns(domain, tld_ip, 'A')
    except Exception:
        pass
        
    auth_latency = -1
    if auth_ns:
        try:
            auth_ip = (dns.resolver.resolve(auth_ns[0], 'A'))[0].to_text()
            auth_latency = await ping_dns(domain, auth_ip, 'A')
        except Exception:
            pass
            
    resolver_latency = await ping_dns(domain, '8.8.8.8', 'A')
    
    latencies = [l for l in [root_latency, tld_latency, auth_latency, resolver_latency] if l >= 0]
    total = sum(latencies)
    
    warnings = []
    if auth_latency > 100:
        warnings.append("Authoritative response > 100ms")
        
    return {
        "root_latency_ms": root_latency,
        "tld_latency_ms": tld_latency,
        "auth_latency_ms": auth_latency,
        "resolver_latency_ms": resolver_latency,
        "total_resolution_time_ms": total,
        "warnings": warnings,
        "tld_name": tld_name
    }
