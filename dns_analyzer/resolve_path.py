import asyncio
import time
import dns.message
import dns.asyncquery
import dns.name
import dns.rdatatype
import dns.resolver
from typing import Dict, Any, List

async def ping_ip(target: str, nameserver: str, qtype: str = 'A') -> int:
    try:
        req = dns.message.make_query(target, dns.rdatatype.from_text(qtype))
        start = time.time()
        await dns.asyncquery.udp(req, nameserver, timeout=3.0)
        return int((time.time() - start) * 1000)
    except Exception:
        return -1

async def measure_single_path(domain: str, auth_ns: list, root_ip: str, provider_name: str) -> Dict[str, Any]:
    tld_name = domain.split('.')[-1]
    
    root_latency = await ping_ip(domain, root_ip, 'A')
    
    tld_latency = -1
    try:
        ans = await asyncio.to_thread(dns.resolver.resolve, tld_name, 'NS')
        if ans:
            tld_ns_name = ans[0].target.to_text()
            tld_ip = (await asyncio.to_thread(dns.resolver.resolve, tld_ns_name, 'A'))[0].to_text()
            tld_latency = await ping_ip(domain, tld_ip, 'A')
    except Exception:
        pass
        
    auth_latency = -1
    if auth_ns:
        try:
            auth_ip = (await asyncio.to_thread(dns.resolver.resolve, auth_ns[0], 'A'))[0].to_text()
            auth_latency = await ping_ip(domain, auth_ip, 'A')
        except Exception:
            pass
            
    final_answer = []
    final_start = time.time()
    try:
        res = await asyncio.to_thread(dns.resolver.resolve, domain, 'A')
        final_answer = [r.to_text() for r in res]
    except Exception:
        pass
    final_latency = int((time.time() - final_start) * 1000)
    
    latencies = [l for l in [root_latency, tld_latency, auth_latency, final_latency] if l > 0]
    total = sum(latencies)
    
    warnings = []
    if auth_latency > 100:
        warnings.append("Authoritative response > 100ms")
        
    return {
        "provider_name": provider_name,
        "root_ip": root_ip,
        "root_latency_ms": root_latency,
        "tld_latency_ms": tld_latency,
        "tld_name": tld_name,
        "auth_latency_ms": auth_latency,
        "final_latency_ms": final_latency,
        "final_answer": final_answer,
        "total_resolution_time_ms": total,
        "warnings": warnings
    }

async def measure_resolve_path(domain: str, auth_ns: list) -> List[Dict[str, Any]]:
    roots = [
        ("198.41.0.4", "A-Root (Verisign)"),
        ("199.7.83.42", "L-Root (ICANN)"),
        ("192.5.5.241", "F-Root (ISC)")
    ]
    tasks = [measure_single_path(domain, auth_ns, ip, name) for ip, name in roots]
    results = await asyncio.gather(*tasks)
    return results
