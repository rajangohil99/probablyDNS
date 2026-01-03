import asyncio
import time
import dns.asyncresolver
from typing import Dict, Any, List, Tuple

async def measure_perf(resolver_ip: str, name: str) -> Tuple[str, int]:
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = [resolver_ip]
        start = time.time()
        await resolver.resolve('google.com', 'A')
        return name, int((time.time() - start) * 1000)
    except Exception:
        return name, -1

async def benchmark_resolvers() -> Dict[str, Any]:
    resolvers = [
        ("1.1.1.1", "Cloudflare (1.1.1.1)"),
        ("8.8.8.8", "Google (8.8.8.8)"),
        ("9.9.9.9", "Quad9 (9.9.9.9)"),
        ("208.67.222.222", "OpenDNS (208.67.222.222)")
    ]
    
    tasks = [measure_perf(ip, name) for ip, name in resolvers]
    results = await asyncio.gather(*tasks)
    
    benchmark = []
    for name, lat in sorted(results, key=lambda x: (x[1] < 0, x[1])):
        benchmark.append({
            "name": name, 
            "latency": f"{lat} ms" if lat >= 0 else "Timeout"
        })
        
    return {
        "benchmark": benchmark,
        "status": "safe"
    }
