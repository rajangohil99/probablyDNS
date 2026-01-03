import asyncio
import time
import socket
from typing import Dict, List, Any

async def measure_latency(nameservers: List[str]) -> Dict[str, Any]:
    """
    Measure response time of authoritative nameservers using simple UDP ping.
    """
    results = {}
    slow_servers = []

    async def ping_ns(ns: str):
        try:
            # Query IP of NS first
            ns_ip = socket.gethostbyname(ns)
            
            # Create a simple DNS query (e.g. for root)
            import dns.message
            req = dns.message.make_query('.', 'NS')
            
            start_time = time.time()
            # Send query to NS IP
            import dns.asyncquery
            res = await dns.asyncquery.udp(req, ns_ip, timeout=5.0)
            end_time = time.time()
            
            latency_ms = int((end_time - start_time) * 1000)
            return latency_ms
        except Exception:
            return None

    tasks = {ns: ping_ns(ns) for ns in nameservers}
    latencies = await asyncio.gather(*tasks.values(), return_exceptions=True)
    
    for ns, latency in zip(tasks.keys(), latencies):
        if not latency or isinstance(latency, Exception):
            results[ns] = "timeout"
            slow_servers.append(ns)
        else:
            results[ns] = f"{latency}ms"
            if latency > 100:
                slow_servers.append(ns)

    return {
        "latencies": results,
        "slow_servers": slow_servers,
        "warning": "Some authoritative servers are slow or unresponsive." if slow_servers else "All nameservers responding quickly."
    }
