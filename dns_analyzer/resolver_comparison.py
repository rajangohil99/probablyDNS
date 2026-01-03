import asyncio
import time
import dns.asyncresolver
from typing import Dict, Any, List

RESOLVERS_TO_TEST = {
    "Cloudflare": "1.1.1.1",
    "Google": "8.8.8.8",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222"
}

async def query_single_resolver(domain: str, record_type: str, resolver_name: str, resolver_ip: str) -> Dict[str, Any]:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [resolver_ip]
    start = time.time()
    try:
        answers = await resolver.resolve(domain, record_type, lifetime=3.0)
        latency = int((time.time() - start) * 1000)
        return {
            "resolver": resolver_name,
            "server": resolver_ip,
            "answers": sorted([r.to_text() for r in answers]),
            "ttl": answers.rrset.ttl if answers.rrset else 0,
            "latency_ms": latency,
            "status": "success"
        }
    except Exception as e:
        latency = int((time.time() - start) * 1000)
        return {
            "resolver": resolver_name,
            "server": resolver_ip,
            "answers": [],
            "ttl": 0,
            "latency_ms": latency,
            "status": "error",
            "error": str(e)
        }

async def get_authoritative_ns(domain: str) -> List[str]:
    try:
        res = dns.asyncresolver.Resolver()
        ans = await res.resolve(domain, 'NS')
        ns_names = [r.to_text() for r in ans]
        if ns_names:
            ip_ans = await res.resolve(ns_names[0], 'A')
            return [ns_names[0], ip_ans[0].to_text()]
    except Exception:
        pass
    return ["Authoritative", "8.8.8.8"]

async def compare_resolvers_for_record(domain: str, record_type: str, provider_dns: str = "9.9.9.9") -> Dict[str, Any]:
    auth_ns_info = await get_authoritative_ns(domain)
    auth_name = auth_ns_info[0]
    auth_ip = auth_ns_info[1]
    
    tasks = []
    tasks.append(query_single_resolver(domain, record_type, "Authoritative", auth_ip))
    tasks.append(query_single_resolver(domain, record_type, "Provider DNS", provider_dns))
    
    for name, ip in RESOLVERS_TO_TEST.items():
        tasks.append(query_single_resolver(domain, record_type, name, ip))
        
    results = await asyncio.gather(*tasks)
    
    # Analysis logic
    auth_res = next((r for r in results if r["resolver"] == "Authoritative"), None)
    auth_answers = auth_res["answers"] if auth_res and auth_res["status"] == "success" else []
    
    all_identical = True
    mismatches = []
    
    for r in results:
        if r["resolver"] != "Authoritative":
            if r["answers"] != auth_answers:
                all_identical = False
                mismatches.append(r["resolver"])
                
    if all_identical:
        analysis = "All resolvers returned identical responses."
        cause = None
    else:
        analysis = f"Response from {', '.join(mismatches)} differs from authoritative DNS."
        if any(not r["answers"] for r in results if r["resolver"] in mismatches):
            cause = "Resolver cache may contain stale NXDOMAIN or propagation is incomplete."
        elif any(any("0.0.0.0" in a for a in r["answers"]) for r in results if r["resolver"] in mismatches):
            cause = "DNS filtering policy applied (sinkhole detected)."
        else:
            cause = "Resolver cache may contain stale record."
            
    return {
        "record_type": record_type,
        "results": results,
        "analysis": analysis,
        "possible_cause": cause
    }

async def run_resolver_comparison(domain: str, provider_dns: str = "9.9.9.9") -> List[Dict[str, Any]]:
    record_types = ["A", "AAAA", "NS"]
    tasks = [compare_resolvers_for_record(domain, rtype, provider_dns) for rtype in record_types]
    return await asyncio.gather(*tasks)
