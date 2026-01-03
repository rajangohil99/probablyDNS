import asyncio
import time
import dns.asyncresolver
from typing import Dict, Any, List

RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT']

async def query_resolver(domain: str, rtype: str, nameservers: List[str]) -> Dict[str, Any]:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [ns for ns in nameservers]
    
    start = time.time()
    try:
        answers = await resolver.resolve(domain, rtype, lifetime=3.0)
        latency = int((time.time() - start) * 1000)
        return {
            "type": rtype,
            "answers": sorted([r.to_text() for r in answers]),
            "ttl": answers.rrset.ttl if answers.rrset else 0,
            "query_time_ms": latency,
            "status": "success"
        }
    except Exception as e:
        latency = int((time.time() - start) * 1000)
        return {
            "type": rtype,
            "answers": [],
            "ttl": 0,
            "query_time_ms": latency,
            "status": "error",
            "error": str(e)
        }

async def query_source(domain: str, source_name: str, nameservers: List[str]) -> Dict[str, Any]:
    tasks = [query_resolver(domain, rtype, nameservers) for rtype in RECORD_TYPES]
    results = await asyncio.gather(*tasks)
    return {
        "source": source_name,
        "nameservers": nameservers,
        "records": results
    }

async def compare_resolvers(domain: str, auth_ns: List[str], provider_ns: List[str] = None) -> Dict[str, Any]:
    if not provider_ns:
        provider_ns = ["9.9.9.9"] # fallback mock
    public_ns = ["1.1.1.1", "8.8.8.8"]
    
    # If no auth_ns provided, try to find one
    if not auth_ns:
        try:
            resolver = dns.asyncresolver.Resolver()
            ans = await resolver.resolve(domain, 'NS')
            auth_ns_names = [r.to_text() for r in ans]
            if auth_ns_names:
                auth_ip_ans = await resolver.resolve(auth_ns_names[0], 'A')
                auth_ns = [auth_ip_ans[0].to_text()]
        except Exception:
            pass

    auth_ns_ips = auth_ns if auth_ns else ["8.8.8.8"] # ultimate fallback
        
    auth_task = query_source(domain, "Authoritative Server", auth_ns_ips)
    prov_task = query_source(domain, "Provider Resolver", provider_ns)
    pub_task = query_source(domain, "Public Resolver", public_ns)
    
    auth_res, prov_res, pub_res = await asyncio.gather(auth_task, prov_task, pub_task)
    
    # Simple analysis based on A records
    auth_a = next((r["answers"] for r in auth_res["records"] if r["type"] == "A"), [])
    prov_a = next((r["answers"] for r in prov_res["records"] if r["type"] == "A"), [])
    pub_a = next((r["answers"] for r in pub_res["records"] if r["type"] == "A"), [])
    
    analysis_points = []
    possible_cause = ""
    
    if auth_a == pub_a and auth_a == prov_a:
        analysis_points.append("Authoritative DNS: correct")
        analysis_points.append("Public resolvers: correct")
        analysis_points.append("Provider resolver: correct")
        possible_cause = "No mismatch detected. Resolution is consistent."
    else:
        if prov_a != auth_a:
            analysis_points.append("Provider resolver: mismatch detected")
            if not prov_a:
                possible_cause = "Resolver cache contains outdated record or NXDOMAIN."
            elif any(ip in ("0.0.0.0", "127.0.0.1") for ip in prov_a):
                possible_cause = "Resolver cache outdated or filtering policy applied."
            else:
                possible_cause = "Resolver cache contains outdated record."
        if pub_a != auth_a:
            analysis_points.append("Public resolver: mismatch detected")
            if not possible_cause:
                possible_cause = "Public DNS propagation delay or caching issue."
                
    if not analysis_points:
         analysis_points.append("Resolution inconsistent across sources.")
         possible_cause = "DNS propagation in progress or misconfigured authoritative zones."
         
    return {
        "authoritative": auth_res,
        "provider": prov_res,
        "public": pub_res,
        "analysis": analysis_points,
        "possible_cause": possible_cause
    }
