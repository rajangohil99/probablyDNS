import asyncio
import dns.asyncresolver
import dns.name
import dns.message
import dns.asyncquery
import dns.rdatatype
import ipaddress
from typing import Dict, Any, List

def is_sinkhole(ip_addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_addr)
        # Check against common bogon/sinkhole ranges
        for net in ["198.18.0.0/15", "10.0.0.0/8", "127.0.0.0/8", "0.0.0.0/8"]:
            if ip in ipaddress.ip_network(net):
                return True
        return False
    except ValueError:
        return False

async def get_auth_ips(domain: str) -> List[str]:
    try:
        resolver = dns.asyncresolver.Resolver()
        answers = await resolver.resolve(domain, 'NS')
        ns_name = answers[0].target.to_text()
        ns_answers = await resolver.resolve(ns_name, 'A')
        return [r.to_text() for r in ns_answers]
    except Exception:
        return []

async def test_dns_filter(domain: str) -> Dict[str, Any]:
    try:
        auth_ips = await get_auth_ips(domain)
        if not auth_ips:
            return {"status": "error", "message": "Could not find authoritative NS"}

        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = [auth_ips[0]]
        auth_ans = await resolver.resolve(domain, 'A')
        auth_ips_res = sorted([r.to_text() for r in auth_ans])

        resolver.nameservers = ['1.1.1.1', '8.8.8.8']
        pub_ans = await resolver.resolve(domain, 'A')
        pub_ips_res = sorted([r.to_text() for r in pub_ans])

        filtered = False
        warning = ""
        returned_sinkhole = ""

        if auth_ips_res != pub_ips_res:
            filtered = True
            warning = "Possible DNS filtering or sinkhole detected."
        
        for ip in pub_ips_res:
            if is_sinkhole(ip):
                filtered = True
                warning = "Sinkhole IP range detected in response."
                returned_sinkhole = ip

        return {
            "expected_ip": auth_ips_res[0] if auth_ips_res else "None",
            "returned_ip": returned_sinkhole or (pub_ips_res[0] if pub_ips_res else "None"),
            "result": warning if filtered else "Clean: No filtering detected.",
            "status": "warning" if filtered else "safe",
            "is_filtered": filtered
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
