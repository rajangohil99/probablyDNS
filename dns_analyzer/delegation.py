import asyncio
import dns.asyncquery
import dns.message
import dns.name
import dns.rdatatype
import dns.ipv4
import dns.ipv6
from typing import Dict, List, Any, Optional

# Root servers addresses
ROOT_SERVERS = {
    'A': '198.41.0.4',
    'B': '199.9.14.201',
    'C': '192.33.4.12',
    'D': '199.7.91.13',
    'E': '192.203.230.10',
    'F': '192.5.5.241',
    'G': '192.112.36.4',
    'H': '198.97.190.53',
    'I': '192.36.148.17',
    'J': '192.58.128.30',
    'K': '193.0.14.129',
    'L': '199.7.83.42',
    'M': '202.12.27.33'
}

async def get_ns_responses(target_name: dns.name.Name, server_ip: str, timeout: float = 5.0) -> Optional[dns.message.Message]:
    """
    Query a specific nameserver for a target's NS records.
    """
    request = dns.message.make_query(target_name, dns.rdatatype.NS)
    try:
        response = await dns.asyncquery.udp(request, server_ip, timeout=timeout)
        return response
    except Exception:
        return None

def extract_next_servers(response: dns.message.Message, level_name: dns.name.Name) -> List[str]:
    """
    Extract IP addresses for the next level of nameservers from the response (glue records)
    """
    ips = []
    # Check additional section for A/AAAA records of the NS
    for rrset in response.additional:
        if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            ips.extend([rdata.to_text() for rdata in rrset])
    return ips

async def trace_delegation(domain: str) -> Dict[str, Any]:
    """
    Performs a trace similar to 'dig +trace' by querying root, TLD, and authoritative nameservers.
    """
    target = dns.name.from_text(domain)
    
    stages = []
    issues = []
    
    # 1. Start with root servers
    current_servers = list(ROOT_SERVERS.values())
    current_level = dns.name.root
    
    labels = domain.strip('.').split('.')
    target_levels = []
    for i in range(1, len(labels) + 1):
        target_levels.append(dns.name.from_text('.'.join(labels[-i:])))
    
    for level_name in target_levels:
        responses = await asyncio.gather(*[get_ns_responses(level_name, ip) for ip in current_servers[:3]]) # Limit to 3 queries per level to be fast
        
        valid_response = next((r for r in responses if r is not None), None)
        
        if not valid_response:
            issues.append(f"Broken delegation at {level_name.to_text()}: No response from parent nameservers.")
            break
            
        stage_info = {
            "level": level_name.to_text(),
            "status": "OK",
            "nameservers": []
        }
        
        # Check authority section for NS records
        ns_found = False
        for rrset in valid_response.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                ns_found = True
                stage_info["nameservers"] = [rdata.target.to_text() for rdata in rrset]
                
        # If no authority section, check answer section (means we reached authoritative)
        for rrset in valid_response.answer:
            if rrset.rdtype == dns.rdatatype.NS:
                ns_found = True
                stage_info["nameservers"] = [rdata.target.to_text() for rdata in rrset]
                
        stages.append(stage_info)
        
        # Update current_servers for next level using glue records
        next_servers = extract_next_servers(valid_response, level_name)
        if next_servers:
            current_servers = next_servers
        else:
            # Need to resolve the NS names if no glue records are provided
            if stage_info["nameservers"]:
                issues.append(f"Missing glue records for {level_name.to_text()}")
                # In a full robust implementation we'd resolve the NS names here.
                # For simplicity in this fast trace, we might stop or use standard resolution.
                try:
                    res = dns.resolver.resolve(stage_info["nameservers"][0], 'A')
                    current_servers = [rdata.to_text() for rdata in res]
                except Exception:
                    issues.append(f"Could not resolve nameserver {stage_info['nameservers'][0]} for {level_name.to_text()}")
                    break

    # Determine final authoritative servers summary
    auth_servers = stages[-1]["nameservers"] if stages else []
    
    chain = " -> ".join([s["level"].strip('.') for s in stages]) if stages else "Unknown"
    
    return {
        "domain": domain,
        "chain": chain,
        "stages": stages,
        "authoritative_nameservers": auth_servers,
        "issues": issues if issues else ["None"]
    }
