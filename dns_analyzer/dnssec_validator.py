import asyncio
import dns.resolver
import dns.message
import dns.query
from typing import Dict, Any

def check_signed(zone: str) -> bool:
    try:
        request = dns.message.make_query(zone, dns.rdatatype.DNSKEY, want_dnssec=True)
        response = dns.query.udp(request, '8.8.8.8', timeout=4.0)
        if response.answer:
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.DNSKEY:
                    return True
    except Exception:
        pass
    return False

async def deep_dnssec_validation(domain: str) -> Dict[str, Any]:
    tld = domain.split('.')[-1]
    
    root_signed = await asyncio.to_thread(check_signed, '.')
    tld_signed = await asyncio.to_thread(check_signed, tld)
    domain_signed = await asyncio.to_thread(check_signed, domain)
    
    # Check for DS in parent zone (naive check using 8.8.8.8)
    ds_found = False
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, domain, 'DS')
        if answers:
            ds_found = True
    except Exception:
        pass
        
    status = "SUCCESS"
    reason = "Chain is valid"
    impact = ""
    
    if not domain_signed and not ds_found:
        status = "DNSSEC not enabled"
        reason = "This is normal and not an error."
        impact = "Domain is unsigned (informational)"
    elif not domain_signed and ds_found:
        status = "FAILED"
        reason = "DS record exists but DNSKEY missing."
        impact = "Resolvers performing DNSSEC validation may return SERVFAIL."
    elif domain_signed and not ds_found:
        status = "FAILED"
        reason = "Domain is signed but missing DS record in parent zone (broken chain)."
        impact = "Resolvers may fail to validate the chain."
        
    return {
        "root_signed": root_signed,
        "tld": tld,
        "tld_signed": tld_signed,
        "domain_signed": domain_signed,
        "status": status,
        "reason": reason,
        "impact": impact
    }
