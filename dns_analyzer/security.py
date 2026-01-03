import asyncio
import dns.zone
import dns.query
import dns.xfr
from typing import List, Dict, Any

async def test_zone_transfer(domain: str, nameservers: List[str]) -> Dict[str, Any]:
    """
    Attempt an AXFR zone transfer against authoritative nameservers.
    """
    results = {}
    exposed = False
    
    for ns in nameservers:
        try:
            # We must resolve the nameserver IP to attempt AXFR
            ns_ip = (dns.resolver.resolve(ns, 'A'))[0].to_text()
            
            # Using synchronous XFR query for simplicity as dnspython async xfr is complex
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5.0))
            if z:
                results[ns] = "allowed"
                exposed = True
            else:
                results[ns] = "denied"
        except dns.xfr.TransferError:
            results[ns] = "denied"
        except Exception:
            results[ns] = "failed to connect or timed out"
            
    return {
        "results": results,
        "exposed": exposed,
        "warning": "Zone transfer is exposed." if exposed else "Zone transfers are secured."
    }

async def check_spf_dmarc(domain: str) -> Dict[str, Any]:
    """
    Check for SPF issues (lookup count) and minimal DMARC functionality.
    """
    issues = []
    
    # Check SPF
    spf_record = None
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, domain, 'TXT')
        for rdata in answers:
            text = rdata.to_text().strip('"')
            if text.startswith("v=spf1"):
                spf_record = text
                break
    except Exception:
        pass
        
    if spf_record:
        # A simple estimation of lookups (include, a, mx, ptr, exists, redirect)
        lookups = sum(spf_record.count(mechanism) for mechanism in ('include:', 'a', 'mx', 'ptr:', 'exists:', 'redirect='))
        if lookups > 10:
            issues.append(f"SPF lookup count ({lookups}) exceeds the limit of 10.")
    else:
        issues.append("No SPF record found.")
        
    # Check DMARC
    dmarc_record = None
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            text = rdata.to_text().strip('"')
            if text.startswith("v=DMARC1"):
                dmarc_record = text
                break
    except Exception:
        pass
        
    if not dmarc_record:
        issues.append("Missing DMARC record.")
    elif "p=" not in dmarc_record:
        issues.append("Invalid DMARC policy.")
        
    return {
        "spf": spf_record,
        "dmarc": dmarc_record,
        "issues": issues
    }
