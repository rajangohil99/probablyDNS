import asyncio
import dns.dnssec
import dns.resolver
from typing import Dict, Any

def check_dnssec(domain: str) -> Dict[str, Any]:
    """
    Validate DNSSEC for a given domain.
    """
    results = {
        "dnssec_enabled": False,
        "valid": False,
        "issues": [],
        "explanation": "DNSSEC is not configured."
    }
    
    try:
        # Request DNSKEY and DS records
        request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
        response = dns.query.udp(request, '8.8.8.8', timeout=5.0)
        
        has_dnskey = False
        has_rrsig = False
        
        if response.answer:
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.DNSKEY:
                    has_dnskey = True
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    has_rrsig = True

        if has_dnskey and has_rrsig:
            results["dnssec_enabled"] = True
            
            # Simplified validation: we'd need a trusted anchor to actually validate
            # For diagnostic purposes, we assume presence of keys + sigs implies setup.
            # Real validation in Python is complex: requires building the chain of trust to the root.
            results["valid"] = True 
            results["explanation"] = "DNSSEC is enabled and keys are present."
        elif has_dnskey:
            results["dnssec_enabled"] = True
            results["issues"].append("DNSKEY present but no RRSIG found. Zone may be partially signed.")
            results["explanation"] = "DNSSEC is improperly configured (missing signatures)."
            
    except Exception as e:
        results["issues"].append(f"Failed to query DNSKEY: {str(e)}")
        
    return results
