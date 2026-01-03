import asyncio
import dns.message
import dns.asyncquery
import dns.rdatatype
import dns.flags
from typing import Dict, Any

async def analyze_resolver_capabilities(resolver_ip="1.1.1.1") -> Dict[str, Any]:
    try:
        # Check recursion, EDNS, and Max UDP
        q = dns.message.make_query("google.com", dns.rdatatype.A)
        q.use_edns(payload=4096, options=[])
        res = await asyncio.wait_for(dns.asyncquery.udp(q, resolver_ip, timeout=3.0), timeout=3.5)
        
        flags = res.flags
        recursion_avail = (flags & dns.flags.RA) != 0
        edns_support = res.edns >= 0
        max_udp = res.payload if edns_support else 512
        
        # Check DNSSEC validation support
        dnssec_support = False
        try:
            q2 = dns.message.make_query("isc.org", dns.rdatatype.A)
            q2.use_edns(edns=0, payload=4096, options=[])
            q2.flags |= dns.flags.AD
            res2 = await asyncio.wait_for(dns.asyncquery.udp(q2, resolver_ip, timeout=3.0), timeout=3.5)
            if (res2.flags & dns.flags.AD) != 0:
                dnssec_support = True
        except Exception:
            pass
            
        return {
            "resolver": resolver_ip,
            "recursion": "enabled" if recursion_avail else "disabled",
            "dnssec_validation": "supported" if dnssec_support else "unsupported",
            "edns": "supported" if edns_support else "unsupported",
            "max_udp_size": max_udp,
            "status": "safe"
        }
    except Exception as e:
        return {
            "resolver": resolver_ip,
            "recursion": "unknown",
            "dnssec_validation": "unknown",
            "edns": "unknown",
            "max_udp_size": "unknown",
            "status": "error",
            "error": str(e)
        }
