import asyncio
import dns.asyncresolver
import dns.resolver
from typing import List, Optional, Any

async def async_query(domain: str, record_type: str, nameservers: Optional[List[str]] = None, timeout: float = 5.0) -> Any:
    """
    Perform an asynchronous DNS query using dnspython.
    If nameservers are provided, those will be used.
    Returns the Answer instance or None on failure.
    """
    res = dns.asyncresolver.Resolver(configure=not bool(nameservers))
    res.timeout = timeout
    res.lifetime = timeout
    
    if nameservers:
        res.nameservers = nameservers
        
    try:
        answers = await res.resolve(domain, record_type)
        return answers
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception:
        return None
