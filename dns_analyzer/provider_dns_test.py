import asyncio
from typing import Dict, Any, List
from dns_analyzer.resolver import async_query

async def test_provider_dns(domain: str, provider_ns: List[str] = None) -> Dict[str, Any]:
    """Test resolution across provider DNS vs public to find filtering or overrides."""
    if not provider_ns:
        provider_ns = ["9.9.9.9"] # Used as mock "Provider DNS" here if none configured

    resolvers = {
        "Provider DNS (ns1.provider)": provider_ns,
        "Cloudflare DNS (1.1.1.1)": ["1.1.1.1"],
        "Google DNS (8.8.8.8)": ["8.8.8.8"]
    }
    
    results = {}
    differs = False
    baseline = None
    
    # We will test A records primarily
    tasks = {name: async_query(domain, 'A', ips) for name, ips in resolvers.items()}
    responses = await asyncio.gather(*tasks.values(), return_exceptions=True)
    
    for name, response in zip(tasks.keys(), responses):
        if not response or isinstance(response, Exception):
            answers = ["NXDOMAIN"]
        else:
            answers = sorted([r.to_text() for r in response])
        results[name] = answers
        
        if name == "Cloudflare DNS (1.1.1.1)":
            baseline = answers
            
    if results.get("Provider DNS (ns1.provider)") != baseline:
        differs = True
        
    return {
        "results": results,
        "differs": differs,
        "conclusion": "Provider resolver response differs from public DNS." if differs else "Provider resolver matches public DNS."
    }
