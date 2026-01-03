from typing import Dict, Any, List

CDN_CNAME_HINTS = {
    "cloudflare": "cloudflare.net",
    "akamai": "akamai.net",
    "fastly": "fastly.net",
    "cloudfront": "cloudfront.net"
}

def detect_cdn(cname_records: List[str], a_records: List[str]) -> Dict[str, Any]:
    detected = []
    
    for cname in cname_records:
        for cdn_name, hint in CDN_CNAME_HINTS.items():
            if hint in cname.lower():
                detected.append(cdn_name)
    
    # We could also check IP ranges or ASNs for A records here
                
    return {
        "cdns_detected": list(set(detected)),
        "is_cdn": len(detected) > 0
    }
