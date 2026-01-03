from typing import Dict, Any, List

def detect_dns_filtering(domain: str, a_records: List[str]) -> Dict[str, Any]:
    """Detect if the domain answers look like standard sinkhole or blockpage queries."""
    is_filtered = False
    
    for ip in a_records:
        if ip in ("0.0.0.0", "127.0.0.1") or ip.startswith("10.") or ip.startswith("192.168."):
            is_filtered = True
            
    response_list = a_records if a_records else ["NXDOMAIN"]
    
    return {
        "is_filtered": is_filtered,
        "response": response_list,
        "conclusion": "Domain appears blocked by DNS filtering policy." if is_filtered else "No standard filtering patterns detected."
    }
