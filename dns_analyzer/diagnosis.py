from typing import Dict, Any, List

def run_diagnosis(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze the full suite of test results and generate a human-readable diagnosis.
    """
    findings = []
    
    # Check multi-resolver consistency
    inconsistent = results.get("multi_resolver", {}).get("inconsistent", False)
    if inconsistent:
        findings.append({
            "issue": "Inconsistent DNS responses across public resolvers.",
            "cause": "DNS propagation is still in progress, or you have a split-DNS or misconfigured authoritative server setup.",
            "action": "Wait for TTL expiry or verify authoritative zone synchronization (Serial numbers in SOA)."
        })
        
    # Check DNSSEC
    dnssec = results.get("dnssec", {})
    if not dnssec.get("valid", False) and dnssec.get("dnssec_enabled", False):
        findings.append({
            "issue": "Broken DNSSEC chain.",
            "cause": "DNSKEY present but missing or invalid RRSIGs.",
            "action": "Re-sign your zone or contact your DNS provider."
        })
        
    # Check Zone Transfers
    security_tests = results.get("security", {})
    if security_tests.get("zone_transfer", {}).get("exposed", False):
        findings.append({
            "issue": "Zone Transfer (AXFR) is exposed.",
            "cause": "Authoritative nameservers permit ANY IP to list all your DNS records.",
            "action": "Configure your nameservers to restrict AXFR to known secondary IPs only."
        })
        
    issues = security_tests.get("spf_dmarc", {}).get("issues", [])
    for issue in issues:
        findings.append({
            "issue": issue,
            "cause": "Misconfigured or missing email authentication records.",
            "action": "Review your SPF/DMARC syntax and limits."
        })
        
    # Check Latency
    latency = results.get("latency", {})
    if latency.get("slow_servers"):
        findings.append({
            "issue": "Slow or unresponsive authoritative nameservers.",
            "cause": f"These servers [{', '.join(latency['slow_servers'])}] took >100ms or timed out.",
            "action": "Investigate network paths to these nameservers or consider an Anycast DNS provider."
        })
        
    # Delegation
    delegation = results.get("delegation", {})
    for issue in delegation.get("issues", []):
        if issue != "None":
            findings.append({
                "issue": issue,
                "cause": "Incorrect NS or glue records at the parent/TLD.",
                "action": "Update the Nameserver records at your domain registrar."
            })
        
    if not findings:
        findings.append({
            "issue": "None detected.",
            "cause": "Your DNS configuration appears healthy.",
            "action": "No action needed."
        })
        
    return {
        "summary": findings,
        "total_issues": len(findings) if findings[0]["issue"] != "None detected." else 0
    }
