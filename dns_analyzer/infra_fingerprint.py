from typing import Dict, Any, List

def fingerprint_infra(records: Dict[str, List[str]], auth_ns: List[str]) -> Dict[str, str]:
    ns_provider = "Unknown or Self-hosted"
    email_provider = "Unknown or Self-hosted"
    cdn_provider = "Unknown or Self-hosted"
    hosting_provider = "Unknown or Self-hosted"
    
    ns_patterns = {
        "cloudflare.com": "Cloudflare",
        "awsdns": "Amazon Web Services",
        "googledomains.com": "Google Cloud",
        "azure-dns": "Microsoft Azure",
        "digitalocean.com": "DigitalOcean",
        "linode.com": "Linode",
        "namecheap.com": "Namecheap"
    }
    mx_patterns = {
        "google.com": "Google Workspace",
        "outlook.com": "Microsoft 365",
        "amazon.com": "Amazon SES",
        "zoho.com": "Zoho Mail",
        "protonmail.ch": "ProtonMail",
        "fastmail.com": "Fastmail"
    }
    cname_patterns = {
        "cloudfront.net": "Amazon Web Services",
        "fastly.net": "Fastly",
        "akamai.net": "Akamai",
        "herokuapp.com": "Heroku",
        "cloudflare.net": "Cloudflare",
        "azureedge.net": "Microsoft Azure",
        "wpengine.com": "WP Engine",
        "github.io": "GitHub Pages"
    }
    
    for ns in auth_ns:
        for pat, prov in ns_patterns.items():
            if pat in ns.lower():
                ns_provider = prov
                
    for mx in records.get('MX', []):
        for pat, prov in mx_patterns.items():
            if pat in mx.lower():
                email_provider = prov
                
    for cname in records.get('CNAME', []):
        for pat, prov in cname_patterns.items():
            if pat in cname.lower():
                cdn_provider = prov
                hosting_provider = prov
                
    return {
        "nameserver_provider": ns_provider,
        "email_provider": email_provider,
        "cdn_provider": cdn_provider,
        "hosting_provider": hosting_provider
    }
