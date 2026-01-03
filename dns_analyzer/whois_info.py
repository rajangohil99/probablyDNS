import asyncio
import whois
from datetime import datetime
from typing import Dict, Any

async def get_whois_info(domain: str) -> Dict[str, Any]:
    try:
        w = await asyncio.to_thread(whois.whois, domain)
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
            
        warnings = []
        if expiration_date:
            exp = expiration_date.replace(tzinfo=None) if hasattr(expiration_date, 'tzinfo') else expiration_date
            days_to_expiry = (exp - datetime.now()).days
            if days_to_expiry < 60:
                warnings.append(f"Domain expires in {days_to_expiry} days.")
                
        return {
            "registrar": w.registrar,
            "creation_date": creation_date.isoformat() if creation_date else None,
            "expiration_date": expiration_date.isoformat() if expiration_date else None,
            "nameservers": w.name_servers,
            "dnssec": w.dnssec,
            "warnings": warnings,
            "status": "success"
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}
