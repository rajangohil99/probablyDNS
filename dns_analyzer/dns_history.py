import json
import os
from datetime import datetime
from typing import Dict, Any, List

CACHE_FILE = ".dns_history.json"

def track_history(domain: str, current_a_records: List[str]) -> Dict[str, Any]:
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, "r") as f:
                history = json.load(f)
        else:
            history = {}
    except Exception:
        history = {}
        
    domain_history = history.get(domain, [])
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sorted_current = sorted(current_a_records)
    
    # Check if changed or new
    if not domain_history or domain_history[-1]["records"] != sorted_current:
        domain_history.append({
            "date": now,
            "records": sorted_current
        })
        history[domain] = domain_history[-5:] # Keep last 5
        
        try:
            with open(CACHE_FILE, "w") as f:
                json.dump(history, f)
        except Exception:
            pass
            
    return {
        "history": domain_history[::-1] # Newest first
    }
