from typing import Dict, Any

def calculate_propagation(ttl: int) -> Dict[str, Any]:
    """
    Calculate theoretical maximum propagation based on TTL.
    """
    if ttl <= 0:
        return {
            "ttl": ttl,
            "max": "Unknown",
            "message": "TTL assumes 0 seconds or invalid. Changes propagate instantly or are broken."
        }
        
    minutes = ttl / 60
    hours = minutes / 60
    
    if hours >= 1:
        message = f"{round(hours, 2)} hours"
    else:
        message = f"{int(minutes)} minutes"
        
    return {
        "ttl": ttl,
        "max": message,
        "explanation": f"DNS caching means changes to this record could take up to {message} to fully propagate globally."
    }
