import asyncio
from typing import Dict, Any, List
from dns_analyzer.resolver import async_query

async def build_dns_map(domain: str, records: Dict[str, List[str]], auth_ns: List[str]) -> Dict[str, Any]:
    tree = {
        "name": domain,
        "children": []
    }
    lines = [domain]
    
    if records.get('A'):
        for ip in records['A']:
            tree["children"].append({"name": f"A -> {ip}"})
            lines.append(f"├─ A -> {ip}")
            
    if records.get('MX'):
        for mx in records['MX']:
            mx_n = mx.split()[-1]
            mx_node = {"name": f"MX -> {mx_n}", "children": []}
            lines.append(f"├─ MX -> {mx_n}")
            
            # Lookup IP for MX
            res = await async_query(mx_n, 'A')
            if res:
                for r in res:
                    mx_node["children"].append({"name": f"A -> {r.to_text()}"})
                    lines.append(f"│  └─ A -> {r.to_text()}")
            
            tree["children"].append(mx_node)
            
    if auth_ns:
        for idx, ns in enumerate(auth_ns):
            prefix = "└─" if idx == len(auth_ns) - 1 else "├─"
            tree["children"].append({"name": f"NS -> {ns}"})
            lines.append(f"{prefix} NS -> {ns}")
                
    return {
        "tree": tree,
        "text_map": "\n".join(lines)
    }
