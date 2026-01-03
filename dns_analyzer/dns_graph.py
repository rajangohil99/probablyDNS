import os
from typing import Dict, Any, List

try:
    from graphviz import Digraph
except ImportError:
    Digraph = None

def generate_dns_graph(domain: str, records: Dict[str, List[str]], auth_ns: List[str]) -> Dict[str, Any]:
    if not Digraph:
        return {"status": "error", "message": "graphviz package not installed"}
        
    dot = Digraph(comment=f'DNS Graph for {domain}')
    dot.attr(rankdir='LR')
    
    dot.node('domain', domain, shape='ellipse', style='filled', color='lightblue')
    
    # A Records
    if records.get('A'):
        for ip in records['A']:
            dot.node(ip, ip, shape='box')
            dot.edge('domain', ip, label='A')
            
    # MX Records
    if records.get('MX'):
        for mx in records['MX']:
            mx_name = mx.split()[-1]
            dot.node(mx_name, mx_name, shape='diamond')
            dot.edge('domain', mx_name, label='MX')
            
    # NS Records
    for ns in auth_ns:
        ns_name = ns.strip('.')
        dot.node(ns_name, ns_name, shape='parallelogram', color='lightgreen')
        dot.edge('domain', ns_name, label='NS')
        
    output_path = f"{domain}_dns_graph"
    try:
        dot.render(output_path, format='png', cleanup=True)
        return {
            "status": "success",
            "png_file": f"{output_path}.png",
            "dot_source": dot.source
        }
    except Exception as e:
        return {"status": "error", "message": f"Graphviz render failed (Executable exists?): {str(e)}", "dot_source": dot.source}
