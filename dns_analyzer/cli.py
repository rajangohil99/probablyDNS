import asyncio
import json
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from typing import Dict, Any, List

from dns_analyzer.resolver import async_query
from dns_analyzer.records import get_all_records
from dns_analyzer.delegation import trace_delegation
from dns_analyzer.multi_resolver import check_multi_resolvers
from dns_analyzer.dnssec import check_dnssec
from dns_analyzer.security import test_zone_transfer, check_spf_dmarc
from dns_analyzer.latency import measure_latency
from dns_analyzer.propagation import calculate_propagation
from dns_analyzer.diagnosis import run_diagnosis

from dns_analyzer.subdomain_enum import discover_subdomains
from dns_analyzer.whois_info import get_whois_info
from dns_analyzer.dns_history import track_history
from dns_analyzer.split_dns import detect_split_dns
from dns_analyzer.cdn_detection import detect_cdn
from dns_analyzer.reverse_dns import check_reverse_dns
from dns_analyzer.wildcard_dns import detect_wildcard
from dns_analyzer.dns_graph import generate_dns_graph
from dns_analyzer.dns_map import build_dns_map

from dns_analyzer.infra_fingerprint import fingerprint_infra
from dns_analyzer.asn_lookup import detect_network_ownership
from dns_analyzer.query_path_timing import measure_query_path

from dns_analyzer.dig_query import run_dig_queries
from dns_analyzer.resolve_path import measure_resolve_path
from dns_analyzer.dnssec_validator import deep_dnssec_validation

from dns_analyzer.provider_dns_test import test_provider_dns
from dns_analyzer.dns_filter_detection import detect_dns_filtering
from dns_analyzer.reachability_test import test_reachability
from dns_analyzer.http_test import check_http
from dns_analyzer.split_dns_detection import detect_split_dns_extended
from dns_analyzer.vpn_reputation_check import check_vpn_reputation
from dns_analyzer.resolver_comparison import run_resolver_comparison

from dns_analyzer.dns_leak_test import run_dns_leak_test
from dns_analyzer.dns_filter_test import test_dns_filter
from dns_analyzer.dns_hijack_detection import check_dns_hijack
from dns_analyzer.resolver_capabilities import analyze_resolver_capabilities
from dns_analyzer.resolver_benchmark import benchmark_resolvers

app = typer.Typer(help="Professional DNS Diagnostic Tool")
console = Console()

async def collect_all_data(
    domain: str,
    run_subdomains: bool = False,
    run_whois: bool = False,
    run_history: bool = False,
    run_split: bool = False,
    run_cdn: bool = False,
    run_ptr: bool = False,
    run_wildcard: bool = False,
    run_graph: bool = False,
    run_map: bool = False,
    run_infra: bool = False,
    run_deep_audit: bool = False
) -> Dict[str, Any]:
    
    results = {"domain": domain}
    
    # Base analysis
    delegation = await trace_delegation(domain)
    results["delegation"] = delegation
    
    auth_ns = delegation.get("authoritative_nameservers", [])
    if not auth_ns:
        try:
            import dns.resolver
            ans = dns.resolver.resolve(domain, 'NS')
            auth_ns = [str(a) for a in ans]
        except Exception:
            auth_ns = []
            
    m_res_task = check_multi_resolvers(domain)
    rec_task = get_all_records(domain)
    
    m_res, records = await asyncio.gather(m_res_task, rec_task)
    results["multi_resolver"] = m_res
    results["records"] = records
    
    dnssec, perf = await asyncio.gather(
        asyncio.to_thread(check_dnssec, domain),
        measure_latency(auth_ns)
    )
    
    results["dnssec"] = dnssec
    results["latency"] = perf
    
    ttl = m_res.get("resolvers", {}).get("Google", {}).get("ttl", 3600)
    if ttl is None:
        ttl = 3600
    results["propagation"] = calculate_propagation(ttl)
    
    # Advanced Optional Modules
    if run_subdomains:
        results["subdomains"] = await discover_subdomains(domain)
    if run_whois:
        results["whois"] = await get_whois_info(domain)
    if run_split:
        results["split_dns"] = await detect_split_dns(domain, auth_ns)
    if run_ptr:
        results["reverse_dns"] = await check_reverse_dns(records.get("A", []))
    if run_wildcard:
        results["wildcard"] = await detect_wildcard(domain)
    if run_map:
        results["map"] = await build_dns_map(domain, records, auth_ns)
        
    if run_infra:
        results["infra_fingerprint"] = fingerprint_infra(records, auth_ns)
        asn_task = detect_network_ownership(records.get("A", []))
        timing_task = measure_query_path(domain, auth_ns)
        asn_res, timing_res = await asyncio.gather(asn_task, timing_task)
        results["asn_lookup"] = asn_res
        results["timing"] = timing_res
        
    if run_history:
        results["history"] = track_history(domain, records.get("A", []))
    if run_cdn:
        results["cdn"] = detect_cdn(records.get("CNAME", []), records.get("A", []))
    if run_graph:
        results["graph"] = generate_dns_graph(domain, records, auth_ns)
        
    if run_deep_audit:
        dig_task = run_dig_queries(domain)
        resolve_task = measure_resolve_path(domain, auth_ns)
        deep_dnssec_task = deep_dnssec_validation(domain)
        
        provider_task = test_provider_dns(domain)
        reach_task = test_reachability(records.get("A", []))
        http_task = check_http(domain)
        split_ext_task = detect_split_dns_extended(domain, auth_ns)
        vpn_task = check_vpn_reputation()
        compare_task = run_resolver_comparison(domain)
        
        leak_task = run_dns_leak_test()
        filter2_task = test_dns_filter(domain)
        hijack_task = check_dns_hijack()
        caps_task = analyze_resolver_capabilities()
        bench_task = benchmark_resolvers()
        
        dig_res, resolve_res, deep_dnssec_res, provider_res, reach_res, http_res, split_ext_res, vpn_res, compare_res, leak_res, filter2_res, hijack_res, caps_res, bench_res = await asyncio.gather(
            dig_task, resolve_task, deep_dnssec_task, provider_task, reach_task, http_task, split_ext_task, vpn_task, compare_task, leak_task, filter2_task, hijack_task, caps_task, bench_task
        )
        
        filter_res = detect_dns_filtering(domain, provider_res.get("results", {}).get("Provider DNS (ns1.provider)", []))
        
        results["dig"] = dig_res
        results["resolve_path"] = resolve_res
        results["deep_dnssec"] = deep_dnssec_res
        results["provider_dns"] = provider_res
        results["dns_filtering"] = filter_res
        results["reachability"] = reach_res
        results["http_test"] = http_res
        results["split_dns_ext"] = split_ext_res
        results["vpn_reputation"] = vpn_res
        results["resolver_compare"] = compare_res

        results["vpn_ext"] = {
            "leak": leak_res,
            "filter": filter2_res,
            "hijack": hijack_res,
            "capabilities": caps_res,
            "benchmark": bench_res
        }

    # Final Diagnosis
    results["diagnosis"] = run_diagnosis(results)
    
    return results



def print_human_report(results: Dict[str, Any], domain: str, full: bool = False):
    console.print(f"[bold blue]DNS Diagnostic Report for:[/bold blue] {domain}\n")
    console.print(Panel(f"[bold]Issues Found:[/bold] {results['diagnosis']['total_issues']}", title="Domain Summary", expand=False))
    
    if "provider_dns" in results:
        p = results["provider_dns"]
        console.print("[bold green]Provider DNS Resolver Test:[/bold green]")
        for resolver, ans in p['results'].items():
            console.print(f"[cyan]{resolver}[/cyan]\n  -> {', '.join(ans)}")
        console.print(f"\nConclusion:\n  {p['conclusion']}\n")
        
    if "dns_filtering" in results:
        fl = results["dns_filtering"]
        console.print("[bold green]DNS Filtering Detection:[/bold green]")
        console.print("Resolver: ns1.provider.net")
        console.print(f"Response: {', '.join(fl['response'])}")
        console.print(f"\nConclusion:\n  {fl['conclusion']}\n")
        
    if "reachability" in results:
        rt = results["reachability"]
        if rt.get("status") != "error":
            console.print("[bold green]Network Reachability:[/bold green]")
            console.print(f"Resolved IP: {rt['ip']}")
            console.print(f"Ping: {rt['ping']}")
            console.print(f"TCP 80: {rt['tcp_80']}")
            console.print(f"TCP 443: {rt['tcp_443']}\n")
        
    if "http_test" in results:
        h = results["http_test"]
        console.print("[bold green]HTTP Connectivity Test:[/bold green]")
        console.print(f"HTTP Status: {h['status_code']}")
        console.print(f"Server: {h['server']}")
        console.print(f"TLS handshake: {h['tls_handshake']}")
        if h.get('possible_cause'):
            console.print(f"\nPossible cause: {h['possible_cause']}")
        console.print()
        
    if "split_dns_ext" in results:
        s = results["split_dns_ext"]
        console.print("[bold green]Split DNS Detection:[/bold green]")
        console.print(f"Authoritative:\n  {', '.join(s['authoritative'])}")
        console.print(f"Provider DNS:\n  {', '.join(s['provider'])}")
        console.print(f"Public DNS:\n  {', '.join(s['public'])}\n")
        
    if "vpn_reputation" in results:
        v = results["vpn_reputation"]
        if v.get('status') != 'error':
            console.print("[bold green]VPN Exit IP Reputation Check:[/bold green]")
            console.print(f"{v['ip']}")
            console.print(f"ASN: {v['asn']}")
            console.print(f"Organization: {v['organization']}")
            console.print(f"Reputation: {v['reputation']}")
            if v.get('possible_cause'):
                console.print(f"\nPossible cause:\n  {v['possible_cause']}")
            console.print()

    if "resolve_path" in results:
        r = results["resolve_path"]
        console.print("[bold green]DNS Resolution Path:[/bold green]")
        console.print(f"Root lookup: {r['root_latency_ms']} ms")
        console.print(f"TLD lookup (.{r['tld_name']}): {r['tld_latency_ms']} ms")
        console.print(f"Authoritative lookup: {r['auth_latency_ms']} ms")
        console.print("\n[cyan]Final Answer[/cyan]")
        for ans in r['final_answer']:
            console.print(f"{domain} -> {ans}")
        console.print(f"\nTotal resolution time: {r['total_resolution_time_ms']} ms")
        for warn in r.get("warnings", []):
            console.print(f"[bold red]Warning:[/bold red] {warn}")
        console.print()
        
    if "deep_dnssec" in results:
        d = results["deep_dnssec"]
        console.print("[bold green]DNSSEC Validation:[/bold green]")
        console.print(f"Root: {'signed' if d['root_signed'] else 'unsigned'}")
        console.print(f"TLD (.{d['tld']}): {'signed' if d['tld_signed'] else 'unsigned'}")
        console.print(f"{domain}: {'signed' if d['domain_signed'] else 'unsigned'}")
        
        if d['status'] == 'SUCCESS':
            console.print(f"\nValidation Result: [bold green]{d['status']}[/bold green]")
        else:
            console.print(f"\nValidation Result: [bold red]{d['status']}[/bold red]")
            
        if d.get('reason'):
            console.print(f"\nReason:\n{d['reason']}")
        if d.get('impact'):
            console.print(f"\nImpact:\n{d['impact']}")
        console.print()

    if "infra_fingerprint" in results:
        fp = results["infra_fingerprint"]
        console.print("[bold green]Infrastructure Fingerprint:[/bold green]")
        console.print(f"Nameserver Provider: {fp['nameserver_provider']}")
        console.print(f"Hosting Provider: {fp['hosting_provider']}")
        console.print(f"Email Provider: {fp['email_provider']}")
        console.print(f"CDN Provider: {fp['cdn_provider']}")
        console.print()
        
    if "resolver_compare" in results:
        rcs = results["resolver_compare"]
        console.print("[bold green]DNS Resolver Comparison[/bold green]")
        for rc in rcs:
            console.print(f"\n[cyan]Record Type: {rc['record_type']}[/cyan]")
            console.print("[bold]Resolver Results[/bold]")
            
            for res in rc["results"]:
                console.print(f"\n{res['resolver']} ({res['server']})")
                if res["status"] == "success" and res["answers"]:
                    for a in res["answers"]:
                        console.print(f"  {a}")
                    console.print(f"  [dim]TTL: {res['ttl']} | Query Time: {res['latency_ms']} ms[/dim]")
                elif res["status"] == "error":
                    console.print(f"  [red]Error: {res['error']}[/red]")
                else:
                    console.print("  [dim]No answers returned[/dim]")
                    
            console.print("\n[bold]Resolver Analysis[/bold]")
            console.print(rc["analysis"])
            if rc.get("possible_cause"):
                console.print(f"Possible cause:\n{rc['possible_cause']}")
        console.print()

    if "dig" in results:
        console.print("[bold green]DNS Query Results (dig-style):[/bold green]")
        for q in results["dig"]["queries"]:
            if q["status"] == "success" and q["answers"]:
                console.print(f"[cyan]> dig {domain} {q['type']}[/cyan]")
                console.print(f"[cyan]{q['type']} Records:[/cyan]")
                for a in q["answers"]:
                    console.print(f"  {a}")
                console.print(f"  [dim]TTL: {q['ttl']} | Query Time: {q['query_time_ms']} ms[/dim]")
                console.print()
                
    console.print("[bold red]Final Diagnosis:[/bold red]")
    for finding in results['diagnosis']['summary']:
        console.print(f"  [bold]Issue:[/bold] {finding['issue']}")
        if finding['issue'] != "None detected.":
            console.print(f"  [bold]Cause:[/bold] {finding['cause']}")
            console.print(f"  [bold]Action:[/bold] {finding['action']}")
        console.print()

@app.command()
def analyze(
    domain: str = typer.Argument(..., help="Domain to analyze"),
    json_out: bool = typer.Option(False, "--json", help="Output results in JSON format"),
    markdown_out: bool = typer.Option(False, "--markdown", help="Output results in Markdown format"),
    trace: bool = typer.Option(False, "--trace", help="Detailed trace analysis output"),
    full_report: bool = typer.Option(False, "--full-report", help="Complete detailed report"),
    subdomains: bool = typer.Option(False, "--subdomains", help="Run subdomain discovery"),
    whois: bool = typer.Option(False, "--whois", help="Fetch WHOIS info"),
    history: bool = typer.Option(False, "--history", help="Track DNS history"),
    split_dns: bool = typer.Option(False, "--split-dns", help="Detect split DNS"),
    cdn: bool = typer.Option(False, "--cdn", help="Detect CDN usage"),
    ptr: bool = typer.Option(False, "--ptr", help="Validate reverse DNS"),
    wildcard: bool = typer.Option(False, "--wildcard", help="Detect wildcard DNS"),
    graph: bool = typer.Option(False, "--graph", help="Generate dependency graph image"),
    dns_map: bool = typer.Option(False, "--map", help="Show dependency map")
):
    try:
        results = asyncio.run(collect_all_data(
            domain,
            run_subdomains=subdomains or full_report,
            run_whois=whois or full_report,
            run_history=history or full_report,
            run_split=split_dns or full_report,
            run_cdn=cdn or full_report,
            run_ptr=ptr or full_report,
            run_wildcard=wildcard or full_report,
            run_graph=graph or full_report,
            run_map=dns_map or full_report,
            run_infra=full_report, 
            run_deep_audit=full_report
        ))
    except Exception as e:
        console.print(f"[red]Failed to run analysis:[red] {str(e)}")
        typer.Exit(1)
        return

    if json_out:
        console.print(json.dumps(results, indent=2))
        return
        
    if markdown_out:
        console.print(json.dumps(results, indent=2))
        return

    print_human_report(results, domain, full_report)

@app.command("compare")
def compare_cmd(
    domain: str = typer.Argument(..., help="Domain to analyze")
):
    """
    Compare DNS responses between authoritative, provider, and public resolvers.
    """
    try:
        results = asyncio.run(run_resolver_comparison(domain))
        rc_wrapper = {"domain": domain, "diagnosis": {"total_issues": 0, "summary": []}, "resolver_compare": results}
        print_human_report(rc_wrapper, domain, False)
    except Exception as e:
        console.print(f"[red]Failed to run compare analysis:[red] {str(e)}")
        typer.Exit(1)

if __name__ == "__main__":
    app()
