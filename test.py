import socket
import dns.resolver
import requests
import subprocess
import platform
import random
import ssl
import time
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Any
import threading

# If you need traceroute capabilities:
from scapy.layers.inet import traceroute

from rich.console import Console
from rich.table import Table
from rich.progress import Progress

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

# Configuration
CONFIG = {
    "dns_servers": [
        "8.8.8.8",    # Google
        "1.1.1.1",    # Cloudflare
        "9.9.9.9",    # Quad9
        "208.67.222.222",  # OpenDNS
        "114.114.114.114", # 114 DNS
        "223.5.5.5"    # AliDNS
    ],
    "ports": [80, 443, 8080],
    "http_methods": ["GET", "POST", "HEAD"],
    "timeout": 5,
    "max_workers": 10,
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
        "curl/7.68.0"
    ]
}


def check_dns_pollution(domain: str) -> Tuple[Dict[str, Any], bool, str]:
    """Enhanced DNS pollution detection"""
    results = {}
    ip_sets = []
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Performing DNS check...", total=len(CONFIG["dns_servers"]))
        
        with ThreadPoolExecutor(max_workers=CONFIG["max_workers"]) as executor:
            def query_dns(server):
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [server]
                    resolver.timeout = CONFIG["timeout"]
                    answers = resolver.resolve(domain)
                    ips = [str(answer) for answer in answers]
                    ip_sets.append(set(ips))
                    return server, {"ips": ips, "status": "success"}
                except Exception as e:
                    return server, {"error": str(e), "status": "error"}

            futures = [executor.submit(query_dns, server) for server in CONFIG["dns_servers"]]
            for future in as_completed(futures):
                server, result = future.result()
                results[server] = result
                progress.advance(task)

    # Analyze results
    successful_queries = [r for r in results.values() if r["status"] == "success"]
    if not successful_queries:
        return results, True, "DNS Pollution (All queries failed)"

    # Check IP consistency
    ip_consistency = len(set.intersection(*[set(r["ips"]) for r in successful_queries])) > 0
    if not ip_consistency:
        return results, True, "DNS Pollution (Inconsistent IPs)"

    return results, False, "Success"


def analyze_dns_pollution(domain, dns_query_results):
    """
    Analyze the DNS query results to detect inconsistencies
    or suspicious IP returns that may indicate DNS pollution.
    """
    ip_sets = []
    for server, result in dns_query_results.items():
        if isinstance(result, list):
            ip_sets.append(set(result))

    # If no successful DNS queries
    if not ip_sets:
        return ("All DNS queries failed; possibly pollution or invalid domain.", True, "DNS Pollution")

    combined_ips = set.union(*ip_sets)
    # Example threshold for suspiciously high IP count
    if len(combined_ips) > 5:
        return (f"Significant discrepancy among DNS results: {combined_ips}", True, "DNS Pollution")

    # Otherwise, treat them as consistent enough
    return (f"DNS results appear consistent: {dns_query_results}", False, "Success")


def check_ip_block(domain: str) -> Tuple[Dict[str, Any], bool, str]:
    """Enhanced IP blocking detection"""
    results = {}
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return {"error": "Failed to resolve domain"}, True, "IP Blocking"

    with Progress() as progress:
        task = progress.add_task("[cyan]Checking ports...", total=len(CONFIG["ports"]))
        
        for port in CONFIG["ports"]:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(CONFIG["timeout"])
            
            try:
                result = sock.connect_ex((ip, port))
                latency = (time.time() - start_time) * 1000
                
                if result == 0:
                    results[port] = {
                        "status": "open",
                        "latency": f"{latency:.2f}ms"
                    }
                else:
                    results[port] = {
                        "status": "closed",
                        "error": f"Connection failed (errno: {result})"
                    }
            except Exception as e:
                results[port] = {
                    "status": "error",
                    "error": str(e)
                }
            finally:
                sock.close()
                progress.advance(task)

    # Determine if blocked
    blocked_ports = [port for port, data in results.items() if data["status"] != "open"]
    is_blocked = len(blocked_ports) == len(CONFIG["ports"])

    return results, is_blocked, "IP Blocking" if is_blocked else "Success"


def check_icmp_ping(domain):
    """
    Test ICMP ping to check reachability.
    Some servers may disable ping, so a failure might be inconclusive.
    """
    try:
        ip = socket.gethostbyname(domain)
        # Platform-specific param for ping count
        count_param = "-n" if platform.system().lower().startswith('win') else "-c"
        cmd = f"ping {count_param} 3 {ip}"
        exit_code = os.system(cmd)
        if exit_code == 0:
            return {"message": "Ping succeeded."}, False, "Success"
        else:
            return {"message": "Ping failed or host did not respond."}, True, "ICMP Blocking"
    except Exception as e:
        return {"error": f"Ping check error: {e}"}, True, "ICMP Blocking"


def check_traceroute(domain):
    """
    Run traceroute to see if traffic is dropped or blocked at a certain hop.
    Requires administrator/root privileges for scapy's raw packets.
    """
    try:
        ip = socket.gethostbyname(domain)
        ans, unans = traceroute(ip, maxttl=20, verbose=False)
        if not ans:
            return {"message": "No traceroute response; may be dropped or blocked."}, True, "Traceroute Possibly Blocked"
        else:
            return {"message": "Traceroute completed with some replies."}, False, "Success"
    except PermissionError:
        return {"error": "Traceroute requires admin privileges."}, True, "Traceroute Possibly Blocked"
    except Exception as e:
        return {"error": f"Traceroute error: {e}"}, True, "Traceroute Possibly Blocked"


def check_dpi(domain):
    """
    Perform HTTP/HTTPS requests with random User-Agents to detect possible DPI blocking.
    """
    try:
        socket.gethostbyname(domain)
    except Exception as e:
        return {"error": f"Domain resolve error: {e}"}, True, "DPI Blocking"

    results = {}
    blocked = False
    for proto in ["http", "https"]:
        try:
            user_agent = random.choice(CONFIG["user_agents"])
            headers = {"User-Agent": user_agent}
            url = f"{proto}://{domain}"
            resp = requests.get(url, headers=headers, timeout=5, verify=False)
            results[proto] = f"{proto.upper()} status: {resp.status_code}"
        except requests.exceptions.Timeout:
            results[proto] = "Connection timed out."
            blocked = True
        except requests.exceptions.SSLError as e:
            results[proto] = f"SSL error: {e}"
            blocked = True
        except Exception as e:
            results[proto] = f"Error: {e}"
            blocked = True

    return {"protocols": results}, blocked, "DPI Blocking" if blocked else "Success"


def check_tls_fingerprint(domain):
    """
    Test TLS handshake for potential fingerprint-based blocking.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert["subject"])
                common_name = subject.get("commonName", "")
                return {"message": f"TLS handshake succeeded, CN={common_name}"}, False, "Success"
    except ssl.SSLError as e:
        return {"error": f"TLS handshake failed (SSL error): {e}"}, True, "TLS Fingerprinting"
    except Exception as e:
        return {"error": f"TLS handshake failed: {e}"}, True, "TLS Fingerprinting"


def check_sni_blocking(domain):
    """
    Test TLS handshake with normal SNI vs. empty SNI.
    This can detect potential SNI-based blocking.
    """
    results = {}
    blocked = False

    def tls_handshake(server_name):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if server_name is None:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=server_name) as ssock:
                    return True, "Handshake OK"
        except Exception as e:
            return False, f"Handshake failed: {e}"

    # Test normal SNI
    ok, msg = tls_handshake(server_name=domain)
    results["normal_SNI"] = msg
    if not ok:
        blocked = True

    # Test empty SNI
    ok, msg = tls_handshake(server_name=None)
    results["empty_SNI"] = msg
    if not ok:
        blocked = True

    return {"tests": results}, blocked, "SNI Blocking" if blocked else "Success"


def check_http_availability(domain: str) -> Tuple[Dict[str, Any], bool, str]:
    """Check HTTP/HTTPS availability"""
    results = {}
    
    with Progress() as progress:
        total_checks = len(CONFIG["http_methods"]) * 2  # HTTP and HTTPS
        task = progress.add_task("[cyan]Checking HTTP/HTTPS...", total=total_checks)
        
        for protocol in ["http", "https"]:
            results[protocol] = {}
            for method in CONFIG["http_methods"]:
                try:
                    url = f"{protocol}://{domain}"
                    headers = {"User-Agent": random.choice(CONFIG["user_agents"])}
                    
                    response = requests.request(
                        method,
                        url,
                        headers=headers,
                        timeout=CONFIG["timeout"],
                        verify=False
                    )
                    
                    results[protocol][method] = {
                        "status_code": response.status_code,
                        "latency": f"{response.elapsed.total_seconds() * 1000:.2f}ms"
                    }
                except Exception as e:
                    results[protocol][method] = {
                        "error": str(e)
                    }
                progress.advance(task)

    # Analyze results
    is_blocked = all(
        "error" in data
        for proto_data in results.values()
        for data in proto_data.values()
    )

    return results, is_blocked, "HTTP Blocking" if is_blocked else "Success"


def check_ssl_cert(domain: str) -> Tuple[Dict[str, Any], bool, str]:
    """Check SSL certificate validity"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=CONFIG["timeout"]) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                return {
                    "subject": dict(x[0] for x in cert["subject"]),
                    "issuer": dict(x[0] for x in cert["issuer"]),
                    "version": cert["version"],
                    "serialNumber": cert["serialNumber"],
                    "notBefore": cert["notBefore"],
                    "notAfter": cert["notAfter"]
                }, False, "Success"
    except Exception as e:
        return {"error": str(e)}, True, "SSL Certificate Invalid"


def detect_blocking(domain):
    """
    Main function that combines all checks.
    Returns a dictionary of results:
    { "Method": {"evidence": evidence, "blocked": is_blocked, "technique": technique} }
    """
    results = {}

    # 1. DNS
    dns_results, dns_blocked, dns_technique = check_dns_pollution(domain)
    results["DNS"] = {"evidence": dns_results, "blocked": dns_blocked, "technique": dns_technique}

    # 2. IP blocking
    ip_results, ip_blocked, ip_technique = check_ip_block(domain)
    results["IP"] = {"evidence": ip_results, "blocked": ip_blocked, "technique": ip_technique}

    # 3. ICMP Ping
    ping_results, ping_blocked, ping_technique = check_icmp_ping(domain)
    results["ICMP"] = {"evidence": ping_results, "blocked": ping_blocked, "technique": ping_technique}

    # 4. Traceroute
    tracer_results, tracer_blocked, tracer_technique = check_traceroute(domain)
    results["Traceroute"] = {"evidence": tracer_results, "blocked": tracer_blocked, "technique": tracer_technique}

    # 5. DPI
    dpi_results, dpi_blocked, dpi_technique = check_dpi(domain)
    results["DPI"] = {"evidence": dpi_results, "blocked": dpi_blocked, "technique": dpi_technique}

    # 6. TLS Fingerprint
    tls_results, tls_blocked, tls_technique = check_tls_fingerprint(domain)
    results["TLS"] = {"evidence": tls_results, "blocked": tls_blocked, "technique": tls_technique}

    # 7. SNI Test
    sni_results, sni_blocked, sni_technique = check_sni_blocking(domain)
    results["SNI"] = {"evidence": sni_results, "blocked": sni_blocked, "technique": sni_technique}

    # 8. HTTP/HTTPS 可用性检测
    http_results, http_blocked, http_technique = check_http_availability(domain)
    results["HTTP"] = {"evidence": http_results, "blocked": http_blocked, "technique": http_technique}

    # 9. SSL 证书检测
    ssl_results, ssl_blocked, ssl_technique = check_ssl_cert(domain)
    results["SSL"] = {"evidence": ssl_results, "blocked": ssl_blocked, "technique": ssl_technique}

    return results


def display_results(domain, results):
    """
    Display detection results in a table using 'rich'.
    """
    table = Table(title=f"Detection Results for {domain}")
    table.add_column("Method", style="cyan", justify="left")
    table.add_column("Evidence", justify="left")
    table.add_column("Technique", style="magenta", justify="left")

    for method, data in results.items():
        status = "[red]Blocked[/red]" if data["blocked"] else "[green]Normal[/green]"
        details = str(data["evidence"])[:100] + "..." if len(str(data["evidence"])) > 100 else str(data["evidence"])
        table.add_row(method, status, details)

    console.print(table)


def main(domain: str):
    """Main function"""
    console.print(f"\n[bold cyan]Starting detection for domain: {domain}[/bold cyan]\n")
    
    results = detect_blocking(domain)
    
    # Display results table
    table = Table(title=f"\nDetection Results Summary - {domain}")
    table.add_column("Check Type", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details", style="yellow")
    
    for check_type, data in results.items():
        status = "[red]Blocked[/red]" if data["blocked"] else "[green]Normal[/green]"
        details = str(data["evidence"])[:100] + "..." if len(str(data["evidence"])) > 100 else str(data["evidence"])
        table.add_row(check_type, status, details)
    
    console.print(table)
    
    # Save detailed results to file
    result_file = f"scan_result_{domain}_{int(time.time())}.json"
    with open(result_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    console.print(f"\n[bold green]Detailed results saved to: {result_file}[/bold green]")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        domain = input("Enter domain to test: ")
    else:
        domain = sys.argv[1]
    
    main(domain)
