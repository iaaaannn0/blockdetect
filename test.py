import socket
import dns.resolver
import requests
import subprocess
import platform
import random
import ssl
import time
import os

# If you need traceroute capabilities:
from scapy.layers.inet import traceroute

from rich.console import Console
from rich.table import Table

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

DNS_SERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]
PORTS = [80, 443]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Version/14.1.2 Safari/537.36",
    "curl/7.68.0"
]


def check_dns_pollution(domain):
    """
    Use multiple public DNS servers to resolve the domain,
    returning a dict of IPs or error messages.
    """
    results = {}
    for server in DNS_SERVERS:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            answers = resolver.resolve(domain)
            results[server] = [str(answer) for answer in answers]
        except dns.resolver.NXDOMAIN:
            results[server] = "Error: NXDOMAIN"
        except dns.resolver.Timeout:
            results[server] = "Error: DNS query timed out"
        except dns.exception.DNSException as e:
            results[server] = f"Error: {e}"
        except Exception as e:
            results[server] = f"Error: {e}"
    return results


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


def check_ip_block(domain):
    """
    Check if the resolved IP is blocked on predefined ports.
    """
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return ("Failed to resolve domain.", True, "IP Blocking")

    results = {}
    blocked_ports = []
    for port in PORTS:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, port))
        latency = (time.time() - start_time) * 1000
        sock.close()

        if result == 0:
            results[port] = f"Port {port} reachable (Latency: {latency:.2f}ms)."
        else:
            results[port] = f"Port {port} seems blocked."
            blocked_ports.append(port)

    # If all tested ports are blocked
    is_blocked = (len(blocked_ports) == len(PORTS))
    return (results, is_blocked, "IP Blocking" if is_blocked else "Success")


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
            return ("Ping succeeded.", False, "Success")
        else:
            return ("Ping failed or host did not respond.", True, "ICMP Blocking")
    except Exception as e:
        return (f"Ping check error: {e}", True, "ICMP Blocking")


def check_traceroute(domain):
    """
    Run traceroute to see if traffic is dropped or blocked at a certain hop.
    Requires administrator/root privileges for scapy's raw packets.
    """
    try:
        ip = socket.gethostbyname(domain)
        ans, unans = traceroute(ip, maxttl=20, verbose=False)
        if not ans:
            return ("No traceroute response; may be dropped or blocked.", True, "Traceroute Possibly Blocked")
        else:
            return ("Traceroute completed with some replies.", False, "Success")
    except PermissionError:
        return ("Traceroute requires admin privileges.", True, "Traceroute Possibly Blocked")
    except Exception as e:
        return (f"Traceroute error: {e}", True, "Traceroute Possibly Blocked")


def check_dpi(domain):
    """
    Perform HTTP/HTTPS requests with random User-Agents to detect possible DPI blocking.
    """
    try:
        socket.gethostbyname(domain)
    except Exception as e:
        return (f"Domain resolve error: {e}", True, "DPI Blocking")

    results = {}
    blocked = False
    for proto in ["http", "https"]:
        try:
            user_agent = random.choice(USER_AGENTS)
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

    return (results, blocked, "DPI Blocking" if blocked else "Success")


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
                return (f"TLS handshake succeeded, CN={common_name}", False, "Success")
    except ssl.SSLError as e:
        return (f"TLS handshake failed (SSL error): {e}", True, "TLS Fingerprinting")
    except Exception as e:
        return (f"TLS handshake failed: {e}", True, "TLS Fingerprinting")


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
            # If we do not set check_hostname to False when server_name is None,
            # Python's SSL may complain "check_hostname requires server_hostname".
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

    return (results, blocked, "SNI Blocking" if blocked else "Success")


def detect_blocking(domain):
    """
    Main function that combines all checks.
    Returns a dictionary of results:
    { "Method": (analysis/evidence, is_blocked, technique) }
    """
    results = {}

    # 1. DNS
    dns_results = check_dns_pollution(domain)
    dns_analysis, dns_blocked, dns_technique = analyze_dns_pollution(domain, dns_results)
    results["DNS"] = (dns_analysis, dns_blocked, dns_technique)

    # 2. IP blocking
    ip_analysis, ip_blocked, ip_technique = check_ip_block(domain)
    results["IP Blocking"] = (ip_analysis, ip_blocked, ip_technique)

    # 3. ICMP Ping
    ping_analysis, ping_blocked, ping_technique = check_icmp_ping(domain)
    results["ICMP Ping"] = (ping_analysis, ping_blocked, ping_technique)

    # 4. Traceroute
    tracer_analysis, tracer_blocked, tracer_technique = check_traceroute(domain)
    results["Traceroute"] = (tracer_analysis, tracer_blocked, tracer_technique)

    # 5. DPI
    dpi_analysis, dpi_blocked, dpi_technique = check_dpi(domain)
    results["DPI"] = (dpi_analysis, dpi_blocked, dpi_technique)

    # 6. TLS Fingerprint
    tls_analysis, tls_blocked, tls_technique = check_tls_fingerprint(domain)
    results["TLS Fingerprint"] = (tls_analysis, tls_blocked, tls_technique)

    # 7. SNI Test
    sni_analysis, sni_blocked, sni_technique = check_sni_blocking(domain)
    results["SNI Test"] = (sni_analysis, sni_blocked, sni_technique)

    return results


def display_results(domain, results):
    """
    Display detection results in a table using 'rich'.
    """
    table = Table(title=f"Detection Results for {domain}")
    table.add_column("Method", style="cyan", justify="left")
    table.add_column("Evidence", justify="left")
    table.add_column("Technique", style="magenta", justify="left")

    for method, (evidence, is_blocked, technique) in results.items():
        color = "red" if is_blocked else "green"
        # Convert evidence to string if it's a dict or list
        if isinstance(evidence, dict):
            evidence_str = "\n".join([f"{k}: {v}" for k, v in evidence.items()])
        elif isinstance(evidence, (list, tuple)):
            evidence_str = str(evidence)
        else:
            evidence_str = str(evidence)

        table.add_row(method, f"[{color}]{evidence_str}[/{color}]", technique)

    console.print(table)


if __name__ == "__main__":
    domain = input("Enter the domain to test: ").strip()
    results = detect_blocking(domain)
    display_results(domain, results)
