import socket
import dns.resolver
import requests
import subprocess
import platform
from scapy.all import *
from rich.console import Console
from rich.table import Table

console = Console()

def check_dns_pollution(domain):
    """Check if DNS pollution occurs."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Public DNS servers
        answers = resolver.resolve(domain)
        return [str(answer) for answer in answers]
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN: The domain does not exist."
    except dns.resolver.NoAnswer:
        return "NoAnswer: DNS server did not return an answer."
    except Exception as e:
        return f"Error: {e}"

def check_ip_block(domain):
    """Check if the IP is blocked."""
    try:
        ip = socket.gethostbyname(domain)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, 80))  # Check HTTP port
        sock.close()
        if result == 0:
            return f"IP {ip} is reachable.", False
        else:
            return f"IP {ip} appears to be blocked.", True
    except socket.gaierror:
        return "Unable to resolve domain to IP.", True
    except Exception as e:
        return f"Error: {e}", True

def check_dpi(domain):
    """Check for DPI-based blocking by sending non-standard packets."""
    try:
        ip = socket.gethostbyname(domain)
        pkt = IP(dst=ip)/TCP(dport=80, flags="S")
        response = sr1(pkt, timeout=3, verbose=0)
        if response and response[TCP].flags == "SA":
            return f"No DPI blocking detected for {domain}.", False
        else:
            return f"Potential DPI blocking detected for {domain}.", True
    except Exception as e:
        return f"Error while checking DPI: {e}", True

def check_fake_packets(domain):
    """Check for fake packets by analyzing responses."""
    try:
        ip = socket.gethostbyname(domain)
        pkt = IP(dst=ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
        response = sr1(pkt, timeout=3, verbose=0)
        if response:
            if response.haslayer(DNS):
                return f"DNS response received: {response[DNS].summary()}", False
            else:
                return f"Unexpected response received: {response.summary()}", True
        else:
            return "No response received; possible packet filtering or blocking.", True
    except Exception as e:
        return f"Error while checking fake packets: {e}", True

def check_http_response(domain):
    """Check if HTTP responses are tampered."""
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        if response.status_code == 200:
            return "HTTP response is normal.", False
        else:
            return f"HTTP returned status code: {response.status_code}. Potential blocking.", True
    except requests.ConnectionError:
        return "Connection error. Potential IP blocking or DNS issue.", True
    except requests.Timeout:
        return "Connection timed out. Potential DPI or blocking.", True
    except Exception as e:
        return f"Error: {e}", True

def detect_blocking(domain):
    """Detect how a domain is being blocked."""
    results = {}

    # Check DNS Pollution
    dns_result = check_dns_pollution(domain)
    if isinstance(dns_result, list):
        results["DNS Pollution"] = (f"Resolved IPs: {', '.join(dns_result)}", False)
    else:
        results["DNS Pollution"] = (dns_result, True)

    # Check IP Blocking
    results["IP Blocking"] = check_ip_block(domain)

    # Check DPI Blocking
    results["DPI"] = check_dpi(domain)

    # Check Fake Packets
    results["Fake Packets"] = check_fake_packets(domain)

    # Check HTTP Response
    results["HTTP Tampering"] = check_http_response(domain)

    return results

def display_results(domain, results):
    table = Table(title=f"Detection Results for {domain}")
    table.add_column("Method", style="cyan", justify="left")
    table.add_column("Evidence", justify="left")

    for method, (evidence, is_blocked) in results.items():
        color = "red" if is_blocked else "green"
        table.add_row(method, f"[{color}]{evidence}[/{color}]")

    console.print(table)

if __name__ == "__main__":
    domain = input("Enter the domain to test: ").strip()
    results = detect_blocking(domain)
    display_results(domain, results)
