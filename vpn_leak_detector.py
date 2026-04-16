"""
VPN Forensics - DNS/IP Leak Detection Tool
Author: Rohan Baba Shaik
Florida Institute of Technology - MS Computer Science
"""

import socket
import requests
import dns.resolver
import json
import csv
from datetime import datetime


# ─── CONFIG ───────────────────────────────────────────────────────────────────

DNS_LEAK_TEST_DOMAINS = [
    "whoami.akamai.net",
    "o-o.myaddr.l.google.com",
    "myip.opendns.com",
]

IP_LEAK_APIS = [
    "https://api.ipify.org?format=json",
    "https://api64.ipify.org?format=json",
]

EXPECTED_VPN_DNS_SERVERS = []  # Fill with your VPN provider's DNS IPs if known


# ─── DNS LEAK DETECTION ───────────────────────────────────────────────────────

def detect_dns_leak():
    """
    Resolves test domains and checks which DNS servers respond.
    If DNS servers outside the VPN tunnel respond, it's a leak.
    """
    results = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    print("\n[*] Checking for DNS leaks...")
    print("-" * 50)

    for domain in DNS_LEAK_TEST_DOMAINS:
        try:
            answers = resolver.resolve(domain, "A")
            for rdata in answers:
                ip = str(rdata)
                geo = get_ip_geolocation(ip)
                leaked = is_dns_leaked(ip, geo)
                result = {
                    "domain": domain,
                    "resolved_ip": ip,
                    "country": geo.get("country", "Unknown"),
                    "org": geo.get("org", "Unknown"),
                    "leaked": leaked,
                    "timestamp": datetime.now().isoformat()
                }
                results.append(result)
                status = "⚠️  LEAK DETECTED" if leaked else "✓ OK"
                print(f"  {status} | {domain} → {ip} | {geo.get('country','?')} | {geo.get('org','?')}")
        except Exception as e:
            print(f"  [!] Could not resolve {domain}: {e}")

    return results


def is_dns_leaked(ip, geo):
    """
    Heuristic: flag as leak if the DNS server is geolocated outside
    expected VPN regions or belongs to a known ISP (not VPN provider).
    """
    suspicious_orgs = ["comcast", "verizon", "at&t", "spectrum", "cox", "isp", "telecom"]
    org = geo.get("org", "").lower()
    for s in suspicious_orgs:
        if s in org:
            return True
    if EXPECTED_VPN_DNS_SERVERS and ip not in EXPECTED_VPN_DNS_SERVERS:
        return True
    return False


# ─── IP LEAK DETECTION ────────────────────────────────────────────────────────

def detect_ip_leak(real_ip):
    """
    Compares the public IP seen by external APIs against the known real IP.
    If they match, the VPN is not masking the IP — it's a leak.
    """
    print("\n[*] Checking for IP leaks...")
    print("-" * 50)

    results = []
    for api in IP_LEAK_APIS:
        try:
            resp = requests.get(api, timeout=5)
            data = resp.json()
            seen_ip = data.get("ip", "")
            geo = get_ip_geolocation(seen_ip)
            leaked = (seen_ip == real_ip)
            result = {
                "api": api,
                "seen_ip": seen_ip,
                "real_ip": real_ip,
                "country": geo.get("country", "Unknown"),
                "org": geo.get("org", "Unknown"),
                "leaked": leaked,
                "timestamp": datetime.now().isoformat()
            }
            results.append(result)
            status = "⚠️  LEAK DETECTED" if leaked else "✓ OK"
            print(f"  {status} | Seen IP: {seen_ip} | {geo.get('country','?')} | {geo.get('org','?')}")
        except Exception as e:
            print(f"  [!] Could not reach {api}: {e}")

    return results


# ─── REQUEST HEADER ANALYSIS ─────────────────────────────────────────────────

def analyze_headers(url="https://httpbin.org/headers"):
    """
    Fetches request headers as seen by a remote server.
    Checks for headers that may reveal the real client IP
    (e.g., X-Forwarded-For, X-Real-IP, Via).
    """
    print("\n[*] Analyzing request headers for IP exposure...")
    print("-" * 50)

    leak_headers = ["X-Forwarded-For", "X-Real-IP", "Via", "Forwarded", "Client-IP"]
    findings = []

    try:
        resp = requests.get(url, timeout=5)
        headers = resp.json().get("headers", {})

        for h in leak_headers:
            if h in headers:
                findings.append({"header": h, "value": headers[h], "risk": "HIGH"})
                print(f"  ⚠️  {h}: {headers[h]}  → may expose real IP")
            else:
                print(f"  ✓  {h}: not present")

        print(f"\n  Full headers received by server:")
        for k, v in headers.items():
            print(f"    {k}: {v}")

    except Exception as e:
        print(f"  [!] Header analysis failed: {e}")

    return findings


# ─── GEOLOCATION ──────────────────────────────────────────────────────────────

def get_ip_geolocation(ip):
    """Query ip-api.com for geolocation data."""
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = resp.json()
        return {
            "country": data.get("country", "Unknown"),
            "region": data.get("regionName", "Unknown"),
            "city": data.get("city", "Unknown"),
            "org": data.get("org", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
        }
    except Exception:
        return {}


# ─── REPORT GENERATION ────────────────────────────────────────────────────────

def generate_report(dns_results, ip_results, header_findings, output_file="vpn_leak_report.json"):
    """Save all findings to a JSON report."""
    report = {
        "scan_time": datetime.now().isoformat(),
        "summary": {
            "dns_leaks_found": sum(1 for r in dns_results if r.get("leaked")),
            "ip_leaks_found": sum(1 for r in ip_results if r.get("leaked")),
            "header_risks_found": len(header_findings),
        },
        "dns_leak_results": dns_results,
        "ip_leak_results": ip_results,
        "header_analysis": header_findings,
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[*] Report saved to {output_file}")
    return report


def generate_csv_report(dns_results, ip_results, output_file="vpn_leak_report.csv"):
    """Save DNS and IP results to CSV for further analysis."""
    rows = []
    for r in dns_results:
        rows.append({"type": "DNS", **r})
    for r in ip_results:
        rows.append({"type": "IP", **r})

    if rows:
        with open(output_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        print(f"[*] CSV report saved to {output_file}")


def print_summary(report):
    """Print a human-readable summary to terminal."""
    s = report["summary"]
    print("\n" + "=" * 50)
    print("  VPN LEAK DETECTION SUMMARY")
    print("=" * 50)
    print(f"  DNS Leaks Found   : {s['dns_leaks_found']}")
    print(f"  IP Leaks Found    : {s['ip_leaks_found']}")
    print(f"  Header Risks Found: {s['header_risks_found']}")

    total = s["dns_leaks_found"] + s["ip_leaks_found"] + s["header_risks_found"]
    if total == 0:
        print("\n  ✅ No leaks detected. VPN appears to be working correctly.")
    else:
        print(f"\n  ⚠️  {total} issue(s) found. Your VPN may be leaking your identity.")
        print("  Recommendation: Switch to a paid VPN with DNS leak protection,")
        print("  or configure DNS servers manually to your VPN provider's DNS.")
    print("=" * 50)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("  VPN FORENSICS — DNS/IP LEAK DETECTOR")
    print("  Author: Rohan Baba Shaik")
    print("=" * 50)

    # Get the machine's real local IP as baseline
    real_ip = socket.gethostbyname(socket.gethostname())
    print(f"\n[*] Local IP detected: {real_ip}")

    dns_results = detect_dns_leak()
    ip_results = detect_ip_leak(real_ip)
    header_findings = analyze_headers()

    report = generate_report(dns_results, ip_results, header_findings)
    generate_csv_report(dns_results, ip_results)
    print_summary(report)
