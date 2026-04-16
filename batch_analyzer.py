"""
VPN Batch Analyzer — tests and compares multiple VPN configurations
Author: Rohan Baba Shaik
"""

import json
import csv
import subprocess
import time
from datetime import datetime
from vpn_leak_detector import detect_dns_leak, detect_ip_leak, analyze_headers, get_ip_geolocation
import socket


VPN_PROFILES = [
    {"name": "No VPN (Baseline)", "active": True},
    # Add more profiles as needed — run each test after connecting to a different VPN
    # {"name": "ProtonVPN", "active": False},
    # {"name": "NordVPN", "active": False},
]


def run_full_scan(profile_name):
    """Run a complete leak scan for a given VPN profile."""
    print(f"\n{'='*60}")
    print(f"  SCANNING: {profile_name}")
    print(f"{'='*60}")

    real_ip = socket.gethostbyname(socket.gethostname())
    dns_results = detect_dns_leak()
    ip_results = detect_ip_leak(real_ip)
    header_findings = analyze_headers()

    leaks = sum(1 for r in dns_results if r.get("leaked")) + \
            sum(1 for r in ip_results if r.get("leaked")) + \
            len(header_findings)

    return {
        "profile": profile_name,
        "timestamp": datetime.now().isoformat(),
        "total_leaks": leaks,
        "dns_leaks": sum(1 for r in dns_results if r.get("leaked")),
        "ip_leaks": sum(1 for r in ip_results if r.get("leaked")),
        "header_risks": len(header_findings),
        "dns_details": dns_results,
        "ip_details": ip_results,
        "header_details": header_findings,
    }


def compare_vpns(profiles):
    """Run scans across multiple VPN profiles and produce comparison report."""
    results = []
    for profile in profiles:
        if profile["active"]:
            result = run_full_scan(profile["name"])
            results.append(result)
            time.sleep(2)

    # Save comparison report
    output = {
        "comparison_time": datetime.now().isoformat(),
        "profiles_tested": len(results),
        "results": results
    }

    with open("vpn_comparison_report.json", "w") as f:
        json.dump(output, f, indent=2)

    # Print comparison table
    print(f"\n{'='*60}")
    print(f"  VPN COMPARISON SUMMARY")
    print(f"{'='*60}")
    print(f"  {'Profile':<25} {'DNS Leaks':>10} {'IP Leaks':>10} {'Header Risks':>13} {'Total':>7}")
    print(f"  {'-'*60}")
    for r in results:
        print(f"  {r['profile']:<25} {r['dns_leaks']:>10} {r['ip_leaks']:>10} {r['header_risks']:>13} {r['total_leaks']:>7}")
    print(f"{'='*60}")
    print("  Full report saved to vpn_comparison_report.json")

    return results


if __name__ == "__main__":
    compare_vpns(VPN_PROFILES)
