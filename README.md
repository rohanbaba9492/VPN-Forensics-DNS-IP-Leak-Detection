# VPN Forensics — DNS/IP Leak Detection Tool

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Focus](https://img.shields.io/badge/Focus-Network%20Forensics-darkred?style=flat-square)
![Institution](https://img.shields.io/badge/Florida%20Institute%20of%20Technology-Research%20Project-navy?style=flat-square)

A Python-based forensic tool that investigates **DNS leaks**, **IP leaks**, and **request header exposure** in free and commercial VPN services. Built to analyze how VPN clients fail to protect user identity — and provide actionable mitigation recommendations.

---

## The Problem

Many free VPN services claim to protect user privacy but silently leak identifying information through three main vectors:

| Leak Type | What It Exposes |
|---|---|
| **DNS Leak** | Your ISP's DNS servers answer queries instead of the VPN's — revealing browsing activity |
| **IP Leak** | Your real public IP is visible to external servers despite the VPN being active |
| **Header Leak** | HTTP headers like `X-Forwarded-For` or `X-Real-IP` expose the real client IP |

This tool detects all three and generates a detailed forensic report.

---

## How It Works

```
Run Tool
    │
    ├── DNS Leak Detection
    │   Resolves test domains via active DNS resolver
    │   Checks if responses come from ISP servers (not VPN)
    │   Flags ISP-owned DNS servers as leaks
    │
    ├── IP Leak Detection
    │   Queries external IP APIs (ipify.org)
    │   Compares seen IP against known real IP
    │   Flags match as leak (VPN not masking IP)
    │
    ├── Header Analysis
    │   Fetches headers as seen by httpbin.org
    │   Checks for X-Forwarded-For, X-Real-IP, Via, Forwarded
    │   Flags any header that could expose real IP
    │
    └── Report Generation
        JSON report + CSV export + terminal summary
```

---

## Detection Logic

### DNS Leak
```python
# Resolves test domains and checks responding DNS server geolocation/org
# Flags as leak if DNS server belongs to known ISPs
suspicious_orgs = ["comcast", "verizon", "at&t", "spectrum", "cox"]
if any(s in org.lower() for s in suspicious_orgs):
    leaked = True
```

### IP Leak
```python
# Compares external-facing IP against local IP baseline
seen_ip = requests.get("https://api.ipify.org?format=json").json()["ip"]
leaked = (seen_ip == real_ip)  # True = VPN not working
```

### Header Leak
```python
# Checks for headers that proxies/VPNs sometimes inject
leak_headers = ["X-Forwarded-For", "X-Real-IP", "Via", "Forwarded", "Client-IP"]
for h in leak_headers:
    if h in server_seen_headers:
        risk = "HIGH"  # Real IP may be exposed
```

---

## Installation

```bash
git clone https://github.com/shaikrohanbaba/vpn-forensics.git
cd vpn-forensics
pip install -r requirements.txt
```

---

## Usage

### Single scan
```bash
python vpn_leak_detector.py
```

### Compare multiple VPN profiles
```bash
# Edit VPN_PROFILES in batch_analyzer.py to add your VPN names
# Connect to each VPN, then run:
python batch_analyzer.py
```

---

## Sample Output

```
==================================================
  VPN FORENSICS — DNS/IP LEAK DETECTOR
==================================================

[*] Local IP detected: 192.168.1.105

[*] Checking for DNS leaks...
--------------------------------------------------
  ⚠️  LEAK DETECTED | whoami.akamai.net → 75.75.75.75 | United States | Comcast Cable
  ✓ OK              | o-o.myaddr.l.google.com → 10.8.0.1 | Netherlands | ProtonVPN

[*] Checking for IP leaks...
--------------------------------------------------
  ⚠️  LEAK DETECTED | Seen IP: 192.168.1.105 | United States | Comcast Cable
  ✓ OK              | Seen IP: 185.159.157.10 | Switzerland | ProtonVPN AG

[*] Analyzing request headers for IP exposure...
--------------------------------------------------
  ⚠️  X-Forwarded-For: 192.168.1.105  → may expose real IP
  ✓  X-Real-IP: not present

==================================================
  VPN LEAK DETECTION SUMMARY
==================================================
  DNS Leaks Found   : 1
  IP Leaks Found    : 1
  Header Risks Found: 1

  ⚠️  3 issue(s) found. Your VPN may be leaking your identity.
  Recommendation: Switch to a paid VPN with DNS leak protection,
  or configure DNS servers manually to your VPN provider's DNS.
==================================================
```

---

## Output Files

| File | Contents |
|---|---|
| `vpn_leak_report.json` | Full structured report with all findings |
| `vpn_leak_report.csv` | Flat CSV for spreadsheet analysis |
| `vpn_comparison_report.json` | Side-by-side comparison across VPN profiles |

---

## Mitigation Recommendations

Based on findings, the tool recommends:

1. **DNS leaks** — Manually configure DNS to your VPN provider's servers (e.g., ProtonVPN: `10.8.8.1`). Enable "DNS leak protection" in VPN client settings if available.
2. **IP leaks** — Ensure your VPN uses a kill switch. Avoid free VPNs that use split tunneling by default.
3. **Header leaks** — Use a VPN that does not inject `X-Forwarded-For` headers. Test with HTTPS-only connections.

---

## Project Structure

```
vpn-forensics/
├── vpn_leak_detector.py      # Core detection engine
├── batch_analyzer.py         # Multi-VPN comparison tool
├── requirements.txt
└── README.md
```

---

## Future Work

- Browser WebRTC leak detection (WebRTC bypasses VPN tunnels entirely)
- Automated VPN rating system based on leak score
- GUI dashboard for non-technical users
- Continuous monitoring mode with alerting

---

## Author

**Rohan Baba Shaik**
- LinkedIn: [rohan-baba-shaik](https://www.linkedin.com/in/rohan-baba-shaik-49353b207/)
- Email: shaikrohanbaba@gmail.com
- MS Computer Science — Florida Institute of Technology (2025)

---

## Disclaimer

This tool is for **educational and research purposes only**. Use only on networks and systems you own or have explicit permission to test.

---

## License

MIT License
