#!/usr/bin/env python3
"""
Feature 2: Captured Traffic Exposure Analyser
Analyses network traffic (live or .pcap) and categorises risk tiers.
Usage:
  Live capture:   sudo python3 analyser.py --live --iface bridge100
  Pcap file:      python3 analyser.py --pcap capture.pcap
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, rdpcap, DNS, DNSQR, TCP, UDP, IP, Raw
except ImportError:
    print("Missing dependency. Run: pip install scapy")
    exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Missing dependency. Run: pip install colorama")
    exit(1)


# ── Risk tier labels ──────────────────────────────────────────────────────────

HIGH   = f"{Fore.RED}🔴 HIGH RISK{Style.RESET_ALL}"
MEDIUM = f"{Fore.YELLOW}🟡 MEDIUM RISK{Style.RESET_ALL}"
LOW    = f"{Fore.GREEN}🟢 LOW RISK / ENCRYPTED{Style.RESET_ALL}"

# Regex patterns for credential-like fields in HTTP payloads
CREDENTIAL_PATTERNS = re.compile(
    r'(username|user|email|login|password|passwd|pass|credential|token|auth)'
    r'[=:]\S+', re.IGNORECASE
)


# ── Data stores ───────────────────────────────────────────────────────────────

findings = {
    "high":   [],   # plaintext HTTP content / credentials
    "medium": [],   # DNS queries, visible URLs
    "low":    [],   # TLS/HTTPS sessions
}

per_ip_summary = defaultdict(lambda: {"http": 0, "https": 0, "dns": []})


# ── Packet analysis ───────────────────────────────────────────────────────────

def analyse_packet(pkt):
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    # ── DNS (Medium Risk) ────────────────────────────────────────────────────
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        query = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        if query:
            entry = {"src": src, "dst": dst, "domain": query}
            findings["medium"].append(entry)
            per_ip_summary[src]["dns"].append(query)

    # ── TCP-based traffic ────────────────────────────────────────────────────
    elif pkt.haslayer(TCP):
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport

        # HTTPS / TLS (Low Risk) — port 443
        if dport == 443 or sport == 443:
            entry = {"src": src, "dst": dst, "note": "TLS encrypted session"}
            findings["low"].append(entry)
            per_ip_summary[src]["https"] += 1

        # HTTP (High or Medium Risk) — port 80
        elif (dport == 80 or sport == 80) and pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode(errors="ignore")

            # Extract HTTP method + path for URL visibility (Medium)
            url_match = re.search(r'(GET|POST|PUT|DELETE) (\S+)', payload)
            host_match = re.search(r'Host:\s*(\S+)', payload)
            host = host_match.group(1) if host_match else dst

            if url_match:
                method, path = url_match.group(1), url_match.group(2)
                url_entry = {
                    "src": src, "dst": dst,
                    "url": f"http://{host}{path}",
                    "method": method
                }
                findings["medium"].append(url_entry)
                per_ip_summary[src]["http"] += 1

            # Check for credentials in POST body (High Risk)
            creds = CREDENTIAL_PATTERNS.findall(payload)
            if creds:
                cred_entry = {
                    "src": src, "dst": dst,
                    "url": f"http://{host}",
                    "exposed_fields": creds[:5],  # cap at 5 for display
                    "method": "POST"
                }
                findings["high"].append(cred_entry)


# ── Display helpers ───────────────────────────────────────────────────────────

def section(title, color=Fore.CYAN):
    bar = "─" * 60
    print(f"\n{color}{bar}")
    print(f"  {title}")
    print(f"{bar}{Style.RESET_ALL}")


def print_results():
    print(f"\n{Fore.CYAN}{'═' * 60}")
    print(f"  TRAFFIC EXPOSURE ANALYSIS REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═' * 60}{Style.RESET_ALL}")

    # ── High Risk ────────────────────────────────────────────────────────────
    section(f"{HIGH}  —  Plaintext Credentials & HTTP Content", Fore.RED)
    if findings["high"]:
        for f in findings["high"]:
            print(f"  {Fore.RED}⚠  {f['src']} → {f['dst']}{Style.RESET_ALL}")
            print(f"     URL:     {f['url']}")
            print(f"     Exposed: {', '.join(f['exposed_fields'])}")
    else:
        print(f"  {Fore.GREEN}No plaintext credentials detected.{Style.RESET_ALL}")

    # ── Medium Risk ──────────────────────────────────────────────────────────
    section(f"{MEDIUM}  —  DNS Queries & Visible URLs", Fore.YELLOW)

    dns_entries = [e for e in findings["medium"] if "domain" in e]
    url_entries = [e for e in findings["medium"] if "url" in e]

    if dns_entries:
        print(f"  {Fore.YELLOW}DNS Queries (domains visited — visible even over HTTPS):{Style.RESET_ALL}")
        seen = set()
        for e in dns_entries:
            key = (e["src"], e["domain"])
            if key not in seen:
                seen.add(key)
                print(f"    {e['src']}  →  {e['domain']}")
        print(f"\n  {Fore.YELLOW}⚠  Note: HTTPS protects content but NOT which domains you visit.{Style.RESET_ALL}")
    else:
        print(f"  No DNS queries captured.")

    if url_entries:
        print(f"\n  {Fore.YELLOW}Plaintext HTTP URLs observed:{Style.RESET_ALL}")
        for e in url_entries[:10]:  # cap display at 10
            print(f"    [{e['method']}] {e['url']}  (from {e['src']})")

    # ── Low Risk ─────────────────────────────────────────────────────────────
    section(f"{LOW}  —  HTTPS / TLS Sessions", Fore.GREEN)
    if findings["low"]:
        count = len(findings["low"])
        print(f"  {Fore.GREEN}{count} encrypted TLS session(s) observed.")
        print(f"  Content is protected. Destination IP and data volume remain visible.{Style.RESET_ALL}")
    else:
        print(f"  No HTTPS traffic detected.")

    # ── Per-IP Summary (Test 3.3) ────────────────────────────────────────────
    section("PER-DEVICE TRAFFIC SUMMARY  (Test 3.3 — App Security Assessment)", Fore.CYAN)
    if per_ip_summary:
        for ip, stats in per_ip_summary.items():
            http_count  = stats["http"]
            https_count = stats["https"]
            dns_count   = len(set(stats["dns"]))
            total = http_count + https_count

            if total == 0:
                rating = f"{Fore.YELLOW}DNS only{Style.RESET_ALL}"
            elif http_count == 0:
                rating = f"{Fore.GREEN}✅ Secure (HTTPS only){Style.RESET_ALL}"
            elif https_count == 0:
                rating = f"{Fore.RED}❌ Insecure (HTTP only){Style.RESET_ALL}"
            else:
                pct = int((https_count / total) * 100)
                rating = f"{Fore.YELLOW}⚠  Mixed ({pct}% encrypted){Style.RESET_ALL}"

            print(f"  {ip:<18} HTTP: {http_count:<4} HTTPS: {https_count:<4} "
                  f"DNS domains: {dns_count:<4} → {rating}")
    else:
        print("  No per-device data available.")

    # ── Stats footer ─────────────────────────────────────────────────────────
    print(f"\n{Fore.CYAN}{'─' * 60}")
    print(f"  SUMMARY COUNTS")
    print(f"{'─' * 60}{Style.RESET_ALL}")
    print(f"  🔴 High Risk findings:   {len(findings['high'])}")
    print(f"  🟡 Medium Risk findings: {len(findings['medium'])}")
    print(f"  🟢 Low Risk sessions:    {len(findings['low'])}")
    print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")


# ── Report export ─────────────────────────────────────────────────────────────

def save_report(path):
    report = {
        "generated": datetime.now().isoformat(),
        "summary": {
            "high_risk":   len(findings["high"]),
            "medium_risk": len(findings["medium"]),
            "low_risk":    len(findings["low"]),
        },
        "high_risk_findings":   findings["high"],
        "medium_risk_findings": findings["medium"],
        "low_risk_sessions":    len(findings["low"]),
        "per_device_summary":   {
            ip: {
                "http": s["http"],
                "https": s["https"],
                "dns_domains": list(set(s["dns"]))
            }
            for ip, s in per_ip_summary.items()
        }
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"{Fore.GREEN}  Report saved to: {path}{Style.RESET_ALL}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Feature 2: Traffic Exposure Analyser"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live",  action="store_true", help="Live capture mode")
    mode.add_argument("--pcap",  type=str,            help="Path to .pcap file")

    parser.add_argument("--iface",  type=str, default="bridge100",
                        help="Network interface for live capture (default: bridge100)")
    parser.add_argument("--count",  type=int, default=0,
                        help="Packets to capture in live mode (0 = until Ctrl+C)")
    parser.add_argument("--report", type=str, default="report.json",
                        help="Output path for JSON report (default: report.json)")

    args = parser.parse_args()

    print(f"{Fore.CYAN}  Traffic Exposure Analyser — Feature 2{Style.RESET_ALL}")

    if args.live:
        print(f"  Mode: Live capture on interface {Fore.YELLOW}{args.iface}{Style.RESET_ALL}")
        print(f"  Press {Fore.YELLOW}Ctrl+C{Style.RESET_ALL} to stop and view results.\n")
        try:
            sniff(iface=args.iface, prn=analyse_packet,
                  count=args.count, store=False)
        except KeyboardInterrupt:
            pass
    else:
        print(f"  Mode: Analysing pcap file {Fore.YELLOW}{args.pcap}{Style.RESET_ALL}\n")
        pkts = rdpcap(args.pcap)
        for pkt in pkts:
            analyse_packet(pkt)

    print_results()
    save_report(args.report)


if __name__ == "__main__":
    main()