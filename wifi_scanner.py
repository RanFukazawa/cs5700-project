#!/usr/bin/env python3
"""
Feature 1: Network Security Scanner and Risk Profiler
Wireless Network Security Assessment Project

Scans nearby WiFi networks using macOS system_profiler XML output,
identifies security types, and displays a colour-coded risk rating
with plain-language explanations.

Note: macOS Tahoe restricts SSID access from unsigned scripts.
      The tool prompts you to label each detected network manually.

Usage: python3 wifi_scanner.py
"""

import subprocess
import plistlib
from datetime import datetime

# ── Colour output ─────────────────────────────────────────────
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    RED    = Fore.RED    + Style.BRIGHT
    YELLOW = Fore.YELLOW + Style.BRIGHT
    GREEN  = Fore.GREEN  + Style.BRIGHT
    CYAN   = Fore.CYAN   + Style.BRIGHT
    WHITE  = Fore.WHITE  + Style.BRIGHT
    RESET  = Style.RESET_ALL
except ImportError:
    RED = YELLOW = GREEN = CYAN = WHITE = RESET = ""

# ── Risk profile definitions ──────────────────────────────────
RISK_PROFILES = {
    "none": {
        "level":       "HIGH",
        "colour":      RED,
        "indicator":   "[!!!]",
        "label":       "OPEN NETWORK",
        "explanation": (
            "No encryption at all. Anyone nearby can capture and read "
            "your traffic, including passwords and personal data."
        ),
    },
    "wpa2_personal": {
        "level":       "MEDIUM",
        "colour":      YELLOW,
        "indicator":   "[!]  ",
        "label":       "WPA2 PERSONAL",
        "explanation": (
            "Encrypted but uses an older standard. Vulnerable to "
            "offline brute-force attacks if a weak password is used."
        ),
    },
    "wpa2_enterprise": {
        "level":       "MEDIUM",
        "colour":      YELLOW,
        "indicator":   "[!]  ",
        "label":       "WPA2 ENTERPRISE",
        "explanation": (
            "Per-user authentication common in corporate or university "
            "networks. Stronger than Personal but still WPA2-generation."
        ),
    },
    "wpa2_wpa3_transition": {
        "level":       "MEDIUM-LOW",
        "colour":      YELLOW,
        "indicator":   "[~]  ",
        "label":       "WPA2/WPA3 TRANSITIONAL",
        "explanation": (
            "Supports both WPA2 and WPA3. Modern devices use WPA3 "
            "automatically; older devices fall back to WPA2. Security "
            "outcome depends on the connecting device's capability."
        ),
    },
    "wpa3_personal": {
        "level":       "LOW",
        "colour":      GREEN,
        "indicator":   "[OK] ",
        "label":       "WPA3 PERSONAL",
        "explanation": (
            "Current gold standard. Strong encryption resistant to "
            "brute-force attacks, with forward secrecy protecting "
            "past sessions even if the password is later compromised."
        ),
    },
    "wpa3_enterprise": {
        "level":       "LOW",
        "colour":      GREEN,
        "indicator":   "[OK] ",
        "label":       "WPA3 ENTERPRISE",
        "explanation": (
            "Highest security tier. Enterprise-grade authentication "
            "with WPA3 encryption — typically found in well-managed "
            "corporate or institutional networks."
        ),
    },
}

UNKNOWN_PROFILE = {
    "level":       "UNKNOWN",
    "colour":      WHITE,
    "indicator":   "[?]  ",
    "label":       "UNKNOWN",
    "explanation": "Security type could not be determined.",
}


def normalise_security(raw):
    """
    Strip prefix variants and return the bare key for risk matching.
    Handles macOS Tahoe bug where leading 's' is missing from keys.

    Examples:
      'pairport_security_mode_wpa3_transition' -> 'wpa3_transition'
      'spairport_security_mode_none'           -> 'none'
      'wpa2_personal'                          -> 'wpa2_personal'
    """
    s = raw.lower().strip()
    for prefix in ("spairport_security_mode_", "pairport_security_mode_"):
        if s.startswith(prefix):
            return s[len(prefix):]
    return s


def get_risk(raw_security):
    """Return the risk profile for a raw security string."""
    key = normalise_security(raw_security)
    if key in RISK_PROFILES:
        return RISK_PROFILES[key]
    # Partial match fallback
    for k in RISK_PROFILES:
        if k in key or key in k:
            return RISK_PROFILES[k]
    return UNKNOWN_PROFILE


def signal_bar(rssi):
    """Convert RSSI dBm to a visual strength bar."""
    if rssi >= -50: return "▂▄▆█ Excellent"
    if rssi >= -60: return "▂▄▆  Good"
    if rssi >= -70: return "▂▄   Fair"
    if rssi >= -80: return "▂    Weak"
    return                  "     Poor"


def scan_networks():
    """
    Parse system_profiler XML to extract WiFi network security info.
    Returns list of dicts: {ssid, security, channel, rssi, connected}
    """
    try:
        result = subprocess.run(
            ["system_profiler", "SPAirPortDataType", "-xml"],
            capture_output=True, timeout=30
        )
    except subprocess.TimeoutExpired:
        print(f"{RED}Error: system_profiler timed out.{RESET}")
        return []

    try:
        data = plistlib.loads(result.stdout)
    except Exception as e:
        print(f"{RED}Error parsing plist: {e}{RESET}")
        return []

    networks = []

    try:
        interfaces = data[0]["_items"][0].get(
            "spairport_airport_interfaces", []
        )
        if not interfaces:
            print(f"{RED}No Wi-Fi interfaces found.{RESET}")
            return []

        iface = interfaces[0]

        # ── Current connected network ─────────────────────────
        # macOS Tahoe stores the current network as a flat dict
        # with all fields at the top level (not nested by SSID).
        # Older macOS versions used a nested structure keyed by SSID —
        # we try both and handle each case.
        curr_flat = (
            iface.get("spairport_current_network_information") or
            iface.get("spairport_airport_current_network_information") or
            {}
        )

        if curr_flat:
            # macOS Tahoe: flat dict — security/channel are direct keys
            if "spairport_security_mode" in curr_flat:
                raw_sec = curr_flat.get("spairport_security_mode", "unknown")
                raw_sig = curr_flat.get("spairport_signal_noise", "")
                rssi = -100
                if raw_sig:
                    try:
                        rssi = int(str(raw_sig).split("/")[0]
                                   .replace("dBm", "").strip())
                    except ValueError:
                        pass
                networks.append({
                    "ssid":      "<redacted>",
                    "security":  raw_sec,
                    "channel":   str(curr_flat.get(
                                     "spairport_network_channel", "—")),
                    "rssi":      rssi,
                    "connected": True,
                })
            else:
                # Older macOS: nested dict keyed by SSID name
                for ssid_key, info in curr_flat.items():
                    if not isinstance(info, dict):
                        continue
                    raw_sec = info.get("spairport_security_mode", "unknown")
                    raw_sig = info.get("spairport_signal_noise", "")
                    rssi = -100
                    if raw_sig:
                        try:
                            rssi = int(str(raw_sig).split("/")[0]
                                       .replace("dBm", "").strip())
                        except ValueError:
                            pass
                    networks.append({
                        "ssid":      "<redacted>",
                        "security":  raw_sec,
                        "channel":   str(info.get(
                                         "spairport_network_channel", "—")),
                        "rssi":      rssi,
                        "connected": True,
                    })

        # ── All other visible networks ────────────────────────
        others = iface.get(
            "spairport_airport_other_local_wireless_networks", []
        )
        for net in others:
            raw_sec = net.get("spairport_security_mode", "unknown")
            networks.append({
                "ssid":      "<redacted>",
                "security":  raw_sec,
                "channel":   str(net.get("spairport_network_channel", "—")),
                "rssi":      -100,
                "connected": False,
            })

    except (KeyError, IndexError) as e:
        print(f"{RED}Error navigating plist structure: {e}{RESET}")
        return []

    # Sort: open networks first, then by channel
    networks.sort(key=lambda x: (
        normalise_security(x["security"]) != "none",
        x["channel"]
    ))
    return networks


def label_networks(networks):
    """
    Prompt user to name each network since macOS Tahoe redacts SSIDs.
    Shows security type and channel as hints for identification.
    Press Enter to skip and auto-assign a number label.
    """
    print(f"  {CYAN}NOTE: macOS Tahoe blocks SSID access from unsigned scripts.{RESET}")
    print(f"  {CYAN}Label your known test networks below using their security{RESET}")
    print(f"  {CYAN}type and channel as hints. Press Enter to skip any network.{RESET}\n")

    print(f"  {'#':<5} {'RISK LEVEL':<14} {'SECURITY TYPE':<24} {'CHANNEL'}")
    print(f"  {'─'*5} {'─'*14} {'─'*24} {'─'*20}")

    for i, n in enumerate(networks):
        profile = get_risk(n["security"])
        col     = profile["colour"]
        level   = profile["level"]
        label   = profile["label"]
        ch      = n["channel"]
        marker  = f"  {GREEN}◄ CONNECTED{RESET}" if n["connected"] else ""

        print(f"  {col}{i+1:<5}{RESET}"
              f" {col}{level:<14}{RESET}"
              f" {label:<24}"
              f" {ch}{marker}")
        name = input(f"       Name this network (Enter to skip): ").strip()
        n["ssid"] = name if name else f"Network {i+1}"
        print()

    return networks


def print_banner():
    print(f"\n{CYAN}{'═' * 70}{RESET}")
    print(f"{CYAN}   WiFi NETWORK SECURITY SCANNER & RISK PROFILER{RESET}")
    print(f"{CYAN}   Feature 1 — Wireless Security Assessment Project{RESET}")
    print(f"{CYAN}   Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{CYAN}{'═' * 70}{RESET}\n")


def print_legend():
    print(f"  Risk Legend:")
    print(f"  {RED}[!!!] HIGH      {RESET}— Open / No encryption")
    print(f"  {YELLOW}[!]   MEDIUM    {RESET}— WPA2 (older standard)")
    print(f"  {YELLOW}[~]   MEDIUM-LOW{RESET}— WPA2/WPA3 Transitional")
    print(f"  {GREEN}[OK]  LOW       {RESET}— WPA3 (current standard)")
    print(f"  {WHITE}[?]   UNKNOWN   {RESET}— Could not determine\n")


def wrap(text, width=60):
    """Simple word wrapper."""
    words, lines, line = text.split(), [], ""
    for w in words:
        if len(line) + len(w) + 1 > width:
            lines.append(line)
            line = w
        else:
            line = (line + " " + w).strip()
    if line:
        lines.append(line)
    return lines


def print_results(networks):
    if not networks:
        print(f"{RED}  No networks found. Ensure Wi-Fi is enabled.{RESET}\n")
        return

    counts = {}

    # ── Results table ─────────────────────────────────────────
    W = (28, 24, 15, 22)
    print(f"  {'SSID (labelled)':<{W[0]}} {'SECURITY':<{W[1]}} "
          f"{'RISK':<{W[2]}} {'CHANNEL':<{W[2]}} RSSI")
    print(f"  {'─'*W[0]} {'─'*W[1]} {'─'*W[2]} {'─'*W[3]} {'─'*10}")

    for n in networks:
        profile = get_risk(n["security"])
        col     = profile["colour"]
        level   = profile["level"]
        ind     = profile["indicator"]
        counts[level] = counts.get(level, 0) + 1

        ssid  = n["ssid"][:W[0]-1]
        label = profile["label"][:W[1]-1]
        ch    = n["channel"][:W[3]-1]
        rssi  = f"{n['rssi']} dBm" if n["rssi"] != -100 else "—"
        conn  = f" {GREEN}●{RESET}" if n["connected"] else ""

        print(f"  {col}{ssid:<{W[0]}}{RESET}"
              f" {label:<{W[1]}}"
              f" {col}{ind} {level:<9}{RESET}"
              f" {ch:<{W[3]}}"
              f" {rssi}{conn}")

    # ── Detailed explanations ─────────────────────────────────
    print(f"\n{'─' * 70}")
    print(f"  DETAILED RISK EXPLANATIONS\n")
    seen = set()
    for n in networks:
        profile = get_risk(n["security"])
        if profile["label"] in seen:
            continue
        seen.add(profile["label"])
        col = profile["colour"]
        print(f"  {col}{profile['indicator']} {profile['label']}{RESET}")
        for ln in wrap(profile["explanation"]):
            print(f"     {ln}")
        print()

    # ── Summary ───────────────────────────────────────────────
    print(f"{'─' * 70}")
    print(f"  SCAN SUMMARY — {len(networks)} network(s) found\n")
    for level, col in [("HIGH", RED), ("MEDIUM", YELLOW),
                        ("MEDIUM-LOW", YELLOW), ("LOW", GREEN),
                        ("UNKNOWN", WHITE)]:
        n = counts.get(level, 0)
        if n:
            pct = round(n / len(networks) * 100)
            bar = "█" * max(1, pct // 5)
            print(f"  {col}{level:<12}{RESET} {n:>3} network(s)  "
                  f"{col}{bar}{RESET} {pct}%")

    print(f"\n  {RED}Recommendation:{RESET} Avoid open (HIGH risk) networks for")
    print(f"  any sensitive activity. Use a VPN if you must connect.\n")
    print(f"{'═' * 70}\n")


# ── Entry point ───────────────────────────────────────────────
if __name__ == "__main__":
    print_banner()
    print_legend()
    print(f"  Scanning nearby networks via system_profiler (XML)...\n")
    networks = scan_networks()
    if networks:
        networks = label_networks(networks)
    print_results(networks)