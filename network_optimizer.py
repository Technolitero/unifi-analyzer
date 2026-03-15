"""
UniFi Network Optimizer
Python port of the NetworkOptimizer (.NET) security audit engine.

Performs comprehensive security audit, WiFi health scoring, VLAN analysis,
firewall analysis, and calculates a 0-100 security posture score.

Based on:
  - ConfigAuditEngine.cs / AuditScorer.cs (scoring)
  - FirewallRuleAnalyzer.cs (firewall conflict detection)
  - VlanAnalyzer.cs (network classification)
  - PortSecurityAnalyzer.cs (switch port security)
  - DnsSecurityAnalyzer.cs (DNS checks)
  - SiteHealthScorer.cs (WiFi scoring)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import re

# ---------------------------------------------------------------------------
# Scoring constants (from ScoreConstants.cs)
# ---------------------------------------------------------------------------
BASE_SCORE = 100

# Score impact per issue by severity
SEVERITY_IMPACT = {
    "critical":      15,   # CriticalImpact
    "recommended":    5,   # RecommendedImpact
    "informational":  2,   # InformationalImpact
}

# Maximum deduction per severity tier
MAX_DEDUCTION = {
    "critical":      50,
    "recommended":   30,
    "informational": 10,
}

# Score thresholds for posture labels
SCORE_EXCELLENT        = 90
SCORE_GOOD             = 75
SCORE_FAIR             = 60
SCORE_NEEDS_ATTENTION  = 40

# Hardening bonus caps (from ScoreConstants.cs)
MAX_HARDENING_MEASURE_BONUS     = 3
MAX_HARDENING_PERCENTAGE_BONUS  = 5

# Critical issue count thresholds for posture override
CRITICAL_POSTURE_THRESHOLD       = 5
NEEDS_ATTENTION_POSTURE_THRESHOLD = 2

# ---------------------------------------------------------------------------
# Network classification patterns (from VlanAnalyzer.cs)
# ---------------------------------------------------------------------------
IOT_PATTERNS          = ["iot", "smart", "automation", "zero trust", "zerotrust"]
MEDIA_PATTERNS        = ["entertainment", "streaming", "theater", "theatre",
                         "recreation", "living room", "a/v"]
MEDIA_WORD_BOUNDARY   = ["media", "av", "tv"]
SECURITY_PATTERNS     = ["camera", "security", "nvr", "surveillance",
                         "protect", "cctv"]
MANAGEMENT_PATTERNS   = ["management", "mgmt", "admin", "infrastructure"]
GUEST_PATTERNS        = ["guest", "visitor", "hotspot"]

# Known IoT device name hints for client placement checks
IOT_CLIENT_HINTS = [
    "ring", "nest", "philips hue", "hue", "wyze", "ecobee", "roomba",
    "amazon echo", "echo dot", "google home", "google nest", "smart plug",
    "lifx", "wemo", "tuya", "shelly", "kasa", "eufy", "arlo",
    "tp-link tapo", "smartthings", "wink hub", "lutron", "leviton",
    "sonos", "august", "yale", "kwikset", "august lock",
]

# Known camera device name hints
CAMERA_CLIENT_HINTS = [
    "camera", "cam", "nvr", "dvr", "doorbell", "reolink",
    "hikvision", "dahua", "axis", "amcrest", "lorex", "unvr",
    "protect", "foscam", "annke", "swann",
]

# Public DNS resolvers that bypass local filtering
PUBLIC_DNS = {
    "8.8.8.8", "8.8.4.4",           # Google
    "1.1.1.1", "1.0.0.1",           # Cloudflare
    "9.9.9.9", "149.112.112.112",   # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
}

# High-risk ports to expose via port-forward
HIGH_RISK_PORTS = {22, 23, 3389, 5900, 5800}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class OptimizerIssue:
    category: str
    severity: str          # "critical" | "recommended" | "informational"
    title: str
    detail: str
    recommendation: str
    score_impact: int = 0
    device_name: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "category":       self.category,
            "severity":       self.severity,
            "title":          self.title,
            "detail":         self.detail,
            "recommendation": self.recommendation,
            "score_impact":   self.score_impact,
        }
        if self.device_name:
            d["device_name"] = self.device_name
        return d


# ---------------------------------------------------------------------------
# Network classification helper
# ---------------------------------------------------------------------------

def _classify_network(name: str) -> str:
    """Return network class based on name patterns (from VlanAnalyzer.cs)."""
    name_lower = name.lower()

    if any(p in name_lower for p in GUEST_PATTERNS):
        return "guest"
    if any(p in name_lower for p in SECURITY_PATTERNS):
        return "security"
    if any(p in name_lower for p in IOT_PATTERNS):
        return "iot"
    if any(p in name_lower for p in MANAGEMENT_PATTERNS):
        return "management"
    if any(p in name_lower for p in MEDIA_PATTERNS):
        return "media"
    for p in MEDIA_WORD_BOUNDARY:
        if re.search(r"\b" + re.escape(p) + r"\b", name_lower):
            return "media"
    return "corporate"


# ---------------------------------------------------------------------------
# Main optimizer class
# ---------------------------------------------------------------------------

class NetworkOptimizer:
    """
    Orchestrates all audit analyzers and calculates a security posture score.
    Call run() to get the full audit result dict.
    """

    def __init__(self, config: dict):
        self.config = config
        self._issues: list[OptimizerIssue] = []
        self._hardening_measures: list[str] = []

        # Build fast-lookup maps
        self._net_class_by_id: dict[str, str] = {}
        self._net_name_by_id:  dict[str, str] = {}
        for net in config.get("networks", []):
            nid = net.get("_id", "")
            name = net.get("name", "")
            if nid:
                self._net_class_by_id[nid] = _classify_network(name)
                self._net_name_by_id[nid]  = name

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add(self, category: str, severity: str, title: str,
             detail: str, recommendation: str,
             device_name: Optional[str] = None) -> None:
        impact = SEVERITY_IMPACT.get(severity, 0)
        self._issues.append(OptimizerIssue(
            category=category,
            severity=severity,
            title=title,
            detail=detail,
            recommendation=recommendation,
            score_impact=impact,
            device_name=device_name,
        ))

    def _hardening(self, measure: str) -> None:
        self._hardening_measures.append(measure)

    # ------------------------------------------------------------------
    # WiFi Analysis  (SiteHealthScorer.cs + config_analyzer logic)
    # ------------------------------------------------------------------

    def _analyze_wifi(self) -> None:
        wlans   = self.config.get("wlans",   [])
        devices = self.config.get("devices", [])

        # ---- Per-WLAN checks ----
        for wlan in wlans:
            name     = wlan.get("name", "unknown")
            security = wlan.get("security", "")
            wpa_enc  = wlan.get("wpa_enc", "")
            wpa_mode = wlan.get("wpa_mode", "")

            # Encryption
            if security == "open":
                self._add("WiFi", "critical",
                    f"Open WiFi network: '{name}'",
                    "No authentication or encryption — any nearby device can intercept traffic.",
                    "Enable WPA2-AES or WPA3 immediately. Open networks should never be used on production hardware.")
            elif security == "wpapsk" and wpa_enc == "tkip":
                self._add("WiFi", "critical",
                    f"Weak TKIP encryption on '{name}'",
                    "TKIP is deprecated and vulnerable to practical key-recovery attacks (TKIP MIC). "
                    "All modern clients support AES/CCMP.",
                    "Switch to AES (CCMP) and enable WPA3 or WPA2/WPA3 mixed mode.")
            elif wpa_mode not in ("wpa3", "wpa2wpa3"):
                self._add("WiFi", "informational",
                    f"WPA3 not enabled on '{name}'",
                    f"Current mode: {wpa_mode or security}. WPA3 uses SAE (Dragonfly) for stronger "
                    "password-based authentication and forward secrecy.",
                    "Enable WPA3 or WPA2/WPA3 mixed mode in WLAN advanced settings.")
            else:
                self._hardening(f"WPA3 enabled on '{name}'")

            # PMF (Protected Management Frames)
            pmf_mode = wlan.get("pmf_mode", "disabled")
            if pmf_mode == "disabled":
                self._add("WiFi", "recommended",
                    f"PMF disabled on '{name}'",
                    "Without Protected Management Frames, clients are vulnerable to deauthentication "
                    "and disassociation attacks (deauth flooding).",
                    "Set PMF to 'optional' or 'required' in WLAN advanced settings. Required if all clients support 802.11w.")
            elif pmf_mode == "required":
                self._hardening(f"PMF required on '{name}'")

            # Minimum RSSI (sticky client mitigation)
            if wlan.get("minrate_na_advertising_rates") is None and wlan.get("minrate_ng_advertising_rates") is None:
                self._add("WiFi", "informational",
                    f"No minimum RSSI configured on '{name}'",
                    "Without a minimum RSSI, sticky clients maintain weak connections (-80 dBm+), "
                    "wasting airtime for all users on the AP.",
                    "Set minimum RSSI (e.g., -75 dBm) to encourage roaming to a better AP.")

            # 802.11r Fast Roaming
            if not wlan.get("fast_roaming_enabled", False):
                self._add("WiFi", "informational",
                    f"802.11r Fast Roaming disabled on '{name}'",
                    "Without 802.11r (Fast BSS Transition), re-authentication on roam adds "
                    "200–500 ms of latency — impacting VoIP and video calls.",
                    "Enable Fast Roaming (802.11r) in WLAN settings. All modern devices support it.")
            else:
                self._hardening(f"802.11r fast roaming enabled on '{name}'")

            # DTIM period
            dtim_na = wlan.get("dtim_na", 1)
            dtim_ng = wlan.get("dtim_ng", 1)
            if dtim_na > 3 or dtim_ng > 3:
                self._add("WiFi", "informational",
                    f"High DTIM period on '{name}' (5 GHz: {dtim_na}, 2.4 GHz: {dtim_ng})",
                    "High DTIM values increase the interval between beacon wake-up signals, "
                    "adding latency for power-saving clients.",
                    "Set DTIM to 1 for latency-sensitive networks (gaming/VoIP). Use 3 for IoT-heavy networks.")

            # Hidden SSID
            if wlan.get("hide_ssid", False):
                self._add("WiFi", "informational",
                    f"Hidden SSID on '{name}'",
                    "Hidden SSIDs provide no real security (easily detected by passive scanning) "
                    "and can cause issues with some clients.",
                    "Keep SSID visible and rely on WPA3 for security rather than obscurity.")

            # Band steering
            if not wlan.get("band_steering_enabled", False):
                self._add("WiFi", "informational",
                    f"Band steering disabled on '{name}'",
                    "Without band steering, capable clients may remain on the congested 2.4 GHz band "
                    "instead of being guided to the faster 5 GHz or 6 GHz band.",
                    "Enable band steering in WLAN settings to push dual-band clients to the best available band.")
            else:
                self._hardening(f"Band steering enabled on '{name}'")

            # BSS Transition (802.11v)
            if not wlan.get("bss_transition", False):
                self._add("WiFi", "informational",
                    f"BSS Transition (802.11v) disabled on '{name}'",
                    "802.11v BSS Transition Management allows the AP to suggest better APs to clients, "
                    "complementing 802.11r for seamless roaming. Without it, clients may not roam optimally.",
                    "Enable BSS Transition in WLAN advanced settings alongside 802.11r for best roaming performance.")
            else:
                self._hardening(f"BSS Transition (802.11v) enabled on '{name}'")

        # ---- Per-AP radio checks (from SiteHealthScorer.cs) ----
        for dev in devices:
            dtype = (dev.get("type") or "").lower()
            if not (dtype.startswith("uap") or dtype.startswith("uwa")):
                continue

            dev_name   = dev.get("name") or dev.get("hostname") or dev.get("mac", "AP")
            radio_table = dev.get("radio_table", [])

            for radio in radio_table:
                band      = radio.get("radio", "")
                cu_total  = radio.get("cu_total",  0)
                cu_self   = radio.get("cu_self",   0)
                tx_mode   = radio.get("tx_power_mode", "auto")
                band_label = ("5 GHz" if band == "na" else
                              "2.4 GHz" if band == "ng" else
                              "6 GHz" if band == "6e" else band)

                if cu_total > 70:
                    self._add("WiFi", "critical",
                        f"Critical channel saturation on '{dev_name}' ({band_label}): {cu_total}%",
                        f"Channel utilization above 70% causes severe retries and throughput drops. "
                        f"Self-generated traffic: {cu_self}%, neighboring interference: {cu_total - cu_self}%.",
                        "Reassign the channel, reduce TX power, or deploy an additional AP to redistribute load.",
                        device_name=dev_name)
                elif cu_total > 50:
                    self._add("WiFi", "recommended",
                        f"High channel utilization on '{dev_name}' ({band_label}): {cu_total}%",
                        "Utilization above 50% begins impacting throughput. May worsen during peak hours.",
                        "Monitor trends. Consider channel reassignment or reducing client density on this AP.",
                        device_name=dev_name)

                if tx_mode == "high":
                    self._add("WiFi", "recommended",
                        f"TX power set to HIGH on '{dev_name}' ({band_label})",
                        "Maximum TX power increases co-channel interference with neighboring APs, "
                        "degrading overall network performance.",
                        "Use 'auto' or 'medium' TX power for balanced coverage and lower interference.",
                        device_name=dev_name)

            # High client density
            num_sta = dev.get("num_sta", 0)
            if num_sta > 30:
                self._add("WiFi", "recommended",
                    f"High client density on '{dev_name}': {num_sta} clients",
                    f"{num_sta} clients associated to a single AP. Above 30 clients per AP, "
                    "airtime contention increases significantly, degrading throughput for all users.",
                    "Deploy additional APs to reduce client density below 25–30 per AP. "
                    "Review band steering and minimum RSSI settings to distribute load evenly.",
                    device_name=dev_name)

    # ------------------------------------------------------------------
    # VLAN / Network Analysis  (VlanAnalyzer.cs)
    # ------------------------------------------------------------------

    def _analyze_networks(self) -> None:
        networks = self.config.get("networks", [])
        clients  = self.config.get("clients",  [])

        has_iot        = False
        has_guest      = False
        has_security   = False
        has_management = False
        vlan_ids: dict[int, list[str]] = {}   # vlan_id -> list of network names

        for net in networks:
            name    = net.get("name", "")
            if not name:
                continue
            purpose   = net.get("purpose", "corporate")
            net_class = _classify_network(name)

            # Track VLAN ID uniqueness
            vlan = net.get("vlan")
            if vlan:
                vid = int(vlan)
                vlan_ids.setdefault(vid, []).append(name)

            # Network class detection
            if purpose == "guest" or net_class == "guest":
                has_guest = True
                self._hardening(f"Guest network '{name}' configured")
            if net_class == "iot":
                has_iot = True
                self._hardening(f"IoT VLAN '{name}' configured")
            if net_class == "security":
                has_security = True
                self._hardening(f"Security/camera VLAN '{name}' configured")
            if net_class == "management":
                has_management = True

            # DHCP lease time
            dhcp_enabled = net.get("dhcpd_enabled", True)
            dhcp_lease   = int(net.get("dhcp_lease_time", 86400))
            if dhcp_enabled and dhcp_lease < 3600:
                self._add("Networks", "informational",
                    f"Very short DHCP lease on '{name}': {dhcp_lease}s",
                    "Very short leases cause excessive DHCP renewal traffic and brief connectivity drops.",
                    "Set DHCP lease time to at least 3600 s (1 h); 86400 s (24 h) is typical for most VLANs.")

            # MTU
            mtu = int(net.get("mtu", 1500))
            if mtu < 1500 and purpose == "corporate":
                self._add("Networks", "informational",
                    f"MTU below standard on '{name}': {mtu}",
                    "Low MTU causes unnecessary packet fragmentation, reducing throughput.",
                    "Set MTU to 1500. Use 9000 only if all devices on the segment support jumbo frames.")

            # Proxy ARP on guest/IoT
            net_class_here = _classify_network(name)
            if net_class_here in ("guest", "iot") and net.get("proxy_arp", False):
                self._add("Networks", "informational",
                    f"Proxy ARP enabled on '{name}' ({net_class_here} network)",
                    "Proxy ARP on guest or IoT networks can expose client presence across VLANs "
                    "and may assist attackers in network reconnaissance.",
                    "Disable Proxy ARP on guest and IoT network segments.")

            # IGMP snooping
            if not net.get("igmp_snooping_enabled", True):
                self._add("Networks", "informational",
                    f"IGMP snooping disabled on '{name}'",
                    "With IGMP snooping disabled, multicast traffic is flooded to all ports on the segment "
                    "instead of only to subscribed receivers, wasting bandwidth.",
                    "Enable IGMP snooping on all network segments to optimize multicast traffic delivery.")

        # ---- Global network checks ----
        if not has_iot:
            self._add("Networks", "critical",
                "No dedicated IoT VLAN detected",
                "IoT devices have poor security track records. On the main LAN they can pivot "
                "to attack PCs, NAS devices, and other sensitive hosts.",
                "Create a dedicated IoT VLAN and block all inter-VLAN access except required services "
                "(e.g., allow IoT → WAN only).")

        if not has_guest:
            self._add("Networks", "recommended",
                "No guest network configured",
                "Visitors sharing the main LAN can access local devices, printers, and NAS shares.",
                "Create a dedicated guest VLAN with client isolation and internet-only access.")

        if not has_security:
            self._add("Networks", "informational",
                "No dedicated security/camera VLAN detected",
                "Cameras and NVRs on the main LAN transmit video over the same segment as workstations.",
                "Create a Security VLAN, restrict cameras to NVR-only access, and block internet for cameras.")

        if not has_management:
            self._add("Networks", "recommended",
                "No Management VLAN detected",
                "Without a dedicated Management VLAN, switch, AP, and UDM management interfaces "
                "are reachable from client networks, enabling lateral movement to the control plane.",
                "Create a Management VLAN, move UniFi device management interfaces to it, "
                "and restrict access to trusted admin IPs only.")

        # ---- Duplicate VLAN IDs ----
        for vid, names in vlan_ids.items():
            if len(names) > 1:
                self._add("Networks", "recommended",
                    f"Duplicate VLAN ID {vid} assigned to multiple networks",
                    f"Networks sharing VLAN {vid}: {', '.join(names)}. "
                    "Duplicate VLAN IDs cause routing confusion and security boundary failures.",
                    "Assign a unique VLAN ID to each network segment.")

        # ---- Client VLAN placement checks ----
        self._check_client_placement(clients)

    def _check_client_placement(self, clients: list) -> None:
        """Flag IoT/camera clients detected on non-IoT/non-security VLANs."""
        iot_misplaced    = []
        camera_misplaced = []

        for client in clients:
            hostname   = (client.get("hostname") or client.get("name") or "").lower()
            oui_lower  = (client.get("oui") or "").lower()
            network_id = client.get("network_id", "")
            net_class  = self._net_class_by_id.get(network_id, "corporate")
            display    = hostname or client.get("mac", "?")

            is_iot    = any(h in hostname for h in IOT_CLIENT_HINTS) or \
                        any(h in oui_lower for h in IOT_CLIENT_HINTS)
            is_camera = any(h in hostname for h in CAMERA_CLIENT_HINTS)

            if is_iot and net_class not in ("iot", "guest"):
                iot_misplaced.append(display)
            if is_camera and net_class not in ("security", "iot"):
                camera_misplaced.append(display)

        if iot_misplaced:
            sample = ", ".join(iot_misplaced[:6])
            extra  = f" (+{len(iot_misplaced) - 6} more)" if len(iot_misplaced) > 6 else ""
            self._add("Networks", "critical",
                f"{len(iot_misplaced)} IoT device(s) detected on non-IoT network",
                f"Devices: {sample}{extra}. These devices can communicate with workstations and servers.",
                "Move IoT devices to the dedicated IoT VLAN and restrict inter-VLAN access.")

        if camera_misplaced:
            sample = ", ".join(camera_misplaced[:6])
            self._add("Networks", "recommended",
                f"{len(camera_misplaced)} camera/NVR device(s) outside Security VLAN",
                f"Devices: {sample}. Cameras stream sensitive footage across the main LAN.",
                "Move cameras to the Security VLAN and restrict traffic to NVR access only.")

    # ------------------------------------------------------------------
    # Firewall Analysis  (FirewallRuleAnalyzer.cs)
    # ------------------------------------------------------------------

    def _analyze_firewall(self) -> None:
        rules         = self.config.get("firewall_rules",    [])
        port_forwards = self.config.get("port_forwards",     [])
        zones         = self.config.get("firewall_zones",    [])
        policies      = self.config.get("firewall_policies", [])

        any_any_allow   = []
        disabled_rules  = []
        logging_off     = []
        rules_by_ruleset: dict[str, list] = {}

        for rule in rules:
            name    = rule.get("name", "unnamed")
            enabled = rule.get("enabled", True)

            if not enabled:
                disabled_rules.append(name)
                continue

            action   = (rule.get("action") or "").lower()
            src_grps = rule.get("src_firewallgroup_ids", [])
            dst_grps = rule.get("dst_firewallgroup_ids", [])
            src_addr = rule.get("src_address", "")
            dst_addr = rule.get("dst_address", "")

            # Any-to-any allow (no restrictions at all)
            if action in ("accept", "allow") and \
               not src_grps and not dst_grps and \
               not src_addr and not dst_addr:
                any_any_allow.append(name)

            # Logging gap
            if action in ("accept", "allow") and not rule.get("logging", False):
                logging_off.append(name)

            # Group by ruleset for conflict detection
            ruleset = rule.get("ruleset", "WAN_IN")
            rules_by_ruleset.setdefault(ruleset, []).append(rule)

        if any_any_allow:
            self._add("Firewall", "critical",
                f"{len(any_any_allow)} allow-all firewall rule(s) — no source/dest restrictions",
                f"Rules: {', '.join(any_any_allow[:5])}{'…' if len(any_any_allow) > 5 else ''}. "
                "Allow-all rules negate the purpose of segmentation by permitting any traffic.",
                "Replace broad allow-all rules with specific source/destination group rules. "
                "Apply least-privilege: permit only what is explicitly needed.")

        if disabled_rules:
            self._add("Firewall", "informational",
                f"{len(disabled_rules)} disabled firewall rule(s)",
                f"Disabled rules: {', '.join(disabled_rules[:5])}{'…' if len(disabled_rules) > 5 else ''}. "
                "Orphaned rules clutter the ruleset and make auditing harder.",
                "Remove disabled rules you no longer need.")

        if len(logging_off) > 5:
            self._add("Firewall", "informational",
                f"Logging disabled on {len(logging_off)} accept rules",
                "Without logging, traffic patterns and potential intrusions remain invisible.",
                "Enable logging on key accept rules, especially those crossing VLAN boundaries or from WAN.")

        # ---- Rule conflict detection (simplified FirewallRuleOverlapDetector.cs) ----
        self._detect_rule_conflicts(rules_by_ruleset)

        # ---- Zone-based firewall policies ----
        if policies:
            self._analyze_zone_policies(policies, zones)
        else:
            # No zone-based policies detected — could mean legacy firewall only
            if not rules:
                self._add("Firewall", "recommended",
                    "No firewall rules or policies detected",
                    "No legacy firewall rules and no zone-based policies were found. "
                    "The network may be relying on default allow-all behavior.",
                    "Configure zone-based firewall policies under Settings > Firewall, "
                    "applying least-privilege between network segments.")
            else:
                self._hardening(f"Zone-based firewall configured ({len(rules)} rule(s))")

        # ---- Port forwards ----
        self._analyze_port_forwards(port_forwards)

    def _detect_rule_conflicts(self, rules_by_ruleset: dict) -> None:
        """
        Detect ALLOW-before-DENY conflicts within each ruleset.
        Simplified port of FirewallRuleAnalyzer.DetectShadowedRules().
        """
        for ruleset, rules in rules_by_ruleset.items():
            ordered = sorted(
                rules,
                key=lambda r: r.get("rule_index", r.get("index", 9999))
            )

            reported: set[tuple] = set()
            for i, later_rule in enumerate(ordered):
                later_action = (later_rule.get("action") or "").lower()
                later_is_deny = later_action in ("drop", "reject", "deny")
                if not later_is_deny:
                    continue

                later_src = set(later_rule.get("src_firewallgroup_ids", []))
                later_dst = set(later_rule.get("dst_firewallgroup_ids", []))

                for earlier_rule in ordered[:i]:
                    earlier_action = (earlier_rule.get("action") or "").lower()
                    if earlier_action not in ("accept", "allow"):
                        continue

                    earlier_src = set(earlier_rule.get("src_firewallgroup_ids", []))
                    earlier_dst = set(earlier_rule.get("dst_firewallgroup_ids", []))

                    # If the allow rule has no restrictions (allow-all) and the
                    # deny rule that follows has specific targets → subvert
                    allow_is_broad = not earlier_src and not earlier_dst
                    deny_has_scope = bool(later_src or later_dst)

                    if allow_is_broad and deny_has_scope:
                        key = (earlier_rule.get("name"), later_rule.get("name"))
                        if key not in reported:
                            reported.add(key)
                            self._add("Firewall", "recommended",
                                f"Allow rule may subvert deny in '{ruleset}': "
                                f"'{earlier_rule.get('name','?')}' before '{later_rule.get('name','?')}'",
                                f"An allow-all rule at index "
                                f"{earlier_rule.get('rule_index', earlier_rule.get('index','?'))} "
                                f"precedes a deny rule at index "
                                f"{later_rule.get('rule_index', later_rule.get('index','?'))}. "
                                "The deny rule may never match because the earlier allow already passes traffic.",
                                "Review rule order. Place specific deny rules before broad allow rules, "
                                "or restructure using zone-based firewall policies.")

    def _analyze_zone_policies(self, policies: list, zones: list) -> None:
        """Analyze zone-based firewall policies for overly permissive rules."""
        zone_names = {z.get("_id", ""): z.get("name", "?") for z in zones}
        any_any = []
        disabled_count = 0

        for policy in policies:
            if not policy.get("enabled", True):
                disabled_count += 1
                continue

            action   = (policy.get("action") or "").lower()
            src_zone = zone_names.get(policy.get("source", {}).get("zone_id", ""), "?")
            dst_zone = zone_names.get(policy.get("destination", {}).get("zone_id", ""), "?")

            # Check for broad allows with no specific matching criteria
            src_match = policy.get("source", {})
            dst_match = policy.get("destination", {})
            has_specifics = (
                src_match.get("addresses") or src_match.get("port_groups") or
                dst_match.get("addresses") or dst_match.get("port_groups") or
                policy.get("schedule")
            )

            if action in ("accept", "allow") and not has_specifics:
                any_any.append(f"{src_zone} → {dst_zone}")

        if any_any:
            self._add("Firewall", "recommended",
                f"{len(any_any)} zone policy(ies) with no specific matching criteria",
                f"Broad allows: {', '.join(any_any[:6])}{'…' if len(any_any) > 6 else ''}. "
                "These policies permit all traffic between zones without restriction.",
                "Add source/destination address groups, port groups, or application filters "
                "to restrict zone policies to only required traffic.")

        if disabled_count:
            self._add("Firewall", "informational",
                f"{disabled_count} disabled zone policy(ies)",
                "Disabled policies add clutter and confusion to the firewall ruleset.",
                "Remove policies you no longer need to keep the ruleset clean.")

        self._hardening("Zone-based firewall policies configured")

    def _analyze_port_forwards(self, port_forwards: list) -> None:
        """Analyze port forwarding rules for exposure risk."""
        enabled_fwds = [pf for pf in port_forwards if pf.get("enabled", True)]
        if not enabled_fwds:
            return

        high_risk = []
        names     = []
        for pf in enabled_fwds:
            name = pf.get("name", f"→{pf.get('dst_port', '?')}")
            names.append(name)
            try:
                if int(pf.get("dst_port", 0)) in HIGH_RISK_PORTS:
                    high_risk.append(f"{name} (port {pf.get('dst_port')})")
            except (ValueError, TypeError):
                pass

        self._add("Firewall", "recommended",
            f"{len(enabled_fwds)} active port forward(s)",
            f"Exposed services: {', '.join(names[:8])}{'…' if len(names) > 8 else ''}. "
            "Every port forward increases the attack surface exposed to the internet.",
            "Restrict source IPs on each rule where possible. "
            "Ensure destination services are up-to-date. Use VPN instead of direct port forwards where feasible.")

        if high_risk:
            self._add("Firewall", "critical",
                f"{len(high_risk)} port forward(s) exposing high-risk service(s)",
                f"Directly exposed: {', '.join(high_risk[:5])}. "
                "SSH (22), Telnet (23), RDP (3389), and VNC (5900/5800) are primary targets for brute-force attacks.",
                "Remove these port forwards immediately and use a VPN (WireGuard/OpenVPN) for remote access. "
                "If port forwards must remain, restrict source IPs to known addresses.")

    # ------------------------------------------------------------------
    # DNS Analysis  (DnsSecurityAnalyzer.cs)
    # ------------------------------------------------------------------

    def _analyze_dns(self) -> None:
        networks = self.config.get("networks", [])
        settings = self.config.get("settings", [])

        public_dns_nets = []
        for net in networks:
            name = net.get("name", "")
            if not name:
                continue
            for dns in net.get("dhcp_dns", []):
                if dns in PUBLIC_DNS:
                    public_dns_nets.append(f"'{name}' ({dns})")

        if public_dns_nets:
            self._add("DNS", "informational",
                f"Public DNS resolvers used on {len(public_dns_nets)} network(s)",
                f"Networks: {', '.join(public_dns_nets[:5])}{'…' if len(public_dns_nets) > 5 else ''}. "
                "Public resolvers may log queries, support split-DNS only with extra config, "
                "and bypass local filtering.",
                "Consider NextDNS, Cloudflare for Teams, or a local resolver (Pi-hole/AdGuard) "
                "with DNS-over-HTTPS or DNS-over-TLS for privacy and filtering.")

        # Check content/DNS filtering setting
        content_filter = next((s for s in settings if s.get("key") == "content_filtering"), None)
        if content_filter is not None:
            if not content_filter.get("enabled", False):
                self._add("DNS", "informational",
                    "DNS-based ad/malware filtering is not enabled",
                    "Without DNS filtering, clients can reach known malicious domains and ad servers.",
                    "Enable Threat Management > DNS Shield, or configure NextDNS/Pi-hole for DNS-level blocking.")
            else:
                self._add("DNS", "informational",
                    "DNS content filtering is enabled",
                    "DNS-level filtering is active, blocking known malicious domains and ad servers "
                    "before connections are established.",
                    "No action needed. Review blocked domain logs periodically to check for false positives.")
                self._hardening("DNS content filtering enabled")

    # ------------------------------------------------------------------
    # IDS/IPS  (from ConfigAuditEngine.cs threat checks)
    # ------------------------------------------------------------------

    def _analyze_threat_management(self) -> None:
        settings = self.config.get("settings", [])
        tm = next((s for s in settings if s.get("key") == "ips"), None)

        if tm is None:
            self._add("Security", "recommended",
                "IDS/IPS configuration not found",
                "Could not retrieve Intrusion Prevention System settings from the controller. "
                "This may mean IPS is not supported or not configured.",
                "Verify IPS is enabled under Settings > Security > Intrusion Prevention.")
            return

        if not tm.get("enabled", False):
            self._add("Security", "critical",
                "IDS/IPS is disabled",
                "No intrusion detection or prevention is active on WAN traffic. "
                "Malicious traffic can enter the network undetected.",
                "Enable IPS under Settings > Security > Intrusion Prevention. "
                "Start in IDS (detect-only) mode to review alerts before switching to IPS (blocking) mode.")
        else:
            mode = tm.get("ips_mode", "ids")
            if mode == "ids":
                self._add("Security", "recommended",
                    "IDS-only mode — threats detected but not blocked",
                    "IDS mode logs malicious traffic but does not drop it. "
                    "Attackers can still complete their attacks even after detection.",
                    "Switch to IPS (Prevention) mode to actively block detected threats. "
                    "Monitor performance impact on first enable and tune sensitivity as needed.")
            else:
                self._add("Security", "informational",
                    "IPS is active — threats are being blocked",
                    "Intrusion Prevention System is enabled in blocking mode. Malicious traffic "
                    "detected on the WAN is actively dropped before reaching internal devices.",
                    "No action needed. Review the threat log periodically under Security > Threat Management.")
                self._hardening("IPS active — threats are blocked")

    # ------------------------------------------------------------------
    # Performance  (from SqmManager.cs / config_analyzer.py)
    # ------------------------------------------------------------------

    def _analyze_performance(self) -> None:
        settings = self.config.get("settings", [])
        health   = self.config.get("health",   [])

        tc = next((s for s in settings if s.get("key") == "traffic_control"), None)
        fw = next((s for s in settings if s.get("key") == "super_fwcfg"),     None)

        if tc is not None:
            if not tc.get("smart_queues_enabled", False):
                self._add("Performance", "recommended",
                    "Smart Queues (SQM/QoS) is not enabled",
                    "Without Smart Queues, a single high-bandwidth download can saturate the WAN link, "
                    "causing severe latency spikes (bufferbloat) for all other users. "
                    "Gaming, VoIP, and video calls are most affected.",
                    "Enable Smart Queues under Settings > Internet > WAN. "
                    "Set rates to 80–90% of your measured WAN speeds to reduce bufferbloat.")
            else:
                self._add("Performance", "informational",
                    "Smart Queues (SQM/QoS) is enabled",
                    "Active queue management is configured, reducing bufferbloat and ensuring "
                    "consistent latency for real-time traffic during high-bandwidth transfers.",
                    "No action needed. Ensure the configured WAN speeds match your actual ISP speeds.")
                self._hardening("Smart Queues (SQM) enabled")

        if fw is not None:
            if not fw.get("offload_accounting", False):
                self._add("Performance", "informational",
                    "Hardware offloading may not be fully enabled",
                    "Software-only packet processing limits throughput on UDM hardware "
                    "and increases CPU load at high traffic volumes.",
                    "Verify Hardware Offloading is enabled under Settings > Internet > Advanced.")
            else:
                self._add("Performance", "informational",
                    "Hardware offloading is enabled",
                    "Packet processing is offloaded to dedicated hardware, maximizing throughput "
                    "and reducing CPU load at high traffic volumes.",
                    "No action needed.")
                self._hardening("Hardware offloading enabled")

        # WAN health
        wan = next((h for h in health if h.get("subsystem") == "wan"), None)
        if wan:
            latency = wan.get("latency", 0)
            if latency and latency > 100:
                self._add("Performance", "recommended",
                    f"High WAN latency detected: {latency} ms",
                    "WAN latency above 100 ms degrades real-time applications (VoIP, gaming, video conferencing). "
                    "Sustained high latency suggests congestion or ISP issues.",
                    "Contact your ISP if latency is consistently high. "
                    "Enabling Smart Queues can significantly reduce bufferbloat-induced latency.")

            uptime = wan.get("uptime", None)
            if uptime is not None and 0 < uptime < 3600:
                self._add("Performance", "informational",
                    f"WAN connection recently restarted (uptime: {uptime}s)",
                    "A very low WAN uptime may indicate a recent dropout, flap, or manual restart.",
                    "Check WAN event logs if dropouts are frequent. Investigate ISP or local equipment stability.")

    # ------------------------------------------------------------------
    # Device Analysis  (config_analyzer.py + NetworkOptimizer patterns)
    # ------------------------------------------------------------------

    def _analyze_devices(self) -> None:
        devices = self.config.get("devices", [])

        offline_devs   = []
        firmware_devs  = []
        firmware_lines = []   # for the version inventory

        for dev in devices:
            name  = dev.get("name") or dev.get("hostname") or dev.get("mac", "unknown")
            state = dev.get("state", 1)
            model = dev.get("model") or dev.get("type") or "Unknown"
            ver   = dev.get("version", "unknown")

            firmware_lines.append(f"{name} ({model}): {ver}")

            if state == 0:
                offline_devs.append(name)
            elif state not in (1, 2, 4, 5):
                # State 4 = upgrading, 5 = provisioning — expected transients
                self._add("Devices", "informational",
                    f"Device '{name}' in unexpected state: {state}",
                    f"State {state} may indicate adoption issues, pending provisioning, or a firmware problem.",
                    "Check the device in UniFi console. Re-adopt if it remains in this state.",
                    device_name=name)

            if dev.get("upgradable", False):
                cur = dev.get("version", "?")
                new = dev.get("upgrade_to_firmware", "?")
                firmware_devs.append(f"{name} ({cur} → {new})")

        if firmware_lines:
            self._add("Devices", "informational",
                f"Firmware versions ({len(firmware_lines)} device(s))",
                "Current firmware: " + "; ".join(firmware_lines) + ".",
                "Verify all devices are running supported firmware. "
                "Cross-reference against the UniFi release notes for known vulnerabilities.")

        if offline_devs:
            self._add("Devices", "recommended",
                f"{len(offline_devs)} device(s) offline",
                f"Offline: {', '.join(offline_devs[:8])}{'…' if len(offline_devs) > 8 else ''}. "
                "Offline devices may indicate power loss, hardware failure, or connectivity issues.",
                "Check power, Ethernet cables, and PoE budget. Re-adopt devices that remain offline.")

        if firmware_devs:
            self._add("Devices", "recommended",
                f"{len(firmware_devs)} firmware update(s) available",
                f"Updates pending: {', '.join(firmware_devs[:5])}{'…' if len(firmware_devs) > 5 else ''}. "
                "Outdated firmware may contain known security vulnerabilities and performance bugs.",
                "Update firmware via UniFi console. Consider enabling auto-update with a scheduled maintenance window.")

    # ------------------------------------------------------------------
    # Port Security  (PortSecurityAnalyzer.cs — simplified)
    # ------------------------------------------------------------------

    def _analyze_port_security(self) -> None:
        devices = self.config.get("devices", [])

        unused_ports = []

        for dev in devices:
            dtype = (dev.get("type") or "").lower()
            if not (dtype.startswith("usw") or dtype.startswith("ubb")):
                continue

            dev_name   = dev.get("name") or dev.get("hostname") or dev.get("mac", "Switch")
            port_table = dev.get("port_table", [])

            for port in port_table:
                # Skip uplink, SFP, or aggregate ports
                if port.get("is_uplink") or port.get("sfp_found") or port.get("aggregated_by"):
                    continue

                port_name = port.get("name") or f"Port {port.get('port_idx', '?')}"
                enabled   = port.get("enable", True)
                up        = port.get("up", False)

                # Unused: enabled but no link and no known device attached
                if enabled and not up:
                    unused_ports.append(f"{dev_name}: {port_name}")

        if len(unused_ports) > 3:
            sample = ", ".join(unused_ports[:5])
            extra  = f" (+{len(unused_ports) - 5} more)" if len(unused_ports) > 5 else ""
            self._add("Port Security", "informational",
                f"{len(unused_ports)} unused switch port(s) left enabled",
                f"Unused enabled ports: {sample}{extra}. "
                "Active but unconnected ports can be used for unauthorized physical access.",
                "Apply a 'disabled' port profile to unused switch ports. "
                "Re-enable only when a device is connected.")

    # ------------------------------------------------------------------
    # System Settings  (UDM management hardening)
    # ------------------------------------------------------------------

    def _analyze_system(self) -> None:
        settings = self.config.get("settings", [])
        devices  = self.config.get("devices",  [])

        mgmt = next((s for s in settings if s.get("key") == "mgmt"), None)
        if mgmt is not None:
            # SSH access — always show status as informational
            ssh_on = mgmt.get("x_ssh_enabled", False) or mgmt.get("x_ssh_auth_password_enabled", False)
            if ssh_on:
                self._add("System", "informational",
                    "SSH access is enabled on UDM",
                    "SSH is currently active on this device. When not in active use this increases "
                    "the attack surface and exposes the device to brute-force attempts.",
                    "Disable SSH when not actively needed (Settings > System > SSH). "
                    "If required, use key-based authentication only and restrict source IPs via firewall.")
            else:
                self._add("System", "informational",
                    "SSH access is disabled on UDM",
                    "SSH is not enabled on this device. This is the recommended configuration "
                    "when remote shell access is not actively required.",
                    "No action needed. Re-enable temporarily via Settings > System > SSH if shell access is required.")
                self._hardening("SSH access disabled on UDM")

        syslog = next((s for s in settings if s.get("key") == "rsyslogd"), None)
        if syslog is not None:
            syslog_on = syslog.get("enabled", False) and bool(syslog.get("ip", ""))
            if not syslog_on:
                self._add("System", "informational",
                    "Remote syslog is not configured",
                    "All logs are stored locally only. A compromised device could destroy its own logs, "
                    "eliminating the audit trail.",
                    "Configure a syslog server (e.g., Graylog, Splunk, or a local syslog host) "
                    "under Settings > System > Remote Logging.")
            else:
                self._add("System", "informational",
                    f"Remote syslog is configured ({syslog.get('ip', 'unknown')})",
                    "Logs are being forwarded to a remote syslog server. This preserves the audit trail "
                    "even if the local device is compromised.",
                    "No action needed. Ensure the syslog destination is secured and monitored.")
                self._hardening(f"Remote syslog configured ({syslog.get('ip', 'unknown')})")

        ntp = next((s for s in settings if s.get("key") == "ntp"), None)
        if ntp is not None:
            # Collect all configured servers across all possible field names/firmware versions
            ntp_servers = []
            for field in ("server_1", "server_2", "ntp_server_1", "ntp_server_2", "server"):
                val = ntp.get(field, "")
                if val and val not in ntp_servers:
                    ntp_servers.append(val)
            for val in (ntp.get("servers") or []):
                if val and val not in ntp_servers:
                    ntp_servers.append(val)

            ntp_mode = ntp.get("mode", "")
            ntp_configured = bool(ntp_servers) or ntp_mode in ("auto", "pool", "dhcp")
            if not ntp_configured:
                self._add("System", "informational",
                    "NTP server is not configured",
                    "Without accurate time synchronization, log timestamps are unreliable, "
                    "certificate validation may fail, and RADIUS/802.1X authentication can break.",
                    "Configure an NTP server under Settings > System. "
                    "Use pool.ntp.org or your ISP-provided NTP server.")
            else:
                label = ", ".join(ntp_servers) if ntp_servers else f"{ntp_mode} mode"
                self._add("System", "informational",
                    f"NTP is configured ({label})",
                    "Time synchronization is active. Accurate timestamps are essential for log correlation, "
                    "certificate validation, and authentication protocols.",
                    "No action needed. Verify the NTP server is reachable and that device clocks are in sync.")

        # Auto-update check across all devices
        # Normalise: field may be bool True/False or string "true"/"false" or absent
        def _au(dev):
            v = dev.get("auto_upgrade")
            if v is None:
                return None
            if isinstance(v, bool):
                return v
            return str(v).lower() == "true"

        all_devices = [dev for dev in devices if dev.get("model")]
        auto_on  = [dev for dev in all_devices if _au(dev) is True]
        auto_off = [dev for dev in all_devices if _au(dev) is False]
        auto_unknown = [dev for dev in all_devices if _au(dev) is None]

        names_off = [dev.get("name") or dev.get("hostname") or dev.get("mac", "?") for dev in auto_off]
        names_unknown = [dev.get("name") or dev.get("hostname") or dev.get("mac", "?") for dev in auto_unknown]

        if names_off:
            sample = ", ".join(names_off[:6])
            extra  = f" (+{len(names_off) - 6} more)" if len(names_off) > 6 else ""
            self._add("System", "informational",
                f"Auto-update disabled on {len(names_off)} device(s)",
                f"Devices: {sample}{extra}. Devices without auto-update may run vulnerable firmware indefinitely.",
                "Enable auto-update or establish a regular manual update schedule via the UniFi console.")
        if auto_on:
            names_on = [dev.get("name") or dev.get("hostname") or dev.get("mac", "?") for dev in auto_on]
            sample = ", ".join(names_on[:6])
            extra  = f" (+{len(names_on) - 6} more)" if len(names_on) > 6 else ""
            self._add("System", "informational",
                f"Auto-update enabled on {len(auto_on)} device(s)",
                f"Devices: {sample}{extra}. These devices will receive firmware updates automatically.",
                "No action needed. Consider setting a maintenance window to avoid updates during peak hours.")
        if names_unknown and all_devices:
            sample = ", ".join(names_unknown[:6])
            extra  = f" (+{len(names_unknown) - 6} more)" if len(names_unknown) > 6 else ""
            self._add("System", "informational",
                f"Auto-update status unknown on {len(names_unknown)} device(s)",
                f"Devices: {sample}{extra}. The auto_upgrade field was not returned by the API for these devices — "
                "status may be controlled by a global setting or not yet reported.",
                "Verify auto-update preference in the UniFi console for each device.")

    # ------------------------------------------------------------------
    # Score Calculation  (AuditScorer.cs)
    # ------------------------------------------------------------------

    def _calculate_score(self) -> dict:
        """Calculate 0-100 security posture score with capped deductions per tier."""
        by_sev: dict[str, list[OptimizerIssue]] = {
            "critical": [], "recommended": [], "informational": []
        }
        for issue in self._issues:
            bucket = by_sev.get(issue.severity)
            if bucket is not None:
                bucket.append(issue)

        deductions: dict[str, int] = {}
        for sev, issues in by_sev.items():
            raw = sum(i.score_impact for i in issues)
            deductions[sev] = min(raw, MAX_DEDUCTION.get(sev, 0))

        # Hardening bonus (up to 8 pts) — from AuditScorer.CalculateHardeningBonus
        n_measures = len(set(self._hardening_measures))  # deduplicate
        if n_measures >= 4:
            hardening_bonus = MAX_HARDENING_MEASURE_BONUS
        elif n_measures >= 2:
            hardening_bonus = 2
        elif n_measures >= 1:
            hardening_bonus = 1
        else:
            hardening_bonus = 0

        total_deduction = sum(deductions.values())
        score = max(0, min(100, BASE_SCORE - total_deduction + hardening_bonus))

        # Label
        if score >= SCORE_EXCELLENT:
            label = "EXCELLENT"
            description = "Outstanding security configuration"
        elif score >= SCORE_GOOD:
            label = "GOOD"
            description = "Solid security posture with minimal issues"
        elif score >= SCORE_FAIR:
            label = "FAIR"
            description = "Acceptable but improvements recommended"
        elif score >= SCORE_NEEDS_ATTENTION:
            label = "NEEDS ATTENTION"
            description = "Several issues require remediation"
        else:
            label = "CRITICAL"
            description = "Immediate attention required"

        # Posture override: many critical issues force downgrade regardless of score
        critical_count = len(by_sev["critical"])
        if critical_count > CRITICAL_POSTURE_THRESHOLD:
            posture = "CRITICAL"
        elif critical_count > NEEDS_ATTENTION_POSTURE_THRESHOLD:
            posture = "NEEDS ATTENTION"
        else:
            posture = label

        return {
            "score":         score,
            "label":         label,
            "posture":       posture,
            "description":   description,
            "deductions":    deductions,
            "hardening_bonus": hardening_bonus,
            "counts": {
                "critical":      critical_count,
                "recommended":   len(by_sev["recommended"]),
                "informational": len(by_sev["informational"]),
                "total":         len(self._issues),
            },
        }

    # ------------------------------------------------------------------
    # Public entrypoint
    # ------------------------------------------------------------------

    def run(self) -> dict:
        """
        Run all analyzers and return the full optimizer result dict.
        Keys: score_info, issues, hardening_measures, categories, stats, timestamp
        """
        self._issues = []
        self._hardening_measures = []

        self._analyze_wifi()
        self._analyze_networks()
        self._analyze_firewall()
        self._analyze_dns()
        self._analyze_threat_management()
        self._analyze_performance()
        self._analyze_devices()
        self._analyze_port_security()
        self._analyze_system()

        # Sort: critical → recommended → informational, then by category
        sev_order = {"critical": 0, "recommended": 1, "informational": 2}
        self._issues.sort(key=lambda i: (sev_order.get(i.severity, 9), i.category))

        score_info = self._calculate_score()

        return {
            "score":               score_info["score"],
            "score_label":         score_info["label"],
            "posture":             score_info["posture"],
            "score_description":   score_info["description"],
            "issue_counts":        score_info["counts"],
            "deductions":          score_info["deductions"],
            "hardening_bonus":     score_info["hardening_bonus"],
            "hardening_measures":  list(set(self._hardening_measures)),
            "issues":              [i.to_dict() for i in self._issues],
            "categories":          sorted(set(i.category for i in self._issues)),
            "stats": {
                "device_count":         len(self.config.get("devices",         [])),
                "client_count":         len(self.config.get("clients",         [])),
                "network_count":        len(self.config.get("networks",        [])),
                "wlan_count":           len(self.config.get("wlans",           [])),
                "firewall_rule_count":  len(self.config.get("firewall_rules",  [])),
                "policy_count":         len(self.config.get("firewall_policies", [])),
                "port_forward_count":   len(self.config.get("port_forwards",   [])),
            },
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
