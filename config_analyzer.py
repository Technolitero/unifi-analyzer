"""
UniFi Configuration Analyzer
Inspects UDM configuration data and produces prioritized performance/security suggestions.
"""

from dataclasses import dataclass, field
from typing import Any
import re


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Suggestion:
    category: str
    severity: str   # critical | high | medium | low | info
    title: str
    detail: str
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }


class ConfigAnalyzer:
    def __init__(self, config: dict):
        self.config = config
        self.suggestions: list[Suggestion] = []

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _add(self, category: str, severity: str, title: str, detail: str, recommendation: str):
        self.suggestions.append(Suggestion(category, severity, title, detail, recommendation))

    def _setting(self, key: str) -> dict:
        """Find a setting block by key."""
        for s in self.config.get("settings", []):
            if s.get("key") == key:
                return s
        return {}

    # ------------------------------------------------------------------
    # WiFi analysis
    # ------------------------------------------------------------------

    def _analyze_wlans(self):
        wlans = self.config.get("wlans", [])
        for wlan in wlans:
            name = wlan.get("name", "unknown")

            # WPA2 vs WPA3
            security = wlan.get("security", "")
            wpa_enc = wlan.get("wpa_enc", "")
            wpa_mode = wlan.get("wpa_mode", "")
            if security == "open":
                self._add(
                    "WiFi", "critical",
                    f"Open WiFi: '{name}'",
                    "Network has no authentication/encryption.",
                    "Enable WPA2-AES or WPA3 encryption to protect wireless traffic.",
                )
            elif security == "wpapsk" and wpa_enc == "tkip":
                self._add(
                    "WiFi", "high",
                    f"Weak encryption (TKIP) on '{name}'",
                    "TKIP is deprecated and vulnerable to attacks.",
                    "Switch encryption to AES (CCMP) and prefer WPA3 where devices support it.",
                )
            elif wpa_mode != "wpa3" and wpa_mode != "wpa2wpa3":
                self._add(
                    "WiFi", "low",
                    f"WPA3 not enabled on '{name}'",
                    f"Current mode: {wpa_mode or security}. WPA3 provides stronger handshakes.",
                    "Enable WPA3 or WPA2/WPA3 mixed mode for improved security and performance.",
                )

            # PMF (Protected Management Frames)
            pmf_mode = wlan.get("pmf_mode", "disabled")
            if pmf_mode == "disabled":
                self._add(
                    "WiFi", "medium",
                    f"PMF disabled on '{name}'",
                    "Protected Management Frames prevent deauth/disassoc attacks.",
                    "Set PMF to 'optional' or 'required' in WLAN advanced settings.",
                )

            # Band steering
            band_steering = wlan.get("bc_filter_enabled", False)
            # Check minimum RSSI
            min_rssi = wlan.get("minrate_na_advertising_rates", None)
            if min_rssi is None:
                self._add(
                    "WiFi", "low",
                    f"Minimum RSSI not configured on '{name}'",
                    "Without minimum RSSI, sticky clients stay connected at low signal strengths, degrading airtime.",
                    "Set a minimum RSSI (e.g., -80 dBm) to encourage roaming to a better AP.",
                )

            # Fast roaming / 802.11r
            fast_roaming = wlan.get("fast_roaming_enabled", False)
            if not fast_roaming:
                self._add(
                    "WiFi", "low",
                    f"802.11r Fast Roaming disabled on '{name}'",
                    "Fast BSS Transition reduces roaming latency for mobile devices.",
                    "Enable Fast Roaming (802.11r) in WLAN settings if all clients support it.",
                )

            # DTIM period (affects power saving / latency)
            dtim_na = wlan.get("dtim_na", 1)
            dtim_ng = wlan.get("dtim_ng", 1)
            if dtim_na > 3 or dtim_ng > 3:
                self._add(
                    "WiFi", "medium",
                    f"High DTIM period on '{name}' (5GHz:{dtim_na}, 2.4GHz:{dtim_ng})",
                    "High DTIM values increase latency for power-saving devices.",
                    "Set DTIM to 1 for latency-sensitive networks (gaming/VoIP) or 3 for IoT.",
                )

            # Hidden SSID
            if wlan.get("hide_ssid", False):
                self._add(
                    "WiFi", "info",
                    f"Hidden SSID on '{name}'",
                    "Hiding SSIDs provides no real security benefit and can cause connection issues.",
                    "Consider making the SSID visible and relying on strong WPA3 encryption instead.",
                )

    # ------------------------------------------------------------------
    # Device / AP analysis
    # ------------------------------------------------------------------

    def _analyze_devices(self):
        devices = self.config.get("devices", [])
        for dev in devices:
            name = dev.get("name") or dev.get("hostname") or dev.get("mac", "unknown")
            dtype = dev.get("type", "")
            inform_url = dev.get("inform_url", "")
            state = dev.get("state", 1)

            if state != 1:
                self._add(
                    "Devices", "high",
                    f"Device '{name}' is not connected/adopted",
                    f"Device state code: {state}",
                    "Check device connectivity. It may need re-adoption or firmware update.",
                )

            # Firmware check
            upgradable = dev.get("upgradable", False)
            current_fw = dev.get("version", "unknown")
            upgrade_fw = dev.get("upgrade_to_firmware", "")
            if upgradable:
                self._add(
                    "Devices", "medium",
                    f"Firmware update available for '{name}'",
                    f"Current: {current_fw}, Available: {upgrade_fw}",
                    "Update firmware to get bug fixes, security patches, and performance improvements.",
                )

            # Channel utilization for APs
            if dtype in ("uap",):
                radio_table = dev.get("radio_table", [])
                for radio in radio_table:
                    band = radio.get("radio", "ng")
                    cu = radio.get("cu_total", 0)
                    if cu > 70:
                        self._add(
                            "WiFi", "high",
                            f"High channel utilization on '{name}' ({band}): {cu}%",
                            "Channel congestion above 70% causes retries and reduced throughput.",
                            "Change the wireless channel, reduce transmit power, or reduce client density.",
                        )
                    elif cu > 50:
                        self._add(
                            "WiFi", "medium",
                            f"Moderate channel utilization on '{name}' ({band}): {cu}%",
                            "Channel utilization above 50% may start impacting performance.",
                            "Monitor and consider adjusting channel or AP placement.",
                        )

            # Tx power override
            radio_table = dev.get("radio_table", [])
            for radio in radio_table:
                tx_power_mode = radio.get("tx_power_mode", "auto")
                if tx_power_mode == "high":
                    band = radio.get("radio", "")
                    self._add(
                        "WiFi", "medium",
                        f"TX power set to HIGH on '{name}' ({band})",
                        "Maximum TX power increases interference with neighboring APs and can degrade performance.",
                        "Use 'auto' or 'medium' TX power to balance coverage and co-channel interference.",
                    )

    # ------------------------------------------------------------------
    # Network / VLAN analysis
    # ------------------------------------------------------------------

    def _analyze_networks(self):
        networks = self.config.get("networks", [])
        has_guest = False
        has_iot = False
        main_nets = []

        for net in networks:
            if not net.get("name"):
                continue
            purpose = net.get("purpose", "corporate")
            name = net.get("name", "unknown")
            ip_subnet = net.get("ip_subnet", "")

            if purpose == "guest":
                has_guest = True
            if "iot" in name.lower():
                has_iot = True
            if purpose == "corporate":
                main_nets.append(net)

            # DHCP lease time
            dhcp_lease = int(net.get("dhcp_lease_time", 86400))
            if dhcp_lease < 3600:
                self._add(
                    "Networks", "low",
                    f"Very short DHCP lease time on '{name}': {dhcp_lease}s",
                    "Short leases cause frequent DHCP renewals increasing broadcast traffic.",
                    "Set DHCP lease time to at least 3600s (1 hour); 86400s (24h) is typical.",
                )

            # Jumbo frames / MTU
            mtu = int(net.get("mtu", 1500))
            if mtu < 1500 and purpose == "corporate":
                self._add(
                    "Networks", "low",
                    f"MTU below 1500 on '{name}': {mtu}",
                    "Low MTU can fragment packets unnecessarily, reducing throughput.",
                    "Set MTU to 1500 (or 9000 for jumbo frames on all-UniFi links).",
                )

            # IPv6
            ipv6_enabled = net.get("ipv6_interface_type", "none")
            if ipv6_enabled == "none" and purpose == "corporate":
                self._add(
                    "Networks", "info",
                    f"IPv6 not configured on '{name}'",
                    "IPv6 is increasingly required for modern internet services.",
                    "Consider enabling IPv6 with SLAAC or DHCPv6-PD if your ISP supports it.",
                )

        if not has_guest:
            self._add(
                "Networks", "medium",
                "No guest network detected",
                "Without a guest network, visitors share the same LAN as your devices.",
                "Create a dedicated guest network with AP isolation to segregate visitor traffic.",
            )

        if not has_iot:
            self._add(
                "Networks", "medium",
                "No IoT VLAN detected",
                "IoT devices often have poor security; placing them on the main LAN is risky.",
                "Create a dedicated IoT VLAN and restrict its access to the internet only.",
            )

        if len(main_nets) > 1:
            self._add(
                "Networks", "info",
                f"{len(main_nets)} corporate networks detected",
                "Multiple corporate networks may indicate planned segmentation.",
                "Ensure inter-VLAN firewall rules enforce least-privilege access between segments.",
            )

    # ------------------------------------------------------------------
    # Firewall analysis
    # ------------------------------------------------------------------

    def _analyze_firewall(self):
        rules = self.config.get("firewall_rules", [])
        any_to_any = []
        disabled_rules = []
        logging_off = []

        for rule in rules:
            if not rule.get("enabled", True):
                disabled_rules.append(rule.get("name", "unnamed"))
                continue

            src_type = rule.get("src_firewallgroup_ids", [])
            dst_type = rule.get("dst_firewallgroup_ids", [])
            action = rule.get("action", "")
            name = rule.get("name", "unnamed")

            # Allow-all rules
            if action == "accept" and not src_type and not dst_type:
                any_to_any.append(name)

            # Logging
            if not rule.get("logging", False) and action == "accept":
                logging_off.append(name)

        if any_to_any:
            self._add(
                "Firewall", "high",
                f"{len(any_to_any)} allow-all firewall rules detected",
                f"Rules: {', '.join(any_to_any[:5])}",
                "Replace broad allow-all rules with specific source/destination group rules following least-privilege.",
            )

        if disabled_rules:
            self._add(
                "Firewall", "low",
                f"{len(disabled_rules)} disabled firewall rules",
                f"Disabled rules: {', '.join(disabled_rules[:5])}",
                "Remove disabled rules you no longer need to keep the rule set clean and understandable.",
            )

        if len(logging_off) > 5:
            self._add(
                "Firewall", "low",
                f"Logging disabled on {len(logging_off)} accept rules",
                "Without logging, it's difficult to audit traffic patterns or detect intrusions.",
                "Enable logging on key accept rules, especially those traversing VLANs or from WAN.",
            )

        port_forwards = self.config.get("port_forwards", [])
        if port_forwards:
            exposed = [pf.get("name", f"port {pf.get('dst_port', '?')}") for pf in port_forwards]
            self._add(
                "Firewall", "medium",
                f"{len(port_forwards)} port forwarding rules active",
                f"Exposed: {', '.join(exposed[:8])}",
                "Review each port forward. Restrict source IPs where possible and ensure destination services are patched.",
            )

    # ------------------------------------------------------------------
    # IDS/IPS and threat management
    # ------------------------------------------------------------------

    def _analyze_threat_management(self):
        settings = self.config.get("settings", [])
        tm_setting = self._setting("ips")
        usg_setting = self._setting("super_fwcfg")

        if not tm_setting:
            self._add(
                "Security", "high",
                "IDS/IPS status unknown or not configured",
                "Could not retrieve IPS settings from the controller.",
                "Verify that Intrusion Prevention System is enabled under Traffic Management in Network settings.",
            )
            return

        enabled = tm_setting.get("enabled", False)
        if not enabled:
            self._add(
                "Security", "high",
                "IDS/IPS is disabled",
                "Intrusion detection/prevention is not active.",
                "Enable IPS under Settings > Security > Intrusion Prevention for threat detection.",
            )
        else:
            mode = tm_setting.get("ips_mode", "ids")
            if mode == "ids":
                self._add(
                    "Security", "medium",
                    "IDS only (not IPS) — threats are detected but not blocked",
                    "IDS mode logs threats without dropping packets.",
                    "Switch to IPS mode to actively block detected threats (monitor performance impact).",
                )

    # ------------------------------------------------------------------
    # DNS and content filtering
    # ------------------------------------------------------------------

    def _analyze_dns(self):
        networks = self.config.get("networks", [])
        for net in networks:
            if not net.get("name"):
                continue
            dns_servers = net.get("dhcp_dns", [])
            name = net.get("name", "unknown")
            if not dns_servers:
                continue
            for dns in dns_servers:
                if dns in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"):
                    self._add(
                        "DNS", "info",
                        f"Using public DNS on '{name}': {dns}",
                        "Public DNS resolvers may log your queries and don't support split-DNS.",
                        "Consider using NextDNS, Cloudflare Gateway, or a local resolver (Pi-hole/AdGuard) with DoH/DoT.",
                    )

    # ------------------------------------------------------------------
    # QoS / traffic management
    # ------------------------------------------------------------------

    def _analyze_qos(self):
        traffic_setting = self._setting("traffic_control")
        if not traffic_setting:
            return
        smart_queue = traffic_setting.get("smart_queues_enabled", False)
        if not smart_queue:
            self._add(
                "Performance", "medium",
                "Smart Queues (SQM/QoS) not enabled",
                "Without Smart Queues, a single high-bandwidth session can saturate the WAN causing latency spikes (bufferbloat).",
                "Enable Smart Queues under Settings > Internet > WAN and set to 80-90% of your WAN speeds to reduce bufferbloat.",
            )

    # ------------------------------------------------------------------
    # Hardware offloading
    # ------------------------------------------------------------------

    def _analyze_offloading(self):
        usg_setting = self._setting("super_fwcfg")
        if not usg_setting:
            return
        hw_offload = usg_setting.get("offload_accounting", False)
        if not hw_offload:
            self._add(
                "Performance", "medium",
                "Hardware offloading may not be enabled",
                "Software-only packet processing limits throughput on UDM hardware.",
                "Verify Hardware Offloading is enabled under Settings > Internet > Advanced.",
            )

    # ------------------------------------------------------------------
    # Main entrypoint
    # ------------------------------------------------------------------

    def analyze(self) -> list[dict]:
        self.suggestions = []
        self._analyze_wlans()
        self._analyze_devices()
        self._analyze_networks()
        self._analyze_firewall()
        self._analyze_threat_management()
        self._analyze_dns()
        self._analyze_qos()
        self._analyze_offloading()

        # Sort by severity
        self.suggestions.sort(key=lambda s: SEVERITY_ORDER.get(s.severity, 99))
        return [s.to_dict() for s in self.suggestions]
