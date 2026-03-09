"""
UniFi UDM API Client
Handles authentication and data retrieval from UniFi Dream Machine controllers.
"""

import requests
import urllib3
import json
from typing import Optional

# Disable SSL warnings for self-signed UDM certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class UnifiClient:
    def __init__(self, host: str, username: str, password: str, port: int = 443, site: str = "default"):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.port = port
        self.site = site
        self.session = requests.Session()
        self.session.verify = False
        self._api_session = requests.Session()  # reused for all integration API calls
        self._api_session.verify = False
        self._api_session.cookies.clear()  # never accumulate cookies between integration calls
        self.base_url = f"https://{self.host}:{self.port}"
        self._is_udm = True  # Assume UDM/UDM-Pro (uses /proxy/network prefix)
        self._csrf_token: Optional[str] = None

    def _api_url(self, path: str) -> str:
        if self._is_udm:
            return f"{self.base_url}/proxy/network/api/s/{self.site}/{path.lstrip('/')}"
        return f"{self.base_url}/api/s/{self.site}/{path.lstrip('/')}"

    def login(self) -> dict:
        """Authenticate with the UDM controller."""
        url = f"{self.base_url}/api/auth/login"
        payload = {"username": self.username, "password": self.password}
        resp = self.session.post(url, json=payload, timeout=15)
        if resp.status_code == 404:
            # Older controller (non-UDM)
            self._is_udm = False
            url = f"{self.base_url}/api/login"
            resp = self.session.post(url, json=payload, timeout=15)
        resp.raise_for_status()
        # Capture CSRF token if present
        if "X-Csrf-Token" in resp.headers:
            self._csrf_token = resp.headers["X-Csrf-Token"]
            self.session.headers.update({"X-Csrf-Token": self._csrf_token})
        data = resp.json()
        return data

    def logout(self):
        try:
            if self._is_udm:
                self.session.post(f"{self.base_url}/api/auth/logout", timeout=5)
            else:
                self.session.get(f"{self.base_url}/api/logout", timeout=5)
        except Exception:
            pass

    def _get(self, path: str) -> dict:
        url = self._api_url(path)
        resp = self.session.get(url, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def get_system_info(self) -> dict:
        """Get controller system information."""
        try:
            if self._is_udm:
                resp = self.session.get(f"{self.base_url}/proxy/network/api/s/{self.site}/stat/sysinfo", timeout=15)
                resp.raise_for_status()
                return resp.json()
        except Exception:
            pass
        return {}

    def get_devices(self) -> list:
        """Get all UniFi devices (APs, switches, gateways)."""
        data = self._get("stat/device")
        return data.get("data", [])

    def get_clients(self) -> list:
        """Get all connected clients."""
        data = self._get("stat/sta")
        return data.get("data", [])

    def get_network_conf(self) -> list:
        """Get network/VLAN configurations."""
        data = self._get("rest/networkconf")
        return data.get("data", [])

    def get_wlan_conf(self) -> list:
        """Get wireless network configurations."""
        data = self._get("rest/wlanconf")
        return data.get("data", [])

    def get_firewall_rules(self) -> list:
        """Get legacy firewall rules (classic firewall, pre-zone-based)."""
        data = self._get("rest/firewallrule")
        return data.get("data", [])

    def get_firewall_zones_v2_session(self) -> list:
        """Get firewall zones via v2 session API (no API key required).
        Tries firewall-zones then firewall/zone as fallback."""
        for path in ("firewall-zones", "firewall/zone"):
            try:
                url = f"{self.base_url}/proxy/network/v2/api/site/{self.site}/{path}"
                resp = self.session.get(url, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    return data if isinstance(data, list) else data.get("data", [])
            except Exception:
                continue
        return []

    def get_firewall_policies_session(self) -> list:
        """Get zone-based firewall policies via v2 session API (no API key required)."""
        url = f"{self.base_url}/proxy/network/v2/api/site/{self.site}/firewall-policies"
        resp = self.session.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else data.get("data", [])

    def get_dns_records_session(self) -> list:
        """Get static DNS records via v2 session API."""
        url = f"{self.base_url}/proxy/network/v2/api/site/{self.site}/static-dns"
        resp = self.session.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else data.get("data", [])

    def get_firewall_groups(self) -> list:
        """Get firewall groups."""
        data = self._get("rest/firewallgroup")
        return data.get("data", [])

    def get_port_forwards(self) -> list:
        """Get port forwarding rules."""
        data = self._get("rest/portforward")
        return data.get("data", [])

    def get_routing(self) -> list:
        """Get static routes."""
        data = self._get("rest/routing")
        return data.get("data", [])

    def get_settings(self) -> list:
        """Get controller settings."""
        data = self._get("rest/setting")
        return data.get("data", [])

    def get_dpi_stats(self) -> list:
        """Get DPI (Deep Packet Inspection) stats."""
        try:
            data = self._get("stat/dpi")
            return data.get("data", [])
        except Exception:
            return []

    def get_health(self) -> list:
        """Get network health subsystems."""
        try:
            data = self._get("stat/health")
            return data.get("data", [])
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Integration API (v1) — requires X-API-KEY, not session auth
    # ------------------------------------------------------------------

    def _integration_get(self, path: str, api_key: str) -> dict:
        """GET against /proxy/network/integration/v1/{path} using API key auth.
        Reuses a persistent session; tries X-API-KEY then Authorization: Bearer on 401."""
        url = f"{self.base_url}/proxy/network/integration/v1/{path.lstrip('/')}"
        headers_xkey = {"X-API-KEY": api_key, "Accept": "application/json"}
        resp = self._api_session.get(url, headers=headers_xkey, timeout=15)
        if resp.status_code == 401:
            headers_bearer = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
            resp = self._api_session.get(url, headers=headers_bearer, timeout=15)
        self._api_session.cookies.clear()  # don't let error cookies affect next call
        resp.raise_for_status()
        return resp.json()

    def get_sites_v1(self, api_key: str) -> list:
        """Return list of sites from the integration API, each with a siteId."""
        data = self._integration_get("sites", api_key)
        return data if isinstance(data, list) else data.get("data", [])

    def get_firewall_zones(self, site_id: str, api_key: str) -> list:
        """Return the list of firewall zone objects for a site."""
        data = self._integration_get(f"sites/{site_id}/firewall/zones", api_key)
        return data if isinstance(data, list) else data.get("data", [])

    def get_firewall_zone(self, site_id: str, zone_id: str, api_key: str) -> dict:
        """Return a single firewall zone by ID."""
        return self._integration_get(f"sites/{site_id}/firewall/zones/{zone_id}", api_key)

    def get_firewall_policies(self, site_id: str, api_key: str, zone_id: str = None) -> list:
        """Return firewall policies, filtered by zone via query param."""
        url = f"{self.base_url}/proxy/network/integration/v1/sites/{site_id}/firewall/policies"
        params = {"zoneId": zone_id} if zone_id else {}
        headers_xkey = {"X-API-KEY": api_key, "Accept": "application/json"}
        resp = self._api_session.get(url, headers=headers_xkey, params=params, timeout=15)
        if resp.status_code == 401:
            headers_bearer = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
            resp = self._api_session.get(url, headers=headers_bearer, params=params, timeout=15)
        self._api_session.cookies.clear()
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else data.get("data", [])

    def get_firewall_policy(self, site_id: str, policy_id: str, api_key: str) -> dict:
        """Return a single firewall policy by ID."""
        return self._integration_get(f"sites/{site_id}/firewall/policies/{policy_id}", api_key)

    def get_all_config(self) -> dict:
        """Retrieve all configuration data in one call."""
        return {
            "devices": self.get_devices(),
            "clients": self.get_clients(),
            "networks": self.get_network_conf(),
            "wlans": self.get_wlan_conf(),
            "firewall_rules": self.get_firewall_rules(),
            "firewall_groups": self.get_firewall_groups(),
            "port_forwards": self.get_port_forwards(),
            "routes": self.get_routing(),
            "settings": self.get_settings(),
            "health": self.get_health(),
        }
