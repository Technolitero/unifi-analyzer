# UniFi UDM Analyzer

A local web application that connects to a UniFi Dream Machine (UDM / UDM-Pro / UDM-SE) to:

1. **Analyze configuration** — inspects WiFi, network, firewall, security, and QoS settings and produces prioritized, actionable suggestions.
2. **Capture packets (PCAP)** — SSH into the UDM, run `tcpdump`, and format the capture as structured text you can paste directly into an AI assistant for analysis.

---

## Requirements

- Python 3.11+
- A UniFi Dream Machine (UDM, UDM-Pro, UDM-SE, or UDR) running UniFi OS
- SSH access enabled on the UDM (for PCAP capture)

---

## Installation

```bash
cd unifi-analyzer
pip install -r requirements.txt
```

---

## Running

```bash
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

Then open **http://localhost:8080** in your browser.

---

## Features

### Configuration Analysis

Enter your UDM's IP, port (default 443), site name (default `default`), and your UniFi admin credentials. The analyzer checks:

| Category | Checks |
|---|---|
| WiFi | WPA3, TKIP/AES, PMF, 802.11r fast roaming, DTIM, hidden SSID, minimum RSSI |
| Devices | Firmware updates, device state, channel utilization, TX power |
| Networks | Guest VLAN, IoT VLAN, DHCP lease time, MTU, IPv6 |
| Firewall | Allow-all rules, disabled rules, logging, port forwards |
| Security | IDS/IPS mode (detect vs. prevent) |
| DNS | Public resolver usage |
| Performance | Smart Queues / SQM (bufferbloat), hardware offloading |

Suggestions are color-coded by severity: **Critical → High → Medium → Low → Info**.

### PCAP Capture

SSH credentials are used to connect to the UDM (default user: `root`) and run `tcpdump`. The output is:

- Parsed into human-readable packet details (Ethernet, IPv4/IPv6, TCP/UDP/ICMP)
- Summarized with protocol counts, top talkers, and top conversations
- Formatted as plain text ready to paste into Claude, ChatGPT, or any AI

**Common UDM interfaces:**

| Interface | Description |
|---|---|
| `eth4` | WAN port (UDM-Pro) |
| `eth0` | WAN1 |
| `br0` | LAN bridge (all wired LAN) |
| `wlan0` | 2.4 GHz radio |
| `wlan1` | 5 GHz radio |

**BPF filter examples:**
- `host 192.168.1.50` — traffic to/from one device
- `tcp port 443` — HTTPS only
- `not arp and not icmp` — exclude ARP/ICMP noise
- `src net 192.168.10.0/24` — traffic from IoT VLAN

---

## Security Notes

- Credentials are **never stored** — they are only held in memory for the duration of each request.
- The backend connects to the UDM with `verify=False` (self-signed cert). Run this tool on your local network only.
- SSH host keys are auto-accepted (suitable for a trusted LAN environment).
- Do not expose port 8080 to the internet.

---

## Architecture

```
unifi-analyzer/
├── main.py              # FastAPI backend + API routes
├── unifi_client.py      # UniFi Controller REST API client
├── config_analyzer.py   # Configuration analysis engine
├── pcap_handler.py      # SSH PCAP capture + parser + AI formatter
├── requirements.txt
└── static/
    └── index.html       # Single-page frontend (no build step)
```

---

## Enabling SSH on UDM

1. In UniFi Network: **Settings → System → SSH**
2. Enable SSH and set a password (or upload an SSH key)
3. Default username is `root`
