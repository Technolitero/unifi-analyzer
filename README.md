# UniFi Analyzer

A comprehensive local web application that connects to a UniFi Dream Machine (UDM / UDM-Pro / UDM-SE / UDR) to provide deep network analysis, configuration insights, live interface discovery, packet capture, and structured data export.

---

## Requirements

- **Python 3.8+** (3.11+ recommended)
- **Windows 10/11**, **macOS**, or **Linux**
- A UniFi Dream Machine or compatible controller running UniFi OS
- SSH access enabled on the controller (required for PCAP capture and interface discovery)

---

## Installation & Running

### Windows (Recommended)

Double-click **`UnifiAnalyzer.bat`**. It will:

1. Detect Python 3.8+ (falls back through `py`, `python3`, `python`)
2. Create a virtual environment at `.venv/` (reuses if it already exists)
3. Install / upgrade all dependencies from `requirements.txt`
4. Start the server at `http://127.0.0.1:8080` and open a browser tab automatically

Press **Ctrl+C** to stop the server.

### Windows Service

Run as Administrator:

```cmd
install.bat     # Install and start as a Windows service
uninstall.bat   # Remove the service
```

The service starts automatically at boot and runs at `http://localhost:8080`. Logs are at `C:\Program Files\UnifiAnalyzer\logs\`.

### From Source (any OS)

```bash
cd unifi-analyzer
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8080
```

Open `http://localhost:8080`.

### macOS App

Copy `UniFi Analyzer.app` from `foundry/dist/` to `/Applications/` and double-click. A status window appears in the dock; closing it stops the server.

> To rebuild the macOS app after code changes: `./rebuild_mac_app.sh`

---

## Credentials

The credential bar at the top of every page stores:

| Field | Description |
|---|---|
| Host | UDM IP or hostname |
| Port | API port (default `443`) |
| Site | Site name (default `default`) |
| Username / Password | UniFi admin credentials |
| SSH Port | SSH port (default `22`) |
| UDM SSH Password | Root password for gateway SSH |
| Device SSH Password | Admin password for switch/AP SSH |

Credentials are **auto-saved** whenever you click **Analyze**, **Load Config**, or **Load Interfaces**, and are reloaded automatically on next launch. All passwords are encrypted at rest using AES-128-CBC (Fernet) stored in `~/.unifi-analyzer/config.json`.

---

## Features

### Analyze Tab

Click **Analyze Configuration** to connect to the controller and run a full inspection. Results are grouped by category with color-coded severity badges.

**Severity levels:** 🔴 Critical → 🟠 High → 🟡 Medium → 🔵 Low → ℹ️ Info

| Category | What is checked |
|---|---|
| **Wi-Fi** | WPA3/WPA2 encryption, TKIP detection, PMF (802.11w), 802.11r fast roaming, DTIM period, minimum RSSI thresholds, band steering, hidden SSIDs, channel utilization per radio (>50% warning, >70% critical) |
| **Devices** | Firmware update availability, offline/unadopted devices, TX power (HIGH = interference risk), channel utilization per AP radio |
| **Networks** | Guest VLAN presence, IoT VLAN segregation, DHCP lease time (<3600s), MTU (<1500), IPv6 enablement, VLAN segmentation count |
| **Firewall** | Allow-all rules (no source/destination), disabled orphan rules, logging gaps (>5 accept rules without logging), port forwarding exposure, zone-based policy analysis |
| **Security** | IDS/IPS mode (detection-only vs. prevention), threat management status |
| **DNS** | Public resolver usage (8.8.8.8, 1.1.1.1) — recommends split-DNS or NextDNS |
| **Performance** | Smart Queues / SQM (bufferbloat prevention), hardware offloading |

**Summary tables shown after analysis:**

- **Devices** — Name, IP, MAC, Type, Model, Firmware, Status, Mesh (APs with meshing enabled are flagged with a warning badge)
- **Clients** — Hostname, IP, MAC, Manufacturer, Wired/Wireless, Network, Signal, RX/TX
- **Networks** — Name, Purpose, Subnet, VLAN, Enabled
- **WLANs** — SSID, Security, Band, VLAN, Hidden, Enabled

Suggestions are filterable by severity and searchable by keyword.

---

### Config Lookup Tab

Click **Load Config** to fetch live configuration data from the controller. Data is displayed in 12 section tabs and can be exported to CSV or Excel.

#### Sections

| Section | Columns |
|---|---|
| **Networks** | Name, Purpose, IP Subnet, Enabled |
| **Wi-Fi** | Name, Security, Band, VLAN ID, Hide SSID, Enabled |
| **Firewall Zones** | Name, Networks |
| **Firewall Policies** | Name, Action, Enabled, Protocol, Logging, Src Zone, Dst Zone, Src/Dst Address, Src/Dst Port, Description, Policy ID |
| **Policy Groups** | Name, Type, Count, Members |
| **DNS Records** | Domain, Type, Value, TTL, Enabled, Priority, Weight, Port |
| **Routing** | Name, Type, Enabled, Gateway Type, Network, Next Hop, Distance |
| **Port Forwards** | Name, Enabled, Protocol, Dst Port, Forward, Forward Port, Source, Interface, Destination IP, Logging |
| **Port Profiles** | Name + all profile flag columns |
| **Ports** | Device, Port, Name, Profile, Enabled, Status, Speed, Duplex, Media, POE |
| **Devices** | Name, Model, IP, MAC, Type, State, Uptime |
| **Clients** | Hostname, IP, MAC, Network, Manufacturer, Connection, Uptime |

#### Data Normalizations (applied in tables and exports)

- **Uptime** — Raw seconds → human-readable (`45 sec`, `12 min`, `1h 48m`, `3d 2h`)
- **Port Speed** — Raw Mbps → `10MB`, `100MB`, `1GB`, `10GB`; `0MB` when port is down
- **Port Status** — Boolean `up` → `Up` / `Down`
- **Media** — `2P5GE` → `2.5GE`
- **POE** — null/empty → `off`
- **Profile** — null/empty → `No Profile`
- **Enabled** — Boolean → `Yes` / `No`
- **Device State** — `1` → `Online`, `0` → `Offline`
- **Wired** — Boolean → `Wired` / `Wireless`
- **Hide SSID** — Boolean → `Hidden` / `Visible`

#### Sorting

- All columns are sortable by clicking the header (ascending / descending toggle)
- **IP addresses** sort numerically by octet (not lexicographically)
- **MAC addresses** sort by hex value
- **Names with numbers** sort naturally (`Switch 2` before `Switch 10`)
- **Devices** — UDM/gateway always first, then alphabetically by name
- **Ports** — UDM/gateway ports first, then by device name, then by port number

#### Exports

**Export CSV** — exports the current section as a `.csv` file:
- Filename: `unifi_<section>_<site>.csv`
- Header row in ALL CAPS
- Same column order and value transformations as the table

**Export All to Excel** — exports all 12 sections as a single `.xlsx` workbook:
- Filename: `unifi_config_<site>.xlsx`
- One worksheet per section, named by section
- Header row: orange background, white bold text, ALL CAPS
- Column widths auto-fitted to the longest value (header always considered)
- Same transformations as the table display

---

### Interfaces Tab

Click **Load Interfaces** to SSH into the UDM and all managed switches and APs, enumerate every network interface, and display them in a card grid.

**Per-interface data:**

| Field | Description |
|---|---|
| Name | Interface name (`eth0`, `br10`, `vlan20`, etc.) |
| Type | ethernet, bridge, vlan, wireless, bond, tunnel |
| State | Link up / no link, with color indicator |
| IP Addresses | IPv4 and IPv6 assignments |
| MAC | Hardware address |
| MTU | Maximum transmission unit |
| VLAN | VLAN ID (parsed from name or bridge membership) |
| Network Name | Mapped from UniFi API if a matching VLAN exists |
| RX / TX | Byte counters from `/proc/net/dev` |
| Link Speed | Mbps from `/sys/class/net` |

**Filtering:**
- Search by interface name, IP, or VLAN
- Toggle to show or hide down interfaces
- Device filter chips appear at the top — click a device name to show only its interfaces

Interfaces can be selected for packet capture. The device filter bar is only visible on the Interfaces tab.

---

### PCAP Capture

With interfaces selected on the Interfaces tab, configure and run a capture:

| Option | Description |
|---|---|
| Duration | Seconds to capture (default 30) |
| Packet Count | Optional hard limit |
| BPF Filter | Berkeley Packet Filter expression |
| Description | Label for the capture |
| Max Display Packets | How many packets to show in browser (default 1000) |

**BPF filter examples:**

```
host 192.168.1.50          # Traffic to/from one device
tcp port 443               # HTTPS only
not arp and not icmp       # Exclude noise
src net 192.168.10.0/24    # IoT VLAN outbound
```

**Output options:**
- Preview parsed packets in the PCAP Viewer tab
- Copy AI-formatted text to clipboard (ready for Claude / ChatGPT)
- Download raw `.pcap` file
- Download formatted text report
- Batch capture multiple interfaces → download as `.zip`

**Common UDM interfaces:**

| Interface | Description |
|---|---|
| `eth4` | WAN port (UDM-Pro) |
| `eth0` | WAN1 |
| `br0` | LAN bridge (all wired LAN) |
| `wlan0` | 2.4 GHz radio |
| `wlan1` | 5 GHz radio |

---

### PCAP Viewer Tab

Activated after a capture completes. Displays parsed packet data with:

- Protocol dissection (Ethernet, IPv4/IPv6, TCP/UDP/ICMP, ARP, DNS, DHCP)
- Search and filter by IP, port, or protocol
- Timeline / chronological view
- Export filtered subsets as text or download

---

### Live Logs

Available from the Interfaces tab after interfaces are loaded. Streams system logs from any managed device in real time via SSH (`tail -f`).

**Controls:**

| Control | Description |
|---|---|
| Device selector | Choose any switch, AP, or gateway |
| Plain text filter | Substring match |
| Regex filter | `/pattern/` syntax |
| Errors only | Show only ERROR-level lines |
| Case sensitivity | Toggle |
| Invert filter | Show non-matching lines only |
| Auto-scroll | Scroll to newest entries |
| Pause / Resume | Freeze the stream |
| Clear | Wipe displayed lines |

---

## Supported Controllers & Devices

**Controllers:**
- UniFi Dream Machine (UDM)
- UniFi Dream Machine Pro (UDM-Pro)
- UniFi Dream Machine SE (UDM-SE)
- UniFi Dream Router (UDR)
- Legacy USG-based controllers (auto-detected)

**Managed devices (SSH):**
- UniFi Access Points (UAP, UWA series)
- UniFi Switches (USW, UBB series)
- UniFi Gateways (UXG series)

**Multi-site:** All sections support multiple sites managed by a single controller.

---

## Enabling SSH on UDM

1. In UniFi Network: **Settings → System → SSH**
2. Enable SSH and set a password (or upload a public key)
3. Default username: `root`

---

## Security Notes

- Credentials are encrypted at rest (AES-128-CBC / Fernet) in `~/.unifi-analyzer/config.json`
- Passwords are decrypted in memory only during active use
- The backend connects to the controller with `verify=False` — run on a trusted local network only
- SSH host keys are auto-accepted (appropriate for a trusted LAN)
- Do not expose port 8080 to the internet

---

## Architecture

```
unifi-analyzer/
├── main.py              # FastAPI backend and all API routes
├── unifi_client.py      # UniFi Controller REST API client (session-based auth)
├── config_analyzer.py   # Configuration analysis and suggestion engine
├── pcap_handler.py      # SSH PCAP capture, parser, and AI formatter
├── config_export.py     # Configuration export utilities
├── credentials.py       # AES-encrypted credential storage
├── app_launcher.py      # Entry point for PyInstaller / macOS app
├── requirements.txt     # Python dependencies
├── UnifiAnalyzer.bat    # Windows one-click launcher
├── install.bat          # Windows service installer (run as Administrator)
├── uninstall.bat        # Windows service uninstaller
├── UniFi Analyzer.spec  # PyInstaller build spec
├── rebuild_mac_app.sh   # macOS app rebuild script
├── fix_mac_app.sh       # macOS app fix script
├── images/              # Application icons (ICNS, PNG, SVG)
├── foundry/             # Build artifacts (build/, dist/)
└── static/
    └── index.html       # Single-page application (all UI)
```

### Dependencies

| Package | Purpose |
|---|---|
| `fastapi` | Web framework and API routing |
| `uvicorn` | ASGI server |
| `requests` | HTTP client for UniFi API calls |
| `urllib3` | Connection pooling and SSL handling |
| `paramiko` | SSH client for PCAP capture and interface discovery |
| `pydantic` | Request/response data validation |
| `cryptography` | AES credential encryption |
| `pandas` | Data manipulation for export |
| `openpyxl` | Excel (.xlsx) file generation |
