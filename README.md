# UniFi UDM Analyzer

A comprehensive local web application that connects to a UniFi Dream Machine (UDM / UDM-Pro / UDM-SE) to provide deep network analysis, configuration insights, packet capture, and device management capabilities.

---

## Requirements

- **Python 3.11+** (3.8+ for Windows service installation)
- **Windows 10/11** (for service installation) or **macOS/Linux** (for source installation)
- A UniFi Dream Machine (UDM, UDM-Pro, UDM-SE, or UDR) running UniFi OS
- SSH access enabled on the UDM (for PCAP capture)

---

## Installation

### Python Installation

1. **Set up a virtual environment** (recommended):
   ```bash
   cd unifi-analyzer
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### Windows Service Installation

For Windows users, you can install the UniFi Analyzer as a Windows service that starts automatically with the system:

1. **Run the installer as Administrator**:
   ```cmd
   install.bat
   ```

   This will:
   - Install the application to `C:\Program Files\UnifiAnalyzer`
   - Create a virtual environment and install all dependencies
   - Register the application as a Windows service
   - Start the service automatically

2. **Access the application** at `http://localhost:8080`

3. **Uninstall** (also requires Administrator):
   ```cmd
   uninstall.bat
   ```

   > **Note**: The installer requires Python 3.8+ and internet access to download NSSM (service manager). Service logs are available at `C:\Program Files\UnifiAnalyzer\logs\`.

### Mac App Installation

A macOS app bundle has been created for easy installation.

1. Locate the `UniFi Analyzer.app` file in the `foundry/dist/` directory.
2. Copy `UniFi Analyzer.app` to your `/Applications/` folder.
3. Double-click `UniFi Analyzer.app` to launch the application. It will start the web server and open your browser to `http://localhost:8080`.

   The app features a custom network-themed icon showing a router with antennas, WiFi signals, and network cables.

> **To rebuild the Mac app with the latest changes:**
> ```bash
> ./rebuild_mac_app.sh
> ```

> **Known Issue**: If the app opens multiple browser tabs and doesn't connect, this is due to a development reload mode being enabled in the packaged app.
>
> **Quick Fix**: Run the fix script:
> ```bash
> chmod +x fix_mac_app.sh
> ./fix_mac_app.sh
> ```
> Then follow the on-screen instructions to replace the broken executable with the fixed one.
>
> **Alternative**: Use the Python source installation method above, which doesn't have this issue.

---

## Running

### As a Windows Service

If installed as a Windows service (see Installation above), the application starts automatically with Windows and runs at `http://localhost:8080`.

### From Source

1. **Activate the virtual environment** (if not already active):
   ```bash
   cd unifi-analyzer
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. **Start the web server**:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8080 --reload
   ```

3. **Open your browser** to **http://localhost:8080**.

### From Mac App

Double-click `UniFi Analyzer.app` in `/Applications/`.

---

## Features

### 🔍 Configuration Analysis

Enter your UDM's IP, port (default 443), site name (default `default`), and your UniFi admin credentials. The analyzer performs comprehensive checks across multiple categories:

| Category | Checks |
|---|---|
| **WiFi** | WPA3/WPA2 encryption, TKIP/AES modes, PMF (802.11w), 802.11r fast roaming, DTIM periods, hidden SSIDs, minimum RSSI thresholds, band steering |
| **Devices** | Firmware updates, device connectivity status, channel utilization (>70% warnings), TX power settings, adoption state |
| **Networks** | Guest VLAN presence, IoT VLAN segregation, DHCP lease times, MTU settings, IPv6 configuration, VLAN segmentation |
| **Firewall** | Allow-all rules detection, disabled rules cleanup, logging configuration, port forwarding security review |
| **Security** | IDS/IPS mode (detection vs prevention), threat management status |
| **DNS** | Public resolver usage (8.8.8.8, 1.1.1.1), split-DNS recommendations |
| **Performance** | Smart Queues/SQM (bufferbloat prevention), hardware offloading status |

Suggestions are color-coded by severity: **🔴 Critical → 🟠 High → 🟡 Medium → 🔵 Low → ℹ️ Info**.

### 📡 PCAP Capture & Analysis

SSH into your UDM (default user: `root`) to run `tcpdump` captures with advanced filtering and AI-ready formatting:

- **Packet Parsing**: Ethernet, IPv4/IPv6, TCP/UDP/ICMP, ARP, DNS, DHCP
- **Traffic Analysis**: Protocol distribution, top talkers, conversation flows
- **AI Integration**: Formatted output ready to paste into Claude, ChatGPT, or any AI assistant
- **Download Options**: Raw PCAP files or formatted text reports
- **Batch Operations**: Capture multiple interfaces simultaneously and download as ZIP

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

### 🔧 Config Lookup

Comprehensive configuration export and lookup tool that fetches all UniFi controller data:

- **Complete Export**: Networks, WLANs, devices, clients, firewall rules, port forwards, routing, DNS records
- **Firewall Analysis**: Zone-based rules, policies, groups, and legacy rules
- **Device Inventory**: APs, switches, gateways with firmware and connectivity status
- **Client Details**: Connected devices with IP, MAC, network assignment, and connection type
- **Policy Groups**: Firewall group definitions and member management

### 🌐 Interface Discovery

Advanced network interface enumeration across your entire UniFi network:

- **Multi-Device Scanning**: SSH into UDM, switches, and APs simultaneously
- **Interface Details**: Name, type, state, MAC address, IP assignments, VLAN membership
- **Traffic Statistics**: Real-time RX/TX byte counters, link speeds
- **VLAN Mapping**: Automatic VLAN ID to network name correlation
- **Hardware Insights**: Bridge VLAN memberships, link aggregation status

### 👁️ PCAP Viewer

Interactive packet analysis interface for captured PCAP files:

- **Packet Inspection**: Detailed protocol dissection with expandable layers
- **Search & Filter**: Find specific packets by IP, port, protocol, or content
- **Timeline View**: Chronological packet flow visualization
- **Export Options**: Filtered PCAP subsets or formatted reports

### 📋 Live Logs

Real-time log streaming from any managed UniFi device:

- **SSH-Based Streaming**: Connect via SSH and stream logs using `tail -f`
- **Multiple Log Sources**: System messages, daemon logs, network events
- **Real-Time Monitoring**: Live updates for troubleshooting and monitoring
- **Device Selection**: Choose any connected switch, AP, or gateway

### 💾 Config Export

Automated UniFi configuration backup and export:

- **Complete Backup**: All controller settings, networks, devices, and policies
- **Structured Output**: JSON format with human-readable timestamps
- **Progress Tracking**: Real-time export progress with detailed logging
- **Archive Management**: Organized file structure with timestamps

### 🛠️ Device Management

Comprehensive device inventory and management:

- **Device Overview**: Model, firmware version, connectivity status, uptime
- **Type Classification**: Gateways, switches, access points with specific details
- **Bulk Operations**: Multi-device firmware checks and status monitoring
- **Topology Insights**: Device relationships and network positioning

### 🔐 Secure Credential Management

Enterprise-grade credential storage and management:

- **AES Encryption**: All credentials encrypted at rest using industry-standard encryption
- **Memory-Only Decryption**: Passwords only decrypted in memory during active use
- **Local Storage**: Credentials stored in `~/.unifi-analyzer/config.json`
- **Multi-Profile Support**: Different credentials for different sites/controllers

---

## Security Notes

- Credentials are **securely stored** locally in `~/.unifi-analyzer/config.json` with AES encryption
- Passwords are encrypted at rest and only decrypted in memory during use
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
├── config_export.py     # UniFi configuration export utilities
├── credentials.py       # Secure credential management
├── app_launcher.py      # Application entry point for PyInstaller
├── requirements.txt     # Python dependencies
├── UniFi Analyzer.spec  # PyInstaller configuration
├── rebuild_mac_app.sh  # Mac app build script
├── fix_mac_app.sh      # Mac app fix script
├── images/              # Application icons and assets
│   ├── network_icon.icns
│   ├── network_icon.png
│   └── network_icon.svg
├── foundry/             # Build artifacts directory
│   ├── build/           # PyInstaller intermediate files
│   └── dist/            # Final application bundles
├── static/              # Web frontend assets
│   └── index.html       # Single-page application
└── __pycache__/         # Python bytecode cache
```

---

## Enabling SSH on UDM

1. In UniFi Network: **Settings → System → SSH**
2. Enable SSH and set a password (or upload an SSH key)
3. Default username is `root`
