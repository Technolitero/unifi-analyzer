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

The installer prompts for an HTTP port (default `8080`, must be 1–65535). The service starts automatically at boot. Logs are at `C:\Program Files\UnifiAnalyzer\logs\`.

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

Click **Analyze Configuration** to connect to the controller and run a full inspection.

#### Layout

Results are structured in two panels:

- **Network** — stat cards for Devices, Clients, Networks, and WLANs with a detail drawer per card
- **Security & Suggestions** — security summary panel followed by all suggestions; filterable by severity and searchable by keyword

#### Security Summary Panel

| Element | Description |
|---|---|
| **Hardening badges** | Green checkmarks for each best-practice that is confirmed active (e.g. IPS enabled, DNS filtering on, hardware offloading on) |
| **Critical count** | Number of critical-severity suggestions |
| **Recommended count** | Combined high + medium suggestions |
| **Informational count** | Combined low + info suggestions |

#### Severity Levels

🔴 Critical → 🟠 High → 🟡 Medium → 🔵 Low → ℹ️ Info

#### Checks Performed

| Category | What is checked |
|---|---|
| **Wi-Fi** | WPA3/WPA2 encryption, TKIP detection, PMF (802.11w), 802.11r fast roaming, DTIM period, minimum RSSI thresholds, band steering enabled/disabled, BSS Transition (802.11v) enabled/disabled, hidden SSIDs, high client density (>30 clients/AP), channel utilization per radio (>50% warning, >70% critical) |
| **Devices** | Firmware update availability, offline/unadopted devices, TX power (HIGH = interference risk), channel utilization per AP radio, firmware versions (informational — lists all managed devices and their current firmware) |
| **Networks** | Guest VLAN presence, IoT VLAN segregation, Management VLAN presence, DHCP lease time (<3600s), MTU (<1500), IPv6 enablement, VLAN segmentation count, Proxy ARP on guest/IoT networks, IGMP snooping disabled |
| **Firewall** | Allow-all rules (no source/destination), disabled orphan rules, logging gaps (>5 accept rules without logging), port forwarding exposure, zone-based policy analysis |
| **Security** | IDS/IPS mode — detection-only vs. prevention (critical if off, informational if active with hardening badge); DNS filtering status (informational with hardening badge if on) |
| **Performance** | Smart Queues / SQM — bufferbloat prevention (informational with hardening badge if on); hardware offloading (informational with hardening badge if on) |
| **System** | SSH access status (always informational — reports enabled/disabled state and whether password auth is allowed); syslog server configuration (informational with hardening badge if configured); NTP server configuration (informational — lists all configured servers; critical if unconfigured); auto-update status per device (informational — lists which devices have auto-update enabled, disabled, or unknown) |

> **Passing checks are always visible.** When a setting is correctly configured, it appears as an informational suggestion confirming the active status rather than being silently ignored.

#### Summary Tables

Shown beneath the suggestions:

- **Devices** — Name, IP, MAC, Type, Model, Firmware, Status, Mesh
- **Clients** — Hostname, IP, MAC, Manufacturer, Wired/Wireless, Network, Signal, RX/TX
- **Networks** — Name, Purpose, Subnet, VLAN, Enabled
- **WLANs** — SSID, Security, Band, VLAN, Hidden, Enabled

---

### Config Lookup Tab

Click **Load Config** to fetch live configuration data from the controller. The section tab bar is hidden until a config is successfully loaded. Data is displayed in 12 section tabs and can be exported to Excel.

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
| **Devices** | Name, Model, Firmware, IP, MAC, Type, State, Uptime |
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

**Export Excel** — exports the current section as a single-sheet `.xlsx` file:
- Filename: `{UDM name}-{datetime}-{section}.xlsx`
- Header row: orange background, white bold text, ALL CAPS
- Column widths auto-fitted to the longest value

**Export All to Excel** — exports all 12 sections as a single `.xlsx` workbook:
- Filename: `{UDM name}-{datetime}-config.xlsx`
- One worksheet per section, named by section
- Header row: orange background, white bold text, ALL CAPS
- Column widths auto-fitted to the longest value
- Same transformations as the table display

**Save to History** — saves the full 12-section Excel workbook to the `history/` directory on the server. The button grays out after saving and re-activates when a new config is loaded via **Load Config**. Saved exports are accessible from the **History tab**.

---

### Interfaces Tab

Click **Load Interfaces** to SSH into the UDM and all managed switches and APs, enumerate every network interface, and display them in a sortable table.

**Per-interface data:**

| Field | Description |
|---|---|
| Device | Device name hosting the interface |
| Interface | Interface name (`eth0`, `br10`, `vlan20`, etc.) |
| Type | ethernet, bridge, vlan, wireless, bond, tunnel |
| State | Link up / no link, with color indicator |
| IP Addresses | IPv4 and IPv6 assignments |
| VLAN | VLAN ID (parsed from name or bridge membership) |
| Network | Mapped from UniFi API if a matching VLAN exists |
| MAC | Hardware address |
| MTU | Maximum transmission unit |
| Speed | Link speed in Mbps |
| RX / TX | Byte counters from `/proc/net/dev` |

**Interface highlighting:**
- Interfaces available for packet capture are highlighted in blue and are selectable
- Non-capturable interfaces are displayed but cannot be selected
- Down interfaces are dimmed and non-selectable

**Connected devices** (shown inline per interface):
- Displays connected client hostnames (with IP) in an expandable dropdown
- Shows count of connected clients; click to expand the full list
- Uplinked switches and APs are discovered via reverse uplink lookup

**Filtering:**
- Search by interface name, IP, or VLAN
- Toggle to show or hide down interfaces
- Device filter chips at the top — click a device name to show only its interfaces

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

**Viewer toolbar buttons:**

| Button | Description |
|---|---|
| **Copy to Clipboard** | Copies AI-formatted packet text (ready for Claude / ChatGPT) |
| **Download Text** | Downloads the formatted text report |
| **Download Raw PCAP** | Downloads the original binary `.pcap` file (shown only when raw data is available) |
| **Save to History** | Saves the raw `.pcap` to the History tab using the naming convention `{UDM name}-{interface}-{timestamp}.pcap`. Grays out permanently after saving; resets when a new capture is loaded. |
| **View in PCAP tab** | Switches to the PCAP Capture tab |

---

### History Tab

Stores and manages saved exports from both the **Config Lookup** and **PCAP Viewer** tabs. The History tab contains two independent sections.

#### Config Exports Section

Manages saved full-configuration Excel workbooks.

##### Saving

Click **Save to History** in the Config Lookup export toolbar to save the current 12-section Excel workbook to the `history/` directory. The button grays out after saving and re-activates when a new config is loaded.

##### History Table

| Column | Description |
|---|---|
| Filename | Export file name including UDM name and timestamp |
| Saved At | Date and time the export was saved |
| Size | File size (KB / MB) |
| Actions | Per-row Download and Delete buttons |

##### Bulk Actions

Select one or more exports using the checkboxes (or **Select All**) to enable:

| Button | Behavior |
|---|---|
| **Compare Selected** | Compares all selected files against the most recent export and downloads a color-coded Excel diff report |
| **Download Selected** | Downloads a single `.xlsx` if one file is selected; downloads a `.zip` archive if multiple files are selected |
| **Delete Selected** | Permanently deletes all selected exports (with confirmation prompt) |

##### Compare Report Format

The comparison report is an Excel workbook downloaded as `comparison-{timestamp}.xlsx`:

- **Summary sheet** — pivoted view with sections as rows and each compared file as a column; cells show `"3 added, 2 removed"` or `"No changes"`
- **One diff sheet per section** that has any differences — contains all differing rows plus one `"vs {filename}"` status column per compared file
  - 🟢 Green row — record exists in the latest export but not in that older file (added)
  - 🔴 Red row — record existed in the older file but is absent from the latest (removed)
  - 🟡 Yellow row — record status is mixed across compared files

#### PCAP Captures Section

Manages raw `.pcap` files saved from the PCAP Viewer.

##### Saving

Click **Save to History** in the PCAP Viewer toolbar after a capture completes. The button grays out permanently after saving and resets when a new capture is loaded.

Files are named: `{UDM name}-{interface}-{timestamp}.pcap`

##### PCAP History Table

| Column | Description |
|---|---|
| Filename | Capture file name including UDM name, interface, and timestamp |
| Saved At | Date and time the capture was saved |
| Size | File size (KB / MB) |
| Actions | Per-row Download and Delete buttons |

##### Bulk Actions

Select one or more captures using the checkboxes (or **Select All**) to enable:

| Button | Behavior |
|---|---|
| **Download Selected** | Downloads a single `.pcap` if one file is selected; downloads a `.zip` archive if multiple files are selected |
| **Delete Selected** | Permanently deletes all selected captures (with confirmation prompt) |

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
- Do not expose the application port to the internet

