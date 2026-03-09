"""
PCAP Handler
SSH into UDM and run tcpdump captures; parse the resulting PCAP and format
it as structured text suitable for pasting into an AI assistant.
"""

import io
import json
import re
import shlex
import struct
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

import paramiko


# ---------------------------------------------------------------------------
# SSH / tcpdump capture
# ---------------------------------------------------------------------------

class PcapCapture:
    """SSH into the UDM and run a tcpdump capture, returning raw PCAP bytes."""

    def __init__(self, host: str, username: str, password: Optional[str] = None,
                 key_path: Optional[str] = None, port: int = 22):
        self.host = host
        self.username = username
        self.password = password
        self.key_path = key_path
        self.port = port

    def _build_ssh_client(self, retries: int = 2, retry_delay: float = 3.0) -> paramiko.SSHClient:
        connect_kwargs: dict = dict(
            hostname=self.host,
            port=self.port,
            username=self.username,
            timeout=15,
            allow_agent=False,
            look_for_keys=False,
        )
        if self.key_path:
            connect_kwargs["key_filename"] = self.key_path
        elif self.password:
            connect_kwargs["password"] = self.password

        last_exc: Exception = RuntimeError("SSH connect failed")
        for attempt in range(retries + 1):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(**connect_kwargs)
                return client
            except Exception as exc:
                client.close()
                last_exc = exc
                # Only retry on banner/handshake errors (transient overload)
                if attempt < retries and "banner" in str(exc).lower():
                    time.sleep(retry_delay)
                else:
                    break
        raise last_exc

    def _run(self, client: paramiko.SSHClient, cmd: str, timeout: int = 10) -> str:
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace").strip()

    def fetch_interfaces(self, vlan_map: Optional[dict] = None) -> list:
        """
        SSH into the UDM and enumerate all network interfaces.

        Args:
            vlan_map: Optional dict mapping {vlan_id (int): network_name (str)}
                      from the UniFi API to enrich VLAN subinterfaces.

        Returns list of interface dicts suitable for JSON serialization.
        """
        client = self._build_ssh_client()
        try:
            # Try JSON output first (iproute2 >= 4.12)
            json_out = self._run(client, "ip -j addr show 2>/dev/null")
            if json_out.startswith("["):
                raw_ifaces = json.loads(json_out)
                interfaces = [_parse_ip_json(i) for i in raw_ifaces]
            else:
                text_out = self._run(client, "ip addr show")
                interfaces = _parse_ip_addr_text(text_out)

            # Bridge VLAN membership (may not exist on all models)
            bvlan_out = self._run(client, "bridge vlan show 2>/dev/null")
            bridge_vlans = _parse_bridge_vlans(bvlan_out)

            # Rx/Tx byte counters from /proc/net/dev
            proc_out = self._run(client, "cat /proc/net/dev 2>/dev/null")
            traffic = _parse_proc_net_dev(proc_out)

            for iface in interfaces:
                name = iface["name"]

                # Bridge VLAN memberships
                if name in bridge_vlans:
                    iface["bridge_vlans"] = bridge_vlans[name]

                # VLAN ID from interface name (br0.10, eth8.20, etc.)
                if "." in name:
                    parts = name.rsplit(".", 1)
                    if parts[1].isdigit():
                        iface["vlan_id"] = int(parts[1])
                        iface["parent"] = parts[0]

                # Enrich with UniFi network name
                vid = iface.get("vlan_id")
                if vlan_map and vid and vid in vlan_map:
                    iface["network_name"] = vlan_map[vid]

                # Traffic stats
                if name in traffic:
                    iface["rx_bytes"] = traffic[name]["rx"]
                    iface["tx_bytes"] = traffic[name]["tx"]

            # Supplement: scan /sys/class/net/ for any interfaces ip addr missed,
            # and enrich all interfaces with carrier-based link state, MAC, speed.
            sysfs_out = self._run(client,
                "for i in $(ls /sys/class/net/ 2>/dev/null); do "
                "op=$(cat /sys/class/net/$i/operstate 2>/dev/null); "
                "ca=$(cat /sys/class/net/$i/carrier 2>/dev/null); "
                "mac=$(cat /sys/class/net/$i/address 2>/dev/null); "
                "spd=$(cat /sys/class/net/$i/speed 2>/dev/null); "
                "printf '%s\\t%s\\t%s\\t%s\\t%s\\n' \"$i\" \"$op\" \"$ca\" \"$mac\" \"$spd\"; "
                "done 2>/dev/null")

            # Build a lookup from the sysfs data
            sysfs_info: dict[str, dict] = {}
            for line in sysfs_out.splitlines():
                parts = line.split("\t")
                if not parts or not parts[0]:
                    continue
                sysfs_name = parts[0]
                op = parts[1].strip() if len(parts) > 1 else ""
                carrier = parts[2].strip() if len(parts) > 2 else ""
                mac_addr = parts[3].strip() if len(parts) > 3 else ""
                speed_raw = parts[4].strip() if len(parts) > 4 else ""
                # carrier=1 → physical link up; carrier=0 → no link; empty → unknown
                if carrier == "1":
                    link_state = "up"
                elif carrier == "0":
                    link_state = "down"
                elif op in ("up", "unknown", "dormant"):
                    link_state = "up"
                else:
                    link_state = "down"
                # Speed: kernel reports in Mbps; -1 means unknown/not applicable
                try:
                    speed_mbps = int(speed_raw)
                    link_speed = None if speed_mbps < 0 else speed_mbps
                except (ValueError, TypeError):
                    link_speed = None
                sysfs_info[sysfs_name] = {
                    "state": link_state,
                    "mac": mac_addr,
                    "link_speed": link_speed,
                }

            # Update existing interfaces with carrier-accurate state and speed
            for iface in interfaces:
                si = sysfs_info.get(iface["name"])
                if si:
                    iface["state"] = si["state"]
                    if si["link_speed"] is not None:
                        iface["link_speed"] = si["link_speed"]
                    if not iface.get("mac") and si["mac"]:
                        iface["mac"] = si["mac"]

            # Add any interfaces that ip addr missed
            known_names = {i["name"] for i in interfaces}
            for name, si in sysfs_info.items():
                if name in known_names or name == "lo":
                    continue
                itype = _classify_type(name, [])
                iface = {
                    "name": name,
                    "type": itype,
                    "state": si["state"],
                    "mac": si["mac"],
                    "mtu": 1500,
                    "ips": [],
                    "vlan_id": None,
                    "parent": None,
                    "master": None,
                    "network_name": None,
                    "bridge_vlans": [],
                    "link_speed": si["link_speed"],
                    "rx_bytes": traffic.get(name, {}).get("rx", 0),
                    "tx_bytes": traffic.get(name, {}).get("tx", 0),
                }
                known_names.add(name)
                interfaces.append(iface)

            # Filter and sort
            interfaces = [i for i in interfaces if not _should_skip(i)]
            interfaces.sort(key=_iface_sort_key)
            return interfaces
        finally:
            client.close()

    def _find_capture_tool(self, client: paramiko.SSHClient) -> tuple[str, str]:
        """
        Locate a packet-capture binary on the remote host.
        Returns (tool_type, full_path) where tool_type is 'tcpdump' or 'tshark'.
        Raises RuntimeError if nothing is found.
        """
        # 1. Check well-known absolute paths quickly
        for path in (
            "/usr/sbin/tcpdump",
            "/usr/bin/tcpdump",
            "/sbin/tcpdump",
            "/usr/local/sbin/tcpdump",
            "/usr/local/bin/tcpdump",
        ):
            out = self._run(client, f"test -x '{path}' 2>/dev/null && echo ok")
            if out.strip() == "ok":
                return "tcpdump", path

        # 2. PATH lookup for tcpdump / tshark / dumpcap
        for binary in ("tcpdump", "tshark", "dumpcap"):
            out = self._run(client, f"which {binary} 2>/dev/null")
            if out.strip():
                tool = "tshark" if binary in ("tshark", "dumpcap") else "tcpdump"
                return tool, out.strip()

        # 3. Filesystem search (slower, last resort)
        out = self._run(
            client,
            "find /usr /sbin /bin /opt -maxdepth 5 -type f "
            r"\( -name tcpdump -o -name tshark -o -name dumpcap \) "
            "2>/dev/null | head -1",
            timeout=15,
        )
        if out.strip():
            path = out.strip()
            tool = "tshark" if ("tshark" in path or "dumpcap" in path) else "tcpdump"
            return tool, path

        raise RuntimeError(
            "No packet-capture tool found on this device (tried tcpdump, tshark, dumpcap). "
            "The device may not support packet capture, or the tool may need to be installed."
        )

    def _has_flag(self, client: paramiko.SSHClient, binary: str, flag: str) -> bool:
        """Return True if `binary --help` output mentions `flag`."""
        out = self._run(client, f"{binary} --help 2>&1 | grep -c '{flag}' || true")
        try:
            return int(out.strip()) > 0
        except ValueError:
            return False

    def capture(
        self,
        interface: str = "eth4",
        duration: int = 30,
        packet_count: Optional[int] = None,
        bpf_filter: str = "",
    ) -> bytes:
        """
        Run a packet capture on the remote device and return raw PCAP bytes.
        Supports tcpdump and tshark/dumpcap depending on what is installed.

        Args:
            interface:    Network interface (e.g. eth4=WAN, br0=LAN)
            duration:     Capture duration in seconds (used if packet_count is None)
            packet_count: Stop after N packets
            bpf_filter:   Optional BPF capture filter expression
        """
        client = self._build_ssh_client()
        try:
            tool_type, tool_path = self._find_capture_tool(client)
            iface_q = shlex.quote(interface)

            if tool_type == "tcpdump":
                cmd_parts = [tool_path, "-i", iface_q, "-w", "-"]
                if self._has_flag(client, tool_path, "immediate"):
                    cmd_parts.append("--immediate-mode")
                if packet_count:
                    cmd_parts += ["-c", str(packet_count)]
                if bpf_filter:
                    cmd_parts.append(bpf_filter)
            else:
                # tshark / dumpcap syntax
                cmd_parts = [tool_path, "-i", iface_q, "-w", "-", "-F", "pcap"]
                if packet_count:
                    cmd_parts += ["-c", str(packet_count)]
                if not packet_count:
                    cmd_parts += ["-a", f"duration:{duration}"]
                if bpf_filter:
                    cmd_parts += ["-f", shlex.quote(bpf_filter)]

            if tool_type == "tcpdump" and not packet_count:
                # Use background-process sleep+kill: compatible with BusyBox and GNU
                inner = " ".join(cmd_parts)
                cmd = f"{inner} & _TD=$!; sleep {duration}; kill $_TD 2>/dev/null; wait $_TD 2>/dev/null"
            else:
                cmd = " ".join(cmd_parts)

            _, stdout, stderr = client.exec_command(cmd, timeout=duration + 60)
            pcap_bytes = stdout.read()
            err_text = stderr.read().decode("utf-8", errors="replace").strip()

            if len(pcap_bytes) < 24:
                detail = f"{tool_path} produced no output."
                if err_text:
                    detail += f" Remote error: {err_text}"
                else:
                    detail += f" Interface '{interface}' may not exist on this device."
                raise RuntimeError(detail)

            return pcap_bytes
        finally:
            client.close()


# ---------------------------------------------------------------------------
# Interface discovery helpers
# ---------------------------------------------------------------------------

def _classify_type(name: str, flags: list, link_type: str = "") -> str:
    if "LOOPBACK" in flags or name == "lo":
        return "loopback"
    if name.startswith("wlan") or name.startswith("wifi") or name.startswith("ath"):
        return "wireless"
    if "." in name:
        return "vlan"
    if name.startswith("br"):
        return "bridge"
    if name.startswith("bond"):
        return "bond"
    if name.startswith("tun") or name.startswith("tap"):
        return "tunnel"
    if name.startswith("veth") or "@" in name:
        return "virtual"
    if name.startswith("ifb") or name.startswith("dummy"):
        return "internal"
    return "ethernet"


_SKIP_PREFIXES = ("intf", "gre", "mii", "mld", "pd", "sit", "soc", "teql")

def _should_skip(iface: dict) -> bool:
    if iface.get("type") in ("loopback", "virtual", "internal"):
        return True
    name = iface.get("name", "")
    if any(name.startswith(p) for p in _SKIP_PREFIXES):
        return True
    return False


def _iface_sort_key(iface: dict) -> tuple:
    order = {"ethernet": 0, "bridge": 1, "vlan": 2, "wireless": 3, "bond": 4, "tunnel": 5, "other": 9}
    return (order.get(iface.get("type", "other"), 9), iface["name"])


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _parse_ip_json(raw: dict) -> dict:
    """Parse one interface object from `ip -j addr show`."""
    name = raw.get("ifname", "")
    flags = raw.get("flags", [])
    link_type = raw.get("link_type", "")
    # LOWER_UP = physical link; fall back to operstate, then admin UP flag
    operstate = (raw.get("operstate") or "").lower()
    if "LOWER_UP" in flags or operstate == "up":
        state = "up"
    elif operstate in ("unknown", "dormant"):
        state = "up"  # treat unknown as usable
    else:
        state = "down"
    mac = raw.get("address", "")
    mtu = raw.get("mtu", 0)

    ips = []
    for addr in raw.get("addr_info", []):
        family = addr.get("family", "")
        local = addr.get("local", "")
        prefix = addr.get("prefixlen", "")
        scope = addr.get("scope", "")
        if local:
            ips.append({"family": family, "address": f"{local}/{prefix}", "scope": scope})

    itype = _classify_type(name, flags, link_type)
    return {
        "name": name,
        "type": itype,
        "state": state,
        "mac": mac,
        "mtu": mtu,
        "ips": ips,
        "vlan_id": None,
        "parent": None,
        "master": raw.get("master") or None,  # bridge this port is enslaved to
        "network_name": None,
        "bridge_vlans": [],
        "link_speed": None,
        "rx_bytes": 0,
        "tx_bytes": 0,
    }


def _parse_ip_addr_text(text: str) -> list:
    """Parse `ip addr show` plain text output."""
    interfaces = []
    current = None

    for line in text.splitlines():
        # New interface block: "2: eth0: <FLAGS> mtu ..."
        m = re.match(r"^\d+:\s+(\S+?)(?:@\S+)?:\s+<([^>]*)>.*mtu\s+(\d+)", line)
        if m:
            if current:
                interfaces.append(current)
            name = m.group(1)
            flags = [f.strip() for f in m.group(2).split(",")]
            mtu = int(m.group(3))
            state = "up" if "UP" in flags else "down"
            itype = _classify_type(name, flags)
            current = {
                "name": name, "type": itype, "state": state,
                "mac": "", "mtu": mtu, "ips": [],
                "vlan_id": None, "parent": None, "master": None, "network_name": None,
                "bridge_vlans": [], "link_speed": None, "rx_bytes": 0, "tx_bytes": 0,
            }
            continue

        if current is None:
            continue

        # MAC address
        m = re.match(r"\s+link/\S+\s+([0-9a-f:]{17})", line)
        if m:
            current["mac"] = m.group(1)
            continue

        # IPv4 address
        m = re.match(r"\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+).*scope\s+(\S+)", line)
        if m:
            current["ips"].append({"family": "inet", "address": m.group(1), "scope": m.group(2)})
            continue

        # IPv6 address
        m = re.match(r"\s+inet6\s+([0-9a-f:]+/\d+).*scope\s+(\S+)", line)
        if m:
            current["ips"].append({"family": "inet6", "address": m.group(1), "scope": m.group(2)})

    if current:
        interfaces.append(current)

    return interfaces


def _parse_bridge_vlans(text: str) -> dict:
    """
    Parse `bridge vlan show` output.
    Returns {interface_name: [vlan_id, ...]}
    """
    result = {}
    current_port = None

    for line in text.splitlines():
        # Port line: "eth8     1 PVID Egress Untagged"
        m = re.match(r"^(\S+)\s+(\d+)(.*)", line)
        if m:
            current_port = m.group(1)
            vid = int(m.group(2))
            result.setdefault(current_port, [])
            if vid != 1:  # Skip default PVID 1 noise
                result[current_port].append(vid)
        elif current_port:
            # Continuation line: "         10"
            m = re.match(r"^\s+(\d+)", line)
            if m:
                vid = int(m.group(1))
                if vid != 1:
                    result[current_port].append(vid)

    return result


def _parse_proc_net_dev(text: str) -> dict:
    """
    Parse /proc/net/dev for Rx/Tx byte counts.
    Returns {iface: {"rx": int, "tx": int}}
    """
    result = {}
    for line in text.splitlines():
        # Format: "  eth0:  rx_bytes ... tx_bytes ..."
        m = re.match(r"\s*(\S+):\s*(\d+)(?:\s+\d+){7}\s+(\d+)", line)
        if m:
            result[m.group(1).rstrip(":")] = {
                "rx": int(m.group(2)),
                "tx": int(m.group(3)),
            }
    return result


# ---------------------------------------------------------------------------
# Minimal PCAP parser (no scapy dependency)
# ---------------------------------------------------------------------------

PCAP_GLOBAL_HEADER_FMT = "<IHHiIII"
PCAP_GLOBAL_HEADER_SIZE = struct.calcsize(PCAP_GLOBAL_HEADER_FMT)
PCAP_PACKET_HEADER_FMT = "<IIII"
PCAP_PACKET_HEADER_SIZE = struct.calcsize(PCAP_PACKET_HEADER_FMT)

# Link-layer type constants
DLT_EN10MB = 1   # Ethernet
DLT_RAW    = 12  # Raw IPv4/IPv6


@dataclass
class ParsedPacket:
    index: int
    timestamp: float
    length: int
    captured_length: int
    eth_src: str = ""
    eth_dst: str = ""
    ip_src: str = ""
    ip_dst: str = ""
    ip_proto: str = ""
    ip_ttl: int = 0
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: str = ""
    payload_preview: str = ""
    raw_layers: list[str] = field(default_factory=list)

    def to_text(self) -> str:
        lines = [
            f"--- Packet #{self.index} ---",
            f"  Time     : {_format_ts(self.timestamp)}",
            f"  Length   : {self.length} bytes (captured: {self.captured_length})",
        ]
        if self.eth_src:
            lines.append(f"  Ethernet : {self.eth_src} -> {self.eth_dst}")
        if self.ip_src:
            port_src = f":{self.src_port}" if self.src_port is not None else ""
            port_dst = f":{self.dst_port}" if self.dst_port is not None else ""
            lines.append(f"  IP       : {self.ip_src}{port_src} -> {self.ip_dst}{port_dst}  proto={self.ip_proto}  TTL={self.ip_ttl}")
        if self.tcp_flags:
            lines.append(f"  TCP Flags: {self.tcp_flags}")
        if self.payload_preview:
            lines.append(f"  Payload  : {self.payload_preview}")
        return "\n".join(lines)


def _format_ts(ts: float) -> str:
    import datetime
    dt = datetime.datetime.utcfromtimestamp(ts)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond:06d} UTC"


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _parse_tcp_flags(flags_byte: int) -> str:
    names = []
    if flags_byte & 0x01: names.append("FIN")
    if flags_byte & 0x02: names.append("SYN")
    if flags_byte & 0x04: names.append("RST")
    if flags_byte & 0x08: names.append("PSH")
    if flags_byte & 0x10: names.append("ACK")
    if flags_byte & 0x20: names.append("URG")
    if flags_byte & 0x40: names.append("ECE")
    if flags_byte & 0x80: names.append("CWR")
    return " | ".join(names) if names else "none"


def _proto_name(proto: int) -> str:
    return {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
            50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP"}.get(proto, str(proto))


def _parse_ipv4(data: bytes, pkt: ParsedPacket, offset: int = 0):
    if len(data) < offset + 20:
        return
    ihl = (data[offset] & 0x0F) * 4
    proto = data[offset + 9]
    pkt.ip_ttl = data[offset + 8]
    pkt.ip_src = socket.inet_ntoa(data[offset + 12: offset + 16])
    pkt.ip_dst = socket.inet_ntoa(data[offset + 16: offset + 20])
    pkt.ip_proto = _proto_name(proto)
    pkt.raw_layers.append("IPv4")
    _parse_transport(data, pkt, offset + ihl, proto)


def _parse_ipv6(data: bytes, pkt: ParsedPacket, offset: int = 0):
    if len(data) < offset + 40:
        return
    next_hdr = data[offset + 6]
    pkt.ip_src = socket.inet_ntop(socket.AF_INET6, data[offset + 8: offset + 24])
    pkt.ip_dst = socket.inet_ntop(socket.AF_INET6, data[offset + 24: offset + 40])
    pkt.ip_ttl = data[offset + 7]  # hop limit
    pkt.ip_proto = _proto_name(next_hdr)
    pkt.raw_layers.append("IPv6")
    _parse_transport(data, pkt, offset + 40, next_hdr)


def _parse_transport(data: bytes, pkt: ParsedPacket, offset: int, proto: int):
    if proto == 6 and len(data) >= offset + 20:  # TCP
        pkt.src_port = struct.unpack(">H", data[offset: offset + 2])[0]
        pkt.dst_port = struct.unpack(">H", data[offset + 2: offset + 4])[0]
        data_offset = ((data[offset + 12] >> 4) & 0xF) * 4
        flags = data[offset + 13]
        pkt.tcp_flags = _parse_tcp_flags(flags)
        pkt.raw_layers.append("TCP")
        payload = data[offset + data_offset:]
        if payload:
            pkt.payload_preview = _safe_preview(payload)
    elif proto == 17 and len(data) >= offset + 8:  # UDP
        pkt.src_port = struct.unpack(">H", data[offset: offset + 2])[0]
        pkt.dst_port = struct.unpack(">H", data[offset + 2: offset + 4])[0]
        pkt.raw_layers.append("UDP")
        payload = data[offset + 8:]
        if payload:
            pkt.payload_preview = _safe_preview(payload)
    elif proto == 1:  # ICMP
        pkt.raw_layers.append("ICMP")
    elif proto == 58:  # ICMPv6
        pkt.raw_layers.append("ICMPv6")


def _safe_preview(data: bytes, max_len: int = 64) -> str:
    """Show printable ASCII or hex preview."""
    printable = bytes(b if 32 <= b < 127 else ord('.') for b in data[:max_len])
    text = printable.decode("ascii", errors="replace")
    if len(data) > max_len:
        text += f"... (+{len(data) - max_len} bytes)"
    return text


def parse_pcap(raw: bytes) -> tuple[dict, list[ParsedPacket]]:
    """
    Parse raw PCAP bytes into a list of ParsedPacket objects.
    Returns (file_info, packets).
    """
    buf = io.BytesIO(raw)

    # Global header
    gh_raw = buf.read(PCAP_GLOBAL_HEADER_SIZE)
    if len(gh_raw) < PCAP_GLOBAL_HEADER_SIZE:
        raise ValueError("Truncated PCAP global header")

    magic, vmaj, vmin, thiszone, sigfigs, snaplen, network = struct.unpack(
        PCAP_GLOBAL_HEADER_FMT, gh_raw
    )
    if magic not in (0xA1B2C3D4, 0xD4C3B2A1):
        raise ValueError(f"Not a valid PCAP file (magic={magic:#010x})")

    file_info = {
        "version": f"{vmaj}.{vmin}",
        "snaplen": snaplen,
        "link_type": network,
        "link_type_name": {DLT_EN10MB: "Ethernet", DLT_RAW: "Raw IP"}.get(network, f"DLT_{network}"),
    }

    packets: list[ParsedPacket] = []
    index = 1

    while True:
        ph_raw = buf.read(PCAP_PACKET_HEADER_SIZE)
        if len(ph_raw) < PCAP_PACKET_HEADER_SIZE:
            break

        ts_sec, ts_usec, caplen, origlen = struct.unpack(PCAP_PACKET_HEADER_FMT, ph_raw)
        frame = buf.read(caplen)
        if len(frame) < caplen:
            break

        timestamp = ts_sec + ts_usec / 1_000_000.0
        pkt = ParsedPacket(index=index, timestamp=timestamp, length=origlen, captured_length=caplen)

        try:
            if network == DLT_EN10MB:
                if len(frame) >= 14:
                    pkt.eth_dst = _mac(frame[0:6])
                    pkt.eth_src = _mac(frame[6:12])
                    pkt.raw_layers.append("Ethernet")
                    etype = struct.unpack(">H", frame[12:14])[0]
                    if etype == 0x0800:
                        _parse_ipv4(frame, pkt, 14)
                    elif etype == 0x86DD:
                        _parse_ipv6(frame, pkt, 14)
                    elif etype == 0x0806:
                        pkt.raw_layers.append("ARP")
            elif network == DLT_RAW:
                if frame and (frame[0] >> 4) == 4:
                    _parse_ipv4(frame, pkt, 0)
                elif frame and (frame[0] >> 4) == 6:
                    _parse_ipv6(frame, pkt, 0)
        except Exception:
            pass  # Best-effort parsing

        packets.append(pkt)
        index += 1

    return file_info, packets


# ---------------------------------------------------------------------------
# Text formatter for AI
# ---------------------------------------------------------------------------

def format_pcap_for_ai(
    raw_pcap: bytes,
    description: str = "",
    interface: str = "",
    max_packets: int = 500,
) -> str:
    """
    Parse a PCAP and return a structured text block ready to paste into an AI.
    """
    try:
        file_info, packets = parse_pcap(raw_pcap)
    except ValueError as e:
        return f"[ERROR] Could not parse PCAP: {e}"

    total = len(packets)
    shown = packets if not max_packets else packets[:max_packets]

    lines = [
        "=" * 70,
        "PACKET CAPTURE ANALYSIS",
        "=" * 70,
    ]
    if description:
        lines.append(f"Description : {description}")
    if interface:
        lines.append(f"Interface   : {interface}")
    lines += [
        f"PCAP Version: {file_info['version']}",
        f"Link Type   : {file_info['link_type_name']}",
        f"Snap Length : {file_info['snaplen']}",
        f"Total Pkts  : {total}" + (f" (showing first {max_packets})" if max_packets and total > max_packets else ""),
        "",
    ]

    # Protocol summary
    proto_counts: dict[str, int] = {}
    src_ips: dict[str, int] = {}
    dst_ips: dict[str, int] = {}
    conversations: dict[tuple, int] = {}

    for p in packets:
        if p.ip_proto:
            proto_counts[p.ip_proto] = proto_counts.get(p.ip_proto, 0) + 1
        if p.ip_src:
            src_ips[p.ip_src] = src_ips.get(p.ip_src, 0) + 1
        if p.ip_dst:
            dst_ips[p.ip_dst] = dst_ips.get(p.ip_dst, 0) + 1
        if p.ip_src and p.ip_dst:
            key = (p.ip_src, p.ip_dst, p.ip_proto)
            conversations[key] = conversations.get(key, 0) + 1

    lines.append("--- Protocol Summary ---")
    for proto, cnt in sorted(proto_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {proto:<10} {cnt} packets")

    lines.append("")
    lines.append("--- Top Talkers (Source IPs) ---")
    for ip, cnt in sorted(src_ips.items(), key=lambda x: -x[1])[:10]:
        lines.append(f"  {ip:<40} {cnt} packets")

    lines.append("")
    lines.append("--- Top Conversations ---")
    for (src, dst, proto), cnt in sorted(conversations.items(), key=lambda x: -x[1])[:10]:
        lines.append(f"  {src:<20} -> {dst:<20}  {proto:<8} {cnt} pkts")

    lines.append("")
    lines.append("--- Packet Details ---")
    for pkt in shown:
        lines.append("")
        lines.append(pkt.to_text())

    if max_packets and total > max_packets:
        lines.append("")
        lines.append(f"[Truncated: {total - max_packets} additional packets not shown]")

    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF CAPTURE")
    lines.append("=" * 70)

    return "\n".join(lines)


# fmt_bytes exposed for templates
fmt_bytes = _fmt_bytes
