"""Network telemetry collector and socket address decoder for Stage 2C.

Collects transport-level socket states from Linux kernel pseudo-files
(/proc/net/tcp, tcp6, udp, udp6) via ADB, decodes little-endian IP addresses
and big-endian ports, and applies strict UID attribution to the target APK.
"""

import ipaddress
import re
import socket
import struct
import subprocess
import time
from typing import Dict, List, Optional, Set, Tuple

from analyzers.network.models import (
    DestinationCategory,
    NetworkAttributionStatus,
    NetworkEvent,
)

TCP_STATES: Dict[str, str] = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def decode_ipv4(hex_addr: str) -> str:
    """Decodes an 8-character little-endian hexadecimal IPv4 address string.
    
    In Linux /proc/net/tcp, 0100007F represents 127.0.0.1.
    """
    if len(hex_addr) != 8:
        return hex_addr
    try:
        ip_int = int(hex_addr, 16)
        return socket.inet_ntoa(struct.pack("<I", ip_int))
    except Exception:
        return hex_addr


def decode_ipv6(hex_addr: str) -> str:
    """Decodes a 32-character hexadecimal IPv6 address string.
    
    Handles IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) and standard IPv6.
    """
    if len(hex_addr) != 32:
        return hex_addr
    try:
        words = [int(hex_addr[i : i + 8], 16) for i in range(0, 32, 8)]
        raw = struct.pack("<4I", *words)
        addr = socket.inet_ntop(socket.AF_INET6, raw)
        if addr.startswith("::ffff:") and "." in addr:
            return addr[7:]  # Return clean IPv4 address for mapped addresses
        return addr
    except Exception:
        return hex_addr


def decode_port(hex_port: str) -> int:
    """Decodes a hexadecimal port string to an integer."""
    try:
        return int(hex_port, 16)
    except Exception:
        return 0


def decode_address(combo: str) -> Tuple[str, int]:
    """Splits and decodes hex IP:PORT pair."""
    parts = combo.split(":")
    if len(parts) != 2:
        return combo, 0
    hex_ip, hex_port = parts
    port = decode_port(hex_port)
    if len(hex_ip) == 8:
        ip = decode_ipv4(hex_ip)
    elif len(hex_ip) == 32:
        ip = decode_ipv6(hex_ip)
    else:
        ip = hex_ip
    return ip, port


def classify_destination(ip_str: str) -> DestinationCategory:
    """Classifies an IP address string into a standard DestinationCategory.

    Explicitly categorizes Android emulator host gateways, loopbacks,
    private subnets, public internet, link-local, multicast, unspecified,
    and unknown/malformed addresses using Python's ipaddress module.
    """
    if not ip_str or not isinstance(ip_str, str):
        return DestinationCategory.UNKNOWN

    clean_ip = ip_str.strip()

    # Special handling for Android emulator host gateways:
    # Standard QEMU/Goldfish Android emulator virtual router host gateway is 10.0.2.2.
    # Genymotion emulator host gateway is 10.0.3.2.
    if clean_ip in ("10.0.2.2", "10.0.3.2"):
        return DestinationCategory.EMULATOR_HOST_GATEWAY

    try:
        ip = ipaddress.ip_address(clean_ip)
    except ValueError:
        return DestinationCategory.UNKNOWN

    if ip.is_loopback:
        return DestinationCategory.LOOPBACK
    if ip.is_unspecified:
        return DestinationCategory.UNSPECIFIED
    if ip.is_multicast:
        return DestinationCategory.MULTICAST
    if ip.is_link_local:
        return DestinationCategory.LINK_LOCAL
    if ip.is_private:
        return DestinationCategory.PRIVATE_NETWORK
    if ip.is_global:
        return DestinationCategory.PUBLIC_INTERNET

    return DestinationCategory.UNKNOWN


def compute_connection_id(
    protocol: str,
    local_address: str,
    local_port: int,
    remote_address: str,
    remote_port: int,
    uid: Optional[int],
) -> str:
    """Computes a stable connection identity string across polling intervals."""
    uid_str = str(uid) if uid is not None else "any"
    return f"{protocol.upper()}:{local_address}:{local_port}->{remote_address}:{remote_port}:uid={uid_str}"


def aggregate_socket_samples(events: List[NetworkEvent]) -> List[NetworkEvent]:
    """Aggregates raw polling samples of identical sockets into distinct connection identities.

    Preserves sample counts and earliest/latest observation context.
    """
    aggregated: Dict[str, NetworkEvent] = {}
    for ev in events:
        key = ev.connection_id or compute_connection_id(
            ev.protocol, ev.local_address, ev.local_port, ev.remote_address, ev.remote_port, ev.uid
        )
        if key not in aggregated:
            ev_copy = ev.model_copy()
            ev_copy.samples_count = ev.samples_count or 1
            aggregated[key] = ev_copy
        else:
            aggregated[key].samples_count += (ev.samples_count or 1)
            if ev.state:
                aggregated[key].state = ev.state
            if ev.http_confirmed is True:
                aggregated[key].http_confirmed = True
                if ev.protocol_evidence:
                    aggregated[key].protocol_evidence = ev.protocol_evidence
    return list(aggregated.values())


class NetworkCollector:
    """Collects and attributes Android socket connections via ADB."""

    def __init__(self):
        self.seen_signatures: Set[Tuple[str, str, int, str, int, Optional[int]]] = set()

    def get_target_uid(
        self,
        adb_path: str,
        package_name: str,
        device_id: Optional[str] = None,
    ) -> Optional[int]:
        """Discovers the dedicated Linux UID assigned to the target application package.
        
        Attempts UID resolution via:
        1. pm list packages -U
        2. dumpsys package <package_name> (userId / appId)
        """
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        # Method 1: pm list packages -U
        try:
            res = subprocess.run(
                base_cmd + ["shell", "pm", "list", "packages", "-U"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            for line in res.stdout.splitlines():
                if f"package:{package_name} " in line or line.strip() == f"package:{package_name}":
                    m = re.search(r"uid:(\d+)", line)
                    if m:
                        return int(m.group(1))
        except (subprocess.SubprocessError, OSError):
            pass

        # Method 2: dumpsys package <package_name>
        try:
            res = subprocess.run(
                base_cmd + ["shell", "dumpsys", "package", package_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            m = re.search(r"(?:userId|appId)=(\d+)", res.stdout)
            if m:
                return int(m.group(1))
        except (subprocess.SubprocessError, OSError):
            pass

        return None

    def get_system_dns(
        self,
        adb_path: str,
        device_id: Optional[str] = None,
    ) -> List[str]:
        """Queries active system DNS resolver addresses from Android getprop."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        dns_servers: List[str] = []
        for prop in ("net.dns1", "net.dns2"):
            try:
                res = subprocess.run(
                    base_cmd + ["shell", "getprop", prop],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                val = res.stdout.strip()
                if val:
                    dns_servers.append(val)
            except (subprocess.SubprocessError, OSError):
                pass
        return dns_servers

    def parse_proc_net_content(
        self,
        content: str,
        protocol: str = "TCP",
        source: str = "/proc/net/tcp",
        timestamp: Optional[float] = None,
        target_uid: Optional[int] = None,
        target_package: Optional[str] = None,
        target_pids: Optional[List[int]] = None,
    ) -> List[NetworkEvent]:
        """Parses the text output of a /proc/net/ socket file into NetworkEvent instances."""
        ts = timestamp if timestamp is not None else time.time()
        events: List[NetworkEvent] = []

        for line in content.splitlines():
            parts = line.strip().split()
            # Must have at least 8 columns: sl, local, rem, st, tx/rx, tr/tm, retrnsmt, uid
            if len(parts) < 8 or parts[0] == "sl":
                continue

            local_str = parts[1]
            remote_str = parts[2]
            st_hex = parts[3]
            uid_str = parts[7]

            local_addr, local_port = decode_address(local_str)
            remote_addr, remote_port = decode_address(remote_str)

            state = TCP_STATES.get(st_hex, st_hex) if protocol == "TCP" else None
            uid = int(uid_str) if uid_str.isdigit() else None

            # Attribution logic
            if target_uid is not None and uid is not None:
                if uid == target_uid:
                    attr_status = NetworkAttributionStatus.ATTRIBUTED
                    pkg_name = target_package
                    confidence = 1.0
                else:
                    attr_status = NetworkAttributionStatus.NOT_ATTRIBUTED
                    pkg_name = None
                    confidence = 1.0
            else:
                attr_status = NetworkAttributionStatus.UNKNOWN
                pkg_name = None
                confidence = 0.5

            pid = target_pids[0] if (attr_status == NetworkAttributionStatus.ATTRIBUTED and target_pids) else None

            evidence_line = f"{protocol} {local_addr}:{local_port} -> {remote_addr}:{remote_port} uid={uid} state={state or 'N/A'}"

            dest_cat = classify_destination(remote_addr)
            conn_id = compute_connection_id(
                protocol=protocol,
                local_address=local_addr,
                local_port=local_port,
                remote_address=remote_addr,
                remote_port=remote_port,
                uid=uid,
            )

            event = NetworkEvent(
                timestamp=ts,
                protocol=protocol,
                local_address=local_addr,
                local_port=local_port,
                remote_address=remote_addr,
                remote_port=remote_port,
                state=state,
                package_name=pkg_name,
                uid=uid,
                pid=pid,
                attribution_status=attr_status,
                source=source,
                evidence=evidence_line,
                confidence=confidence,
                destination_category=dest_cat,
                connection_id=conn_id,
                samples_count=1,
            )
            events.append(event)

        return events

    def poll_proc_net(
        self,
        adb_path: str,
        target_uid: Optional[int] = None,
        target_package: Optional[str] = None,
        target_pids: Optional[List[int]] = None,
        device_id: Optional[str] = None,
    ) -> List[NetworkEvent]:
        """Polls current kernel socket states from /proc/net/ and returns deduplicated events."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        # Capture tcp, tcp6, udp, udp6 in a single round-trip
        cmd = base_cmd + [
            "shell",
            "cat /proc/net/tcp; echo '==SEP=='; cat /proc/net/tcp6; echo '==SEP=='; cat /proc/net/udp; echo '==SEP=='; cat /proc/net/udp6",
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if res.returncode != 0:
                return []
            sections = res.stdout.split("==SEP==")
        except (subprocess.SubprocessError, OSError):
            return []

        ts = time.time()
        all_events: List[NetworkEvent] = []

        files_meta = [
            ("TCP", "/proc/net/tcp"),
            ("TCP", "/proc/net/tcp6"),
            ("UDP", "/proc/net/udp"),
            ("UDP", "/proc/net/udp6"),
        ]

        for i, text in enumerate(sections):
            if i >= len(files_meta):
                break
            proto, src = files_meta[i]
            parsed = self.parse_proc_net_content(
                content=text,
                protocol=proto,
                source=src,
                timestamp=ts,
                target_uid=target_uid,
                target_package=target_package,
                target_pids=target_pids,
            )
            all_events.extend(parsed)

        return all_events
