"""Unit tests for Stage 2C NetworkCollector, address decoding, and UID attribution."""

import pytest
from analyzers.network.collector import (
    NetworkCollector,
    decode_address,
    decode_ipv4,
    decode_ipv6,
    decode_port,
)
from analyzers.network.models import NetworkAttributionStatus


def test_decode_ipv4():
    # Little-endian 127.0.0.1
    assert decode_ipv4("0100007F") == "127.0.0.1"
    # Little-endian 10.0.2.2
    assert decode_ipv4("0202000A") == "10.0.2.2"
    # Little-endian 0.0.0.0
    assert decode_ipv4("00000000") == "0.0.0.0"
    # Little-endian 192.168.1.100 -> C0 A8 01 64 -> 6401A8C0
    assert decode_ipv4("6401A8C0") == "192.168.1.100"


def test_decode_ipv6():
    # IPv6 loopback ::1
    assert decode_ipv6("00000000000000000000000001000000") == "::1"
    # IPv4-mapped IPv6 for 10.0.2.2
    assert decode_ipv6("0000000000000000FFFF00000202000A") == "10.0.2.2"


def test_decode_port():
    assert decode_port("0050") == 80
    assert decode_port("1F90") == 8080
    assert decode_port("01BB") == 443
    assert decode_port("223D") == 8765


def test_decode_address():
    ip, port = decode_address("0202000A:223D")
    assert ip == "10.0.2.2"
    assert port == 8765


def test_parse_proc_net_content_target_attribution():
    """Verifies that sockets with matching UID are ATTRIBUTED and non-matching are NOT_ATTRIBUTED."""
    raw_proc_net = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  10228        0 12345 1 0 100 0 0 10 0
   1: 0202000A:CE12 0202000A:0050 01 00000000:00000000 00:00000000 00000000  10228        0 12346 1 0 100 0 0 10 0
   2: 0100007F:D001 0100007F:0035 01 00000000:00000000 00:00000000 00000000   1000        0 54321 1 0 100 0 0 10 0
   3: 0202000A:E123 D83AD24A:01BB 01 00000000:00000000 00:00000000 00000000  10045        0 99999 1 0 100 0 0 10 0
"""
    collector = NetworkCollector()
    events = collector.parse_proc_net_content(
        content=raw_proc_net,
        protocol="TCP",
        target_uid=10228,
        target_package="com.spyaware.test",
        target_pids=[9876],
    )

    assert len(events) == 4

    # Event 0: UID 10228 (target app)
    assert events[0].uid == 10228
    assert events[0].attribution_status == NetworkAttributionStatus.ATTRIBUTED
    assert events[0].package_name == "com.spyaware.test"
    assert events[0].pid == 9876
    assert events[0].local_address == "127.0.0.1"
    assert events[0].local_port == 8080

    # Event 1: UID 10228 (target app connecting to port 80)
    assert events[1].uid == 10228
    assert events[1].attribution_status == NetworkAttributionStatus.ATTRIBUTED
    assert events[1].remote_address == "10.0.2.2"
    assert events[1].remote_port == 80
    assert events[1].state == "ESTABLISHED"

    # Event 2: UID 1000 (system_server) -> MUST NOT BE ATTRIBUTED
    assert events[2].uid == 1000
    assert events[2].attribution_status == NetworkAttributionStatus.NOT_ATTRIBUTED
    assert events[2].package_name is None
    assert events[2].pid is None

    # Event 3: UID 10045 (unrelated Google Play Services / Chrome) -> MUST NOT BE ATTRIBUTED
    assert events[3].uid == 10045
    assert events[3].attribution_status == NetworkAttributionStatus.NOT_ATTRIBUTED
    assert events[3].package_name is None


def test_classify_destination_all_categories():
    """Verifies that classify_destination correctly classifies all required IP categories."""
    from analyzers.network.collector import classify_destination
    from analyzers.network.models import DestinationCategory

    # Loopback
    assert classify_destination("127.0.0.1") == DestinationCategory.LOOPBACK
    assert classify_destination("::1") == DestinationCategory.LOOPBACK

    # Emulator Host Gateway
    assert classify_destination("10.0.2.2") == DestinationCategory.EMULATOR_HOST_GATEWAY
    assert classify_destination("10.0.3.2") == DestinationCategory.EMULATOR_HOST_GATEWAY

    # Private network
    assert classify_destination("192.168.1.1") == DestinationCategory.PRIVATE_NETWORK
    assert classify_destination("192.168.0.254") == DestinationCategory.PRIVATE_NETWORK
    assert classify_destination("172.16.0.1") == DestinationCategory.PRIVATE_NETWORK
    assert classify_destination("172.31.255.255") == DestinationCategory.PRIVATE_NETWORK
    assert classify_destination("10.0.2.15") == DestinationCategory.PRIVATE_NETWORK

    # Public Internet
    assert classify_destination("8.8.8.8") == DestinationCategory.PUBLIC_INTERNET
    assert classify_destination("1.1.1.1") == DestinationCategory.PUBLIC_INTERNET
    assert classify_destination("142.250.190.46") == DestinationCategory.PUBLIC_INTERNET
    assert classify_destination("93.184.216.34") == DestinationCategory.PUBLIC_INTERNET

    # Link-local
    assert classify_destination("169.254.1.1") == DestinationCategory.LINK_LOCAL
    assert classify_destination("fe80::1") == DestinationCategory.LINK_LOCAL

    # Multicast
    assert classify_destination("224.0.0.1") == DestinationCategory.MULTICAST
    assert classify_destination("ff02::1") == DestinationCategory.MULTICAST

    # Unspecified
    assert classify_destination("0.0.0.0") == DestinationCategory.UNSPECIFIED
    assert classify_destination("::") == DestinationCategory.UNSPECIFIED

    # Malformed / Unknown
    assert classify_destination("invalid_host") == DestinationCategory.UNKNOWN
    assert classify_destination("999.999.999.999") == DestinationCategory.UNKNOWN
    assert classify_destination("") == DestinationCategory.UNKNOWN
    assert classify_destination(None) == DestinationCategory.UNKNOWN


def test_aggregate_socket_samples_deduplication():
    """Verifies that 10 raw samples of the same socket are aggregated into 1 distinct connection with samples_count=10."""
    from analyzers.network.collector import aggregate_socket_samples
    from analyzers.network.models import NetworkEvent

    samples = [
        NetworkEvent(
            timestamp=1000.0 + i * 0.5,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=45678,
            remote_address="10.0.2.2",
            remote_port=8765,
            uid=10229,
            state="ESTABLISHED",
            connection_id="TCP:10.0.2.15:45678->10.0.2.2:8765:uid=10229",
            samples_count=1,
        )
        for i in range(10)
    ]

    aggregated = aggregate_socket_samples(samples)
    assert len(aggregated) == 1
    assert aggregated[0].samples_count == 10
    assert aggregated[0].local_port == 45678
    assert aggregated[0].remote_port == 8765


def test_aggregate_socket_samples_distinct_connections():
    """Verifies that distinct connections with different local ephemeral ports remain separate."""
    from analyzers.network.collector import aggregate_socket_samples
    from analyzers.network.models import NetworkEvent

    distinct_events = [
        NetworkEvent(
            timestamp=1000.0,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=45670 + i,
            remote_address="10.0.2.2",
            remote_port=8765,
            uid=10229,
            state="ESTABLISHED",
            connection_id=f"TCP:10.0.2.15:{45670 + i}->10.0.2.2:8765:uid=10229",
            samples_count=1,
        )
        for i in range(3)
    ]

    aggregated = aggregate_socket_samples(distinct_events)
    assert len(aggregated) == 3
    assert {e.local_port for e in aggregated} == {45670, 45671, 45672}

