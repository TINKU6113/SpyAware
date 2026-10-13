"""Comprehensive tests for Stage 2C Target Attribution & Telemetry Isolation.

Verifies the strict target attribution hierarchy:
1. Target Linux UID resolution from package manager
2. Socket attribution strictly based on kernel UID ownership
3. Unrelated emulator traffic (GMS, Chrome, netd) strictly isolated as NOT_ATTRIBUTED
4. Ambient DNS resolver queries reported as NOT_AVAILABLE without per-UID ownership
5. Positive and negative control behavior guarantees
"""

from unittest.mock import MagicMock, patch
import pytest

from analyzers.network.collector import NetworkCollector
from analyzers.network.models import (
    NetworkAttributionStatus,
    NetworkBehaviorCategory,
    NetworkBehaviorStatus,
    NetworkEvent,
)
from analyzers.network.observer import NetworkObserver
from analyzers.network.worker import NetworkWorker


def test_target_uid_resolution_hierarchy():
    """Tests UID discovery via pm list packages -U and fallback to dumpsys package."""
    collector = NetworkCollector()

    # Method 1: pm list packages -U
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="package:com.android.chrome uid:10045\npackage:com.spyaware.target uid:10228\n",
            returncode=0,
        )
        uid = collector.get_target_uid(adb_path="adb", package_name="com.spyaware.target")
        assert uid == 10228

    # Method 2: Fallback to dumpsys package if pm list output doesn't match
    with patch("subprocess.run") as mock_run:
        # First call pm returns nothing, second call dumpsys returns userId=10235
        mock_run.side_effect = [
            MagicMock(stdout="package:com.other uid:10001\n", returncode=0),
            MagicMock(stdout="Package [com.spyaware.fallback] (2991fa):\n    userId=10235\n", returncode=0),
        ]
        uid = collector.get_target_uid(adb_path="adb", package_name="com.spyaware.fallback")
        assert uid == 10235


def test_strict_attribution_kernel_socket_isolation():
    """Tests that matching UID is ATTRIBUTED and all other UIDs are marked NOT_ATTRIBUTED."""
    raw_sockets = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  10229        0 10001 1 0 100 0 0 10 0
   1: 0202000A:223D 0202000A:0050 01 00000000:00000000 00:00000000 00000000  10229        0 10002 1 0 100 0 0 10 0
   2: 0202000A:3333 0202000A:01BB 01 00000000:00000000 00:00000000 00000000   1000        0 10003 1 0 100 0 0 10 0
   3: 0202000A:4444 8EFA0123:01BB 01 00000000:00000000 00:00000000 00000000  10045        0 10004 1 0 100 0 0 10 0
   4: 0202000A:5555 08080808:0035 01 00000000:00000000 00:00000000 00000000   1051        0 10005 1 0 100 0 0 10 0
"""
    collector = NetworkCollector()
    events = collector.parse_proc_net_content(
        content=raw_sockets,
        protocol="TCP",
        target_uid=10229,
        target_package="com.spyaware.positive.network",
        target_pids=[5432],
    )

    assert len(events) == 5

    attributed = [e for e in events if e.attribution_status == NetworkAttributionStatus.ATTRIBUTED]
    unattributed = [e for e in events if e.attribution_status == NetworkAttributionStatus.NOT_ATTRIBUTED]

    assert len(attributed) == 2
    assert len(unattributed) == 3

    # Check attributed events
    for e in attributed:
        assert e.uid == 10229
        assert e.package_name == "com.spyaware.positive.network"
        assert e.pid == 5432
        assert e.confidence == 1.0

    # Check unattributed events (system UID 1000, GMS UID 10045, DNS daemon UID 1051)
    for e in unattributed:
        assert e.uid in (1000, 10045, 1051)
        assert e.package_name is None
        assert e.confidence == 1.0


def test_observer_dns_attribution_limitation():
    """Verifies that ambient system DNS queries without target socket ownership report NOT_AVAILABLE."""
    events = [
        NetworkEvent(
            timestamp=100.0,
            protocol="UDP",
            local_address="10.0.2.15",
            local_port=53535,
            remote_address="8.8.8.8",
            remote_port=53,
            uid=1051,  # system dns resolver daemon
            attribution_status=NetworkAttributionStatus.NOT_ATTRIBUTED,
        )
    ]

    observer = NetworkObserver()
    result = observer.evaluate(
        events=events,
        target_package="com.spyaware.target",
        target_uid=10228,
        duration_seconds=5.0,
    )

    dns_obs = result.observations[NetworkBehaviorCategory.DNS_ACTIVITY.value]
    assert dns_obs.status == NetworkBehaviorStatus.NOT_AVAILABLE.value
    assert "NOT_ATTRIBUTED" in dns_obs.description or "not available" in dns_obs.description.lower()
    assert result.score == 0.0
    assert len(result.findings) == 0


def test_positive_network_control_evaluation():
    """Verifies complete observation matrix when target application performs network exfiltration."""
    events = [
        # Socket 1: Cleartext HTTP connection to external host
        NetworkEvent(
            timestamp=100.0,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=40001,
            remote_address="142.250.190.46",
            remote_port=80,
            uid=10229,
            package_name="com.spyaware.positive.network",
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
            http_confirmed=True,
            protocol_evidence="HTTP/1.1 200 OK verified via test server",
        ),
        # Socket 2: Outbound connection to non-standard port 8765
        NetworkEvent(
            timestamp=101.0,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=40002,
            remote_address="10.0.2.2",
            remote_port=8765,
            uid=10229,
            package_name="com.spyaware.positive.network",
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
        ),
        # Socket 3: Repeated connection to non-standard port 8765
        NetworkEvent(
            timestamp=102.0,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=40003,
            remote_address="10.0.2.2",
            remote_port=8765,
            uid=10229,
            package_name="com.spyaware.positive.network",
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
        ),
    ]

    observer = NetworkObserver()
    result = observer.evaluate(
        events=events,
        target_package="com.spyaware.positive.network",
        target_uid=10229,
        duration_seconds=5.0,
    )

    assert result.status == "COMPLETED"
    assert result.attributed_events_count == 3
    assert result.score > 0.0

    obs = result.observations
    assert obs[NetworkBehaviorCategory.NETWORK_CONNECTION.value].status == NetworkBehaviorStatus.OBSERVED.value
    assert obs[NetworkBehaviorCategory.CLEAR_TEXT_HTTP.value].status == NetworkBehaviorStatus.OBSERVED.value
    assert obs[NetworkBehaviorCategory.EXTERNAL_DESTINATION.value].status == NetworkBehaviorStatus.OBSERVED.value
    assert obs[NetworkBehaviorCategory.REPEATED_CONNECTION.value].status == NetworkBehaviorStatus.OBSERVED.value
    assert obs[NetworkBehaviorCategory.UNUSUAL_PORT.value].status == NetworkBehaviorStatus.OBSERVED.value

    # Check generated findings
    titles = [f.title for f in result.findings]
    assert any("Network Socket Connection" in t for t in titles)
    assert any("Cleartext HTTP" in t for t in titles)
    assert any("Outbound External" in t for t in titles)
    assert any("Repeated" in t for t in titles)
    assert any("Non-Standard" in t for t in titles)


def test_negative_network_control_evaluation():
    """Verifies that an idle application with 0 attributed connections scores 0.0 with 0 findings."""
    events = [
        # Only ambient system traffic
        NetworkEvent(
            timestamp=100.0,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=50000,
            remote_address="142.250.190.46",
            remote_port=443,
            uid=10045,  # GMS
            attribution_status=NetworkAttributionStatus.NOT_ATTRIBUTED,
        )
    ]

    observer = NetworkObserver()
    result = observer.evaluate(
        events=events,
        target_package="com.spyaware.benign",
        target_uid=10228,
        duration_seconds=5.0,
    )

    assert result.status == "NOT_ATTRIBUTED"
    assert result.score == 0.0
    assert result.attributed_events_count == 0
    assert result.unattributed_events_count == 1
    assert len(result.findings) == 0

    obs = result.observations
    assert obs[NetworkBehaviorCategory.NETWORK_CONNECTION.value].status == NetworkBehaviorStatus.NOT_OBSERVED.value
    assert obs[NetworkBehaviorCategory.CLEAR_TEXT_HTTP.value].status == NetworkBehaviorStatus.NOT_OBSERVED.value
    assert obs[NetworkBehaviorCategory.EXTERNAL_DESTINATION.value].status == NetworkBehaviorStatus.NOT_OBSERVED.value
    assert obs[NetworkBehaviorCategory.REPEATED_CONNECTION.value].status == NetworkBehaviorStatus.NOT_OBSERVED.value
    assert obs[NetworkBehaviorCategory.UNUSUAL_PORT.value].status == NetworkBehaviorStatus.NOT_OBSERVED.value
    assert obs[NetworkBehaviorCategory.DNS_ACTIVITY.value].status == NetworkBehaviorStatus.NOT_AVAILABLE.value
