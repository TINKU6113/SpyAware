"""Unit tests for Stage 2C NetworkObserver behavioral matrix and attribution isolation."""

import pytest
from analyzers.network.models import (
    NetworkAttributionStatus,
    NetworkBehaviorCategory,
    NetworkBehaviorStatus,
    NetworkEvent,
)
from analyzers.network.observer import NetworkObserver


def test_observer_negative_control_idle_app():
    """Verifies that an idle application with 0 attributed connections scores 0.0 and NOT_OBSERVED."""
    events = [
        # Ambient system connection (UID 1000)
        NetworkEvent(
            timestamp=1000.0,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=54321,
            remote_address="10.0.2.2",
            remote_port=80,
            uid=1000,
            attribution_status=NetworkAttributionStatus.NOT_ATTRIBUTED,
        ),
        # Ambient DNS query (UID 1051)
        NetworkEvent(
            timestamp=1001.0,
            protocol="UDP",
            local_address="10.0.2.15",
            local_port=43210,
            remote_address="8.8.8.8",
            remote_port=53,
            uid=1051,
            attribution_status=NetworkAttributionStatus.NOT_ATTRIBUTED,
        ),
    ]

    observer = NetworkObserver()
    result = observer.evaluate(
        events=events,
        target_package="com.spyaware.benign",
        target_uid=10228,
        duration_seconds=5.0,
    )

    assert result.score == 0.0
    assert result.risk_level == "LOW"
    assert result.attributed_events_count == 0
    assert result.unattributed_events_count == 2
    assert result.status == "NOT_ATTRIBUTED"
    assert len(result.findings) == 0

    obs = result.observations
    assert obs[NetworkBehaviorCategory.NETWORK_CONNECTION.value].status == NetworkBehaviorStatus.NOT_OBSERVED.value
    assert obs[NetworkBehaviorCategory.CLEAR_TEXT_HTTP.value].status == NetworkBehaviorStatus.NOT_OBSERVED.value
    assert obs[NetworkBehaviorCategory.EXTERNAL_DESTINATION.value].status == NetworkBehaviorStatus.NOT_OBSERVED.value
    assert obs[NetworkBehaviorCategory.REPEATED_CONNECTION.value].status == NetworkBehaviorStatus.NOT_OBSERVED.value
    assert obs[NetworkBehaviorCategory.UNUSUAL_PORT.value].status == NetworkBehaviorStatus.NOT_OBSERVED.value
    # DNS activity without target ownership is NOT_AVAILABLE
    assert obs[NetworkBehaviorCategory.DNS_ACTIVITY.value].status == NetworkBehaviorStatus.NOT_AVAILABLE.value


def test_observer_attributed_cleartext_http():
    """Verifies that attributed cleartext HTTP connection is OBSERVED when confirmed and triggers risk findings."""
    events = [
        NetworkEvent(
            timestamp=1000.0,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=45678,
            remote_address="142.250.190.46",
            remote_port=80,
            package_name="com.spyaware.positive.network",
            uid=10229,
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
            http_confirmed=True,
            protocol_evidence="HTTP/1.1 GET / HTTP/1.1 (200 OK)",
        )
    ]

    observer = NetworkObserver()
    result = observer.evaluate(
        events=events,
        target_package="com.spyaware.positive.network",
        target_uid=10229,
        duration_seconds=5.0,
    )

    assert result.score > 0.0
    assert result.attributed_events_count == 1
    assert result.unattributed_events_count == 0
    assert result.status == "COMPLETED"

    obs = result.observations
    assert obs[NetworkBehaviorCategory.NETWORK_CONNECTION.value].status == NetworkBehaviorStatus.OBSERVED.value
    assert obs[NetworkBehaviorCategory.CLEAR_TEXT_HTTP.value].status == NetworkBehaviorStatus.OBSERVED.value
    assert obs[NetworkBehaviorCategory.EXTERNAL_DESTINATION.value].status == NetworkBehaviorStatus.OBSERVED.value

    # Finding generated for cleartext HTTP
    finding_titles = [f.title for f in result.findings]
    assert any("Cleartext" in t for t in finding_titles)


def test_observer_unusual_port_and_repeated_connections():
    """Verifies that non-standard surveillance C2 port and repeated connections are detected."""
    events = [
        NetworkEvent(
            timestamp=1000.0,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=41111,
            remote_address="142.250.190.46",
            remote_port=8765,
            package_name="com.spyaware.c2",
            uid=10230,
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
        ),
        NetworkEvent(
            timestamp=1002.0,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=41112,
            remote_address="142.250.190.46",
            remote_port=8765,
            package_name="com.spyaware.c2",
            uid=10230,
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
        ),
    ]

    observer = NetworkObserver()
    result = observer.evaluate(
        events=events,
        target_package="com.spyaware.c2",
        target_uid=10230,
        duration_seconds=5.0,
    )

    obs = result.observations
    assert obs[NetworkBehaviorCategory.NETWORK_CONNECTION.value].status == NetworkBehaviorStatus.OBSERVED.value
    assert obs[NetworkBehaviorCategory.UNUSUAL_PORT.value].status == NetworkBehaviorStatus.OBSERVED.value
    assert obs[NetworkBehaviorCategory.REPEATED_CONNECTION.value].status == NetworkBehaviorStatus.OBSERVED.value
    assert obs[NetworkBehaviorCategory.EXTERNAL_DESTINATION.value].status == NetworkBehaviorStatus.OBSERVED.value

    finding_titles = [f.title for f in result.findings]
    assert any("Repeated" in t for t in finding_titles)
    assert any("Non-Standard" in t for t in finding_titles)


def test_observer_port_80_without_http_evidence_is_not_available():
    """Verifies that connecting to port 80 without application-layer HTTP evidence reports NOT_AVAILABLE."""
    events = [
        NetworkEvent(
            timestamp=1000.0,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=45678,
            remote_address="10.0.2.2",
            remote_port=80,
            package_name="com.spyaware.test",
            uid=10229,
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
            http_confirmed=None,  # Unverified
        )
    ]

    observer = NetworkObserver()
    result = observer.evaluate(events=events, target_package="com.spyaware.test", target_uid=10229)

    obs = result.observations[NetworkBehaviorCategory.CLEAR_TEXT_HTTP.value]
    assert obs.status == NetworkBehaviorStatus.NOT_AVAILABLE.value
    assert "cannot be confirmed without payload inspection" in obs.description
    # Must NOT generate a High-severity cleartext HTTP finding
    assert not any("Cleartext HTTP" in f.title for f in result.findings)


def test_observer_port_8765_without_http_evidence_is_not_available():
    """Verifies that connecting to non-standard port 8765 without HTTP evidence reports NOT_AVAILABLE for CLEAR_TEXT_HTTP."""
    events = [
        NetworkEvent(
            timestamp=1000.0,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=45678,
            remote_address="10.0.2.2",
            remote_port=8765,
            package_name="com.spyaware.test",
            uid=10229,
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
            http_confirmed=None,
        )
    ]

    observer = NetworkObserver()
    result = observer.evaluate(events=events, target_package="com.spyaware.test", target_uid=10229)

    obs = result.observations[NetworkBehaviorCategory.CLEAR_TEXT_HTTP.value]
    assert obs.status == NetworkBehaviorStatus.NOT_AVAILABLE.value


def test_observer_https_port_443_not_cleartext_http():
    """Verifies that HTTPS (port 443) traffic is NOT classified as cleartext HTTP."""
    events = [
        NetworkEvent(
            timestamp=1000.0,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=45678,
            remote_address="142.250.190.46",
            remote_port=443,
            package_name="com.spyaware.test",
            uid=10229,
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
        )
    ]

    observer = NetworkObserver()
    result = observer.evaluate(events=events, target_package="com.spyaware.test", target_uid=10229)

    obs = result.observations[NetworkBehaviorCategory.CLEAR_TEXT_HTTP.value]
    assert obs.status == NetworkBehaviorStatus.NOT_OBSERVED.value


def test_observer_single_socket_sampled_10_times_not_repeated():
    """Verifies that a single persistent socket sampled 10 times does NOT count as repeated connections."""
    events = [
        NetworkEvent(
            timestamp=1000.0 + i * 0.5,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=45678,
            remote_address="10.0.2.2",
            remote_port=8765,
            package_name="com.spyaware.test",
            uid=10229,
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
            samples_count=1,
            connection_id="TCP:10.0.2.15:45678->10.0.2.2:8765:uid=10229",
        )
        for i in range(10)
    ]

    observer = NetworkObserver()
    result = observer.evaluate(events=events, target_package="com.spyaware.test", target_uid=10229)

    assert result.distinct_connections_count == 1
    assert result.total_samples_count == 10

    obs = result.observations[NetworkBehaviorCategory.REPEATED_CONNECTION.value]
    assert obs.status == NetworkBehaviorStatus.NOT_OBSERVED.value
    assert "single persistent socket sampled 10 times" in obs.description
    assert not any("Repeated" in f.title for f in result.findings)


def test_observer_multiple_distinct_connections_repeated_observed():
    """Verifies that 3 distinct connections with different local ports to the same remote count as REPEATED_CONNECTION."""
    events = [
        NetworkEvent(
            timestamp=1000.0 + i,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=45670 + i,
            remote_address="10.0.2.2",
            remote_port=8765,
            package_name="com.spyaware.test",
            uid=10229,
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
            connection_id=f"TCP:10.0.2.15:{45670 + i}->10.0.2.2:8765:uid=10229",
        )
        for i in range(3)
    ]

    observer = NetworkObserver()
    result = observer.evaluate(events=events, target_package="com.spyaware.test", target_uid=10229)

    assert result.distinct_connections_count == 3
    obs = result.observations[NetworkBehaviorCategory.REPEATED_CONNECTION.value]
    assert obs.status == NetworkBehaviorStatus.OBSERVED.value
    assert any("Repeated" in f.title for f in result.findings)


def test_observer_distinct_destinations_not_repeated():
    """Verifies that 1 connection to 8.8.8.8:53 and 1 to 1.1.1.1:53 does NOT count as repeated connection."""
    events = [
        NetworkEvent(
            timestamp=1000.0,
            protocol="UDP",
            local_address="10.0.2.15",
            local_port=50001,
            remote_address="8.8.8.8",
            remote_port=53,
            package_name="com.spyaware.test",
            uid=10229,
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
        ),
        NetworkEvent(
            timestamp=1001.0,
            protocol="UDP",
            local_address="10.0.2.15",
            local_port=50002,
            remote_address="1.1.1.1",
            remote_port=53,
            package_name="com.spyaware.test",
            uid=10229,
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
        ),
    ]

    observer = NetworkObserver()
    result = observer.evaluate(events=events, target_package="com.spyaware.test", target_uid=10229)

    obs = result.observations[NetworkBehaviorCategory.REPEATED_CONNECTION.value]
    assert obs.status == NetworkBehaviorStatus.NOT_OBSERVED.value


def test_observer_host_gateway_and_private_do_not_trigger_external_destination():
    """Verifies that connections to 10.0.2.2 and 192.168.1.1 do NOT trigger EXTERNAL_DESTINATION."""
    events = [
        NetworkEvent(
            timestamp=1000.0,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=40001,
            remote_address="10.0.2.2",
            remote_port=8765,
            package_name="com.spyaware.test",
            uid=10229,
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
        ),
        NetworkEvent(
            timestamp=1001.0,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=40002,
            remote_address="192.168.1.50",
            remote_port=8080,
            package_name="com.spyaware.test",
            uid=10229,
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
        ),
    ]

    observer = NetworkObserver()
    result = observer.evaluate(events=events, target_package="com.spyaware.test", target_uid=10229)

    obs = result.observations[NetworkBehaviorCategory.EXTERNAL_DESTINATION.value]
    assert obs.status == NetworkBehaviorStatus.NOT_OBSERVED.value
    assert "No public internet destinations contacted" in obs.description
    assert not any("Public Internet" in f.title for f in result.findings)


def test_observer_scoring_regression_ordinary_connection_conservative():
    """Verifies that an ordinary HTTPS connection to a local gateway scores low and is not malicious."""
    events = [
        NetworkEvent(
            timestamp=1000.0,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=40001,
            remote_address="10.0.2.2",
            remote_port=443,
            package_name="com.spyaware.test",
            uid=10229,
            attribution_status=NetworkAttributionStatus.ATTRIBUTED,
        )
    ]

    observer = NetworkObserver()
    result = observer.evaluate(events=events, target_package="com.spyaware.test", target_uid=10229)

    assert result.score == 5.0
    assert result.risk_level == "LOW"
    assert len(result.findings) == 1
    assert result.findings[0].title == "Target Application Network Socket Connection"



def test_observer_unattributed_traffic_does_not_affect_score():
    """Proves that a flood of ambient emulator traffic (Google Play, Chrome) never inflates target risk score."""
    ambient_events = [
        NetworkEvent(
            timestamp=1000.0 + i,
            protocol="TCP",
            local_address="10.0.2.15",
            local_port=30000 + i,
            remote_address=f"142.250.190.{i % 250}",
            remote_port=443,
            uid=10045,  # Unrelated app/GMS
            attribution_status=NetworkAttributionStatus.NOT_ATTRIBUTED,
        )
        for i in range(50)
    ]

    observer = NetworkObserver()
    result = observer.evaluate(
        events=ambient_events,
        target_package="com.spyaware.benign",
        target_uid=10228,
        duration_seconds=5.0,
    )

    assert result.score == 0.0
    assert result.attributed_events_count == 0
    assert result.unattributed_events_count == 50
    assert len(result.findings) == 0
    assert result.status == "NOT_ATTRIBUTED"
