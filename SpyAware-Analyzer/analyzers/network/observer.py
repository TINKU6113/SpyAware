"""Stage 2C Network Behavioral Observer and Risk Evaluator.

Analyzes attributed vs. unattributed network events across 6 behavioral categories:
1. NETWORK_CONNECTION
2. DNS_ACTIVITY
3. CLEAR_TEXT_HTTP
4. EXTERNAL_DESTINATION
5. REPEATED_CONNECTION
6. UNUSUAL_PORT

Enforces strict target attribution: ambient emulator and framework traffic
(Google Play Services, Chrome, system_server) are explicitly categorized as
NOT_ATTRIBUTED and never contribute to target risk findings or scores.
"""

from collections import Counter
from typing import Dict, List, Optional, Set, Tuple

from backend.models.analysis import Finding, Severity
from analyzers.network.collector import (
    classify_destination,
    compute_connection_id,
)
from analyzers.network.models import (
    DestinationCategory,
    NetworkAnalysisResult,
    NetworkAttributionStatus,
    NetworkBehaviorCategory,
    NetworkBehaviorStatus,
    NetworkEvent,
    NetworkObservation,
)

STANDARD_PORTS: Set[int] = {53, 80, 443, 8080, 8443}
HTTP_ASSOCIATED_PORTS: Set[int] = {80, 8080, 8765}
LOOPBACK_ADDRESSES: Set[str] = {"127.0.0.1", "::1", "0.0.0.0", "::"}


class NetworkObserver:
    """Evaluates collected network events with strict target attribution and conservative scoring."""

    def evaluate(
        self,
        events: List[NetworkEvent],
        target_package: Optional[str] = None,
        target_uid: Optional[int] = None,
        target_pids: Optional[List[int]] = None,
        duration_seconds: float = 0.0,
    ) -> NetworkAnalysisResult:
        """Evaluates network telemetry against the 6 Stage 2C behavioral categories."""
        # 1. Partition events into attributed and unattributed
        attributed_events = [
            e for e in events if e.attribution_status == NetworkAttributionStatus.ATTRIBUTED
        ]
        unattributed_events = [
            e for e in events if e.attribution_status == NetworkAttributionStatus.NOT_ATTRIBUTED
        ]

        # 2. Separate socket samples from distinct connection identities
        # Group attributed events by stable connection identity:
        # (protocol, local_address, local_port, remote_address, remote_port, uid)
        distinct_attributed_map: Dict[str, NetworkEvent] = {}
        for e in attributed_events:
            # Ensure destination category is classified
            if (
                e.destination_category == DestinationCategory.UNKNOWN
                and e.remote_address
            ):
                e.destination_category = classify_destination(e.remote_address)

            conn_id = e.connection_id or compute_connection_id(
                e.protocol, e.local_address, e.local_port, e.remote_address, e.remote_port, e.uid
            )
            if conn_id not in distinct_attributed_map:
                entry = e.model_copy()
                entry.connection_id = conn_id
                entry.samples_count = e.samples_count or 1
                distinct_attributed_map[conn_id] = entry
            else:
                distinct_attributed_map[conn_id].samples_count += (e.samples_count or 1)
                if e.state:
                    distinct_attributed_map[conn_id].state = e.state
                if e.http_confirmed is True:
                    distinct_attributed_map[conn_id].http_confirmed = True
                    if e.protocol_evidence:
                        distinct_attributed_map[conn_id].protocol_evidence = e.protocol_evidence

        unique_attributed = list(distinct_attributed_map.values())

        # Destination category breakdown across distinct attributed connections
        dest_breakdown = Counter(e.destination_category.value for e in unique_attributed)

        observations: Dict[str, NetworkObservation] = {}
        findings: List[Finding] = []
        limitations: List[str] = [
            "Transport-level socket observation only; payload content is not decrypted.",
            "Ambient system DNS resolver traffic is not attributed to target UID without packet-level inspection.",
            "Attribution is strictly enforced via Linux kernel UID socket ownership.",
            "Destination classification is contextual: private/host gateway addresses are distinguished from public endpoints.",
            "Transport-level port heuristic does not prove application-layer HTTP protocol without application metadata or server correlation.",
            "Short observation window limits long-term beaconing detection; repeated connections reflect distinct sockets in-window.",
            "Absence of observed runtime network traffic does not prove the application lacks network capability (e.g. traffic may be dormant, background-triggered, or evaded sandbox observation).",
        ]

        # -------------------------------------------------------------
        # Category 1: NETWORK_CONNECTION
        # -------------------------------------------------------------
        if unique_attributed:
            distinct_remotes = {
                f"{e.remote_address}:{e.remote_port} ({e.destination_category.value})"
                for e in unique_attributed
                if e.remote_port > 0
            }
            total_samples = sum(e.samples_count for e in unique_attributed)
            ev = f"Attributed {len(unique_attributed)} distinct connection(s) across {total_samples} socket sample(s). Destinations: {', '.join(sorted(distinct_remotes)) or 'listening sockets'}"
            observations[NetworkBehaviorCategory.NETWORK_CONNECTION.value] = NetworkObservation(
                category=NetworkBehaviorCategory.NETWORK_CONNECTION.value,
                status=NetworkBehaviorStatus.OBSERVED.value,
                description="Application established verified network socket connection(s).",
                evidence=ev,
                count=len(unique_attributed),
                confidence=1.0,
            )
            findings.append(
                Finding(
                    category="NETWORK",
                    severity=Severity.LOW,
                    title="Target Application Network Socket Connection",
                    description="The target application established one or more outbound network connections verified by UID socket ownership.",
                    evidence=ev,
                    score=5.0,
                )
            )
        else:
            observations[NetworkBehaviorCategory.NETWORK_CONNECTION.value] = NetworkObservation(
                category=NetworkBehaviorCategory.NETWORK_CONNECTION.value,
                status=NetworkBehaviorStatus.NOT_OBSERVED.value,
                description="No runtime network socket connections observed for target application within the observation window. Note: Absence of observed traffic during this bounded test window does not prove absence of dormant or condition-dependent network capability.",
                evidence=None,
                count=0,
                confidence=1.0,
            )

        # -------------------------------------------------------------
        # Category 2: DNS_ACTIVITY
        # -------------------------------------------------------------
        direct_dns_events = [e for e in unique_attributed if e.remote_port == 53]
        if direct_dns_events:
            ev_dns = f"Target UID directly opened socket to DNS port 53: {', '.join(e.remote_address for e in direct_dns_events)}"
            observations[NetworkBehaviorCategory.DNS_ACTIVITY.value] = NetworkObservation(
                category=NetworkBehaviorCategory.DNS_ACTIVITY.value,
                status=NetworkBehaviorStatus.OBSERVED.value,
                description="Direct DNS query socket opened by target application.",
                evidence=ev_dns,
                count=len(direct_dns_events),
                confidence=1.0,
            )
            findings.append(
                Finding(
                    category="NETWORK",
                    severity=Severity.INFO,
                    title="Direct Application DNS Activity",
                    description="Target application directly initiated DNS socket communications.",
                    evidence=ev_dns,
                    score=5.0,
                )
            )
        else:
            ambient_dns = [e for e in unattributed_events if e.remote_port == 53]
            ambient_note = f" (Observed {len(ambient_dns)} ambient system DNS query sample(s), NOT_ATTRIBUTED to target)" if ambient_dns else ""
            observations[NetworkBehaviorCategory.DNS_ACTIVITY.value] = NetworkObservation(
                category=NetworkBehaviorCategory.DNS_ACTIVITY.value,
                status=NetworkBehaviorStatus.NOT_AVAILABLE.value,
                description=f"Per-socket DNS resolution attribution is not available at transport layer without packet-level capture.{ambient_note}",
                evidence=None,
                count=0,
                confidence=0.5,
            )

        # -------------------------------------------------------------
        # Category 3: CLEAR_TEXT_HTTP
        # -------------------------------------------------------------
        confirmed_http = [e for e in unique_attributed if e.http_confirmed is True]
        potential_http = [
            e for e in unique_attributed
            if e.remote_port in HTTP_ASSOCIATED_PORTS and e.http_confirmed is not True
        ]

        if confirmed_http:
            confirmed_endpoints = {f"{e.remote_address}:{e.remote_port}" for e in confirmed_http}
            ev_clear = f"Cleartext HTTP verified: {', '.join(sorted(confirmed_endpoints))}. Protocol evidence: {confirmed_http[0].protocol_evidence or 'Confirmed application-layer HTTP'}"
            observations[NetworkBehaviorCategory.CLEAR_TEXT_HTTP.value] = NetworkObservation(
                category=NetworkBehaviorCategory.CLEAR_TEXT_HTTP.value,
                status=NetworkBehaviorStatus.OBSERVED.value,
                description="Application initiated verified unencrypted cleartext HTTP communication.",
                evidence=ev_clear,
                count=len(confirmed_http),
                confidence=1.0,
            )
            findings.append(
                Finding(
                    category="NETWORK",
                    severity=Severity.HIGH,
                    title="Cleartext HTTP Communication Observed",
                    description="The application transmitted unencrypted HTTP requests, which exposes network telemetry and endpoints to interception.",
                    evidence=ev_clear,
                    score=15.0,
                )
            )
        elif potential_http:
            endpoints_str = ", ".join(f"{e.remote_address}:{e.remote_port}" for e in potential_http)
            observations[NetworkBehaviorCategory.CLEAR_TEXT_HTTP.value] = NetworkObservation(
                category=NetworkBehaviorCategory.CLEAR_TEXT_HTTP.value,
                status=NetworkBehaviorStatus.NOT_AVAILABLE.value,
                description=f"Transport-level TCP connection to port(s) {endpoints_str} observed, but application-layer HTTP protocol cannot be confirmed without payload inspection.",
                evidence=f"TCP {endpoints_str} (Transport-level port heuristic only; application-layer protocol unconfirmed)",
                count=0,
                confidence=0.5,
            )
        else:
            observations[NetworkBehaviorCategory.CLEAR_TEXT_HTTP.value] = NetworkObservation(
                category=NetworkBehaviorCategory.CLEAR_TEXT_HTTP.value,
                status=NetworkBehaviorStatus.NOT_OBSERVED.value,
                description="No unencrypted HTTP connections observed for target application.",
                evidence=None,
                count=0,
                confidence=1.0,
            )

        # -------------------------------------------------------------
        # Category 4: EXTERNAL_DESTINATION
        # -------------------------------------------------------------
        # Strictly check for PUBLIC_INTERNET destinations.
        # EMULATOR_HOST_GATEWAY, PRIVATE_NETWORK, LOOPBACK, LINK_LOCAL do NOT trigger external public destination.
        public_events = [
            e for e in unique_attributed
            if e.destination_category == DestinationCategory.PUBLIC_INTERNET and e.remote_port > 0
        ]

        if public_events:
            public_destinations = {f"{e.remote_address}:{e.remote_port}" for e in public_events}
            ev_ext = f"Public internet destination(s) contacted: {', '.join(sorted(public_destinations))}"
            observations[NetworkBehaviorCategory.EXTERNAL_DESTINATION.value] = NetworkObservation(
                category=NetworkBehaviorCategory.EXTERNAL_DESTINATION.value,
                status=NetworkBehaviorStatus.OBSERVED.value,
                description="Application established connection to public external internet destination.",
                evidence=ev_ext,
                count=len(public_events),
                confidence=1.0,
            )
            findings.append(
                Finding(
                    category="NETWORK",
                    severity=Severity.LOW,
                    title="Outbound External Public Internet Destination",
                    description="The application established network communication with a public external internet IP address.",
                    evidence=ev_ext,
                    score=10.0,
                )
            )
        else:
            non_public = [e for e in unique_attributed if e.remote_port > 0]
            if non_public:
                non_pub_desc = ", ".join(sorted({f"{e.remote_address}:{e.remote_port} ({e.destination_category.value})" for e in non_public}))
                desc = f"No public internet destinations contacted. Observed connections were limited to local/private/emulator host gateway: {non_pub_desc}."
            else:
                desc = "No external network destinations contacted by target application."

            observations[NetworkBehaviorCategory.EXTERNAL_DESTINATION.value] = NetworkObservation(
                category=NetworkBehaviorCategory.EXTERNAL_DESTINATION.value,
                status=NetworkBehaviorStatus.NOT_OBSERVED.value,
                description=desc,
                evidence=None,
                count=0,
                confidence=1.0,
            )

        # -------------------------------------------------------------
        # Category 5: REPEATED_CONNECTION
        # -------------------------------------------------------------
        # Conservative repeated-connection detection:
        # Only OBSERVED when multiple DISTINCT connections exist to the same destination.
        # Repeated samples of a single socket do NOT count as repeated connections.
        dest_counts = Counter(
            (e.remote_address, e.remote_port)
            for e in unique_attributed
            if e.remote_port > 0
        )
        repeated = [dest for dest, count in dest_counts.items() if count >= 2]

        if repeated:
            ev_rep = f"Multiple distinct connections ({sum(dest_counts[d] for d in repeated)} distinct sockets) to: {', '.join(f'{d[0]}:{d[1]} (x{dest_counts[d]} distinct sockets)' for d in repeated)}"
            observations[NetworkBehaviorCategory.REPEATED_CONNECTION.value] = NetworkObservation(
                category=NetworkBehaviorCategory.REPEATED_CONNECTION.value,
                status=NetworkBehaviorStatus.OBSERVED.value,
                description="Multiple distinct network connections established to the same endpoint within observation window.",
                evidence=ev_rep,
                count=sum(dest_counts[d] for d in repeated),
                confidence=1.0,
            )
            findings.append(
                Finding(
                    category="NETWORK",
                    severity=Severity.MEDIUM,
                    title="Repeated Network Connection Activity",
                    description="Multiple distinct sockets were opened to the same remote host/port, characteristic of telemetry beaconing or retry polling.",
                    evidence=ev_rep,
                    score=10.0,
                )
            )
        else:
            sampled_sockets = [e for e in unique_attributed if e.samples_count > 1 and e.remote_port > 0]
            if sampled_sockets:
                desc = f"No repeated distinct connections observed (single persistent socket sampled {sampled_sockets[0].samples_count} times across polling intervals)."
            else:
                desc = "No repeated connection activity observed for target application."

            observations[NetworkBehaviorCategory.REPEATED_CONNECTION.value] = NetworkObservation(
                category=NetworkBehaviorCategory.REPEATED_CONNECTION.value,
                status=NetworkBehaviorStatus.NOT_OBSERVED.value,
                description=desc,
                evidence=None,
                count=0,
                confidence=1.0,
            )

        # -------------------------------------------------------------
        # Category 6: UNUSUAL_PORT
        # -------------------------------------------------------------
        unusual_events = [
            e
            for e in unique_attributed
            if e.remote_port > 0 and e.remote_port not in STANDARD_PORTS
        ]
        if unusual_events:
            unusual_ports = {e.remote_port for e in unusual_events}
            ev_unusual = f"Non-standard port(s) contacted: {', '.join(str(p) for p in sorted(unusual_ports))}"
            observations[NetworkBehaviorCategory.UNUSUAL_PORT.value] = NetworkObservation(
                category=NetworkBehaviorCategory.UNUSUAL_PORT.value,
                status=NetworkBehaviorStatus.OBSERVED.value,
                description="Application connected to non-standard network port(s).",
                evidence=ev_unusual,
                count=len(unusual_events),
                confidence=1.0,
            )
            findings.append(
                Finding(
                    category="NETWORK",
                    severity=Severity.LOW,
                    title="Connection to Non-Standard Network Port",
                    description="The application connected to a port outside standard web services, which may indicate custom telemetry or surveillance protocols.",
                    evidence=ev_unusual,
                    score=10.0,
                )
            )
        else:
            observations[NetworkBehaviorCategory.UNUSUAL_PORT.value] = NetworkObservation(
                category=NetworkBehaviorCategory.UNUSUAL_PORT.value,
                status=NetworkBehaviorStatus.NOT_OBSERVED.value,
                description="All observed connections used standard network ports.",
                evidence=None,
                count=0,
                confidence=1.0,
            )

        # -------------------------------------------------------------
        # Score Computation
        # -------------------------------------------------------------
        score = 0.0
        if unique_attributed:
            score += 5.0  # Base attributed connection
            if observations[NetworkBehaviorCategory.EXTERNAL_DESTINATION.value].status == NetworkBehaviorStatus.OBSERVED.value:
                score += 10.0
            if observations[NetworkBehaviorCategory.CLEAR_TEXT_HTTP.value].status == NetworkBehaviorStatus.OBSERVED.value:
                score += 15.0
            if observations[NetworkBehaviorCategory.REPEATED_CONNECTION.value].status == NetworkBehaviorStatus.OBSERVED.value:
                score += 10.0
            if observations[NetworkBehaviorCategory.UNUSUAL_PORT.value].status == NetworkBehaviorStatus.OBSERVED.value:
                score += 10.0
            if observations[NetworkBehaviorCategory.DNS_ACTIVITY.value].status == NetworkBehaviorStatus.OBSERVED.value:
                score += 5.0

        score = max(0.0, min(100.0, score))

        if score < 25.0:
            risk_level = "LOW"
        elif score < 50.0:
            risk_level = "MEDIUM"
        elif score < 75.0:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        # Determine overall analysis status
        if target_uid is None and not events:
            status = "NO_TARGET_UID"
        elif not unique_attributed and unattributed_events:
            status = "NOT_ATTRIBUTED"
        else:
            status = "COMPLETED"

        return NetworkAnalysisResult(
            module="network",
            stage="2C",
            status=status,
            score=round(score, 1),
            risk_level=risk_level,
            target_package=target_package,
            target_uid=target_uid,
            target_pids=target_pids or [],
            duration_seconds=round(duration_seconds, 2),
            total_events=len(events),
            attributed_events_count=len(attributed_events),
            unattributed_events_count=len(unattributed_events),
            distinct_connections_count=len(unique_attributed),
            total_samples_count=len(events),
            destination_breakdown=dict(dest_breakdown),
            events=unique_attributed + unattributed_events[:50],  # Bound payload size
            observations=observations,
            findings=findings,
            limitations=limitations,
        )
