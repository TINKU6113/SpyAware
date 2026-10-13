"""Pydantic schemas and models for Stage 2C Network Analysis.

Defines schemas for network events, socket states, target attribution,
behavior observations, and network analysis results.
"""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from backend.models.analysis import Finding, Severity


class NetworkAttributionStatus(str, Enum):
    """Status indicating socket ownership mapping to the analyzed application."""

    ATTRIBUTED = "ATTRIBUTED"
    NOT_ATTRIBUTED = "NOT_ATTRIBUTED"
    UNKNOWN = "UNKNOWN"


class NetworkBehaviorCategory(str, Enum):
    """Categories of runtime network surveillance behaviors evaluated in Stage 2C."""

    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    DNS_ACTIVITY = "DNS_ACTIVITY"
    CLEAR_TEXT_HTTP = "CLEAR_TEXT_HTTP"
    EXTERNAL_DESTINATION = "EXTERNAL_DESTINATION"
    REPEATED_CONNECTION = "REPEATED_CONNECTION"
    UNUSUAL_PORT = "UNUSUAL_PORT"


class NetworkBehaviorStatus(str, Enum):
    """Status of network behavior observation."""

    OBSERVED = "OBSERVED"
    NOT_OBSERVED = "NOT_OBSERVED"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    NOT_ATTRIBUTED = "NOT_ATTRIBUTED"
    ERROR = "ERROR"


class DestinationCategory(str, Enum):
    """Classification categories for remote network destinations."""

    LOOPBACK = "LOOPBACK"
    PRIVATE_NETWORK = "PRIVATE_NETWORK"
    EMULATOR_HOST_GATEWAY = "EMULATOR_HOST_GATEWAY"
    PUBLIC_INTERNET = "PUBLIC_INTERNET"
    LINK_LOCAL = "LINK_LOCAL"
    MULTICAST = "MULTICAST"
    UNSPECIFIED = "UNSPECIFIED"
    UNKNOWN = "UNKNOWN"


class NetworkEvent(BaseModel):
    """A transport-level socket or network event captured during dynamic execution."""

    timestamp: float = Field(..., description="UNIX epoch timestamp of capture")
    protocol: str = Field("TCP", description="Transport protocol: TCP or UDP")
    local_address: str = Field(..., description="Local IP address")
    local_port: int = Field(..., description="Local port number")
    remote_address: str = Field(..., description="Remote IP address")
    remote_port: int = Field(..., description="Remote port number")
    state: Optional[str] = Field(None, description="Socket state (ESTABLISHED, LISTEN, etc.)")
    package_name: Optional[str] = Field(None, description="Attributed application package name")
    uid: Optional[int] = Field(None, description="Linux UID owning the socket")
    pid: Optional[int] = Field(None, description="Process ID owning the socket")
    attribution_status: NetworkAttributionStatus = Field(
        NetworkAttributionStatus.UNKNOWN,
        description="Whether this socket belongs to the target APK",
    )
    source: str = Field("/proc/net/tcp", description="Provenance of telemetry")
    evidence: Optional[str] = Field(None, description="Raw socket telemetry string")
    confidence: float = Field(1.0, description="Attribution confidence metric (0.0 to 1.0)")
    destination_category: DestinationCategory = Field(
        DestinationCategory.UNKNOWN,
        description="Classification of remote destination IP address",
    )
    connection_id: Optional[str] = Field(
        None,
        description="Stable connection identity string (protocol:local_ip:local_port->remote_ip:remote_port:uid)",
    )
    samples_count: int = Field(
        1,
        description="Number of polling samples observing this distinct connection",
    )
    http_confirmed: Optional[bool] = Field(
        None,
        description="Whether HTTP was confirmed at the application layer (True/False/None)",
    )
    protocol_evidence: Optional[str] = Field(
        None,
        description="Application-layer protocol evidence or verification note",
    )


class NetworkObservation(BaseModel):
    """Behavioral observation for a specific Stage 2C network category."""

    category: str = Field(..., description="Target category (NETWORK_CONNECTION, CLEAR_TEXT_HTTP, etc.)")
    status: str = Field(..., description="OBSERVED, NOT_OBSERVED, NOT_AVAILABLE, NOT_ATTRIBUTED, ERROR")
    description: str = Field(..., description="Human-readable explanation of network findings")
    evidence: Optional[str] = Field(None, description="Technical snippet or socket summary")
    count: int = Field(0, description="Number of attributed events matching this category")
    confidence: float = Field(1.0, description="Confidence metric (0.0 to 1.0)")
    source: str = Field("socket_inspection", description="Provenance of evidence")


class NetworkAnalysisResult(BaseModel):
    """Full result structure produced by Network Analyzer (Stage 2C Milestone 1)."""

    module: str = "network"
    stage: str = "2C"
    status: str = Field(
        ...,
        description="COMPLETED, NOT_ATTRIBUTED, UNAVAILABLE, FAILED, TIMEOUT, NO_TARGET_UID",
    )
    score: float = Field(0.0, description="Conservative network risk score (0-100)")
    risk_level: str = "LOW"
    target_package: Optional[str] = None
    target_uid: Optional[int] = None
    target_pids: List[int] = Field(default_factory=list)
    duration_seconds: float = 0.0
    total_events: int = 0
    attributed_events_count: int = 0
    unattributed_events_count: int = 0
    distinct_connections_count: int = Field(
        0, description="Count of distinct attributed connection identities"
    )
    total_samples_count: int = Field(
        0,
        description="Total raw socket telemetry samples collected across polling intervals",
    )
    destination_breakdown: Dict[str, int] = Field(
        default_factory=dict,
        description="Counts of attributed connections per destination category",
    )
    events: List[NetworkEvent] = Field(default_factory=list)
    observations: Dict[str, NetworkObservation] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None
