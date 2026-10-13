"""Pydantic models for Dynamic Analysis (Stage 2A & 2B) in SpyAware-Analyzer.

Defines schemas for runtime observations, behavior events, execution metadata,
environment discovery status, AVD inventory, and dynamic analysis results.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.models.analysis import Finding, Severity


class RuntimeBehaviorStatus(str, Enum):
    """Canonical status indicating whether a sensitive behavior was observed at runtime."""

    OBSERVED = "OBSERVED"
    NOT_OBSERVED = "NOT_OBSERVED"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_TESTED = "NOT_TESTED"
    # Backwards-compatibility aliases
    NOT_AVAILABLE = "UNAVAILABLE"
    ERROR = "UNAVAILABLE"


class RuntimeBehaviorCategory(str, Enum):
    """Categories of runtime surveillance behaviors audited during dynamic analysis."""

    CAMERA = "CAMERA"
    MICROPHONE = "MICROPHONE"
    LOCATION = "LOCATION"
    ACCESSIBILITY = "ACCESSIBILITY"
    MEDIA_PROJECTION = "MEDIA_PROJECTION"
    SMS = "SMS"
    CALL = "CALL"
    BACKGROUND_SERVICE = "BACKGROUND_SERVICE"
    PERSISTENCE = "PERSISTENCE"
    PROCESS = "PROCESS"
    CRASH = "CRASH"


CANONICAL_CATEGORY_NAMES: Dict[str, str] = {
    "CAMERA": "Camera / Video Capture",
    "MICROPHONE": "Microphone / Audio Capture",
    "LOCATION": "Location Tracking",
    "ACCESSIBILITY": "Accessibility Service Abuse",
    "MEDIA_PROJECTION": "Screen Capture / MediaProjection",
    "SMS": "SMS Telephony & Interception",
    "CALL": "Call Activity & Telephony",
    "BACKGROUND_SERVICE": "Active Background Services",
    "PERSISTENCE": "Persistence & Boot Receivers",
    "PROCESS": "Runtime Process Lifecycle",
}

CANONICAL_CATEGORIES_ORDER: List[str] = [
    "CAMERA",
    "MICROPHONE",
    "LOCATION",
    "ACCESSIBILITY",
    "MEDIA_PROJECTION",
    "SMS",
    "CALL",
    "BACKGROUND_SERVICE",
    "PERSISTENCE",
    "PROCESS",
]


class RuntimeObservation(BaseModel):
    """Detailed observation record for a specific runtime behavioral category."""

    category: str = Field(..., description="Target category (CAMERA, MICROPHONE, etc.)")
    name: Optional[str] = Field(None, description="Human-readable category display name")
    status: str = Field(..., description="OBSERVED, NOT_OBSERVED, UNAVAILABLE, NOT_TESTED")
    description: str = Field(..., description="Human-readable explanation of runtime findings")
    evidence: Optional[str] = Field(None, description="Technical log line, dumpsys dump, or PID information")
    timestamp: Optional[str] = Field(None, description="ISO timestamp if available")
    confidence: float = Field(1.0, description="Confidence metric (0.0 to 1.0)")
    source: str = Field("telemetry", description="Provenance of evidence (dumpsys:media.camera, logcat, ps, etc.)")
    reason: Optional[str] = Field(None, description="Concise reason explaining why this status was determined")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Structured technical event details")


class CanonicalTelemetryResult(BaseModel):
    """Canonical single-source-of-truth telemetry result model for Stage 2B."""

    categories_observed: int = 0
    categories_tested: int = 0
    categories_unavailable: int = 0
    categories_not_tested: int = 0
    categories_total: int = 10
    categories: Dict[str, RuntimeObservation] = Field(default_factory=dict)
    surveillance_observed_count: int = 0
    headline: str = ""
    summary: str = ""
    additional_findings: List[Finding] = Field(default_factory=list)


class CanonicalBehaviorDict(dict):
    """Case-insensitive dictionary allowing access via uppercase, lowercase, or exact keys."""

    def __getitem__(self, key: Any) -> Any:
        if super().__contains__(key):
            return super().__getitem__(key)
        if isinstance(key, str):
            k_upper = key.upper()
            if super().__contains__(k_upper):
                return super().__getitem__(k_upper)
            k_lower = key.lower()
            if super().__contains__(k_lower):
                return super().__getitem__(k_lower)
        raise KeyError(key)

    def get(self, key: Any, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: Any) -> bool:
        if super().__contains__(key):
            return True
        if isinstance(key, str):
            return super().__contains__(key.upper()) or super().__contains__(key.lower())
        return False


class Observation(BaseModel):
    """A runtime observation recorded during dynamic emulator execution."""

    type: str = Field(..., description="Observation type (e.g. APPLICATION_STARTED, CAMERA_ACCESSED)")
    severity: Severity = Field(Severity.INFO, description="Observation severity")
    description: str = Field(..., description="Human-readable explanation of the observation")
    evidence: Optional[str] = Field(None, description="Technical snippet or log line")
    timestamp: Optional[str] = Field(None, description="Timestamp if available")


class AVDFallbackAttempt(BaseModel):
    """Record of an individual AVD startup, boot, or installation attempt."""

    avd_name: str
    status: str = Field("ATTEMPTED", description="ATTEMPTED, SUCCESS, SKIPPED, FAILED")
    failure_classification: Optional[str] = None
    reason: Optional[str] = None
    duration_seconds: float = 0.0


class AVDProfile(BaseModel):
    """Configured Android Virtual Device metadata and capability diagnostics."""

    name: str
    display_name: Optional[str] = None
    target: str = "unknown"
    api_level: Optional[int] = None
    android_version: Optional[str] = None
    abis: List[str] = Field(default_factory=list)
    system_image_dir: Optional[str] = None
    system_image_installed: bool = False
    ready: bool = True
    error_message: Optional[str] = None
    is_running: bool = False
    device_serial: Optional[str] = None


class AVDInventory(BaseModel):
    """Complete inventory of configured AVDs and installed Android SDK system images."""

    profiles: List[AVDProfile] = Field(default_factory=list)
    installed_system_images: List[str] = Field(default_factory=list)
    available_avd_names: List[str] = Field(default_factory=list)
    running_devices: List[str] = Field(default_factory=list)
    emulator_available: bool = False
    adb_available: bool = False
    recommended_targets: List[Dict[str, Any]] = Field(default_factory=list)


class ExecutionMetadata(BaseModel):
    """Metadata regarding emulator execution environment and runtime metrics."""

    package_name: Optional[str] = None
    launchable_activity: Optional[str] = None
    launch_success: bool = False
    duration_seconds: float = 0.0
    avd_name: Optional[str] = None
    device_id: Optional[str] = None
    emulator_started_by_job: bool = False
    exit_reason: Optional[str] = None
    selected_avd_reason: Optional[str] = None
    avd_attempts: List[AVDFallbackAttempt] = Field(default_factory=list)


class EnvironmentStatus(BaseModel):
    """Dynamic analysis host environment discovery diagnostics."""

    adb_available: bool = False
    emulator_available: bool = False
    avdmanager_available: bool = False
    frida_available: bool = False
    available_avds: List[str] = Field(default_factory=list)
    running_devices: List[str] = Field(default_factory=list)
    selected_avd: Optional[str] = None
    ready: bool = False
    message: str = "Dynamic analysis environment status"


class DynamicAnalysisResult(BaseModel):
    """Full result structure produced by the Dynamic Analyzer (Stage 2A & 2B)."""

    module: str = "dynamic"
    stage: str = "2B"
    status: str = Field(..., description="COMPLETED, UNAVAILABLE, FAILED, TIMEOUT, NO_LAUNCHABLE_ACTIVITY")
    score: float = Field(0.0, description="Conservative dynamic risk score (0-100)")
    risk_level: str = "LOW"
    execution: ExecutionMetadata = Field(default_factory=ExecutionMetadata)
    observations: List[Observation] = Field(default_factory=list)
    runtime_behavior: Dict[str, RuntimeObservation] = Field(default_factory=dict)
    telemetry: Optional[CanonicalTelemetryResult] = None
    findings: List[Finding] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None
    raw_logcat_snippet: Optional[str] = None
