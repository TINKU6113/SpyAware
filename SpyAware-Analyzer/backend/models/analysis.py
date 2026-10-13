"""Pydantic data models for SpyAware-Analyzer.

Defines schemas for findings, analyzer results, risk scoring, and JSON reports.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Category(str, Enum):
    STATIC = "STATIC"
    PERMISSION = "PERMISSION"
    DYNAMIC = "DYNAMIC"
    NETWORK = "NETWORK"
    BLE = "BLE"


class Finding(BaseModel):
    category: str = Field(..., description="Finding category: STATIC, PERMISSION, etc.")
    severity: Severity = Field(..., description="Severity level")
    title: str = Field(..., description="Short descriptive title of the finding")
    description: str = Field(..., description="Detailed explanation of the surveillance/security risk")
    evidence: str = Field(..., description="Observed technical indicator or matched pattern")
    score: float = Field(..., description="Risk score contribution (0-100)")
    finding_id: Optional[str] = Field(None, description="Stable, unique identifier for this finding")
    rule_id: Optional[str] = Field(None, description="Canonical rule ID (e.g. STATIC_DEX_REFLECTION)")
    confidence: float = Field(1.0, description="Confidence metric from 0.0 to 1.0")
    evidence_source: str = Field("static", description="Provenance of evidence (manifest, dex, native, cert, etc.)")
    location: Optional[str] = Field(None, description="File, component, or class location")
    security_impact: Optional[str] = Field(None, description="Analysis of potential security or privacy exploit impact")
    false_positive_notes: Optional[str] = Field(None, description="Context regarding benign usage scenarios")
    remediation: Optional[str] = Field(None, description="Recommended remediation or mitigation steps")
    detection_method: str = Field("heuristic", description="Method: pattern_match, manifest_audit, elf_analysis, etc.")


class ExportedComponent(BaseModel):
    component_type: str = Field(..., description="activity, service, receiver, or provider")
    name: str = Field(..., description="Full component class name")
    exported: bool = Field(..., description="Whether exported='true' explicitly or implicitly")
    permission: Optional[str] = Field(None, description="Guarding permission if defined")


class CertificateInfo(BaseModel):
    is_signed: bool = False
    signature_schemes: List[str] = Field(default_factory=list)
    issuer: Optional[str] = None
    subject: Optional[str] = None
    sha256_fingerprint: Optional[str] = None
    sha1_fingerprint: Optional[str] = None
    serial_number: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    signature_algorithm: Optional[str] = None
    verification_status: str = "METADATA_EXTRACTED_UNVERIFIED"
    verification_details: Optional[str] = None
    is_debug_key: bool = False


class ManifestConfiguration(BaseModel):
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext_traffic: Optional[bool] = None
    network_security_config: Optional[str] = None
    has_custom_permissions: bool = False
    custom_permissions: List[str] = Field(default_factory=list)
    dangerous_permissions_count: int = 0
    exported_components_count: int = 0
    unprotected_exported_count: int = 0


class StaticAnalysisResult(BaseModel):
    apk_filename: str
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None
    requested_permissions: List[str] = Field(default_factory=list)
    activities: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    receivers: List[str] = Field(default_factory=list)
    providers: List[str] = Field(default_factory=list)
    exported_components: List[ExportedComponent] = Field(default_factory=list)
    foreground_service_indicators: List[str] = Field(default_factory=list)
    boot_completed_receivers: List[str] = Field(default_factory=list)
    accessibility_services: List[str] = Field(default_factory=list)
    overlay_capabilities: List[str] = Field(default_factory=list)
    camera_api_indicators: List[str] = Field(default_factory=list)
    microphone_api_indicators: List[str] = Field(default_factory=list)
    location_api_indicators: List[str] = Field(default_factory=list)
    sms_call_api_indicators: List[str] = Field(default_factory=list)
    contacts_api_indicators: List[str] = Field(default_factory=list)
    screen_capture_indicators: List[str] = Field(default_factory=list)
    network_api_indicators: List[str] = Field(default_factory=list)
    native_libraries: List[str] = Field(default_factory=list)
    native_architectures: List[str] = Field(default_factory=list)
    dex_file_count: int = 0
    dex_files_analyzed: List[str] = Field(default_factory=list)
    dex_files_failed: Dict[str, str] = Field(default_factory=dict)
    is_multidex: bool = False
    suspicious_strings_urls: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    score: float = Field(0.0, description="Normalized static score (0-100)")
    is_valid_apk: bool = True
    error_message: Optional[str] = None
    launchable_activity: Optional[str] = None
    certificate_info: Optional[CertificateInfo] = None
    manifest_config: Optional[ManifestConfiguration] = None
    is_split: bool = False
    split_count: int = 0
    limitations: List[str] = Field(default_factory=list)
    sha256: Optional[str] = None
    sha1: Optional[str] = None
    md5: Optional[str] = None
    file_size_bytes: Optional[int] = None
    framework: Optional[str] = None
    framework_details: Optional[Dict[str, Any]] = None
    packing_info: Optional[Dict[str, Any]] = None
    max_sdk: Optional[str] = None


class PermissionAnalysisResult(BaseModel):
    declared_permissions: List[str] = Field(default_factory=list)
    individual_findings: List[Finding] = Field(default_factory=list)
    combination_findings: List[Finding] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    score: float = Field(0.0, description="Normalized permission score (0-100)")


class ModuleScores(BaseModel):
    static: Optional[float] = Field(None, description="Static analysis score (0-100)")
    permissions: Optional[float] = Field(None, description="Permission analysis score (0-100)")
    dynamic: Optional[float] = Field(None, description="Dynamic analysis score (0-100)")
    network: Optional[float] = Field(None, description="Network analysis score (0-100, future)")
    ble: Optional[float] = Field(None, description="BLE analysis score (0-100, future)")


class RiskReport(BaseModel):
    analysis_id: str
    timestamp: str
    apk_filename: str
    overall_score: float = Field(..., description="Overall risk score (0-100)")
    risk_level: str = Field(..., description="LOW, MEDIUM, HIGH, CRITICAL, or UNKNOWN")
    analysis_status: str = Field(
        "COMPLETED_WITH_FINDINGS",
        description="COMPLETED_CLEAN, COMPLETED_WITH_FINDINGS, PARTIAL, FAILED, or INCONCLUSIVE",
    )
    module_scores: ModuleScores
    module_status: Dict[str, str] = Field(default_factory=dict)
    module_errors: Dict[str, Optional[str]] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    summary: str
    disclaimer: str = (
        "Risk assessment is based on observed indicators and does not by itself prove malicious intent."
    )
    is_split: bool = False
    split_count: int = 0
    split_names: List[str] = Field(default_factory=list)
    dex_file_count: int = 0
    dex_files_analyzed: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    certificate_info: Optional[CertificateInfo] = None
    manifest_config: Optional[ManifestConfiguration] = None
    static_details: Optional[StaticAnalysisResult] = None
    permission_details: Optional[PermissionAnalysisResult] = None
    dynamic_details: Optional[Any] = None
    network_details: Optional[Any] = None
    sha256: Optional[str] = None
    framework: Optional[str] = None
    native_abis: List[str] = Field(default_factory=list)
    has_native_libraries: bool = False
    coverage_percent: Optional[float] = None
    confidence_score: Optional[float] = None
    correlation_summary: Optional[Dict[str, Any]] = None
    compatibility_details: Optional[Any] = None
    analysis_profile: str = "STANDARD"
    duration_seconds: Optional[float] = None
    export_markdown_url: Optional[str] = None
    export_json_url: Optional[str] = None

