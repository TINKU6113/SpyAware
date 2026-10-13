"""Pydantic data models for historical analysis comparisons in SpyAware-Analyzer.

Defines schemas for comparing two risk reports: finding diffs, module score deltas,
coverage shifts, and package identity integrity checks.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from backend.models.analysis import Finding, Severity


class FindingDiffStatus(str, Enum):
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    MODIFIED = "MODIFIED"
    UNCHANGED = "UNCHANGED"


class AnalysisRelationship(str, Enum):
    SAME_APK_EXACT = "SAME_APK_EXACT"
    SAME_PACKAGE_VERSION_UPDATE = "SAME_PACKAGE_VERSION_UPDATE"
    SAME_PACKAGE_SAME_VERSION = "SAME_PACKAGE_SAME_VERSION"
    UNRELATED_APKS = "UNRELATED_APKS"
    UNKNOWN = "UNKNOWN"


class FindingDiff(BaseModel):
    finding_key: str = Field(..., description="Normalized stable identity for the finding")
    status: FindingDiffStatus = Field(..., description="ADDED, REMOVED, MODIFIED, or UNCHANGED")
    category: str = Field(..., description="Category: STATIC, PERMISSION, DYNAMIC, etc.")
    title: str = Field(..., description="Finding title")
    base_finding: Optional[Finding] = Field(None, description="Finding as it was in base report")
    target_finding: Optional[Finding] = Field(None, description="Finding as it is in target report")
    base_severity: Optional[Severity] = Field(None, description="Severity in base report")
    target_severity: Optional[Severity] = Field(None, description="Severity in target report")
    base_score: Optional[float] = Field(None, description="Score contribution in base report")
    target_score: Optional[float] = Field(None, description="Score contribution in target report")
    score_delta: float = Field(0.0, description="target_score - base_score")
    confidence_delta: float = Field(0.0, description="target_confidence - base_confidence")
    description: Optional[str] = Field(None, description="Summary explanation of change")


class ModuleScoreDiff(BaseModel):
    module_name: str = Field(..., description="Module identifier (static, permissions, dynamic, network, ble)")
    base_score: Optional[float] = Field(None, description="Base module score (0-100)")
    target_score: Optional[float] = Field(None, description="Target module score (0-100)")
    score_delta: Optional[float] = Field(None, description="target_score - base_score if both defined")
    base_status: Optional[str] = Field(None, description="Base module execution status")
    target_status: Optional[str] = Field(None, description="Target module execution status")
    status_changed: bool = Field(False, description="True if execution status changed between analyses")


class PackageIdentityDiff(BaseModel):
    relationship: AnalysisRelationship = Field(..., description="Relationship between the two compared APKs")
    base_package_name: Optional[str] = None
    target_package_name: Optional[str] = None
    is_package_changed: bool = False
    base_version: Optional[str] = None
    target_version: Optional[str] = None
    is_version_changed: bool = False
    base_sha256: Optional[str] = None
    target_sha256: Optional[str] = None
    is_hash_identical: bool = False
    base_min_sdk: Optional[str] = None
    target_min_sdk: Optional[str] = None
    base_target_sdk: Optional[str] = None
    target_target_sdk: Optional[str] = None
    base_cert_sha256: Optional[str] = None
    target_cert_sha256: Optional[str] = None
    is_cert_changed: bool = False
    warnings: List[str] = Field(default_factory=list, description="Warnings regarding application identity shifts")


class CoverageDiff(BaseModel):
    base_dex_count: int = 0
    target_dex_count: int = 0
    dex_count_delta: int = 0
    base_permissions_count: int = 0
    target_permissions_count: int = 0
    permissions_count_delta: int = 0
    base_components_count: int = 0
    target_components_count: int = 0
    components_count_delta: int = 0
    base_dynamic_status: Optional[str] = None
    target_dynamic_status: Optional[str] = None
    dynamic_depth_changed: bool = False
    base_coverage_percent: Optional[float] = None
    target_coverage_percent: Optional[float] = None
    coverage_percent_delta: Optional[float] = None
    base_confidence_score: Optional[float] = None
    target_confidence_score: Optional[float] = None
    confidence_score_delta: Optional[float] = None
    notes: List[str] = Field(default_factory=list, description="Notable shifts in test or analysis surface")


class ComparisonRequest(BaseModel):
    base_analysis_id: str = Field(..., description="Identifier of the baseline analysis report")
    target_analysis_id: str = Field(..., description="Identifier of the target analysis report to compare against")


class AnalysisComparisonReport(BaseModel):
    base_analysis_id: str
    target_analysis_id: str
    base_apk_filename: str
    target_apk_filename: str
    timestamp_comparison: str
    package_identity: PackageIdentityDiff
    overall_score_base: float
    overall_score_target: float
    overall_score_delta: float
    risk_level_base: str
    risk_level_target: str
    analysis_status_base: str
    analysis_status_target: str
    module_diffs: Dict[str, ModuleScoreDiff] = Field(default_factory=dict)
    findings_summary: Dict[str, int] = Field(default_factory=dict)
    added_findings: List[FindingDiff] = Field(default_factory=list)
    removed_findings: List[FindingDiff] = Field(default_factory=list)
    modified_findings: List[FindingDiff] = Field(default_factory=list)
    unchanged_findings: List[FindingDiff] = Field(default_factory=list)
    coverage_diff: CoverageDiff
    is_unrelated_warning: bool = False
    summary: str
