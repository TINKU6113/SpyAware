"""Pydantic data models for the SpyAware-Analyzer Detection Validation Corpus and Harness.

Milestone M4: Detection Validation and Analysis Accuracy.
Provides structured models for validation test cases, expected detection rules,
rule evaluations, confusion matrix metrics (with explicit undefined handling),
and comprehensive harness execution reports.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


class ValidationCategory(str, Enum):
    """Categorization for controlled validation test cases."""
    BENIGN_PERMISSIONS = "BENIGN_PERMISSIONS"
    EXPORTED_COMPONENTS = "EXPORTED_COMPONENTS"
    BACKUP_ENABLED = "BACKUP_ENABLED"
    DEBUG_SIGNING = "DEBUG_SIGNING"
    REFLECTION = "REFLECTION"
    RUNTIME_CODE_LOADING = "RUNTIME_CODE_LOADING"
    SHELL_COMMANDS = "SHELL_COMMANDS"
    WEAK_CRYPTO = "WEAK_CRYPTO"
    NATIVE_LIBRARIES = "NATIVE_LIBRARIES"
    EMBEDDED_CREDENTIALS = "EMBEDDED_CREDENTIALS"
    MALFORMED_ARCHIVE = "MALFORMED_ARCHIVE"
    SPLIT_APKS = "SPLIT_APKS"
    # M5 Expanded Benign Categories
    LEGIT_CAMERA_MIC = "LEGIT_CAMERA_MIC"
    LEGIT_LOCATION = "LEGIT_LOCATION"
    LEGIT_NETWORK = "LEGIT_NETWORK"
    LEGIT_REFLECTION = "LEGIT_REFLECTION"
    LEGIT_DYNAMIC_CODE = "LEGIT_DYNAMIC_CODE"
    LEGIT_NATIVE_LIB = "LEGIT_NATIVE_LIB"
    LEGIT_EXPORTED = "LEGIT_EXPORTED"


class ExpectedRuleMatch(BaseModel):
    """Defines an expected rule detection criterion."""
    rule_id: str
    min_severity: Optional[str] = None
    max_severity: Optional[str] = None
    evidence_source: Optional[str] = None
    must_match: bool = True
    description: Optional[str] = None


class ValidationTestCase(BaseModel):
    """Defines a deterministic test case in the controlled validation corpus."""
    case_id: str
    name: str
    category: ValidationCategory
    description: str
    fixture_filename: str
    expected_ground_truth: str  # "BENIGN", "SUSPICIOUS", "MALICIOUS", "MALFORMED", "INCOMPLETE"
    expected_rules: List[ExpectedRuleMatch] = Field(default_factory=list)
    prohibited_rules: List[str] = Field(default_factory=list)
    expected_severity_range: Tuple[str, str] = ("LOW", "LOW")
    expected_evidence_source: str
    dynamic_required: bool = False
    expected_limitations: List[str] = Field(default_factory=list)
    limitations_notes: Optional[str] = None
    is_malformed_case: bool = False
    is_split_case: bool = False
    split_count: int = 0


class RuleEvaluation(BaseModel):
    """Result of evaluating a specific rule against test case findings."""
    rule_id: str
    expected: bool
    matched: bool
    passed: bool
    severity: Optional[str] = None
    evidence_source: Optional[str] = None
    evidence: Optional[str] = None
    details: Optional[str] = None


class TestCaseResult(BaseModel):
    """Execution result for a single validation test case."""
    case_id: str
    name: str
    category: str
    fixture: str
    passed: bool
    ground_truth: str
    predicted_risk_level: Optional[str] = None
    predicted_risk_score: Optional[float] = None
    rule_evaluations: List[RuleEvaluation] = Field(default_factory=list)
    matched_rules: List[str] = Field(default_factory=list)
    missing_rules: List[str] = Field(default_factory=list)
    prohibited_violations: List[str] = Field(default_factory=list)
    redaction_verified: bool = True
    limitations_recorded: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0


class MetricValue(BaseModel):
    """Metric calculation with explicit representation of undefined mathematical states.
    
    Prevents meaningless values (e.g. 0.0 or 1.0) when denominator is 0.
    """
    value: Optional[float] = None
    is_defined: bool = True
    numerator: int = 0
    denominator: int = 0
    explanation: Optional[str] = None


class ConfusionMatrixMetrics(BaseModel):
    """Rigorous confusion matrix and performance metrics with zero-division guards."""
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    accuracy: MetricValue
    precision: MetricValue
    recall: MetricValue
    f1_score: MetricValue
    false_positive_rate: MetricValue
    false_negative_rate: MetricValue


class DynamicReadiness(BaseModel):
    """Audit of host runtime environment readiness and attribution isolation."""
    status: str  # "VERIFIED", "PARTIALLY_VERIFIED", "BLOCKED"
    device_count: int = 0
    devices: List[str] = Field(default_factory=list)
    reason: str
    attribution_audit: str
    lifecycle_audit: str


class ValidationHarnessReport(BaseModel):
    """Complete summary report of the detection validation harness."""
    timestamp: str
    total_cases: int
    passed_cases: int
    failed_cases: int
    unit_test_status: str
    rule_validation_status: str
    pipeline_e2e_status: str
    dynamic_readiness: DynamicReadiness
    rule_level_metrics: ConfusionMatrixMetrics
    classification_metrics: ConfusionMatrixMetrics
    case_results: List[TestCaseResult]
    engine_boundaries_verified: bool = True
    redaction_audit_passed: bool = True
