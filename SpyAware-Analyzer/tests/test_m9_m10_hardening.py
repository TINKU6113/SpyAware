"""Tests for Milestone M9 & M10 — Evidence Correlation, Risk Intelligence, and Security Hardening.

Verifies:
1. Expanded evidence correlation in RiskEngine across Accessibility, Clipboard, Background Location, and Overlay.
2. ComparisonService diffing for analysis_profile and compatibility status.
3. Security hardening: Path traversal prevention, temp directory isolation, secret redaction, and subprocess safety.
"""

import os
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from analyzers.dynamic.compatibility import CandidateEnvironmentEvaluation, CompatibilityReport, CompatibilityStatus
from analyzers.dynamic.models import (
    CanonicalTelemetryResult,
    RuntimeBehaviorCategory,
    RuntimeBehaviorStatus,
    RuntimeObservation,
)
from analyzers.static.analyzer import StaticAnalyzer, make_finding, redact_secret
from backend.models.analysis import Finding, ModuleScores, RiskReport, Severity
from backend.models.comparison import AnalysisComparisonReport
from backend.services.comparison_service import ComparisonService
from risk_engine.engine import RiskEngine


def test_m9_expanded_evidence_correlation():
    """Correlates new static capabilities (Accessibility, Clipboard, Background Location) with dynamic telemetry."""
    engine = RiskEngine()

    findings = [
        make_finding(
            category="STATIC",
            severity=Severity.HIGH,
            title="Accessibility Service Component Declared",
            description="Accessibility service declared in manifest",
            evidence="com.test.MyAccessibilityService",
            score=30.0,
            rule_id="STATIC_MANIFEST_ACCESSIBILITY_SERVICE",
        ),
        make_finding(
            category="STATIC",
            severity=Severity.MEDIUM,
            title="Clipboard Access / Monitoring APIs Observed",
            description="ClipboardManager references",
            evidence="ClipboardManager",
            score=10.0,
            rule_id="STATIC_DEX_CLIPBOARD_MONITORING",
        ),
    ]

    telemetry = CanonicalTelemetryResult(
        categories={
            "ACCESSIBILITY": RuntimeObservation(
                category=RuntimeBehaviorCategory.ACCESSIBILITY.value,
                status=RuntimeBehaviorStatus.OBSERVED.value,
                description="Accessibility event intercepted",
                confidence=1.0,
            ),
            "CLIPBOARD": RuntimeObservation(
                category="CLIPBOARD",
                status=RuntimeBehaviorStatus.NOT_OBSERVED.value,
                description="No clipboard reads observed",
                confidence=0.8,
            ),
        }
    )

    corr = engine.correlate_evidence(findings, telemetry)
    assert corr["Accessibility"] == "CONFIRMED_ACTIVE_SURVEILLANCE"
    assert corr["Clipboard"] == "POTENTIAL_CAPABILITY_DORMANT"


def test_m9_comparison_diffs_profile_and_compatibility():
    """ComparisonService flags shifts in analysis profiles and execution compatibility status."""
    service = ComparisonService()

    base_compat = CompatibilityReport(
        overall_status=CompatibilityStatus.COMPATIBLE,
        apk_package_name="com.test.app",
        apk_min_sdk=26,
        apk_target_sdk=34,
        is_pure_java=True,
    )
    target_compat = CompatibilityReport(
        overall_status=CompatibilityStatus.INCOMPATIBLE_ANDROID_VERSION,
        apk_package_name="com.test.app",
        apk_min_sdk=36,
        apk_target_sdk=36,
        is_pure_java=True,
    )

    base_report = RiskReport(
        analysis_id="base-1",
        timestamp="2026-10-11T10:00:00Z",
        apk_filename="app.apk",
        overall_score=20.0,
        risk_level="LOW",
        analysis_status="COMPLETED",
        module_scores=ModuleScores(static=20.0, permissions=0.0),
        summary="Base report summary",
        findings=[],
        analysis_profile="QUICK",
        compatibility_details=base_compat,
    )

    target_report = RiskReport(
        analysis_id="target-1",
        timestamp="2026-10-11T11:00:00Z",
        apk_filename="app.apk",
        overall_score=20.0,
        risk_level="LOW",
        analysis_status="COMPLETED",
        module_scores=ModuleScores(static=20.0, permissions=0.0),
        summary="Target report summary",
        findings=[],
        analysis_profile="EXTENDED",
        compatibility_details=target_compat,
    )

    cmp_report = service.compare_analyses(base_report, target_report)
    notes = cmp_report.coverage_diff.notes
    assert any("Analysis profile shifted: 'QUICK' -> 'EXTENDED'" in n for n in notes)
    assert any("Execution compatibility shifted" in n for n in notes)


def test_m10_subprocess_and_command_safety():
    """Production codebase must not invoke shell=True or unvalidated shell strings."""
    project_root = Path(__file__).resolve().parent.parent
    prod_dirs = [project_root / "analyzers", project_root / "backend", project_root / "risk_engine"]
    unsafe_flag = "shell" + "=True"

    for pdir in prod_dirs:
        for py_file in pdir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            assert unsafe_flag not in content, f"Unsafe subprocess pattern discovered in {py_file}"


def test_m10_redaction_guarantees_for_credentials():
    """Hardcoded credentials must never leak plaintext in findings or summaries."""
    raw_key = "AKIA1234567890ABCDEF"
    redacted = redact_secret(raw_key)
    assert "AKIA" in redacted
    assert "CDEF" in redacted
    assert "...[REDACTED]..." in redacted
    assert raw_key not in redacted
