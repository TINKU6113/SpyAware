"""Milestone M4: Risk Engine Audit, Boundary Cases, and Contradictory Evidence Tests.

Verifies:
1. Deduplication consistency across categories and titles.
2. Boundary conditions: empty findings, single finding, maximum bound cap (100.0), negative score guards.
3. Separation of risk severity from evidence confidence.
4. Static vs runtime evidence distinction (dormant vs active vs undocumented vs incomplete).
5. Missing or failed telemetry cannot lower the risk score by implying safety.
6. Incomplete analysis representation (coverage and module state tracking).
7. Benign capabilities (permissions, reflection, native code, backup, debug key) never trigger malicious/elevated risk.
"""

from typing import Dict, List, Optional
import pytest

from backend.models.analysis import Finding, Severity
from risk_engine.engine import RiskEngine


@pytest.fixture
def engine():
    return RiskEngine()


class MockTelemetryCategory:
    def __init__(self, status: str, count: int = 0):
        self.status = status
        self.observation_count = count


class MockTelemetryResult:
    def __init__(self, categories: Dict[str, MockTelemetryCategory], tested: int = 5, total: int = 10):
        self.categories = categories
        self.categories_tested = tested
        self.categories_total = total


# =========================================================================
# 1. Deduplication Consistency
# =========================================================================

def test_finding_deduplication_consistency(engine):
    """Duplicate findings within the same category and title are eliminated."""
    f1 = Finding(category="STATIC", severity=Severity.LOW, title="Duplicate Issue", description="d1", evidence="e1", score=10.0)
    f2 = Finding(category="STATIC", severity=Severity.LOW, title="Duplicate Issue", description="d2", evidence="e2", score=10.0)
    f3 = Finding(category="STATIC", severity=Severity.MEDIUM, title="Different Issue", description="d3", evidence="e3", score=15.0)
    f4 = Finding(category="PERMISSION", severity=Severity.LOW, title="Duplicate Issue", description="d4", evidence="e4", score=10.0)

    deduped = engine.deduplicate_findings([f1, f2, f3, f4])
    assert len(deduped) == 3
    # Check that STATIC:Duplicate Issue appears once, STATIC:Different Issue once, PERMISSION:Duplicate Issue once
    keys = [(f.category, f.title) for f in deduped]
    assert keys == [
        ("STATIC", "Duplicate Issue"),
        ("STATIC", "Different Issue"),
        ("PERMISSION", "Duplicate Issue"),
    ]


# =========================================================================
# 2. Boundary Cases and Capping
# =========================================================================

def test_boundary_empty_findings_and_modules(engine):
    """When no modules are active and no findings exist, score is 0.0 and level is UNKNOWN."""
    res = engine.calculate_overall_risk(
        module_scores={"static": None, "permissions": None, "dynamic": None},
        findings=[],
    )
    assert res["overall_score"] == 0.0
    assert res["risk_level"] == "UNKNOWN"
    assert res["coverage_percent"] == 0.0
    assert res["confidence_score"] == 0.0


def test_boundary_single_finding_exact_preservation(engine):
    """A single finding's score is preserved exactly without distortion."""
    single_score = engine.compute_peak_mean([17.5])
    assert single_score == 17.5


def test_boundary_maximum_capping_at_100(engine):
    """Aggregated scores cannot exceed the 100.0 ceiling."""
    capped = engine.compute_peak_mean([150.0, 120.0, 100.0])
    assert capped == 100.0

    res = engine.calculate_overall_risk(
        module_scores={"static": 100.0, "permissions": 100.0},
        findings=[
            Finding(category="STATIC", severity=Severity.CRITICAL, title="C1", description="d", evidence="e", score=100.0),
            Finding(category="PERMISSION", severity=Severity.CRITICAL, title="C2", description="d", evidence="e", score=100.0),
        ],
    )
    assert res["overall_score"] == 100.0
    assert res["risk_level"] == "CRITICAL"


def test_boundary_negative_and_zero_scores(engine):
    """Zero or invalid negative scores do not corrupt calculations."""
    scores = [0.0, -5.0, 20.0]
    calc = engine.compute_peak_mean(scores)
    assert calc == 20.0


# =========================================================================
# 3. Severity vs Confidence Distinction
# =========================================================================

def test_severity_and_confidence_remain_distinct(engine):
    """High severity findings must not artificially inflate confidence when coverage is low."""
    # Only static module completed (coverage = 30%)
    res = engine.calculate_overall_risk(
        module_scores={"static": 85.0, "permissions": None, "dynamic": None, "network": None},
        findings=[
            Finding(
                category="STATIC",
                severity=Severity.CRITICAL,
                title="Critical Keylogger",
                description="desc",
                evidence="ev",
                score=85.0,
            )
        ],
    )
    # Severity / Risk is CRITICAL
    assert res["risk_level"] == "CRITICAL"
    assert res["overall_score"] == 85.0
    # Confidence must reflect incomplete coverage (30% -> 0.30), NOT 1.0!
    assert res["coverage_percent"] == 30.0
    assert res["confidence_score"] == 0.30


# =========================================================================
# 4. Static vs Runtime Evidence Correlation
# =========================================================================

def test_static_vs_runtime_evidence_correlation(engine):
    """Correlates static capabilities with dynamic observation states."""
    findings = [
        Finding(
            category="STATIC",
            severity=Severity.HIGH,
            rule_id="STATIC_DEX_CAMERA",
            title="Camera Hardware Access",
            description="d",
            evidence="e",
            score=15.0,
        ),
        Finding(
            category="STATIC",
            severity=Severity.HIGH,
            rule_id="STATIC_DEX_LOCATION",
            title="Location Tracking",
            description="d",
            evidence="e",
            score=15.0,
        ),
    ]

    # Camera: OBSERVED (Active)
    # Location: NOT_OBSERVED (Dormant)
    # Microphone: OBSERVED but no static (Undocumented runtime activity)
    # SMS: NOT_TESTED (Incomplete evaluation)
    telemetry = MockTelemetryResult(
        categories={
            "CAMERA": MockTelemetryCategory("OBSERVED", count=3),
            "LOCATION": MockTelemetryCategory("NOT_OBSERVED", count=0),
            "MICROPHONE": MockTelemetryCategory("OBSERVED", count=1),
            "SMS": MockTelemetryCategory("NOT_TESTED", count=0),
            "MEDIA_PROJECTION": MockTelemetryCategory("NOT_OBSERVED", count=0),
        }
    )

    corr = engine.correlate_evidence(findings, telemetry)

    assert corr["Camera"] == "CONFIRMED_ACTIVE_SURVEILLANCE"
    assert corr["Location"] == "POTENTIAL_CAPABILITY_DORMANT"
    assert corr["Microphone"] == "UNDOCUMENTED_RUNTIME_ACTIVITY"
    assert corr["SMS / Telephony"] == "INCOMPLETE_DYNAMIC_EVALUATION"
    assert corr["Screen Capture"] == "NOT_DETECTED"


# =========================================================================
# 5. Missing or Failed Telemetry Cannot Lower Risk Score
# =========================================================================

def test_missing_telemetry_never_dilutes_risk(engine):
    """Missing or skipped dynamic analysis leaves module as None and does not lower risk score."""
    # Case A: Static analyzer found severe risk 80.0. Dynamic analysis was not run (None).
    res_static_only = engine.calculate_overall_risk(
        module_scores={"static": 80.0, "permissions": None, "dynamic": None, "network": None},
        findings=[],
    )

    # If dynamic had mistakenly been treated as 0.0 (safe), overall score would drop to 0.60*80 + 0.40*40 = 64.0
    # Because dynamic is None, the overall score remains 80.0.
    assert res_static_only["overall_score"] == 80.0
    assert res_static_only["risk_level"] == "CRITICAL"

    # Coverage should explicitly reflect that dynamic was not executed (30% instead of 100%)
    assert res_static_only["coverage_percent"] == 30.0


# =========================================================================
# 6. Benign Capabilities Do Not Establish Malicious Intent
# =========================================================================

@pytest.mark.parametrize(
    "score,title,rule_id",
    [
        (4.0, "Network & Internet Access", "RULE_PERM_INTERNET"),
        (2.0, "Application Backup Enabled", "STATIC_MANIFEST_BACKUP_ENABLED"),
        (6.0, "Reflection API Invocation Observed", "STATIC_DEX_REFLECTION"),
        (8.0, "Exported Components Without Permission", "STATIC_MANIFEST_UNPROTECTED_EXPORTED"),
        (0.0, "Native Libraries Bundled", "STATIC_NATIVE_LIBRARIES"),
        (10.0, "Debug Certificate Key", "STATIC_CERT_DEBUG_KEY"),
        (12.0, "Insecure Cryptographic Mode", "STATIC_INSECURE_CRYPTO_ECB"),
    ],
)
def test_individual_benign_hygiene_indicators_remain_in_low_risk_band(engine, score, title, rule_id):
    """Individual permissions, reflection, native code, or hygiene flags alone never exceed LOW risk."""
    f = Finding(category="STATIC", severity=Severity.LOW, title=title, description="d", evidence="e", score=score, rule_id=rule_id)
    res = engine.calculate_overall_risk(
        module_scores={"static": score, "permissions": 0.0},
        findings=[f],
    )
    # Peak & mean: 0.60 * score + 0.40 * (score / 2) = 0.80 * score
    assert res["overall_score"] < 25.0
    assert res["risk_level"] == "LOW"
