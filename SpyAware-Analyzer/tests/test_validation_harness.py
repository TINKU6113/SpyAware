"""Unit and integration regression tests for the Validation Corpus and Harness.

Milestone M4: Detection Validation and Analysis Accuracy.
Verifies:
1. Zero-division guards and undefined metric state representation.
2. Confusion matrix computations.
3. Corpus builder generation for all 12 test fixtures.
4. End-to-end execution of validation cases through the harness.
5. Secret redaction verification on embedded credential samples.
6. Malformed archive error containment.
"""

from pathlib import Path
import pytest

from analyzers.validation.corpus import VALIDATION_CORPUS_CASES, build_validation_corpus
from analyzers.validation.harness import (
    ValidationHarness,
    compute_confusion_matrix,
    compute_metric,
)
from analyzers.validation.models import ValidationCategory


def test_metric_zero_division_guard():
    """Undefined mathematical states are explicitly preserved instead of crashing or returning zero."""
    m_valid = compute_metric(8, 10, "undefined")
    assert m_valid.is_defined is True
    assert m_valid.value == 0.8
    assert m_valid.explanation is None

    m_undef = compute_metric(0, 0, "Undefined: denominator is zero.")
    assert m_undef.is_defined is False
    assert m_undef.value is None
    assert "denominator is zero" in m_undef.explanation


def test_confusion_matrix_with_zero_detections():
    """When no positive detections occur, precision is explicitly undefined, not 0.0 or 1.0."""
    cm = compute_confusion_matrix(tp=0, tn=10, fp=0, fn=2)
    assert cm.true_positives == 0
    assert cm.precision.is_defined is False
    assert cm.precision.value is None
    assert "denominator (TP + FP) is zero" in cm.precision.explanation

    assert cm.recall.is_defined is True
    assert cm.recall.value == 0.0  # 0 / (0 + 2) = 0.0
    assert cm.false_positive_rate.value == 0.0  # 0 / (0 + 10) = 0.0
    assert cm.false_negative_rate.value == 1.0  # 2 / (0 + 2) = 1.0


def test_confusion_matrix_perfect_score():
    """Evaluates standard confusion matrix metrics when all denominators are non-zero."""
    cm = compute_confusion_matrix(tp=10, tn=20, fp=0, fn=0)
    assert cm.accuracy.value == 1.0
    assert cm.precision.value == 1.0
    assert cm.recall.value == 1.0
    assert cm.f1_score.value == 1.0
    assert cm.false_positive_rate.value == 0.0
    assert cm.false_negative_rate.value == 0.0


def test_corpus_definitions_catalog():
    """Ensures deterministic test cases covering all required validation categories."""
    assert len(VALIDATION_CORPUS_CASES) >= 12
    cats = {c.category for c in VALIDATION_CORPUS_CASES}
    assert cats == set(ValidationCategory)


def test_corpus_fixtures_exist():
    """Ensures all corpus fixtures are generated and accessible."""
    paths = build_validation_corpus()
    assert len(paths) == len(VALIDATION_CORPUS_CASES)
    for case in VALIDATION_CORPUS_CASES:
        p = paths.get(case.case_id)
        assert p is not None, f"Missing path for {case.case_id}"
        assert p.exists(), f"File does not exist: {p}"
        assert p.stat().st_size > 0, f"File is empty: {p}"


def test_harness_single_benign_case(tmp_path):
    """Executes TC01 (Benign Manifest Permissions) and verifies expected rule and LOW score."""
    harness = ValidationHarness(reports_dir=tmp_path)
    paths = build_validation_corpus()
    case01 = next(c for c in VALIDATION_CORPUS_CASES if c.case_id == "TC_01_BENIGN_PERMISSIONS")
    res = harness.execute_test_case(case01, paths[case01.case_id])

    assert res.passed is True
    assert "RULE_PERM_INTERNET" in res.matched_rules
    assert len(res.missing_rules) == 0
    assert len(res.prohibited_violations) == 0
    assert res.predicted_risk_level == "LOW"


def test_harness_credential_redaction_verification(tmp_path):
    """Executes TC10 and ensures synthetic keys are never exposed in unredacted plaintext."""
    harness = ValidationHarness(reports_dir=tmp_path)
    paths = build_validation_corpus()
    case10 = next(c for c in VALIDATION_CORPUS_CASES if c.case_id == "TC_10_EMBEDDED_CREDENTIALS")
    res = harness.execute_test_case(case10, paths[case10.case_id])

    assert res.passed is True
    assert "STATIC_SECRET_HARDCODED_KEY" in res.matched_rules
    assert res.redaction_verified is True


def test_harness_malformed_archive_resilience(tmp_path):
    """Executes TC11 and ensures corrupt archive is handled gracefully without unhandled crash."""
    harness = ValidationHarness(reports_dir=tmp_path)
    paths = build_validation_corpus()
    case11 = next(c for c in VALIDATION_CORPUS_CASES if c.case_id == "TC_11_MALFORMED_ARCHIVE")
    res = harness.execute_test_case(case11, paths[case11.case_id])

    assert res.passed is True
    assert "STATIC_INVALID_ZIP_ARCHIVE" in res.matched_rules
    assert res.ground_truth == "MALFORMED"


def test_harness_dynamic_readiness_audit():
    """Audits dynamic readiness when no devices are connected."""
    harness = ValidationHarness()
    dyn = harness.audit_dynamic_readiness()
    assert dyn.status in ("VERIFIED", "BLOCKED")
    assert "attribution" in dyn.attribution_audit.lower()
    assert "lifecycle" in dyn.lifecycle_audit.lower()


def test_harness_run_all_e2e(tmp_path):
    """Executes full harness and verifies report generation and metrics."""
    harness = ValidationHarness(reports_dir=tmp_path)
    rep = harness.run_all()

    assert rep.total_cases == len(VALIDATION_CORPUS_CASES)
    assert rep.passed_cases == len(VALIDATION_CORPUS_CASES)
    assert rep.failed_cases == 0
    assert rep.rule_level_metrics.precision.value == 1.0
    assert rep.rule_level_metrics.recall.value == 1.0
    assert rep.classification_metrics.precision.value == 1.0
    assert rep.classification_metrics.recall.value == 1.0
    assert rep.redaction_audit_passed is True
    assert (tmp_path / "validation_results.json").exists()
