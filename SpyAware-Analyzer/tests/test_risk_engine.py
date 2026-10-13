"""Unit tests for RiskEngine in SpyAware-Analyzer."""

import pytest
from backend.models.analysis import Finding, Severity
from risk_engine.engine import RiskEngine


@pytest.fixture
def engine():
    return RiskEngine()


def test_risk_classification(engine):
    """Verifies standard 4-tier classification: LOW, MEDIUM, HIGH, CRITICAL."""
    assert engine.classify_risk_level(0.0) == "LOW"
    assert engine.classify_risk_level(24.9) == "LOW"
    assert engine.classify_risk_level(25.0) == "MEDIUM"
    assert engine.classify_risk_level(49.9) == "MEDIUM"
    assert engine.classify_risk_level(50.0) == "HIGH"
    assert engine.classify_risk_level(74.9) == "HIGH"
    assert engine.classify_risk_level(75.0) == "CRITICAL"
    assert engine.classify_risk_level(100.0) == "CRITICAL"


def test_empty_findings_risk(engine):
    """Empty findings produce 0 score and LOW classification."""
    res = engine.calculate_overall_risk(
        module_scores={"static": 0.0, "permissions": 0.0},
        findings=[],
    )
    assert res["overall_score"] == 0.0
    assert res["risk_level"] == "LOW"
    assert "LOW risk" in res["summary"]


def test_single_module_evaluation(engine):
    """When only one module is evaluated, its score is directly preserved."""
    res = engine.calculate_overall_risk(
        module_scores={"static": None, "permissions": 60.0},
        findings=[],
    )
    assert res["overall_score"] == 60.0
    assert res["risk_level"] == "HIGH"


def test_multi_module_aggregation_and_bounds(engine):
    """Formula weighs peak and average, never exceeding 100."""
    res = engine.calculate_overall_risk(
        module_scores={"static": 70.0, "permissions": 80.0},
        findings=[],
    )
    # 0.60 * 80 + 0.40 * 75 = 48 + 30 = 78.0
    assert res["overall_score"] == 78.0
    assert res["risk_level"] == "CRITICAL"

    # Extreme boundary check
    res_max = engine.calculate_overall_risk(
        module_scores={"static": 100.0, "permissions": 100.0},
        findings=[],
    )
    assert res_max["overall_score"] == 100.0


def test_future_modules_graceful_handling(engine):
    """Future dynamic/network/ble modules set to None do not break risk calculation."""
    res = engine.calculate_overall_risk(
        module_scores={
            "static": 30.0,
            "permissions": 40.0,
            "dynamic": None,
            "network": None,
            "ble": None,
        },
        findings=[],
    )
    # active: 30, 40 -> max=40, mean=35 -> 0.60*40 + 0.40*35 = 24 + 14 = 38.0
    assert res["overall_score"] == 38.0
    assert res["risk_level"] == "MEDIUM"
