"""Validation package for SpyAware-Analyzer.

Provides deterministic validation corpus, test harness, and performance metrics.
"""

from analyzers.validation.models import (
    ConfusionMatrixMetrics,
    DynamicReadiness,
    ExpectedRuleMatch,
    MetricValue,
    RuleEvaluation,
    TestCaseResult,
    ValidationCategory,
    ValidationHarnessReport,
    ValidationTestCase,
)

__all__ = [
    "ValidationCategory",
    "ExpectedRuleMatch",
    "ValidationTestCase",
    "RuleEvaluation",
    "TestCaseResult",
    "MetricValue",
    "ConfusionMatrixMetrics",
    "DynamicReadiness",
    "ValidationHarnessReport",
]
