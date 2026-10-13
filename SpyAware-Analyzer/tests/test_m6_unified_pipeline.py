"""Tests for Milestone M6 — Unified Integration & Pipeline Reliability.

Verifies:
1. Execution profiles: QUICK (5s), STANDARD (15s), EXTENDED (30s), STATIC_ONLY.
2. Profile-driven dynamic and network timeout calibration.
3. STATIC_ONLY profile cleanly skipping dynamic and network stages with SKIPPED module status.
4. Compatibility details attachment to RiskReport.
5. Markdown report export rendering profile, duration, and Android Execution Compatibility.
6. JSON report and export URLs population.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from backend.services.analysis_service import AnalysisService
from analyzers.dynamic.models import DynamicAnalysisResult
from analyzers.network.models import NetworkAnalysisResult


@pytest.fixture
def analysis_service(tmp_path):
    return AnalysisService(reports_dir=tmp_path)


def test_analysis_profiles_configuration(analysis_service):
    """Verifies profile mapping to execution durations and stage skipping."""
    # QUICK
    assert analysis_service._get_profile_duration("QUICK") == 5
    # STANDARD
    assert analysis_service._get_profile_duration("STANDARD") == 15
    # EXTENDED
    assert analysis_service._get_profile_duration("EXTENDED") == 30
    # Fallback / Default
    assert analysis_service._get_profile_duration("UNKNOWN") == 15


def test_static_only_profile_skips_dynamic_and_network(analysis_service):
    """STATIC_ONLY profile explicitly bypasses dynamic and network modules."""
    analysis_service.dynamic_worker = MagicMock()
    analysis_service.network_worker = MagicMock()

    report = analysis_service.analyze_apk_full(
        apk_path="samples/benign_sample.apk",
        original_filename="benign_sample.apk",
        analysis_profile="STATIC_ONLY",
        include_dynamic=True,
        include_network=True,
    )

    assert report.analysis_profile == "STATIC_ONLY"
    assert report.module_status["dynamic"] in ("NOT_REQUESTED", "SKIPPED")
    assert report.module_status["network"] in ("NOT_REQUESTED", "SKIPPED")
    assert report.module_scores.dynamic is None
    assert report.module_scores.network is None
    assert analysis_service.dynamic_worker.run_analysis.call_count == 0
    assert analysis_service.network_worker.run_analysis.call_count == 0


def test_profile_duration_passed_to_dynamic_and_network(analysis_service):
    """Profile specifies the dynamic test window and network capture duration."""
    analysis_service.dynamic_worker = MagicMock()
    analysis_service.dynamic_worker.run_analysis.return_value = DynamicAnalysisResult(
        status="COMPLETED", score=0.0, risk_level="LOW"
    )
    analysis_service.network_worker = MagicMock()
    analysis_service.network_worker.run_analysis.return_value = NetworkAnalysisResult(
        status="COMPLETED", score=0.0, risk_level="LOW"
    )

    report = analysis_service.analyze_apk_full(
        apk_path="samples/benign_sample.apk",
        original_filename="benign_sample.apk",
        analysis_profile="EXTENDED",
        include_dynamic=True,
        include_network=True,
    )

    assert report.analysis_profile == "EXTENDED"
    # Dynamic worker should be called with observation_seconds=30
    _, dyn_kwargs = analysis_service.dynamic_worker.run_analysis.call_args
    assert dyn_kwargs.get("observation_seconds") == 30

    # Network worker should be called with capture_seconds=30
    _, net_kwargs = analysis_service.network_worker.run_analysis.call_args
    assert net_kwargs.get("capture_seconds") == 30


def test_report_contains_compatibility_and_exports(analysis_service):
    """RiskReport includes compatibility details, duration_seconds, and export URLs."""
    report = analysis_service.analyze_apk_full(
        apk_path="samples/benign_sample.apk",
        original_filename="benign_sample.apk",
        analysis_profile="QUICK",
        include_dynamic=False,
        include_network=False,
    )

    assert report.compatibility_details is not None
    assert hasattr(report.compatibility_details, "overall_status") or isinstance(report.compatibility_details, dict)
    assert report.duration_seconds is not None
    assert report.duration_seconds >= 0.0
    assert report.export_markdown_url == f"/api/analysis/{report.analysis_id}/export/markdown"
    assert report.export_json_url == f"/api/analysis/{report.analysis_id}"

    # Verify markdown export includes profile and compatibility
    md = analysis_service.generate_markdown_report(report)
    assert "QUICK" in md
    assert "Android Execution Compatibility" in md
    assert "Execution Duration" in md
