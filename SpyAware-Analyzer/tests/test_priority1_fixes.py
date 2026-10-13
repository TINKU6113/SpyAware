"""Regression tests for Priority 1 Integration Fixes.

Covers:
- FIX 1: Prevent risk score dilution on analysis failure or unavailability.
- FIX 2: Reject invalid or corrupted APK files at the API boundary.
"""

import io
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from analyzers.dynamic.models import (
    DynamicAnalysisResult,
    ExecutionMetadata,
    Observation,
)
from analyzers.network.models import (
    NetworkAnalysisResult,
    NetworkObservation,
)
from backend.main import app
from backend.models.analysis import Finding, Severity, StaticAnalysisResult, PermissionAnalysisResult
from backend.services.analysis_service import AnalysisService, InvalidAPKError
from risk_engine.engine import RiskEngine

client = TestClient(app)
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
BENIGN_APK = SAMPLES_DIR / "benign_sample.apk"
CORRUPT_APK = SAMPLES_DIR / "malformed_corrupt.apk"
NO_MANIFEST_APK = SAMPLES_DIR / "malformed_no_manifest.apk"


# ==============================================================================
# FIX 1 REGRESSION TESTS: RISK SCORE INTEGRITY & DILUTION PREVENTION
# ==============================================================================

def test_aggregation_baseline_static_80_permission_70():
    """Baseline calculation: static=80.0, permissions=70.0 yields overall 78.0 (CRITICAL)."""
    engine = RiskEngine()
    res = engine.calculate_overall_risk(
        module_scores={
            "static": 80.0,
            "permissions": 70.0,
            "dynamic": None,
            "network": None,
            "ble": None,
        },
        findings=[],
    )
    # 0.60 * 80 + 0.40 * 75 = 48.0 + 30.0 = 78.0
    assert res["overall_score"] == 78.0
    assert res["risk_level"] == "CRITICAL"


def test_failed_dynamic_does_not_dilute_overall_score():
    """When dynamic analysis fails or is unavailable, its score must be None and not dilute risk."""
    service = AnalysisService()

    # Mock static and permission analyzers to return 80 and 70
    mock_static = StaticAnalysisResult(
        apk_filename="test.apk",
        package_name="com.test.app",
        launchable_activity="MainActivity",
        score=80.0,
        is_valid_apk=True,
    )
    mock_perm = PermissionAnalysisResult(
        declared_permissions=["android.permission.CAMERA"],
        score=70.0,
    )
    # Dynamic worker returns UNAVAILABLE with score=0.0
    mock_dyn_unavailable = DynamicAnalysisResult(
        status="UNAVAILABLE",
        score=0.0,
        risk_level="LOW",
        error_message="Host dynamic environment not ready",
    )

    with patch.object(service.static_analyzer, "analyze", return_value=mock_static), \
         patch.object(service.permission_analyzer, "analyze", return_value=mock_perm), \
         patch.object(service.dynamic_worker, "run_analysis", return_value=mock_dyn_unavailable), \
         patch.object(service, "save_report"):

        report = service.analyze_apk_full(
            apk_path=str(BENIGN_APK),
            original_filename="test.apk",
            include_dynamic=True,
            include_network=False,
        )

        # Dynamic score must be excluded (None)
        assert report.module_scores.dynamic is None
        # Overall score must NOT be diluted to 68.0; must remain 78.0
        assert report.overall_score == 78.0
        assert report.risk_level == "CRITICAL"
        # Dynamic details must preserve UNAVAILABLE status and error message
        assert report.dynamic_details.status == "UNAVAILABLE"
        assert "not ready" in report.dynamic_details.error_message


def test_failed_network_does_not_dilute_overall_score():
    """When network analysis fails or is unavailable, its score must be None and not dilute risk."""
    service = AnalysisService()

    mock_static = StaticAnalysisResult(
        apk_filename="test.apk",
        package_name="com.test.app",
        launchable_activity="MainActivity",
        score=80.0,
        is_valid_apk=True,
    )
    mock_perm = PermissionAnalysisResult(
        declared_permissions=["android.permission.INTERNET"],
        score=70.0,
    )
    mock_net_failed = NetworkAnalysisResult(
        module="network",
        stage="2C",
        status="FAILED",
        score=0.0,
        risk_level="LOW",
        error_message="APK installation failed on device",
    )

    with patch.object(service.static_analyzer, "analyze", return_value=mock_static), \
         patch.object(service.permission_analyzer, "analyze", return_value=mock_perm), \
         patch.object(service.network_worker, "run_analysis", return_value=mock_net_failed), \
         patch.object(service, "save_report"):

        report = service.analyze_apk_full(
            apk_path=str(BENIGN_APK),
            original_filename="test.apk",
            include_dynamic=False,
            include_network=True,
        )

        assert report.module_scores.network is None
        assert report.overall_score == 78.0
        assert report.risk_level == "CRITICAL"
        assert report.network_details.status == "FAILED"
        assert "installation failed" in report.network_details.error_message


def test_completed_optional_module_with_genuine_zero_score_remains_included():
    """A genuinely completed module with score 0.0 must be included in aggregation."""
    service = AnalysisService()

    mock_static = StaticAnalysisResult(
        apk_filename="test.apk",
        package_name="com.test.app",
        launchable_activity="MainActivity",
        score=80.0,
        is_valid_apk=True,
    )
    mock_perm = PermissionAnalysisResult(
        declared_permissions=[],
        score=70.0,
    )
    # Successfully completed dynamic run observing zero malicious indicators
    mock_dyn_completed_clean = DynamicAnalysisResult(
        status="COMPLETED",
        score=0.0,
        risk_level="LOW",
        execution=ExecutionMetadata(package_name="com.test.app", launch_success=True),
        findings=[],
    )

    with patch.object(service.static_analyzer, "analyze", return_value=mock_static), \
         patch.object(service.permission_analyzer, "analyze", return_value=mock_perm), \
         patch.object(service.dynamic_worker, "run_analysis", return_value=mock_dyn_completed_clean), \
         patch.object(service, "save_report"):

        report = service.analyze_apk_full(
            apk_path=str(BENIGN_APK),
            original_filename="test.apk",
            include_dynamic=True,
            include_network=False,
        )

        # Score must be 0.0 and active in aggregation
        assert report.module_scores.dynamic == 0.0
        # Active: [80, 70, 0] -> max=80, mean=50 -> 0.60*80 + 0.40*50 = 48 + 20 = 68.0
        assert report.overall_score == 68.0
        assert report.risk_level == "HIGH"


def test_dynamic_only_failure_not_misrepresented_as_low_risk():
    """Failed dynamic-only analysis must yield UNKNOWN risk rather than masquerading as clean."""
    service = AnalysisService()

    mock_static = StaticAnalysisResult(
        apk_filename="benign_sample.apk",
        package_name="com.spyaware.benign",
        launchable_activity="MainActivity",
        is_valid_apk=True,
    )
    mock_dyn_failed = DynamicAnalysisResult(
        status="FAILED",
        score=0.0,
        risk_level="LOW",
        error_message="Emulator boot timed out",
    )

    with patch.object(service.static_analyzer, "analyze", return_value=mock_static), \
         patch.object(service.dynamic_worker, "run_analysis", return_value=mock_dyn_failed), \
         patch.object(service, "save_report"):

        report = service.analyze_dynamic_only(
            apk_path=str(BENIGN_APK),
            original_filename="benign_sample.apk",
        )

        assert report.module_scores.dynamic is None
        assert report.risk_level == "UNKNOWN"
        assert report.dynamic_details.status == "FAILED"
        assert "inconclusive" in report.summary.lower()


def test_network_only_failure_not_misrepresented_as_low_risk():
    """Failed network-only analysis must yield UNKNOWN risk rather than masquerading as clean."""
    service = AnalysisService()

    mock_static = StaticAnalysisResult(
        apk_filename="benign_sample.apk",
        package_name="com.spyaware.benign",
        launchable_activity="MainActivity",
        is_valid_apk=True,
    )
    mock_net_unavail = NetworkAnalysisResult(
        module="network",
        stage="2C",
        status="UNAVAILABLE",
        score=0.0,
        risk_level="LOW",
        error_message="ADB server offline",
    )

    with patch.object(service.static_analyzer, "analyze", return_value=mock_static), \
         patch.object(service.network_worker, "run_analysis", return_value=mock_net_unavail), \
         patch.object(service, "save_report"):

        report = service.analyze_network_only(
            apk_path=str(BENIGN_APK),
            original_filename="benign_sample.apk",
        )

        assert report.module_scores.network is None
        assert report.risk_level == "UNKNOWN"
        assert report.network_details.status == "UNAVAILABLE"
        assert "inconclusive" in report.summary.lower()


# ==============================================================================
# FIX 2 REGRESSION TESTS: REJECT INVALID OR CORRUPTED APK FILES
# ==============================================================================

def test_reject_non_apk_file_full_analysis():
    """Non-APK random file uploaded to /api/analyze is rejected with HTTP 400 Bad Request."""
    fake_content = b"This is not a zip or apk file header."
    response = client.post(
        "/api/analyze",
        files={"file": ("fake_app.apk", io.BytesIO(fake_content), "application/vnd.android.package-archive")},
    )
    assert response.status_code == 400
    assert "Invalid APK" in response.json()["detail"]


def test_reject_corrupted_apk_full_analysis():
    """Corrupted APK uploaded to /api/analyze is rejected with HTTP 400."""
    with open(CORRUPT_APK, "rb") as f:
        response = client.post(
            "/api/analyze",
            files={"file": ("malformed_corrupt.apk", f, "application/octet-stream")},
        )
    assert response.status_code == 400
    assert "Invalid APK" in response.json()["detail"]


def test_reject_missing_manifest_apk_full_analysis():
    """Zip file missing AndroidManifest.xml is rejected with HTTP 400."""
    with open(NO_MANIFEST_APK, "rb") as f:
        response = client.post(
            "/api/analyze",
            files={"file": ("malformed_no_manifest.apk", f, "application/octet-stream")},
        )
    assert response.status_code == 400
    assert "AndroidManifest.xml" in response.json()["detail"]


def test_reject_invalid_apk_static_only():
    """Corrupted APK submitted to /api/analyze/static is rejected with HTTP 400."""
    with open(CORRUPT_APK, "rb") as f:
        response = client.post(
            "/api/analyze/static",
            files={"file": ("malformed_corrupt.apk", f, "application/octet-stream")},
        )
    assert response.status_code == 400
    assert "Invalid APK" in response.json()["detail"]


def test_reject_invalid_apk_dynamic_only():
    """Corrupted APK submitted to /api/analyze/dynamic is rejected with HTTP 400."""
    with open(CORRUPT_APK, "rb") as f:
        response = client.post(
            "/api/analyze/dynamic",
            files={"file": ("malformed_corrupt.apk", f, "application/octet-stream")},
        )
    assert response.status_code == 400
    assert "Invalid APK" in response.json()["detail"]


def test_reject_invalid_apk_network_only():
    """Corrupted APK submitted to /api/analyze/network is rejected with HTTP 400."""
    with open(CORRUPT_APK, "rb") as f:
        response = client.post(
            "/api/analyze/network",
            files={"file": ("malformed_corrupt.apk", f, "application/octet-stream")},
        )
    assert response.status_code == 400
    assert "Invalid APK" in response.json()["detail"]


def test_reject_invalid_apk_permissions_upload():
    """Corrupted APK submitted as multipart upload to /api/analyze/permissions returns 400."""
    with open(CORRUPT_APK, "rb") as f:
        response = client.post(
            "/api/analyze/permissions",
            files={"file": ("malformed_corrupt.apk", f, "application/octet-stream")},
        )
    assert response.status_code == 400
    assert "Invalid APK" in response.json()["detail"]


def test_reject_invalid_apk_sample_preset():
    """Sample preset referencing corrupted file returns HTTP 400."""
    response = client.post("/api/analyze/sample/malformed_corrupt")
    assert response.status_code == 400
    assert "Invalid sample APK" in response.json()["detail"]


def test_invalid_apk_does_not_trigger_downstream_workers_or_save():
    """Invalid APK must abort immediately without calling dynamic, network, or saving."""
    service = AnalysisService()

    with patch.object(service.dynamic_worker, "run_analysis") as mock_dyn, \
         patch.object(service.network_worker, "run_analysis") as mock_net, \
         patch.object(service.permission_analyzer, "analyze") as mock_perm, \
         patch.object(service, "save_report") as mock_save:

        with pytest.raises(InvalidAPKError):
            service.analyze_apk_full(
                apk_path=str(CORRUPT_APK),
                original_filename="corrupt.apk",
                include_dynamic=True,
                include_network=True,
            )

        # None of the downstream modules or saving may be reached
        mock_dyn.assert_not_called()
        mock_net.assert_not_called()
        mock_perm.assert_not_called()
        mock_save.assert_not_called()


def test_valid_apk_analysis_continues_working():
    """Valid APK continues to produce successful full analysis report with 200 OK."""
    with open(BENIGN_APK, "rb") as f:
        response = client.post(
            "/api/analyze",
            files={"file": ("benign_sample.apk", f, "application/vnd.android.package-archive")},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["apk_filename"] == "benign_sample.apk"
    assert data["risk_level"] == "LOW"
    assert data["overall_score"] < 25.0
    assert data["static_details"]["is_valid_apk"] is True
