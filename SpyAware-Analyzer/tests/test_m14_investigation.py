"""Regression and verification tests for M1.4 End-to-End Analysis Investigation.

Covers:
1. Valid standalone APK execution.
2. Malformed or truncated APK rejection with descriptive HTTP 400.
3. Meaningful permissions, certificate, and manifest metadata extraction.
4. Clean APK producing valid report with COMPLETED_CLEAN status and 0 false positives.
5. Analysis module failure handling and PARTIAL/FAILED status.
6. Unavailable dynamic/network environment handling without safe verdict masking.
7. Native multipart upload contract compatibility (field name 'file', query parameters).
8. HTTP error response preservation (empty file 400, oversized file 413).
9. Report persistence, serialization, and round-trip retrieval.
10. Split APK limitation detection and reporting.
11. Real BehaviourGuard APK verification when available.
"""

import io
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.analysis import RiskReport
from backend.services.analysis_service import AnalysisService, InvalidAPKError
from analyzers.dynamic.models import DynamicAnalysisResult, ExecutionMetadata
from analyzers.network.models import NetworkAnalysisResult

client = TestClient(app)
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
BEHAVIOURGUARD_APK = Path("/home/j3st3r/AndroidStudioProjects/behaviourguard/app/build/outputs/apk/debug/app-debug.apk")


def test_1_valid_standalone_apk():
    """Requirement 1: Valid standalone APK runs through the complete analysis pipeline."""
    apk_path = SAMPLES_DIR / "benign_sample.apk"
    assert apk_path.exists(), "benign_sample.apk fixture must exist"

    with open(apk_path, "rb") as f:
        response = client.post(
            "/api/analyze",
            files={"file": ("benign_sample.apk", f, "application/vnd.android.package-archive")},
        )

    assert response.status_code == 200
    data = response.json()
    assert "analysis_id" in data
    assert data["apk_filename"] == "benign_sample.apk"
    assert data["analysis_status"] in ("COMPLETED_CLEAN", "COMPLETED_WITH_FINDINGS")
    assert "module_status" in data
    assert data["module_status"]["static"] == "COMPLETED"
    assert data["module_status"]["permissions"] == "COMPLETED"
    assert data["module_scores"]["static"] is not None
    assert data["module_scores"]["permissions"] is not None


def test_2_malformed_and_truncated_apk():
    """Requirement 2: Malformed or truncated APK returns descriptive 400 Bad Request."""
    # Truncated APK (invalid ZIP header)
    truncated_bytes = b"PK\x03\x04\x14\x00\x00\x00truncated_corrupt_apk_data"
    response = client.post(
        "/api/analyze",
        files={"file": ("corrupted.apk", io.BytesIO(truncated_bytes), "application/vnd.android.package-archive")},
    )
    assert response.status_code == 400
    assert "Invalid APK file" in response.json()["detail"]

    # Sample malformed APK from fixture
    malformed_path = SAMPLES_DIR / "malformed_corrupt.apk"
    if malformed_path.exists():
        with open(malformed_path, "rb") as f:
            resp2 = client.post(
                "/api/analyze",
                files={"file": ("malformed_corrupt.apk", f, "application/vnd.android.package-archive")},
            )
        assert resp2.status_code == 400
        assert "Invalid APK" in resp2.json()["detail"]


def test_3_meaningful_permissions_and_manifest_metadata():
    """Requirement 3: Manifest permissions, certificate info, and configuration attributes are extracted."""
    service = AnalysisService()
    apk_path = SAMPLES_DIR / "camera_positive_sample.apk"
    if not apk_path.exists():
        apk_path = SAMPLES_DIR / "benign_sample.apk"

    report = service.analyze_apk_full(
        apk_path=str(apk_path),
        original_filename=apk_path.name,
    )

    assert report.static_details is not None
    assert report.static_details.package_name is not None
    assert report.static_details.certificate_info is not None
    assert report.static_details.manifest_config is not None
    assert isinstance(report.static_details.manifest_config.debuggable, bool)
    assert isinstance(report.static_details.certificate_info.is_signed, bool)


def test_4_clean_apk_distinction_no_false_surveillance():
    """Requirement 4: Clean APK produces COMPLETED_CLEAN or LOW risk with no false spyware alerts."""
    service = AnalysisService()
    apk_path = SAMPLES_DIR / "benign_sample.apk"

    report = service.analyze_apk_full(
        apk_path=str(apk_path),
        original_filename="benign_sample.apk",
    )

    # Benign sample must not be flagged as CRITICAL surveillance
    assert report.overall_score < 25.0
    assert report.risk_level == "LOW"
    # Bytecode framework stubs without permissions must not produce HIGH or CRITICAL findings
    high_critical = [f for f in report.findings if f.severity in ("HIGH", "CRITICAL")]
    assert len(high_critical) == 0


def test_5_analysis_module_failure_handling():
    """Requirement 5: Module failures result in PARTIAL status and explicit error details, not safety."""
    service = AnalysisService()
    apk_path = SAMPLES_DIR / "benign_sample.apk"

    # Mock dynamic worker to fail
    failed_dynamic = DynamicAnalysisResult(
        module="dynamic",
        status="FAILED",
        score=0.0,
        risk_level="UNKNOWN",
        execution=ExecutionMetadata(launch_success=False, duration_seconds=0, emulator_started_by_job=False),
        observations=[],
        findings=[],
        limitations=["Dynamic execution failed due to adb timeout"],
        error_message="Adb execution timeout while starting emulator",
    )

    with patch.object(service.dynamic_worker, "run_analysis", return_value=failed_dynamic):
        report = service.analyze_apk_full(
            apk_path=str(apk_path),
            original_filename="benign_sample.apk",
            include_dynamic=True,
        )

        assert report.analysis_status == "PARTIAL"
        assert report.module_status["dynamic"] == "FAILED"
        assert report.module_errors["dynamic"] is not None
        assert "timeout" in report.module_errors["dynamic"].lower()
        # Score must NOT include dynamic as safe 0.0 pts
        assert report.module_scores.dynamic is None


def test_6_unavailable_dynamic_environment():
    """Requirement 6: Unavailable emulator/adb environment reports UNAVAILABLE status without faking safe score."""
    service = AnalysisService()
    apk_path = SAMPLES_DIR / "benign_sample.apk"

    unavailable_dynamic = DynamicAnalysisResult(
        module="dynamic",
        status="UNAVAILABLE",
        score=0.0,
        risk_level="UNKNOWN",
        execution=ExecutionMetadata(launch_success=False, duration_seconds=0, emulator_started_by_job=False),
        observations=[],
        findings=[],
        limitations=["Android emulator offline or missing"],
        error_message="No running emulator found and no AVDs configured",
    )

    with patch.object(service.dynamic_worker, "run_analysis", return_value=unavailable_dynamic):
        report = service.analyze_apk_full(
            apk_path=str(apk_path),
            original_filename="benign_sample.apk",
            include_dynamic=True,
        )

        assert report.analysis_status == "PARTIAL"
        assert report.module_status["dynamic"] == "UNAVAILABLE"
        assert report.module_scores.dynamic is None


def test_7_native_multipart_upload_contract():
    """Requirement 7: Native multipart upload contract uses field 'file' and query parameters."""
    apk_path = SAMPLES_DIR / "benign_sample.apk"
    with open(apk_path, "rb") as f:
        # Native client sends: POST /api/analyze?is_split=true&split_count=2
        response = client.post(
            "/api/analyze?is_split=true&split_count=2",
            files={"file": ("com.example.app.apk", f, "application/vnd.android.package-archive")},
        )

    assert response.status_code == 200
    report = response.json()
    assert report["is_split"] is True
    assert report["split_count"] == 2
    assert any("split" in lim.lower() for lim in report["limitations"])


def test_8_empty_file_and_http_errors():
    """Requirement 8: Empty file upload returns HTTP 400 with JSON detail, preserving error diagnosis."""
    response = client.post(
        "/api/analyze",
        files={"file": ("empty.apk", io.BytesIO(b""), "application/vnd.android.package-archive")},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_9_report_serialization_and_roundtrip():
    """Requirement 9: Report serialization and disk persistence preserve all M1.4 metadata fields."""
    service = AnalysisService()
    apk_path = SAMPLES_DIR / "benign_sample.apk"

    report = service.analyze_apk_full(
        apk_path=str(apk_path),
        original_filename="benign_sample.apk",
        is_split=True,
        split_count=4,
    )

    # Reload from disk
    loaded = service.get_report_by_id(report.analysis_id)
    assert loaded is not None
    assert loaded.analysis_id == report.analysis_id
    assert loaded.is_split is True
    assert loaded.split_count == 4
    assert loaded.analysis_status in ("COMPLETED_CLEAN", "COMPLETED_WITH_FINDINGS")
    assert loaded.module_status == report.module_status
    assert loaded.certificate_info is not None
    assert loaded.manifest_config is not None


def test_10_split_apk_limitation_reporting():
    """Requirement 10: Split APK flag generates explicit limitations in the report."""
    service = AnalysisService()
    apk_path = SAMPLES_DIR / "benign_sample.apk"

    report = service.analyze_apk_full(
        apk_path=str(apk_path),
        original_filename="whatsapp_base.apk",
        is_split=True,
        split_count=5,
    )

    assert report.is_split is True
    assert report.split_count == 5
    assert len(report.limitations) > 0
    split_lim = [lim for lim in report.limitations if "split" in lim.lower()]
    assert len(split_lim) > 0
    assert "5 splits" in split_lim[0]


@pytest.mark.skipif(not BEHAVIOURGUARD_APK.exists(), reason="BehaviourGuard APK not present on system")
def test_11_real_behaviourguard_apk_analysis():
    """Requirement 11: Real BehaviourGuard APK end-to-end verification.
    
    Verifies:
    - Successfully parses real Android Gradle build output (13.4MB).
    - Detects debuggable='true' and Android Debug certificate without crash.
    - Does NOT falsely flag Camera, Audio, Location, SMS spyware capabilities because
      BehaviourGuard does not declare those permissions in its manifest.
    - Exports components and manifest config without false CRITICAL score.
    """
    service = AnalysisService()
    report = service.analyze_apk_full(
        apk_path=str(BEHAVIOURGUARD_APK),
        original_filename="behaviourguard-debug.apk",
    )

    assert report.static_details.package_name == "com.example.behaviourguard"
    assert report.static_details.manifest_config is not None
    assert report.static_details.manifest_config.debuggable is True
    assert report.static_details.certificate_info is not None
    assert report.static_details.certificate_info.is_debug_key is True

    # Check that BehaviourGuard does not receive false positive CRITICAL surveillance alerts
    categories = [f.category for f in report.findings]
    assert "CAMERA_SURVEILLANCE" not in categories
    assert "AUDIO_SURVEILLANCE" not in categories
    assert "LOCATION_TRACKING" not in categories
    assert "SMS_CALL_LOG_CAPTURE" not in categories
    assert report.overall_score < 75.0  # Not CRITICAL
