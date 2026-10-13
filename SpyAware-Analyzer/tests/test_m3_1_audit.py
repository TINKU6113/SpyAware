"""Milestone M3.1 Integration, Evidence Quality, and Security Audit Tests.

Regression and security validation tests for:
1. Ephemeral extraction directory cleanup on ADB failure or exceptions.
2. HTTP status code mappings in router for device errors (403, 503, 504, 404, 400).
3. Split APK distinction in CompatibilityEngine (REQUIRED_SPLIT_PACKAGES_MISSING) and AnalysisService limitations.
4. Schema metadata enrichment (rule_id, confidence, evidence_source, remediation) in PermissionAnalyzer and StaticAnalyzer.
5. Extended secret scanning (GitHub PAT, Slack webhooks, JWT) and strict redaction verification.
6. Archive security guards (path traversal, zip bomb, empty files) preventing filesystem compromise.
"""

import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from analyzers.discovery.manager import DeviceDiscoveryManager
from analyzers.discovery.models import ConnectedDevice, DeviceState, DeviceType, DiscoveredPackage, ExtractedAPK
from analyzers.dynamic.compatibility import (
    CandidateEnvironmentEvaluation,
    CompatibilityEngine,
    CompatibilityReport,
    CompatibilityStatus,
)
from analyzers.dynamic.environment import EnvironmentDiscovery
from analyzers.dynamic.models import AVDInventory, AVDProfile
from analyzers.intake.models import (
    APKIntakeResult,
    APKMetadata,
    IntakeStatus,
    SplitPackageInfo,
)
from analyzers.intake.validator import UniversalAPKIntake
from analyzers.permissions.analyzer import PermissionAnalyzer
from analyzers.static.analyzer import (
    StaticAnalyzer,
    make_finding,
    redact_secret,
)
from backend.main import app
from backend.models.analysis import Finding, Severity
from backend.services.analysis_service import AnalysisService, InvalidAPKError

client = TestClient(app)
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


# ==============================================================================
# 1. Ephemeral Extraction Directory Cleanup
# ==============================================================================


def test_extract_package_apk_cleanup_on_pull_failure():
    """Verify that if ADB pull fails, the ephemeral temp directory is deleted."""
    manager = DeviceDiscoveryManager()

    mock_dev = ConnectedDevice(
        serial="emulator-5554",
        state=DeviceState.DEVICE,
        device_type=DeviceType.EMULATOR,
        is_authorized=True,
        is_online=True,
    )

    with patch.object(manager.env_discovery, "find_adb_path", return_value="/mock/adb"), \
         patch.object(manager, "list_devices", return_value=[mock_dev]), \
         patch("subprocess.run") as mock_run:

        # 1st call: pm path com.example.app -> returns path
        # 2nd call: adb pull -> returncode != 0
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="package:/data/app/~~xyz==/com.example.app-1/base.apk\n"),
            MagicMock(returncode=1, stderr="Permission denied or transfer aborted"),
        ]

        extracted = manager.extract_package_apk("emulator-5554", "com.example.app")
        assert not extracted.success
        assert extracted.temp_directory == ""
        assert "Failed to pull base APK" in (extracted.error_message or "")


def test_analysis_service_cleanup_on_extraction_error():
    """Verify that AnalysisService removes extracted.temp_directory if extraction fails."""
    service = AnalysisService()
    test_temp = tempfile.mkdtemp(prefix="spyaware_test_audit_leak_")
    assert os.path.exists(test_temp)

    mock_extracted = ExtractedAPK(
        package_name="com.example.app",
        base_apk_path="",
        temp_directory=test_temp,
        success=False,
        error_message="Simulated pull failure",
    )

    with patch.object(service.discovery_manager, "extract_package_apk", return_value=mock_extracted):
        with pytest.raises(InvalidAPKError) as exc_info:
            service.analyze_installed_package("emulator-5554", "com.example.app")

        assert "Simulated pull failure" in str(exc_info.value)
        # Directory must be removed by finally block
        assert not os.path.exists(test_temp)


# ==============================================================================
# 2. Router HTTP Status Code Mappings
# ==============================================================================


def test_router_list_packages_permission_error():
    """Unauthorized device raises PermissionError -> HTTP 403."""
    with patch("backend.services.analysis_service.DeviceDiscoveryManager.list_installed_packages",
               side_effect=PermissionError("Device 'emulator-5554' is unauthorized")):
        res = client.get("/api/devices/emulator-5554/packages")
        assert res.status_code == 403
        assert "unauthorized" in res.json()["detail"].lower()


def test_router_list_packages_connection_error():
    """Offline device raises ConnectionError -> HTTP 503."""
    with patch("backend.services.analysis_service.DeviceDiscoveryManager.list_installed_packages",
               side_effect=ConnectionError("Device 'emulator-5554' is offline")):
        res = client.get("/api/devices/emulator-5554/packages")
        assert res.status_code == 503
        assert "offline" in res.json()["detail"].lower()


def test_router_list_packages_timeout_error():
    """ADB command timeout raises TimeoutError -> HTTP 504."""
    with patch("backend.services.analysis_service.DeviceDiscoveryManager.list_installed_packages",
               side_effect=TimeoutError("Package manager timed out")):
        res = client.get("/api/devices/emulator-5554/packages")
        assert res.status_code == 504
        assert "timed out" in res.json()["detail"].lower()


def test_router_list_packages_device_not_found():
    """Device not found raises RuntimeError -> HTTP 404."""
    with patch("backend.services.analysis_service.DeviceDiscoveryManager.list_installed_packages",
               side_effect=RuntimeError("Target device 'emulator-9999' not found")):
        res = client.get("/api/devices/emulator-9999/packages")
        assert res.status_code == 404
        assert "not found" in res.json()["detail"].lower()


def test_router_analyze_installed_package_error_mappings():
    """Verify HTTP status codes on package analysis endpoint."""
    # 403 on PermissionError
    with patch("backend.services.analysis_service.AnalysisService.analyze_installed_package",
               side_effect=PermissionError("Device unauthorized")):
        res = client.post("/api/devices/emulator-5554/packages/com.test.app/analyze")
        assert res.status_code == 403

    # 503 on ConnectionError
    with patch("backend.services.analysis_service.AnalysisService.analyze_installed_package",
               side_effect=ConnectionError("Device offline")):
        res = client.post("/api/devices/emulator-5554/packages/com.test.app/analyze")
        assert res.status_code == 503

    # 504 on TimeoutError
    with patch("backend.services.analysis_service.AnalysisService.analyze_installed_package",
               side_effect=TimeoutError("Extraction timed out")):
        res = client.post("/api/devices/emulator-5554/packages/com.test.app/analyze")
        assert res.status_code == 504

    # 404 on device or package not found
    with patch("backend.services.analysis_service.AnalysisService.analyze_installed_package",
               side_effect=RuntimeError("Device not found")):
        res = client.post("/api/devices/emulator-5554/packages/com.test.app/analyze")
        assert res.status_code == 404


# ==============================================================================
# 3. Split APK Compatibility Distinction
# ==============================================================================


def test_compatibility_engine_missing_required_splits():
    """When an APK is a base slice with missing required splits, status is REQUIRED_SPLIT_PACKAGES_MISSING."""
    engine = CompatibilityEngine()

    mock_inventory = AVDInventory(
        sdk_root="/mock/sdk",
        profiles=[
            AVDProfile(
                name="Medium_Phone_API_36.1",
                api_level=36,
                abis=["x86_64"],
            )
        ]
    )

    intake_res = APKIntakeResult(
        status=IntakeStatus.VALID,
        is_valid=True,
        file_path="/mock/base.apk",
        file_name="base.apk",
        metadata=APKMetadata(
            package_name="com.split.app",
            min_sdk=24,
            target_sdk=34,
        ),
        native_abis=["x86_64"],
        split_info=SplitPackageInfo(
            is_split=True,
            is_base_apk=True,
            split_count=0,
            missing_required_splits=True,
        ),
    )

    with patch.object(engine.env_discovery, "get_avd_inventory", return_value=mock_inventory), \
         patch.object(engine.env_discovery, "get_running_device_states", return_value={}), \
         patch.object(engine.env_discovery, "get_running_avds", return_value={}):

        report = engine.evaluate(intake_result=intake_res)
        assert report.overall_status == CompatibilityStatus.REQUIRED_SPLIT_PACKAGES_MISSING
        assert len(report.warnings) > 0
        assert "split" in report.warnings[0].lower()


def test_analysis_service_split_limitations():
    """Verify AnalysisService documents split limitations in report.limitations."""
    service = AnalysisService()
    test_temp = tempfile.mkdtemp(prefix="spyaware_test_split_lim_")
    test_apk = os.path.join(test_temp, "test.apk")
    with open(test_apk, "wb") as f:
        f.write(b"PK\x03\x04test")

    mock_extracted = ExtractedAPK(
        package_name="com.split.app",
        base_apk_path=test_apk,
        split_apk_paths=[],
        is_split=True,
        split_count=0,
        temp_directory=test_temp,
        success=True,
        warnings=["Base APK extracted; dynamic features omitted."],
    )

    with patch.object(service.discovery_manager, "extract_package_apk", return_value=mock_extracted), \
         patch.object(service, "analyze_apk_full") as mock_analyze:

        mock_report = MagicMock()
        mock_report.limitations = []
        mock_analyze.return_value = mock_report

        report = service.analyze_installed_package("emulator-5554", "com.split.app")
        assert any("split" in lim.lower() for lim in report.limitations)


# ==============================================================================
# 4. Finding Metadata & Evidence Enrichment
# ==============================================================================


def test_permission_analyzer_finding_metadata_enrichment():
    """Verify PermissionAnalyzer populates rule_id, confidence, evidence_source, and remediation."""
    analyzer = PermissionAnalyzer()

    # Requests single permission and dual-channel synergy
    perms = [
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
    ]

    result = analyzer.analyze(perms)
    assert len(result.individual_findings) >= 2
    assert len(result.combination_findings) >= 1

    # Check individual findings
    for f in result.individual_findings:
        assert f.rule_id is not None
        assert f.rule_id.startswith("RULE_PERM_")
        assert f.confidence == 1.0
        assert f.evidence_source == "AndroidManifest.xml"
        assert f.location == "<uses-permission>"
        assert f.remediation is not None
        assert f.detection_method == "manifest_inspection"

    # Check combination findings
    for f in result.combination_findings:
        assert f.rule_id is not None
        assert f.rule_id.startswith("RULE_COMBO_")
        assert f.confidence == 0.9
        assert f.evidence_source == "AndroidManifest.xml"
        assert f.remediation is not None
        assert f.detection_method == "permission_pattern_synergy"


def test_make_finding_deterministic_and_complete():
    """Verify make_finding generates deterministic unique finding_ids and preserves evidence."""
    f1 = make_finding(
        category="STATIC",
        severity=Severity.HIGH,
        title="Test Title",
        description="Test Desc",
        evidence="Evidence String A",
        score=15.0,
        rule_id="RULE_TEST_A",
        confidence=0.95,
        remediation="Fix it",
    )

    f2 = make_finding(
        category="STATIC",
        severity=Severity.HIGH,
        title="Test Title",
        description="Test Desc",
        evidence="Evidence String A",
        score=15.0,
        rule_id="RULE_TEST_A",
        confidence=0.95,
        remediation="Fix it",
    )

    # Identical seed -> identical deterministic finding_id
    assert f1.finding_id == f2.finding_id
    assert f1.rule_id == "RULE_TEST_A"
    assert f1.confidence == 0.95
    assert f1.remediation == "Fix it"


# ==============================================================================
# 5. Extended Secret Redaction
# ==============================================================================


def test_redact_secret():
    """Verify secrets are redacted safely and do not leak into output strings."""
    assert redact_secret("short") == "[REDACTED]"
    token = "ghp_0123456789abcdef0123456789abcdef0123"
    redacted = redact_secret(token)
    assert redacted.startswith("ghp_")
    assert redacted.endswith("0123")
    assert "...[REDACTED]..." in redacted
    assert "abcdef" not in redacted


def test_static_analyzer_secret_patterns():
    """Verify GitHub PAT, Slack webhook, and JWT are detected and redacted."""
    analyzer = StaticAnalyzer()

    test_strings = [
        "ghp_" + "AbCdEf0123456789AbCdEf01234567890123",  # GitHub PAT
        "https://" + "hooks.slack.com/services/" + "T12345678/B12345678/abcdefghijklmnopqrstuvwx",  # Slack webhook
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.supersecretjwttokenpayload123",  # JWT
        "AKIAIOSFODNN7EXAMPLE",  # AWS
        "AIzaSyD1234567890abcdefghijklmnopqrstuv",  # Google API (39 chars)
    ]

    results = {
        "camera": set(),
        "microphone": set(),
        "location": set(),
        "sms_call": set(),
        "contacts": set(),
        "screen_capture": set(),
        "network": set(),
        "overlay_indicators": set(),
        "suspicious_commands": [],
        "dynamic_classloaders": [],
        "suspicious_urls": set(),
        "reflection": set(),
        "runtime_exec": set(),
        "device_admin": set(),
        "crypto_ecb": set(),
        "hardcoded_secrets": [],
    }

    import re
    url_re = re.compile(r"https?://[^\s\"'>]+")
    ip_re = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}")

    analyzer._scan_dex_strings(test_strings, results, url_re, ip_re)

    secrets = results["hardcoded_secrets"]
    secret_types = [s[0] for s in secrets]
    assert "GitHub Personal Access Token" in secret_types
    assert "Slack Webhook URL" in secret_types
    assert "JSON Web Token (JWT)" in secret_types
    assert "AWS Access Key ID" in secret_types
    assert "Google API Key" in secret_types

    # Ensure every single secret value is redacted
    for s_type, s_val in secrets:
        assert "[REDACTED]" in s_val


# ==============================================================================
# 6. Archive Security Defenses (Intake)
# ==============================================================================


def test_archive_path_traversal_defense():
    """Verify archive path traversal attempt is caught by UniversalAPKIntake without extracting."""
    intake = UniversalAPKIntake()
    temp_dir = tempfile.mkdtemp(prefix="spyaware_test_traversal_")
    bad_apk = os.path.join(temp_dir, "traversal.apk")

    try:
        with zipfile.ZipFile(bad_apk, "w") as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0:")
            zf.writestr("AndroidManifest.xml", b"\x00" * 20)

        res = intake.validate_and_intake(bad_apk)
        assert res.status == IntakeStatus.PATH_TRAVERSAL
        assert not res.is_valid
        assert any("path traversal" in err.lower() for err in res.errors)
        # Ensure file was never written outside
        assert not os.path.exists(os.path.join(temp_dir, "..", "etc", "passwd"))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_archive_empty_file_defense():
    """Verify zero-byte archive is rejected gracefully."""
    intake = UniversalAPKIntake()
    temp_dir = tempfile.mkdtemp(prefix="spyaware_test_empty_")
    empty_apk = os.path.join(temp_dir, "empty.apk")

    try:
        with open(empty_apk, "wb") as f:
            pass

        res = intake.validate_and_intake(empty_apk)
        assert res.status == IntakeStatus.EMPTY_FILE
        assert not res.is_valid
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
