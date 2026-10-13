"""Regression tests for Priority 3 Fixes.

Covers:
- FIX 1: NetworkWorker emulator lifecycle tracking, process cleanup, and pre-existing device preservation.
- FIX 2: Malformed, truncated, or schema-invalid saved-report error handling and listing resilience.
- FIX 3: Accurate health-check capability and runtime readiness reporting without emulator startup.
"""

import json
from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from analyzers.dynamic.models import EnvironmentStatus
from analyzers.network.worker import NetworkWorker
from backend.main import app
from backend.models.analysis import RiskReport, ModuleScores, Finding, Severity
from backend.services.analysis_service import AnalysisService, CorruptedReportError

client = TestClient(app)
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
BENIGN_APK = SAMPLES_DIR / "benign_sample.apk"


# ==============================================================================
# FIX 1 REGRESSION TESTS: NETWORK WORKER EMULATOR LIFECYCLE
# ==============================================================================

def test_network_worker_job_started_emulator_is_cleaned_up_on_success():
    """When NetworkWorker starts an emulator, it must stop it upon analysis completion."""
    worker = NetworkWorker()
    mock_proc = MagicMock()
    mock_runner = worker.runner

    with patch.object(worker.env_discovery, "find_adb_path", return_value="/mock/adb"), \
         patch.object(worker.env_discovery, "find_emulator_path", return_value="/mock/emulator"), \
         patch.object(worker.env_discovery, "get_status", return_value=EnvironmentStatus(
             adb_available=True, emulator_available=True, avdmanager_available=True,
             available_avds=["Test_AVD"], running_devices=[], ready=True, message="Ready"
         )), \
         patch.object(mock_runner, "get_first_online_device", side_effect=[None, "emulator-5554"]), \
         patch.object(mock_runner, "start_emulator", return_value=mock_proc) as mock_start, \
         patch.object(mock_runner, "wait_for_boot", return_value=True), \
         patch.object(mock_runner, "install_apk", return_value=(True, "Success")), \
         patch.object(mock_runner, "clear_logcat"), \
         patch.object(mock_runner, "launch_activity", return_value=(True, "Launched")), \
         patch.object(mock_runner, "get_package_pids", return_value=["1234"]), \
         patch.object(mock_runner, "dump_logcat", return_value=""), \
         patch.object(mock_runner, "force_stop"), \
         patch.object(mock_runner, "uninstall_apk"), \
         patch.object(mock_runner, "stop_emulator") as mock_stop, \
         patch.object(worker.collector, "get_target_uid", return_value=10100), \
         patch.object(worker.collector, "poll_proc_net", return_value=[]):

        res = worker.run_analysis(str(BENIGN_APK), observation_seconds=0)

        # Verified startup
        mock_start.assert_called_once_with("/mock/emulator", "Test_AVD", port=5554)
        # Verified guaranteed cleanup
        mock_stop.assert_called_once_with(mock_proc, "/mock/adb", "emulator-5554")
        assert res.status in ("COMPLETED", "NOT_ATTRIBUTED")


def test_network_worker_preexisting_emulator_is_not_terminated():
    """An emulator that was already online before the job must NOT be stopped."""
    worker = NetworkWorker()
    mock_runner = worker.runner

    with patch.object(worker.env_discovery, "find_adb_path", return_value="/mock/adb"), \
         patch.object(worker.env_discovery, "get_status", return_value=EnvironmentStatus(
             adb_available=True, emulator_available=True, avdmanager_available=True,
             available_avds=["Test_AVD"], running_devices=["emulator-5554"], ready=True, message="Ready"
         )), \
         patch.object(mock_runner, "get_first_online_device", return_value="emulator-5554"), \
         patch.object(mock_runner, "start_emulator") as mock_start, \
         patch.object(mock_runner, "install_apk", return_value=(True, "Success")), \
         patch.object(mock_runner, "clear_logcat"), \
         patch.object(mock_runner, "launch_activity", return_value=(True, "Launched")), \
         patch.object(mock_runner, "get_package_pids", return_value=["1234"]), \
         patch.object(mock_runner, "dump_logcat", return_value=""), \
         patch.object(mock_runner, "force_stop") as mock_force_stop, \
         patch.object(mock_runner, "uninstall_apk") as mock_uninstall, \
         patch.object(mock_runner, "stop_emulator") as mock_stop, \
         patch.object(worker.collector, "get_target_uid", return_value=10100), \
         patch.object(worker.collector, "poll_proc_net", return_value=[]):

        res = worker.run_analysis(str(BENIGN_APK), observation_seconds=0)

        # start_emulator and stop_emulator must NOT have been called
        mock_start.assert_not_called()
        mock_stop.assert_not_called()
        # APK cleanup must still be performed on device
        mock_force_stop.assert_called_once()
        mock_uninstall.assert_called_once()


def test_network_worker_cleans_up_emulator_on_boot_timeout():
    """If emulator startup boots times out, the started process must be killed."""
    worker = NetworkWorker()
    mock_proc = MagicMock()
    mock_runner = worker.runner

    with patch.object(worker.env_discovery, "find_adb_path", return_value="/mock/adb"), \
         patch.object(worker.env_discovery, "find_emulator_path", return_value="/mock/emulator"), \
         patch.object(worker.env_discovery, "get_status", return_value=EnvironmentStatus(
             adb_available=True, emulator_available=True, avdmanager_available=True,
             available_avds=["Test_AVD"], running_devices=[], ready=True, message="Ready"
         )), \
         patch.object(mock_runner, "get_first_online_device", return_value=None), \
         patch.object(mock_runner, "start_emulator", return_value=mock_proc), \
         patch.object(mock_runner, "wait_for_boot", return_value=False), \
         patch.object(mock_runner, "stop_emulator") as mock_stop:

        res = worker.run_analysis(str(BENIGN_APK), observation_seconds=0)

        assert res.status == "TIMEOUT"
        assert "boot timed out" in res.error_message.lower()
        mock_stop.assert_called_once_with(mock_proc, "/mock/adb", "emulator-5554")


def test_network_worker_cleans_up_emulator_on_install_failure():
    """If APK installation fails, the started emulator must be shut down."""
    worker = NetworkWorker()
    mock_proc = MagicMock()
    mock_runner = worker.runner

    with patch.object(worker.env_discovery, "find_adb_path", return_value="/mock/adb"), \
         patch.object(worker.env_discovery, "find_emulator_path", return_value="/mock/emulator"), \
         patch.object(worker.env_discovery, "get_status", return_value=EnvironmentStatus(
             adb_available=True, emulator_available=True, avdmanager_available=True,
             available_avds=["Test_AVD"], running_devices=[], ready=True, message="Ready"
         )), \
         patch.object(mock_runner, "get_first_online_device", side_effect=[None, "emulator-5554"]), \
         patch.object(mock_runner, "start_emulator", return_value=mock_proc), \
         patch.object(mock_runner, "wait_for_boot", return_value=True), \
         patch.object(mock_runner, "install_apk", return_value=(False, "INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES")), \
         patch.object(mock_runner, "stop_emulator") as mock_stop:

        res = worker.run_analysis(str(BENIGN_APK), observation_seconds=0)

        assert res.status in ("UNAVAILABLE", "FAILED")
        assert "installation failed" in res.error_message.lower()
        mock_stop.assert_called_once_with(mock_proc, "/mock/adb", "emulator-5554")


def test_network_worker_cleans_up_emulator_on_exception_and_preserves_error():
    """If telemetry raises an unexpected exception, started emulator is stopped and FAILED returned."""
    worker = NetworkWorker()
    mock_proc = MagicMock()
    mock_runner = worker.runner

    with patch.object(worker.env_discovery, "find_adb_path", return_value="/mock/adb"), \
         patch.object(worker.env_discovery, "find_emulator_path", return_value="/mock/emulator"), \
         patch.object(worker.env_discovery, "get_status", return_value=EnvironmentStatus(
             adb_available=True, emulator_available=True, avdmanager_available=True,
             available_avds=["Test_AVD"], running_devices=[], ready=True, message="Ready"
         )), \
         patch.object(mock_runner, "get_first_online_device", side_effect=[None, "emulator-5554"]), \
         patch.object(mock_runner, "start_emulator", return_value=mock_proc), \
         patch.object(mock_runner, "wait_for_boot", return_value=True), \
         patch.object(mock_runner, "install_apk", return_value=(True, "Success")), \
         patch.object(worker.collector, "get_target_uid", side_effect=RuntimeError("Kernel socket error")), \
         patch.object(mock_runner, "stop_emulator") as mock_stop:

        res = worker.run_analysis(str(BENIGN_APK), observation_seconds=0)

        assert res.status == "FAILED"
        assert "Kernel socket error" in res.error_message
        mock_stop.assert_called_once_with(mock_proc, "/mock/adb", "emulator-5554")


# ==============================================================================
# FIX 2 REGRESSION TESTS: MALFORMED SAVED-REPORT HANDLING
# ==============================================================================

def test_get_report_by_id_corrupt_json_raises_corrupted_report_error(tmp_path):
    """AnalysisService.get_report_by_id raises CorruptedReportError on malformed JSON."""
    service = AnalysisService(reports_dir=tmp_path)
    corrupt_file = tmp_path / "corrupt-id.json"
    corrupt_file.write_text("{ incomplete json ...", encoding="utf-8")

    with pytest.raises(CorruptedReportError) as exc_info:
        service.get_report_by_id("corrupt-id")
    assert "corrupt-id" in str(exc_info.value)


def test_get_report_by_id_invalid_schema_raises_corrupted_report_error(tmp_path):
    """AnalysisService.get_report_by_id raises CorruptedReportError when required fields are missing."""
    service = AnalysisService(reports_dir=tmp_path)
    invalid_file = tmp_path / "invalid-schema.json"
    # Missing overall_score, risk_level, findings, etc.
    invalid_file.write_text(json.dumps({"some_key": "some_value"}), encoding="utf-8")

    with pytest.raises(CorruptedReportError) as exc_info:
        service.get_report_by_id("invalid-schema")
    assert "invalid-schema" in str(exc_info.value)


def test_api_get_analysis_corrupt_file_returns_http_500():
    """GET /api/analysis/{analysis_id} returns HTTP 500 without leaking file paths or traces."""
    with patch("backend.api.router.analysis_service.get_report_by_id",
               side_effect=CorruptedReportError("Report 'test-corrupt' is corrupted or unreadable JSON")):
        response = client.get("/api/analysis/test-corrupt")
        assert response.status_code == 500
        detail = response.json()["detail"]
        assert "test-corrupt" in detail
        assert "corrupted" in detail.lower()
        # Ensure server file system paths are not exposed
        assert "/home" not in detail
        assert ".json" not in detail


def test_api_list_analyses_skips_malformed_and_invalid_reports(tmp_path):
    """GET /api/analyses skips malformed or partial reports and preserves valid reports."""
    service = AnalysisService(reports_dir=tmp_path)

    # 1. Valid report
    valid_report = RiskReport(
        analysis_id="valid-report-1",
        timestamp="2026-10-09T00:00:00Z",
        apk_filename="valid.apk",
        overall_score=42.0,
        risk_level="MEDIUM",
        module_scores=ModuleScores(static=40.0, permissions=44.0, dynamic=None, network=None, ble=None),
        findings=[],
        summary="Valid summary",
        disclaimer="Valid disclaimer",
    )
    service.save_report(valid_report)

    # 2. Malformed JSON file
    (tmp_path / "corrupt1.json").write_text("{ unclosed", encoding="utf-8")

    # 3. Truncated empty file
    (tmp_path / "corrupt2.json").write_text("", encoding="utf-8")

    # 4. JSON with non-dict content
    (tmp_path / "corrupt3.json").write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")

    # 5. Dict with missing essential metadata
    (tmp_path / "corrupt4.json").write_text(json.dumps({"random": 123}), encoding="utf-8")

    # 6. Another valid report
    valid_report_2 = RiskReport(
        analysis_id="valid-report-2",
        timestamp="2026-10-09T01:00:00Z",
        apk_filename="valid2.apk",
        overall_score=10.0,
        risk_level="LOW",
        module_scores=ModuleScores(static=10.0, permissions=10.0, dynamic=None, network=None, ble=None),
        findings=[],
        summary="Valid summary 2",
        disclaimer="Valid disclaimer",
    )
    service.save_report(valid_report_2)

    with patch("backend.api.router.analysis_service", service):
        response = client.get("/api/analyses")
        assert response.status_code == 200
        items = response.json()

        # Must only contain the 2 valid reports, skipping the 4 corrupt files
        assert len(items) == 2
        ids = {item["analysis_id"] for item in items}
        assert ids == {"valid-report-1", "valid-report-2"}
        for item in items:
            assert item["overall_score"] is not None
            assert item["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")


# ==============================================================================
# FIX 3 REGRESSION TESTS: ACCURATE HEALTH-CHECK CAPABILITIES
# ==============================================================================

def test_health_check_replaces_coming_soon_and_reports_capabilities():
    """GET /api/health accurately reports capabilities and does not use COMING_SOON for implemented modules."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "healthy"
    assert data["modules"]["static"] == "AVAILABLE"
    assert data["modules"]["permissions"] == "AVAILABLE"
    assert data["modules"]["ble"] == "COMING_SOON"

    # dynamic and network must never be COMING_SOON
    assert data["modules"]["dynamic"] != "COMING_SOON"
    assert data["modules"]["network"] != "COMING_SOON"

    # Capabilities structure
    caps = data["capabilities"]
    assert caps["static"]["implemented"] is True
    assert caps["dynamic"]["implemented"] is True
    assert caps["network"]["implemented"] is True
    assert caps["ble"]["implemented"] is False


def test_health_check_status_resolution_states():
    """Verify health endpoint accurately reflects all runtime readiness conditions."""
    # Condition A: Live running device detected -> AVAILABLE
    env_live = EnvironmentStatus(
        adb_available=True, emulator_available=True, avdmanager_available=True,
        available_avds=["Test_AVD"], running_devices=["emulator-5554"], ready=True, message="Active device"
    )
    with patch("backend.api.router.analysis_service.get_dynamic_environment", return_value=env_live):
        res = client.get("/api/health").json()
        assert res["modules"]["dynamic"] == "AVAILABLE"
        assert res["modules"]["network"] == "AVAILABLE"
        assert res["capabilities"]["dynamic"]["live_device"] is True

    # Condition B: AVD configured but no live device -> CONFIGURED
    env_configured = EnvironmentStatus(
        adb_available=True, emulator_available=True, avdmanager_available=True,
        available_avds=["Test_AVD"], running_devices=[], ready=True, message="AVD available"
    )
    with patch("backend.api.router.analysis_service.get_dynamic_environment", return_value=env_configured):
        res = client.get("/api/health").json()
        assert res["modules"]["dynamic"] == "CONFIGURED"
        assert res["modules"]["network"] == "CONFIGURED"
        assert res["capabilities"]["dynamic"]["live_device"] is False

    # Condition C: Tools installed but no AVD or device -> UNAVAILABLE_EMULATOR_OFFLINE
    env_offline = EnvironmentStatus(
        adb_available=True, emulator_available=True, avdmanager_available=True,
        available_avds=[], running_devices=[], ready=False, message="No AVD"
    )
    with patch("backend.api.router.analysis_service.get_dynamic_environment", return_value=env_offline):
        res = client.get("/api/health").json()
        assert res["modules"]["dynamic"] == "UNAVAILABLE_EMULATOR_OFFLINE"
        assert res["modules"]["network"] == "UNAVAILABLE_EMULATOR_OFFLINE"

    # Condition D: Missing host adb/emulator -> UNAVAILABLE_MISSING_DEPENDENCIES
    env_missing = EnvironmentStatus(
        adb_available=False, emulator_available=False, avdmanager_available=False,
        available_avds=[], running_devices=[], ready=False, message="Missing adb"
    )
    with patch("backend.api.router.analysis_service.get_dynamic_environment", return_value=env_missing):
        res = client.get("/api/health").json()
        assert res["modules"]["dynamic"] == "UNAVAILABLE_MISSING_DEPENDENCIES"
        assert res["modules"]["network"] == "UNAVAILABLE_MISSING_DEPENDENCIES"


def test_health_check_does_not_start_emulator():
    """GET /api/health must never launch an emulator process."""
    with patch("analyzers.dynamic.runner.DynamicRunner.start_emulator") as mock_start:
        response = client.get("/api/health")
        assert response.status_code == 200
        mock_start.assert_not_called()
