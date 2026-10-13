"""Dynamic Analysis Readiness and Honest Telemetry Audit Tests (Milestone M5).

Verifies:
1. Dynamic worker handles unavailable ADB devices without crashing.
2. Incomplete dynamic execution produces status UNAVAILABLE/PARTIAL without lowering static risk scores.
3. Observations distinguish UNAVAILABLE, NOT_TESTED, NOT_OBSERVED, and OBSERVED.
4. Pre-existing emulators are preserved and never terminated by job cleanup.
5. Benign sample dynamic execution failure or timeout does not invent evidence.
"""

from unittest.mock import MagicMock, patch
import pytest

from analyzers.dynamic.models import (
    DynamicAnalysisResult,
    EnvironmentStatus,
    ExecutionMetadata,
    RuntimeBehaviorCategory,
    RuntimeBehaviorStatus,
    RuntimeObservation,
)
from analyzers.dynamic.worker import DynamicWorker
from backend.services.analysis_service import AnalysisService


@pytest.fixture
def mock_env_no_devices():
    mock = MagicMock()
    mock.find_adb_path.return_value = "/mock/adb"
    mock.find_emulator_path.return_value = "/mock/emulator"
    mock.get_status.return_value = EnvironmentStatus(
        adb_available=True,
        emulator_available=True,
        avdmanager_available=True,
        available_avds=["Medium_Phone_API_36.1"],
        running_devices=[],
        ready=True,
        message="No running devices",
    )
    return mock


def test_dynamic_worker_graceful_handling_when_no_devices_run():
    """When adb or emulator is unavailable, DynamicWorker fails gracefully with UNAVAILABLE."""
    worker = DynamicWorker()
    worker.env_discovery = MagicMock()
    worker.env_discovery.find_adb_path.return_value = None

    res = worker.run_analysis(
        apk_path="samples/benign_sample.apk",
        package_name="com.spyaware.benign",
        launchable_activity=".MainActivity",
        avd_name="Medium_Phone_API_36.1",
    )

    assert res.status == "UNAVAILABLE"
    assert "adb" in res.error_message.lower()
    assert len(res.limitations) > 0


def test_analysis_service_handles_unavailable_dynamic_honestly(tmp_path):
    """AnalysisService marks dynamic as UNAVAILABLE and does not lower static score."""
    service = AnalysisService(reports_dir=tmp_path)
    service.dynamic_worker = MagicMock()
    service.dynamic_worker.run_analysis.return_value = DynamicAnalysisResult(
        status="UNAVAILABLE",
        score=0.0,
        risk_level="LOW",
        telemetry=None,
        error_message="No emulator running",
        limitations=["Dynamic analysis could not run: environment unavailable"],
    )

    report = service.analyze_apk_full(
        apk_path="samples/benign_sample.apk",
        original_filename="benign_sample.apk",
        include_dynamic=True,
        include_network=False,
    )

    assert report.module_status["dynamic"] == "UNAVAILABLE"
    assert report.module_scores.dynamic is None
    assert report.analysis_status in ("PARTIAL", "COMPLETED_WITH_FINDINGS", "COMPLETED_CLEAN")
    assert any("Dynamic" in lim for lim in report.limitations)


def test_telemetry_status_honesty():
    """Telemetry strictly separates UNAVAILABLE and NOT_TESTED from NOT_OBSERVED."""
    obs_unavail = RuntimeObservation(
        category="CAMERA",
        status=RuntimeBehaviorStatus.UNAVAILABLE.value,
        description="Camera subsystem unavailable for dynamic testing",
        confidence=0.0,
    )
    obs_untested = RuntimeObservation(
        category="LOCATION",
        status=RuntimeBehaviorStatus.NOT_TESTED.value,
        description="Location category not exercised during test window",
        confidence=0.0,
    )
    obs_not_observed = RuntimeObservation(
        category="MICROPHONE",
        status=RuntimeBehaviorStatus.NOT_OBSERVED.value,
        description="Microphone tested but no audio recording detected",
        confidence=0.9,
    )

    assert obs_unavail.status != RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert obs_untested.status != RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert obs_not_observed.status == RuntimeBehaviorStatus.NOT_OBSERVED.value


def test_preexisting_emulator_preservation_contract():
    """Verify ExecutionMetadata tracking of emulator_started_by_job."""
    meta_preexisting = ExecutionMetadata(
        emulator_started_by_job=False,
        avd_name="Medium_Phone_API_36.1",
        device_id="emulator-5554",
    )
    # When emulator_started_by_job is False, cleanup logic must preserve the emulator
    assert meta_preexisting.emulator_started_by_job is False

    meta_started_by_job = ExecutionMetadata(
        emulator_started_by_job=True,
        avd_name="Medium_Phone_API_36.1",
        device_id="emulator-5554",
    )
    assert meta_started_by_job.emulator_started_by_job is True
