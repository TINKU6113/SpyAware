"""Unit tests for DynamicWorker orchestrator in SpyAware-Analyzer."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from analyzers.dynamic.models import EnvironmentStatus
from analyzers.dynamic.worker import DynamicWorker

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def test_worker_file_not_found():
    """Worker fails safely when target APK file does not exist."""
    worker = DynamicWorker()
    res = worker.run_analysis("/non/existent/path.apk")
    assert res.status == "FAILED"
    assert "does not exist" in res.error_message


def test_worker_environment_unavailable():
    """Worker reports UNAVAILABLE when adb/emulator are not configured."""
    mock_env = MagicMock()
    mock_env.get_status.return_value = EnvironmentStatus(
        ready=False,
        message="Dynamic environment not ready: Missing adb",
    )
    worker = DynamicWorker(environment_discovery=mock_env)
    res = worker.run_analysis(str(SAMPLES_DIR / "benign_sample.apk"))
    assert res.status == "UNAVAILABLE"
    assert res.score == 0.0
    assert "not ready" in res.error_message


def test_worker_no_launchable_activity():
    """When an app has no launchable activity, reports NO_LAUNCHABLE_ACTIVITY without treating as malicious."""
    mock_env = MagicMock()
    mock_env.get_status.return_value = EnvironmentStatus(
        ready=True,
        selected_avd="Test_AVD",
    )
    mock_env.find_adb_path.return_value = "/fake/adb"
    mock_env.find_emulator_path.return_value = "/fake/emulator"

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.install_apk.return_value = (True, "Success")

    worker = DynamicWorker(
        environment_discovery=mock_env,
        runner=mock_runner,
    )

    # Force launchable_activity=None explicitly
    res = worker.run_analysis(
        str(SAMPLES_DIR / "benign_sample.apk"),
        package_name="com.test.serviceonly",
        launchable_activity=None,
    )

    assert res.status == "NO_LAUNCHABLE_ACTIVITY"
    assert res.score == 0.0
    assert any("no launchable activity" in o.description.lower() for o in res.observations)


def test_worker_mocked_end_to_end_surveillance_run():
    """Simulates a complete dynamic run with surveillance indicators in logcat."""
    mock_env = MagicMock()
    mock_env.get_status.return_value = EnvironmentStatus(
        ready=True,
        selected_avd="Test_AVD",
    )
    mock_env.find_adb_path.return_value = "/fake/adb"
    mock_env.find_emulator_path.return_value = "/fake/emulator"

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.install_apk.return_value = (True, "Success")
    mock_runner.launch_activity.return_value = (True, "Success")
    mock_runner.dump_logcat.return_value = (
        "01-01 10:00:00.000  1234  1250 I CameraDevice: openCamera 0 for com.spyaware.suspicious\n"
        "01-01 10:00:01.000  1234  1250 I AudioRecord: startRecording for com.spyaware.suspicious\n"
    )
    mock_runner.dump_services.return_value = ""
    mock_runner.dump_processes.return_value = "u0_a100 1234 800 1200000 50000 0 0 S com.spyaware.suspicious"
    mock_runner.get_package_pids.return_value = ["1234"]

    worker = DynamicWorker(
        environment_discovery=mock_env,
        runner=mock_runner,
    )

    res = worker.run_analysis(
        str(SAMPLES_DIR / "suspicious_surveillance_sample.apk"),
        launchable_activity=".MainActivity",
        observation_seconds=0,  # Fast for test
    )

    assert res.status == "COMPLETED"
    assert res.score == 30.0  # Camera (15) + Audio (15)
    assert res.risk_level in ("MEDIUM", "HIGH")
    assert res.execution.launch_success is True
    assert len(res.findings) == 2
    assert any("Camera" in f.title for f in res.findings)
    assert any("Audio" in f.title for f in res.findings)

    # Confirm cleanup was called
    mock_runner.force_stop.assert_called_once()
    mock_runner.uninstall_apk.assert_called_once()


def test_worker_cleanup_isolated_exception_handling():
    """Cleanup exceptions (e.g. force_stop failure) must not prevent uninstall or emulator stop, and must not mask result."""
    mock_env = MagicMock()
    mock_env.get_status.return_value = EnvironmentStatus(
        ready=True,
        selected_avd="Test_AVD",
        available_avds=["Test_AVD"],
    )
    mock_env.find_adb_path.return_value = "/fake/adb"
    mock_env.find_emulator_path.return_value = "/fake/emulator"

    mock_proc = MagicMock()
    mock_runner = MagicMock()
    # Cold start: first call returns None (no device), then after boot returns device
    mock_runner.get_first_online_device.side_effect = [None, "emulator-5554"]
    mock_runner.start_emulator.return_value = mock_proc
    mock_runner.wait_for_boot.return_value = True
    mock_runner.install_apk.return_value = (True, "Success")
    mock_runner.launch_activity.return_value = (True, "Success")
    mock_runner.dump_logcat.return_value = ""
    mock_runner.dump_services.return_value = ""
    mock_runner.dump_processes.return_value = ""
    mock_runner.get_package_pids.return_value = ["1234"]

    # force_stop raises an error during cleanup
    mock_runner.force_stop.side_effect = RuntimeError("ADB pipe failure during force-stop")
    # uninstall_apk also raises
    mock_runner.uninstall_apk.side_effect = RuntimeError("ADB failure during uninstall")

    worker = DynamicWorker(
        environment_discovery=mock_env,
        runner=mock_runner,
    )

    res = worker.run_analysis(
        str(SAMPLES_DIR / "benign_sample.apk"),
        launchable_activity=".MainActivity",
        observation_seconds=0,
    )

    # Result must not be masked by cleanup exceptions
    assert res.status == "COMPLETED"
    assert res.score == 0.0

    # All cleanup steps must have been attempted despite exceptions
    mock_runner.force_stop.assert_called_once()
    mock_runner.uninstall_apk.assert_called_once()
    mock_runner.stop_emulator.assert_called_once_with(mock_proc, "/fake/adb", "emulator-5554")
