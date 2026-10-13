"""Regression test suite for Milestone M2.1: Reliable Emulator Reuse and Boot Synchronization.

Covers all 6 required regression scenarios:
1. Reuse of an already-booted compatible emulator without redundant startup.
2. Avoidance of duplicate launches for the same AVD (never start a second instance of a running AVD).
3. Boot taking longer than the former 90s timeout (e.g. ~159s cold boot completes before deadline).
4. Preservation of a pre-existing emulator during job cleanup under both success and failure conditions.
5. Proper handling of offline, unauthorized, and missing devices during boot synchronization.
6. Sequential fallback triggered only after a real startup/compatibility failure, never preemptively.
"""

import os
from pathlib import Path
import subprocess
from unittest.mock import MagicMock, call, patch
import pytest

from analyzers.dynamic.environment import EnvironmentDiscovery
from analyzers.dynamic.models import (
    AVDFallbackAttempt,
    AVDProfile,
    EnvironmentStatus,
)
from analyzers.dynamic.runner import (
    BOOT_TIMEOUT_SECONDS,
    DynamicRunner,
    _ACTIVE_AVD_RUNS,
    _ACTIVE_PORT_RESERVATIONS,
)
from analyzers.dynamic.worker import DynamicWorker

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
BENIGN_APK = str(SAMPLES_DIR / "benign_sample.apk")


@pytest.fixture(autouse=True)
def clean_locks_and_ports():
    """Ensure in-process locks and port reservations are clean before and after each test."""
    _ACTIVE_AVD_RUNS.clear()
    _ACTIVE_PORT_RESERVATIONS.clear()
    yield
    _ACTIVE_AVD_RUNS.clear()
    _ACTIVE_PORT_RESERVATIONS.clear()


def make_mock_env(
    available_avds=None,
    running_devices=None,
    selected_avd="Medium_Phone_API_36.1",
    ready=True,
):
    env = MagicMock()
    env.find_adb_path.return_value = "/mock/adb"
    env.find_emulator_path.return_value = "/mock/emulator"
    env.get_status.return_value = EnvironmentStatus(
        ready=ready,
        selected_avd=selected_avd,
        available_avds=available_avds or ["Medium_Phone_API_36.1"],
        running_devices=running_devices or [],
    )
    env.get_avd_supported_abis.return_value = ["x86_64", "x86"]
    return env


def make_mock_runner(proc=None):
    runner = MagicMock()
    mock_proc = proc or MagicMock()
    runner.start_emulator.return_value = mock_proc
    runner.wait_for_boot.return_value = True
    runner.install_apk.return_value = (True, "Success")
    runner.launch_activity.return_value = (True, "Success")
    runner.get_package_pids.return_value = ["1000"]
    runner.dump_logcat.return_value = ""
    runner.dump_services.return_value = ""
    runner.dump_processes.return_value = "u0_a100 1000 800 1200000 50000 0 0 S com.spyaware.benign"
    runner.dump_camera_service.return_value = ""
    runner.dump_audio_service.return_value = ""
    runner.dump_location_service.return_value = ""
    runner.dump_accessibility_service.return_value = ""
    runner.dump_media_projection_service.return_value = ""
    return runner


# ==============================================================================
# SCENARIO 1: REUSE OF AN ALREADY-BOOTED COMPATIBLE EMULATOR
# ==============================================================================

def test_reuse_of_already_booted_compatible_emulator():
    """An active compatible emulator matching the configured AVD is reused without launching a new one."""
    mock_env = make_mock_env(running_devices=["emulator-5554"])
    mock_runner = make_mock_runner()
    mock_runner.get_device_states.return_value = {"emulator-5554": "device"}
    mock_runner.get_device_avd_name.return_value = "Medium_Phone_API_36.1"
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.get_device_supported_abis.return_value = ["x86_64", "x86"]
    mock_runner.get_device_sdk_version.return_value = 36
    mock_runner.is_device_booted.return_value = True

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status == "COMPLETED"
    assert res.execution.device_id == "emulator-5554"
    assert res.execution.emulator_started_by_job is False
    # Verified: start_emulator is never called
    mock_runner.start_emulator.assert_not_called()
    # Verified: install, launch, observation target explicit serial
    mock_runner.install_apk.assert_called_once_with("/mock/adb", BENIGN_APK, "emulator-5554")
    mock_runner.launch_activity.assert_called_once_with(
        "/mock/adb", "com.spyaware.benign", "com.spyaware.benign.MainActivity", "emulator-5554"
    )
    # Verified: cleanup removes app but does not stop emulator
    mock_runner.force_stop.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5554")
    mock_runner.uninstall_apk.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5554")
    mock_runner.stop_emulator.assert_not_called()


# ==============================================================================
# SCENARIO 2: AVOIDANCE OF DUPLICATE LAUNCHES FOR THE SAME AVD
# ==============================================================================

def test_avoidance_of_duplicate_launches_for_same_avd():
    """When an AVD is already running on ADB, worker never launches a second instance of that AVD."""
    mock_proc = MagicMock()
    mock_env = make_mock_env(
        available_avds=["Medium_Phone_API_36.1", "Pixel_ARM64_API_30"],
        running_devices=["emulator-5554"],
    )
    p_x86 = AVDProfile(name="Medium_Phone_API_36.1", abis=["x86_64"], api_level=36)
    p_arm = AVDProfile(name="Pixel_ARM64_API_30", abis=["arm64-v8a"], api_level=30)
    mock_env.rank_compatible_avds.return_value = [(p_x86, "primary"), (p_arm, "fallback")]

    mock_runner = make_mock_runner(mock_proc)
    mock_runner.get_device_states.return_value = {"emulator-5554": "device"}
    mock_runner.get_device_avd_name.return_value = "Medium_Phone_API_36.1"
    mock_runner.find_running_avd.side_effect = lambda adb, name: "emulator-5554" if name == "Medium_Phone_API_36.1" else None
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.get_device_supported_abis.return_value = ["x86_64"]
    mock_runner.reserve_emulator_port.return_value = 5556

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    # APK requires arm64-v8a native library; running emulator-5554 is x86_64 only
    with patch("analyzers.dynamic.worker.extract_apk_abis", return_value=["arm64-v8a"]):
        res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status == "COMPLETED"
    assert res.execution.device_id == "emulator-5556"
    assert res.execution.avd_name == "Pixel_ARM64_API_30"

    # Crucial assertion: start_emulator was NEVER called with Medium_Phone_API_36.1
    # Only Pixel_ARM64_API_30 was launched
    mock_runner.start_emulator.assert_called_once_with("/mock/emulator", "Pixel_ARM64_API_30", port=5556)
    # The running AVD was marked SKIPPED with ALREADY_RUNNING in attempt history
    skipped_attempt = [a for a in res.execution.avd_attempts if a.avd_name == "Medium_Phone_API_36.1"]
    assert len(skipped_attempt) == 1
    assert skipped_attempt[0].status == "SKIPPED"
    assert skipped_attempt[0].failure_classification == "ALREADY_RUNNING"


# ==============================================================================
# SCENARIO 3: BOOT TAKING LONGER THAN FORMER TIMEOUT (159s COLD BOOT)
# ==============================================================================

def test_boot_taking_longer_than_former_timeout_succeeds_before_deadline():
    """A cold boot completing at ~159s succeeds when configured boot_timeout allows it (e.g. 180s)."""
    runner = DynamicRunner(boot_timeout=180)
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None  # Emulator process alive

    # Simulate elapsed time progressing from 0 to 159 seconds
    simulated_times = [0.0]
    current_time = [0.0]

    def mock_time():
        return current_time[0]

    def mock_sleep(seconds):
        current_time[0] += seconds

    # Responses: "0" while booting, then "1" when completed at 159s
    def mock_subprocess_run(cmd, **kwargs):
        if "sys.boot_completed" in cmd:
            if current_time[0] < 158.0:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="0\n", stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="1\n", stderr="")
        elif "pm" in cmd and "android" in cmd:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="package:/system/framework/framework-res.apk\n", stderr="")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with patch("time.time", side_effect=mock_time), \
         patch("time.sleep", side_effect=mock_sleep), \
         patch("subprocess.run", side_effect=mock_subprocess_run):

        booted = runner.wait_for_boot("/mock/adb", device_id="emulator-5554", emulator_proc=mock_proc)

    assert booted is True
    assert current_time[0] >= 158.0
    # Former timeout was 90s: verifying this took well past 90s
    assert current_time[0] > 90.0


def test_boot_timeout_configurable_via_environment():
    """DynamicRunner honors SPYAWARE_BOOT_TIMEOUT environment variable when not explicitly passed."""
    with patch.dict(os.environ, {"SPYAWARE_BOOT_TIMEOUT": "240"}):
        runner = DynamicRunner()
        assert runner.boot_timeout == 240

    with patch.dict(os.environ, {}, clear=True):
        runner_default = DynamicRunner()
        assert runner_default.boot_timeout == BOOT_TIMEOUT_SECONDS == 90


# ==============================================================================
# SCENARIO 4: PRESERVATION OF PRE-EXISTING EMULATOR DURING CLEANUP
# ==============================================================================

def test_preservation_of_preexisting_emulator_during_launch_failure():
    """When an app crashes or fails to launch on a pre-existing emulator, the emulator is never stopped."""
    mock_env = make_mock_env(running_devices=["emulator-5554"])
    mock_runner = make_mock_runner()
    mock_runner.get_device_states.return_value = {"emulator-5554": "device"}
    mock_runner.get_device_avd_name.return_value = "Medium_Phone_API_36.1"
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.get_device_supported_abis.return_value = ["x86_64"]
    mock_runner.launch_activity.return_value = (False, "Error: Activity class does not exist")

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status == "FAILED"
    assert res.execution.device_id == "emulator-5554"
    assert res.execution.emulator_started_by_job is False
    # App is cleaned up
    mock_runner.force_stop.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5554")
    mock_runner.uninstall_apk.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5554")
    # Pre-existing emulator is NOT terminated
    mock_runner.stop_emulator.assert_not_called()


def test_preservation_of_preexisting_emulator_during_exception():
    """When an unhandled exception occurs during observation, pre-existing emulator is never terminated."""
    mock_env = make_mock_env(running_devices=["emulator-5554"])
    mock_runner = make_mock_runner()
    mock_runner.get_device_states.return_value = {"emulator-5554": "device"}
    mock_runner.get_device_avd_name.return_value = "Medium_Phone_API_36.1"
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.get_device_supported_abis.return_value = ["x86_64"]
    mock_runner.dump_logcat.side_effect = RuntimeError("ADB server connection reset")

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    with pytest.raises(RuntimeError, match="ADB server connection reset"):
        worker.run_analysis(BENIGN_APK, observation_seconds=0)

    mock_runner.force_stop.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5554")
    mock_runner.uninstall_apk.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5554")
    mock_runner.stop_emulator.assert_not_called()


# ==============================================================================
# SCENARIO 5: PROPER HANDLING OF OFFLINE AND MISSING DEVICES
# ==============================================================================

def test_wait_for_boot_handles_transition_from_missing_to_offline_to_device():
    """wait_for_boot retries across not_found -> offline -> device state transitions."""
    runner = DynamicRunner(boot_timeout=30)
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None

    responses = [
        subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error: device 'emulator-5554' not found"),
        subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error: device offline"),
        subprocess.CompletedProcess(args=[], returncode=0, stdout="0\n", stderr=""),
        subprocess.CompletedProcess(args=[], returncode=0, stdout="1\n", stderr=""),
        subprocess.CompletedProcess(args=[], returncode=0, stdout="package:/system/framework/framework-res.apk\n", stderr=""),
    ]

    with patch("subprocess.run", side_effect=responses), \
         patch("time.sleep", return_value=None):
        booted = runner.wait_for_boot("/mock/adb", device_id="emulator-5554", emulator_proc=mock_proc)

    assert booted is True


def test_wait_for_boot_device_stuck_offline_reports_timeout_with_last_state():
    """When device remains offline until deadline, wait_for_boot returns False cleanly."""
    runner = DynamicRunner(boot_timeout=6)
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None

    offline_resp = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error: device offline")

    with patch("subprocess.run", return_value=offline_resp), \
         patch("time.sleep", return_value=None):
        booted = runner.wait_for_boot("/mock/adb", device_id="emulator-5554", emulator_proc=mock_proc)

    assert booted is False


def test_wait_for_boot_unauthorized_device_logs_and_returns_false():
    """When device reports unauthorized, wait_for_boot does not crash and handles state safely."""
    runner = DynamicRunner(boot_timeout=4)
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None

    unauth_resp = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error: device unauthorized")

    with patch("subprocess.run", return_value=unauth_resp), \
         patch("time.sleep", return_value=None):
        booted = runner.wait_for_boot("/mock/adb", device_id="emulator-5554", emulator_proc=mock_proc)

    assert booted is False


# ==============================================================================
# SCENARIO 6: SEQUENTIAL FALLBACK ONLY AFTER REAL FAILURE
# ==============================================================================

def test_sequential_fallback_not_attempted_when_first_candidate_succeeds():
    """Candidate 2 is NEVER attempted when Candidate 1 boots and installs successfully."""
    mock_proc1 = MagicMock()
    mock_proc2 = MagicMock()

    mock_env = make_mock_env(
        available_avds=["Candidate_1", "Candidate_2"],
        running_devices=[],
    )
    p1 = AVDProfile(name="Candidate_1", abis=["x86_64"], api_level=36)
    p2 = AVDProfile(name="Candidate_2", abis=["x86_64"], api_level=30)
    mock_env.rank_compatible_avds.return_value = [(p1, "rank 1"), (p2, "rank 2")]

    mock_runner = make_mock_runner(mock_proc1)
    mock_runner.get_device_states.return_value = {}
    mock_runner.get_first_online_device.return_value = None
    mock_runner.reserve_emulator_port.return_value = 5554
    mock_runner.start_emulator.return_value = mock_proc1
    mock_runner.wait_for_boot.return_value = True
    mock_runner.install_apk.return_value = (True, "Success")

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status == "COMPLETED"
    assert res.execution.avd_name == "Candidate_1"
    # Candidate 1 succeeded: Candidate 2 was NEVER launched or attempted
    mock_runner.start_emulator.assert_called_once_with("/mock/emulator", "Candidate_1", port=5554)
    assert len(res.execution.avd_attempts) == 1
    assert res.execution.avd_attempts[0].avd_name == "Candidate_1"
    assert res.execution.avd_attempts[0].status == "SUCCESS"


def test_sequential_fallback_triggers_only_after_real_startup_failure():
    """Candidate 2 is attempted ONLY after Candidate 1 experiences genuine startup/boot failure."""
    proc1 = MagicMock()
    proc1.poll.return_value = 1  # Crash on startup
    proc2 = MagicMock()

    mock_env = make_mock_env(
        available_avds=["Candidate_Fail", "Candidate_Pass"],
        running_devices=[],
    )
    p1 = AVDProfile(name="Candidate_Fail", abis=["x86_64"], api_level=36)
    p2 = AVDProfile(name="Candidate_Pass", abis=["x86_64"], api_level=30)
    mock_env.rank_compatible_avds.return_value = [(p1, "rank 1"), (p2, "rank 2")]

    mock_runner = make_mock_runner()
    mock_runner.get_device_states.return_value = {}
    mock_runner.get_first_online_device.return_value = None
    mock_runner.reserve_emulator_port.side_effect = [5554, 5556]
    mock_runner.start_emulator.side_effect = [proc1, proc2]
    # First attempt fails boot, second succeeds
    mock_runner.wait_for_boot.side_effect = [False, True]
    mock_runner.install_apk.return_value = (True, "Success")

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status == "COMPLETED"
    assert res.execution.avd_name == "Candidate_Pass"
    assert res.execution.device_id == "emulator-5556"

    # Both emulators were started sequentially
    assert mock_runner.start_emulator.call_count == 2
    mock_runner.start_emulator.assert_has_calls([
        call("/mock/emulator", "Candidate_Fail", port=5554),
        call("/mock/emulator", "Candidate_Pass", port=5556),
    ])

    # First emulator was stopped upon failure before second started
    mock_runner.stop_emulator.assert_any_call(proc1, "/mock/adb", "emulator-5554")

    # History records the real failure classification
    assert len(res.execution.avd_attempts) == 2
    assert res.execution.avd_attempts[0].avd_name == "Candidate_Fail"
    assert res.execution.avd_attempts[0].status == "FAILED"
    assert res.execution.avd_attempts[0].failure_classification == "PROCESS_EXITED"
    assert res.execution.avd_attempts[1].avd_name == "Candidate_Pass"
    assert res.execution.avd_attempts[1].status == "SUCCESS"
