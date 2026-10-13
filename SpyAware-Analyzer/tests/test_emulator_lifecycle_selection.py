"""Comprehensive test suite for safe Android emulator device selection, port allocation, and lifecycle management.

Verifies:
1. Cold start without devices starts AVD on reserved port.
2. Physical device connected -> new emulator selected explicitly (emulator-5554), physical device untouched.
3. Pre-existing emulator-5554 running -> new emulator selects emulator-5556.
4. Selected emulator not yet in ADB during early polling.
5. Selected emulator boot timeout.
6. Process death during boot (PROCESS_EXITED).
7. APK installation failure cleans up spawned emulator.
8. Application launch failure cleans up spawned emulator.
9. Telemetry collection exception cleans up spawned emulator.
10. Cleanup targets spawned emulator only.
11. Pre-existing emulator never terminated.
12. Physical device never terminated (emu kill never called on non-emulator serial).
13. Port allocation detects occupied ports via socket and ADB.
14. Concurrent startup attempts with same AVD blocked via AVDLock.
15. Network Analysis follows identical device-ownership rules.
16. ABI incompatibility handling preserved.
"""

from pathlib import Path
import socket
import subprocess
from unittest.mock import MagicMock, patch
import pytest

from analyzers.dynamic.environment import EnvironmentDiscovery
from analyzers.dynamic.models import DynamicAnalysisResult, EnvironmentStatus, ExecutionMetadata
from analyzers.dynamic.runner import (
    AVDLock,
    DynamicRunner,
    _ACTIVE_AVD_RUNS,
    _ACTIVE_PORT_RESERVATIONS,
)
from analyzers.dynamic.worker import DynamicWorker
from analyzers.network.models import NetworkAnalysisResult
from analyzers.network.worker import NetworkWorker
from backend.services.analysis_service import AnalysisService

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
BENIGN_APK = str(SAMPLES_DIR / "benign_sample.apk")


@pytest.fixture(autouse=True)
def clean_locks_and_ports():
    """Ensure in-process locks and port reservations are clear before and after each test."""
    _ACTIVE_AVD_RUNS.clear()
    _ACTIVE_PORT_RESERVATIONS.clear()
    yield
    _ACTIVE_AVD_RUNS.clear()
    _ACTIVE_PORT_RESERVATIONS.clear()


def make_mock_env(
    available_avds=None,
    running_devices=None,
    selected_avd="Test_AVD",
    ready=True,
):
    """Helper to create a configured EnvironmentDiscovery mock."""
    env = MagicMock()
    env.find_adb_path.return_value = "/mock/adb"
    env.find_emulator_path.return_value = "/mock/emulator"
    env.get_status.return_value = EnvironmentStatus(
        ready=ready,
        selected_avd=selected_avd,
        available_avds=available_avds or ["Test_AVD"],
        running_devices=running_devices or [],
    )
    env.get_avd_supported_abis.return_value = ["arm64-v8a", "x86_64"]
    return env


def make_mock_runner(proc=None):
    """Helper to create a configured DynamicRunner mock with successful defaults."""
    runner = MagicMock()
    mock_proc = proc or MagicMock()
    runner.start_emulator.return_value = mock_proc
    runner.wait_for_boot.return_value = True
    runner.install_apk.return_value = (True, "Success")
    runner.launch_activity.return_value = (True, "Success")
    runner.get_package_pids.return_value = ["1000"]
    runner.dump_logcat.return_value = ""
    runner.dump_services.return_value = ""
    runner.dump_processes.return_value = ""
    runner.dump_camera_service.return_value = ""
    runner.dump_audio_service.return_value = ""
    runner.dump_location_service.return_value = ""
    runner.dump_accessibility_service.return_value = ""
    runner.dump_media_projection_service.return_value = ""
    return runner


# ==============================================================================
# TEST 1: COLD START WITHOUT DEVICES STARTS AVD
# ==============================================================================

def test_cold_start_without_devices_starts_avd():
    """Cold start with no running devices allocates port, launches AVD, and verifies boot on that serial."""
    mock_proc = MagicMock()
    mock_env = make_mock_env()
    mock_runner = make_mock_runner(mock_proc)
    mock_runner.get_first_online_device.return_value = None
    mock_runner.reserve_emulator_port.return_value = 5554

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status == "COMPLETED"
    mock_runner.reserve_emulator_port.assert_called_once_with("/mock/adb")
    mock_runner.start_emulator.assert_called_once_with("/mock/emulator", "Test_AVD", port=5554)
    mock_runner.wait_for_boot.assert_called_once_with("/mock/adb", device_id="emulator-5554", emulator_proc=mock_proc)
    mock_runner.stop_emulator.assert_called_once_with(mock_proc, "/mock/adb", "emulator-5554")


# ==============================================================================
# TEST 2: PHYSICAL DEVICE CONNECTED -> NEW EMULATOR SELECTED EXPLICITLY
# ==============================================================================

def test_physical_device_connected_launches_new_emulator_untouched_physical_device():
    """A pre-existing physical device is never targeted for dynamic APK execution; a new emulator is spawned."""
    physical_serial = "physical-device-usb-12345"
    mock_proc = MagicMock()
    mock_env = make_mock_env(running_devices=[physical_serial])
    mock_runner = make_mock_runner(mock_proc)
    mock_runner.get_first_online_device.return_value = physical_serial
    mock_runner.reserve_emulator_port.return_value = 5554

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, launchable_activity=".MainActivity", observation_seconds=0)

    assert res.status == "COMPLETED"
    assert res.execution.device_id == "emulator-5554"
    mock_runner.start_emulator.assert_called_once_with("/mock/emulator", "Test_AVD", port=5554)
    mock_runner.wait_for_boot.assert_called_once_with("/mock/adb", device_id="emulator-5554", emulator_proc=mock_proc)
    mock_runner.install_apk.assert_called_once_with("/mock/adb", BENIGN_APK, "emulator-5554")
    mock_runner.launch_activity.assert_called_once_with("/mock/adb", "com.spyaware.benign", ".MainActivity", "emulator-5554")
    mock_runner.force_stop.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5554")
    mock_runner.uninstall_apk.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5554")
    mock_runner.stop_emulator.assert_called_once_with(mock_proc, "/mock/adb", "emulator-5554")


# ==============================================================================
# TEST 3: PRE-EXISTING EMULATOR-5554 RUNNING -> NEW EMULATOR SELECTS EMULATOR-5556
# ==============================================================================

def test_preexisting_emulator_5554_running_incompatible_launches_emulator_5556():
    """When emulator-5554 is incompatible, port reservation picks 5556 for new emulator."""
    mock_proc = MagicMock()
    mock_env = make_mock_env(
        selected_avd="Default_AVD",
        available_avds=["Default_AVD", "Arm_AVD"],
        running_devices=["emulator-5554"],
    )
    mock_env.find_compatible_avd.return_value = "Arm_AVD"

    mock_runner = make_mock_runner(mock_proc)
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.get_device_supported_abis.return_value = ["x86_64"]
    mock_runner.reserve_emulator_port.return_value = 5556

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    with patch("analyzers.dynamic.worker.extract_apk_abis", return_value=["arm64-v8a"]):
        res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status == "COMPLETED"
    assert res.execution.device_id == "emulator-5556"
    mock_runner.reserve_emulator_port.assert_called_once_with("/mock/adb")
    mock_runner.start_emulator.assert_called_once_with("/mock/emulator", "Arm_AVD", port=5556)
    mock_runner.wait_for_boot.assert_called_once_with("/mock/adb", device_id="emulator-5556", emulator_proc=mock_proc)
    mock_runner.stop_emulator.assert_called_once_with(mock_proc, "/mock/adb", "emulator-5556")


# ==============================================================================
# TEST 4: SELECTED EMULATOR NOT YET IN ADB DURING EARLY POLLING
# ==============================================================================

def test_selected_emulator_not_yet_in_adb_during_early_polling():
    """DynamicRunner.wait_for_boot retries polling when device is not initially reported by adb."""
    runner = DynamicRunner(boot_timeout=10)
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None  # Process running

    calls = [
        subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error: device not found"),
        subprocess.CompletedProcess(args=[], returncode=0, stdout="0\n", stderr=""),
        subprocess.CompletedProcess(args=[], returncode=0, stdout="1\n", stderr=""),
        subprocess.CompletedProcess(args=[], returncode=0, stdout="package:/system/framework/framework-res.apk\n", stderr=""),
    ]

    with patch("subprocess.run", side_effect=calls) as mock_run, \
         patch("time.sleep", return_value=None):
        booted = runner.wait_for_boot("/mock/adb", device_id="emulator-5554", emulator_proc=mock_proc)

    assert booted is True
    assert mock_run.call_count == 4
    for c in mock_run.call_args_list:
        assert "-s" in c[0][0]
        assert "emulator-5554" in c[0][0]


# ==============================================================================
# TEST 5: SELECTED EMULATOR BOOT TIMEOUT
# ==============================================================================

def test_selected_emulator_boot_timeout():
    """When boot polling expires and process is still running, worker returns TIMEOUT and stops emulator."""
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None  # Process alive
    mock_env = make_mock_env()
    mock_runner = make_mock_runner(mock_proc)
    mock_runner.get_first_online_device.return_value = None
    mock_runner.reserve_emulator_port.return_value = 5554
    mock_runner.wait_for_boot.return_value = False

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status == "TIMEOUT"
    assert res.execution.exit_reason == "BOOT_TIMEOUT"
    assert "boot timed out" in res.error_message.lower()
    mock_runner.stop_emulator.assert_called_once_with(mock_proc, "/mock/adb", "emulator-5554")


# ==============================================================================
# TEST 6: PROCESS DEATH DURING BOOT (PROCESS_EXITED)
# ==============================================================================

def test_process_death_during_boot():
    """If the emulator process exits during boot, worker returns FAILED with PROCESS_EXITED."""
    mock_proc = MagicMock()
    mock_proc.poll.return_value = 1  # Process crashed with exit code 1
    mock_env = make_mock_env()
    mock_runner = make_mock_runner(mock_proc)
    mock_runner.get_first_online_device.return_value = None
    mock_runner.reserve_emulator_port.return_value = 5554
    mock_runner.wait_for_boot.return_value = False

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status == "FAILED"
    assert res.execution.exit_reason == "PROCESS_EXITED"
    assert "exited unexpectedly during boot" in res.error_message.lower()
    mock_runner.stop_emulator.assert_called_once_with(mock_proc, "/mock/adb", "emulator-5554")


# ==============================================================================
# TEST 7: APK INSTALLATION FAILURE CLEANS UP SPAWNED EMULATOR
# ==============================================================================

def test_apk_installation_failure_cleans_up_spawned_emulator():
    """If APK installation fails on the target emulator, the spawned emulator is shut down."""
    mock_proc = MagicMock()
    mock_env = make_mock_env()
    mock_runner = make_mock_runner(mock_proc)
    mock_runner.get_first_online_device.return_value = None
    mock_runner.reserve_emulator_port.return_value = 5554
    mock_runner.install_apk.return_value = (False, "INSTALL_FAILED_INVALID_APK")

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status == "FAILED"
    assert res.execution.exit_reason == "INSTALL_FAILED"
    assert "installation failed" in res.error_message.lower()
    mock_runner.stop_emulator.assert_called_once_with(mock_proc, "/mock/adb", "emulator-5554")


# ==============================================================================
# TEST 8: APPLICATION LAUNCH FAILURE CLEANS UP SPAWNED EMULATOR
# ==============================================================================

def test_application_launch_failure_cleans_up_spawned_emulator():
    """If activity launch fails, app is uninstalled and spawned emulator is shut down."""
    mock_proc = MagicMock()
    mock_env = make_mock_env()
    mock_runner = make_mock_runner(mock_proc)
    mock_runner.get_first_online_device.return_value = None
    mock_runner.reserve_emulator_port.return_value = 5554
    mock_runner.launch_activity.return_value = (False, "Error: Activity class does not exist")

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status == "FAILED"
    assert res.execution.exit_reason == "LAUNCH_FAILED"
    mock_runner.force_stop.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5554")
    mock_runner.uninstall_apk.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5554")
    mock_runner.stop_emulator.assert_called_once_with(mock_proc, "/mock/adb", "emulator-5554")


# ==============================================================================
# TEST 9: TELEMETRY COLLECTION EXCEPTION CLEANS UP SPAWNED EMULATOR
# ==============================================================================

def test_telemetry_collection_exception_cleans_up_spawned_emulator():
    """An unexpected exception during telemetry collection triggers guaranteed cleanup."""
    mock_proc = MagicMock()
    mock_env = make_mock_env()
    mock_runner = make_mock_runner(mock_proc)
    mock_runner.get_first_online_device.return_value = None
    mock_runner.reserve_emulator_port.return_value = 5554
    mock_runner.dump_logcat.side_effect = RuntimeError("Pipe broken")

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    with pytest.raises(RuntimeError, match="Pipe broken"):
        worker.run_analysis(BENIGN_APK, observation_seconds=0)

    mock_runner.force_stop.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5554")
    mock_runner.uninstall_apk.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5554")
    mock_runner.stop_emulator.assert_called_once_with(mock_proc, "/mock/adb", "emulator-5554")


# ==============================================================================
# TEST 10: CLEANUP TARGETS SPAWNED EMULATOR ONLY
# ==============================================================================

def test_cleanup_targets_spawned_emulator_only():
    """Cleanup does not kill or touch another emulator running alongside the spawned one."""
    mock_proc = MagicMock()
    mock_env = make_mock_env(
        available_avds=["Test_AVD", "Arm_AVD"],
        running_devices=["emulator-5554"],
    )
    mock_env.find_compatible_avd.return_value = "Arm_AVD"

    mock_runner = make_mock_runner(mock_proc)
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.get_device_supported_abis.return_value = ["x86"]
    mock_runner.reserve_emulator_port.return_value = 5556

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    with patch("analyzers.dynamic.worker.extract_apk_abis", return_value=["arm64-v8a"]):
        worker.run_analysis(BENIGN_APK, observation_seconds=0)

    # Only emulator-5556 was targeted for cleanup
    mock_runner.force_stop.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5556")
    mock_runner.uninstall_apk.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5556")
    mock_runner.stop_emulator.assert_called_once_with(mock_proc, "/mock/adb", "emulator-5556")


# ==============================================================================
# TEST 11: PRE-EXISTING EMULATOR NEVER TERMINATED
# ==============================================================================

def test_preexisting_emulator_never_terminated():
    """An emulator already running before the analysis job is never stopped."""
    mock_env = make_mock_env(running_devices=["emulator-5554"])
    mock_runner = make_mock_runner()
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.get_device_supported_abis.return_value = ["arm64-v8a", "x86_64"]

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status == "COMPLETED"
    assert res.execution.emulator_started_by_job is False
    mock_runner.start_emulator.assert_not_called()
    mock_runner.stop_emulator.assert_not_called()
    mock_runner.force_stop.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5554")
    mock_runner.uninstall_apk.assert_called_once_with("/mock/adb", "com.spyaware.benign", "emulator-5554")


# ==============================================================================
# TEST 12: PHYSICAL DEVICE NEVER TERMINATED
# ==============================================================================

def test_physical_device_never_terminated():
    """DynamicRunner.stop_emulator never issues emu kill against a physical device serial."""
    runner = DynamicRunner()
    physical_serial = "physical-usb-phone-1234"

    with patch("subprocess.run") as mock_run:
        runner.stop_emulator(emulator_proc=None, adb_path="/mock/adb", device_id=physical_serial)
        # emu kill must NOT be executed because physical serial doesn't start with emulator-
        mock_run.assert_not_called()


# ==============================================================================
# TEST 13: PORT ALLOCATION DETECTS OCCUPIED PORTS VIA SOCKET AND ADB
# ==============================================================================

def test_port_allocation_detects_occupied_ports_via_socket_and_adb():
    """reserve_emulator_port skips occupied ports in ADB and socket binds."""
    runner = DynamicRunner()

    with patch.object(runner, "get_all_device_serials", return_value=["emulator-5554"]), \
         patch.object(DynamicRunner, "is_port_in_use", side_effect=lambda p: p == 5556):

        port = runner.reserve_emulator_port("/mock/adb")
        assert port == 5558  # 5554 in ADB, 5556 socket occupied -> selects 5558

        # Calling again in same process sees 5558 as in-process reserved -> selects 5560
        port_2 = runner.reserve_emulator_port("/mock/adb")
        assert port_2 == 5560

        # Release reservation
        runner.release_port_reservation(5558)
        port_3 = runner.reserve_emulator_port("/mock/adb")
        assert port_3 == 5558


# ==============================================================================
# TEST 14: CONCURRENT STARTUP ATTEMPTS WITH SAME AVD BLOCKED VIA AVDLOCK
# ==============================================================================

def test_concurrent_startup_attempts_with_same_avd_blocked_via_avd_lock():
    """Two concurrent operations targeting the same AVD: second fails with AVD_LOCKED."""
    lock1 = AVDLock("Test_AVD_Concurrent")
    assert lock1.acquire(timeout=0) is True

    # Second lock on same AVD in another thread/worker
    lock2 = AVDLock("Test_AVD_Concurrent")
    assert lock2.acquire(timeout=0) is False

    # Once lock1 releases, lock2 can acquire
    lock1.release()
    assert lock2.acquire(timeout=0) is True
    lock2.release()


# ==============================================================================
# TEST 15: NETWORK ANALYSIS FOLLOWS IDENTICAL DEVICE-OWNERSHIP RULES
# ==============================================================================

def test_network_analysis_follows_identical_device_ownership_rules():
    """NetworkWorker reserves port, targets serial, and cleans up only spawned emulator on failure."""
    mock_proc = MagicMock()
    mock_env = make_mock_env()
    mock_runner = make_mock_runner(mock_proc)
    mock_runner.get_first_online_device.return_value = None
    mock_runner.reserve_emulator_port.return_value = 5554
    mock_runner.install_apk.return_value = (False, "INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES")

    worker = NetworkWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status in ("UNAVAILABLE", "FAILED")
    assert "installation failed" in res.error_message.lower()
    mock_runner.reserve_emulator_port.assert_called_once_with("/mock/adb")
    mock_runner.start_emulator.assert_called_once_with("/mock/emulator", "Test_AVD", port=5554)
    mock_runner.stop_emulator.assert_called_once_with(mock_proc, "/mock/adb", "emulator-5554")


# ==============================================================================
# TEST 16: ABI INCOMPATIBILITY HANDLING PRESERVED
# ==============================================================================

def test_abi_incompatibility_handling_preserved():
    """When target APK requires an ABI unsupported by available AVDs, worker returns FAILED without starting emulator."""
    mock_env = make_mock_env(selected_avd="X86_AVD", available_avds=["X86_AVD"])
    mock_env.get_avd_supported_abis.return_value = ["x86_64"]
    mock_env.find_compatible_avd.return_value = None

    mock_runner = make_mock_runner()
    mock_runner.get_first_online_device.return_value = None

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    with patch("analyzers.dynamic.worker.extract_apk_abis", return_value=["arm64-v8a"]):
        res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status == "FAILED"
    assert res.execution.exit_reason == "INCOMPATIBLE_ABI"
    assert "ABI incompatibility" in res.error_message
    mock_runner.start_emulator.assert_not_called()
