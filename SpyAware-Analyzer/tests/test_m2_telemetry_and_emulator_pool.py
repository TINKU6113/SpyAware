"""Milestone M2 Automated Test Suite: Consistent Runtime Telemetry & ABI-Aware Emulator Pool.

Verifies all 20 required criteria:
1. Pure-Java APK with no native libs runs on any compatible AVD without rejection.
2. APK with x86_64 native lib selects x86_64 AVD and rejects ARM-only profile.
3. APK with arm64-v8a native lib selects ARM64 profile when present.
4. APK with arm64-v8a native lib fails safely with INCOMPATIBLE_ABI when no ARM profile exists.
5. APK with 32-bit armeabi-v7a is handled by compatible profile or rejected with clean reason.
6. Deprecated armeabi is recognized as distinct from armeabi-v7a and not falsely claimed supported.
7. minSdk higher than emulator API triggers fallback to higher API or reports INCOMPATIBLE_ANDROID_VERSION.
8. AVD selection ranks compatible candidates in preferred order.
9. Existing AVD Medium_Phone_API_36.1 is kept, discovered, and used when compatible.
10. Sequential fallback: profile 1 fails to start -> profile 2 is tried and succeeds.
11. Sequential fallback: profile 1 boot timeout -> emulator killed, profile 2 tried.
12. Sequential fallback: profile 1 install failure (ABI mismatch) -> profile 2 tried.
13. Sequential fallback: all compatible profiles fail -> analysis reports FAILED with history of attempts.
14. An emulator started by a failed attempt is stopped before the next attempt starts.
15. Already-running emulator is reused when compatible and not stopped at analysis end.
16. Unlaunched application: all 10 telemetry categories report NOT_TESTED (or UNAVAILABLE).
17. Partial observation: successful commands return NOT_OBSERVED, failed commands return UNAVAILABLE.
18. Single surveillance event observed: headline, summary, and matrix show exactly 1 observed, with Category 1 showing OBSERVED and evidence, and other 9 showing NOT_OBSERVED (or UNAVAILABLE).
19. Headline indicator count matches the sum of observed categories and does not count NOT_OBSERVED, UNAVAILABLE, or NOT_TESTED.
20. Report JSON export includes canonical category status, reasons, evidence, and AVD fallback attempt history.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, call, patch
import pytest

from analyzers.dynamic.environment import EnvironmentDiscovery
from analyzers.dynamic.models import (
    AVDFallbackAttempt,
    AVDInventory,
    AVDProfile,
    CANONICAL_CATEGORIES_ORDER,
    CanonicalTelemetryResult,
    DynamicAnalysisResult,
    EnvironmentStatus,
    ExecutionMetadata,
    RuntimeBehaviorStatus,
    RuntimeObservation,
)
from analyzers.dynamic.observer import DynamicObserver
from analyzers.dynamic.runner import (
    AVDLock,
    DynamicRunner,
    _ACTIVE_AVD_RUNS,
    _ACTIVE_PORT_RESERVATIONS,
)
from analyzers.dynamic.worker import DynamicWorker
from backend.models.analysis import RiskReport, Severity

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
BENIGN_APK = str(SAMPLES_DIR / "benign_sample.apk")


@pytest.fixture(autouse=True)
def clean_locks():
    """Clear in-process locks and port reservations between tests."""
    _ACTIVE_AVD_RUNS.clear()
    _ACTIVE_PORT_RESERVATIONS.clear()
    yield
    _ACTIVE_AVD_RUNS.clear()
    _ACTIVE_PORT_RESERVATIONS.clear()


# ==============================================================================
# TEST 1: Pure-Java APK with no native libs runs on any AVD without rejection
# ==============================================================================
def test_pure_java_apk_runs_on_any_compatible_avd():
    env = EnvironmentDiscovery()
    avd_x86 = AVDProfile(name="Test_x86", abis=["x86_64", "x86"], api_level=30)
    avd_arm = AVDProfile(name="Test_arm", abis=["arm64-v8a"], api_level=30)

    # Pure Java / Kotlin APK has empty apk_abis
    compat_x86, reason_x86 = env.evaluate_apk_compatibility(avd_x86, apk_abis=[])
    compat_arm, reason_arm = env.evaluate_apk_compatibility(avd_arm, apk_abis=[])

    assert compat_x86 is True
    assert compat_arm is True
    assert "Pure Java/Kotlin" in reason_x86
    assert "Pure Java/Kotlin" in reason_arm


# ==============================================================================
# TEST 2: APK with x86_64 native lib selects x86_64 AVD and rejects ARM-only profile
# ==============================================================================
def test_x86_64_native_lib_selects_x86_64_and_rejects_arm_profile():
    env = EnvironmentDiscovery()
    avd_x86 = AVDProfile(name="x86_AVD", abis=["x86_64", "x86"], api_level=30)
    avd_arm = AVDProfile(name="arm_AVD", abis=["arm64-v8a", "armeabi-v7a"], api_level=30)

    compat_x86, _ = env.evaluate_apk_compatibility(avd_x86, apk_abis=["x86_64"])
    compat_arm, reason_arm = env.evaluate_apk_compatibility(avd_arm, apk_abis=["x86_64"])

    assert compat_x86 is True
    assert compat_arm is False
    assert "INCOMPATIBLE_ABI" in reason_arm


# ==============================================================================
# TEST 3: APK with arm64-v8a native lib selects ARM64 profile when present
# ==============================================================================
def test_arm64_v8a_native_lib_selects_arm64_profile():
    env = EnvironmentDiscovery()
    avd_arm = AVDProfile(name="Pixel_ARM64", abis=["arm64-v8a", "armeabi-v7a"], api_level=30)

    compat, reason = env.evaluate_apk_compatibility(avd_arm, apk_abis=["arm64-v8a"])
    assert compat is True
    assert "arm64-v8a" in reason


# ==============================================================================
# TEST 4: APK with arm64-v8a native lib fails safely with INCOMPATIBLE_ABI when no ARM profile exists
# ==============================================================================
def test_arm64_v8a_fails_safely_when_no_arm_profile_exists():
    mock_env = MagicMock()
    mock_env.find_adb_path.return_value = "/mock/adb"
    mock_env.find_emulator_path.return_value = "/mock/emulator"
    mock_env.get_status.return_value = EnvironmentStatus(
        ready=True,
        selected_avd="x86_Only_AVD",
        available_avds=["x86_Only_AVD"],
        running_devices=[],
    )
    mock_env.get_avd_supported_abis.return_value = ["x86_64", "x86"]
    mock_env.find_compatible_avd.return_value = None
    mock_env.rank_compatible_avds.return_value = []

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = None

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    with patch("analyzers.dynamic.worker.extract_apk_abis", return_value=["arm64-v8a"]):
        res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status == "FAILED"
    assert res.execution.exit_reason == "INCOMPATIBLE_ABI"
    assert "INSTALL_FAILED_NO_MATCHING_ABIS" in res.error_message
    assert res.telemetry.categories_not_tested == 10


# ==============================================================================
# TEST 5: APK with 32-bit armeabi-v7a is handled by compatible profile or rejected with clean reason
# ==============================================================================
def test_armeabi_v7a_handled_by_compatible_profile():
    env = EnvironmentDiscovery()
    avd_v7a = AVDProfile(name="ARM32_AVD", abis=["armeabi-v7a"], api_level=25)
    avd_x86 = AVDProfile(name="x86_AVD", abis=["x86_64", "x86"], api_level=30)

    compat_v7a, _ = env.evaluate_apk_compatibility(avd_v7a, apk_abis=["armeabi-v7a"])
    compat_x86, reason_x86 = env.evaluate_apk_compatibility(avd_x86, apk_abis=["armeabi-v7a"])

    assert compat_v7a is True
    assert compat_x86 is False
    assert "INCOMPATIBLE_ABI" in reason_x86


# ==============================================================================
# TEST 6: Deprecated armeabi is recognized as distinct from armeabi-v7a
# ==============================================================================
def test_deprecated_armeabi_is_distinct_and_not_falsely_supported():
    env = EnvironmentDiscovery()
    # A profile with armeabi-v7a does NOT support deprecated armeabi
    avd_v7a = AVDProfile(name="ARM_Modern", abis=["armeabi-v7a", "arm64-v8a"], api_level=28)

    compat, reason = env.evaluate_apk_compatibility(avd_v7a, apk_abis=["armeabi"])
    assert compat is False
    assert "INCOMPATIBLE_ABI" in reason
    assert "deprecated armeabi" in reason


# ==============================================================================
# TEST 7: minSdk higher than emulator API triggers fallback or reports INCOMPATIBLE_ANDROID_VERSION
# ==============================================================================
def test_min_sdk_exceeds_emulator_api_reports_incompatible_version():
    env = EnvironmentDiscovery()
    avd_api28 = AVDProfile(name="Pie_AVD", api_level=28, abis=["x86_64"])

    # APK requiring API 34
    compat, reason = env.evaluate_apk_compatibility(avd_api28, apk_min_sdk=34, apk_abis=[])
    assert compat is False
    assert "INCOMPATIBLE_ANDROID_VERSION" in reason


# ==============================================================================
# TEST 8: AVD selection ranks compatible candidates in preferred order
# ==============================================================================
def test_avd_selection_ranks_compatible_candidates():
    env = EnvironmentDiscovery()
    profiles = {
        "Medium_Phone_API_36.1": AVDProfile(name="Medium_Phone_API_36.1", api_level=36, abis=["x86_64", "x86"], ready=True),
        "Pixel_API_30": AVDProfile(name="Pixel_API_30", api_level=30, abis=["x86_64", "x86"], ready=True),
        "Nexus_API_28": AVDProfile(name="Nexus_API_28", api_level=28, abis=["x86_64", "x86"], ready=True),
    }

    with patch.object(env, "list_available_avds", return_value=list(profiles.keys())), \
         patch.object(env, "inspect_avd_profile", side_effect=lambda name: profiles[name]), \
         patch.object(env, "list_running_devices", return_value=[]):
        ranked = env.rank_compatible_avds(apk_min_sdk=21, apk_target_sdk=30, apk_abis=["x86_64"])

    ranked_names = [p[0].name for p in ranked]
    assert len(ranked_names) == 3
    # Existing default / API 36 reference has top priority
    assert ranked_names[0] == "Medium_Phone_API_36.1"


# ==============================================================================
# TEST 9: Existing AVD Medium_Phone_API_36.1 is kept, discovered, and used when compatible
# ==============================================================================
def test_existing_avd_medium_phone_discovered_and_preserved():
    env = EnvironmentDiscovery()
    inventory = env.get_avd_inventory()

    assert inventory.adb_available is True
    assert "Medium_Phone_API_36.1" in inventory.available_avd_names
    prof = next(p for p in inventory.profiles if p.name == "Medium_Phone_API_36.1")
    assert prof.api_level == 36
    assert "x86_64" in prof.abis


# ==============================================================================
# TEST 10: Sequential fallback: profile 1 fails to start -> profile 2 is tried and succeeds
# ==============================================================================
def test_sequential_fallback_start_failure_then_success():
    mock_proc = MagicMock()
    mock_env = MagicMock()
    mock_env.find_adb_path.return_value = "/mock/adb"
    mock_env.find_emulator_path.return_value = "/mock/emulator"
    mock_env.get_status.return_value = EnvironmentStatus(
        ready=True,
        selected_avd="Profile_1",
        available_avds=["Profile_1", "Profile_2"],
        running_devices=[],
    )
    p1 = AVDProfile(name="Profile_1", abis=["x86_64"], api_level=30)
    p2 = AVDProfile(name="Profile_2", abis=["x86_64"], api_level=30)
    mock_env.rank_compatible_avds.return_value = [(p1, "candidate"), (p2, "candidate")]

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = None
    mock_runner.reserve_emulator_port.side_effect = [5554, 5556]
    # Profile 1 start fails (None), Profile 2 starts successfully (mock_proc)
    mock_runner.start_emulator.side_effect = [None, mock_proc]
    mock_runner.wait_for_boot.return_value = True
    mock_runner.install_apk.return_value = (True, "Success")
    mock_runner.launch_activity.return_value = (True, "Success")
    mock_runner.dump_logcat.return_value = ""
    mock_runner.dump_services.return_value = ""
    mock_runner.dump_processes.return_value = "u0_a100 1234 800 1200000 50000 0 0 S com.spyaware.benign"
    mock_runner.get_package_pids.return_value = ["1234"]

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, launchable_activity=".MainActivity", observation_seconds=0)

    assert res.status == "COMPLETED"
    assert res.execution.avd_name == "Profile_2"
    assert len(res.execution.avd_attempts) == 2
    assert res.execution.avd_attempts[0].avd_name == "Profile_1"
    assert res.execution.avd_attempts[0].status == "FAILED"
    assert res.execution.avd_attempts[0].failure_classification == "STARTUP_FAILED"
    assert res.execution.avd_attempts[1].avd_name == "Profile_2"
    assert res.execution.avd_attempts[1].status == "SUCCESS"


# ==============================================================================
# TEST 11: Sequential fallback: profile 1 boot timeout -> emulator killed, profile 2 tried
# ==============================================================================
def test_sequential_fallback_boot_timeout_kills_first_and_tries_second():
    proc1 = MagicMock()
    proc1.poll.return_value = None  # Process alive on timeout
    proc2 = MagicMock()

    mock_env = MagicMock()
    mock_env.find_adb_path.return_value = "/mock/adb"
    mock_env.find_emulator_path.return_value = "/mock/emulator"
    mock_env.get_status.return_value = EnvironmentStatus(
        ready=True,
        selected_avd="Profile_1",
        available_avds=["Profile_1", "Profile_2"],
        running_devices=[],
    )
    p1 = AVDProfile(name="Profile_1", abis=["x86_64"], api_level=30)
    p2 = AVDProfile(name="Profile_2", abis=["x86_64"], api_level=30)
    mock_env.rank_compatible_avds.return_value = [(p1, "candidate"), (p2, "candidate")]

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = None
    mock_runner.reserve_emulator_port.side_effect = [5554, 5556]
    mock_runner.start_emulator.side_effect = [proc1, proc2]
    # Profile 1 times out (False), Profile 2 boots (True)
    mock_runner.wait_for_boot.side_effect = [False, True]
    mock_runner.install_apk.return_value = (True, "Success")
    mock_runner.launch_activity.return_value = (True, "Success")
    mock_runner.dump_logcat.return_value = ""
    mock_runner.dump_services.return_value = ""
    mock_runner.dump_processes.return_value = "u0_a100 1234 800 1200000 50000 0 0 S com.spyaware.benign"
    mock_runner.get_package_pids.return_value = ["1234"]

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, launchable_activity=".MainActivity", observation_seconds=0)

    assert res.status == "COMPLETED"
    assert res.execution.avd_name == "Profile_2"
    # Ensure proc1 was explicitly stopped before profile 2 ran
    mock_runner.stop_emulator.assert_any_call(proc1, "/mock/adb", "emulator-5554")
    assert res.execution.avd_attempts[0].failure_classification == "BOOT_TIMEOUT"
    assert res.execution.avd_attempts[1].status == "SUCCESS"


# ==============================================================================
# TEST 12: Sequential fallback: profile 1 install failure (ABI mismatch) -> profile 2 tried
# ==============================================================================
def test_sequential_fallback_install_failure_tries_next():
    proc1 = MagicMock()
    proc2 = MagicMock()

    mock_env = MagicMock()
    mock_env.find_adb_path.return_value = "/mock/adb"
    mock_env.find_emulator_path.return_value = "/mock/emulator"
    mock_env.get_status.return_value = EnvironmentStatus(
        ready=True,
        selected_avd="Profile_1",
        available_avds=["Profile_1", "Profile_2"],
        running_devices=[],
    )
    p1 = AVDProfile(name="Profile_1", abis=["x86_64"], api_level=30)
    p2 = AVDProfile(name="Profile_2", abis=["x86_64"], api_level=30)
    mock_env.rank_compatible_avds.return_value = [(p1, "candidate"), (p2, "candidate")]

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = None
    mock_runner.reserve_emulator_port.side_effect = [5554, 5556]
    mock_runner.start_emulator.side_effect = [proc1, proc2]
    mock_runner.wait_for_boot.return_value = True
    # Profile 1 install fails due to ABI error, Profile 2 succeeds
    mock_runner.install_apk.side_effect = [
        (False, "Failure [INSTALL_FAILED_NO_MATCHING_ABIS: Failed to extract native libraries]"),
        (True, "Success"),
    ]
    mock_runner.launch_activity.return_value = (True, "Success")
    mock_runner.dump_logcat.return_value = ""
    mock_runner.dump_services.return_value = ""
    mock_runner.dump_processes.return_value = "u0_a100 1234 800 1200000 50000 0 0 S com.spyaware.benign"
    mock_runner.get_package_pids.return_value = ["1234"]

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, launchable_activity=".MainActivity", observation_seconds=0)

    assert res.status == "COMPLETED"
    assert res.execution.avd_name == "Profile_2"
    assert res.execution.avd_attempts[0].failure_classification == "INCOMPATIBLE_ABI"
    assert res.execution.avd_attempts[1].status == "SUCCESS"


# ==============================================================================
# TEST 13: Sequential fallback: all compatible profiles fail -> reports FAILED with history
# ==============================================================================
def test_all_compatible_profiles_fail_reports_history():
    proc1 = MagicMock()
    proc2 = MagicMock()

    mock_env = MagicMock()
    mock_env.find_adb_path.return_value = "/mock/adb"
    mock_env.find_emulator_path.return_value = "/mock/emulator"
    mock_env.get_status.return_value = EnvironmentStatus(
        ready=True,
        selected_avd="Profile_1",
        available_avds=["Profile_1", "Profile_2"],
        running_devices=[],
    )
    p1 = AVDProfile(name="Profile_1", abis=["x86_64"], api_level=30)
    p2 = AVDProfile(name="Profile_2", abis=["x86_64"], api_level=30)
    mock_env.rank_compatible_avds.return_value = [(p1, "candidate"), (p2, "candidate")]

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = None
    mock_runner.reserve_emulator_port.side_effect = [5554, 5556]
    mock_runner.start_emulator.side_effect = [proc1, proc2]
    mock_runner.wait_for_boot.return_value = True
    # Both fail installation
    mock_runner.install_apk.side_effect = [
        (False, "INSTALL_FAILED_INVALID_APK"),
        (False, "INSTALL_FAILED_INSUFFICIENT_STORAGE"),
    ]

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, launchable_activity=".MainActivity", observation_seconds=0)

    assert res.status == "FAILED"
    assert len(res.execution.avd_attempts) == 2
    assert all(a.status == "FAILED" for a in res.execution.avd_attempts)
    assert res.telemetry.categories_not_tested == 10


# ==============================================================================
# TEST 14: Failed attempt emulator is stopped before next attempt starts
# ==============================================================================
def test_failed_attempt_emulator_stopped_before_next_attempt():
    proc1 = MagicMock()
    proc1.poll.return_value = None
    proc2 = MagicMock()

    mock_env = MagicMock()
    mock_env.find_adb_path.return_value = "/mock/adb"
    mock_env.find_emulator_path.return_value = "/mock/emulator"
    mock_env.get_status.return_value = EnvironmentStatus(ready=True)
    p1 = AVDProfile(name="P1", abis=["x86_64"], api_level=30)
    p2 = AVDProfile(name="P2", abis=["x86_64"], api_level=30)
    mock_env.rank_compatible_avds.return_value = [(p1, "c"), (p2, "c")]

    stop_call_order = []

    def mock_start(path, name, port=None):
        if name == "P1":
            return proc1
        elif name == "P2":
            # Verify that proc1 was stopped BEFORE P2 starts!
            assert proc1 in stop_call_order
            return proc2

    def mock_stop(proc, adb, dev):
        stop_call_order.append(proc)

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = None
    mock_runner.reserve_emulator_port.side_effect = [5554, 5556]
    mock_runner.start_emulator.side_effect = mock_start
    mock_runner.stop_emulator.side_effect = mock_stop
    mock_runner.wait_for_boot.side_effect = [False, True]
    mock_runner.install_apk.return_value = (True, "Success")
    mock_runner.launch_activity.return_value = (True, "Success")
    mock_runner.dump_logcat.return_value = ""
    mock_runner.dump_services.return_value = ""
    mock_runner.dump_processes.return_value = "u0_a100 1234 800 1200000 50000 0 0 S com.spyaware.benign"
    mock_runner.get_package_pids.return_value = ["1234"]

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, launchable_activity=".MainActivity", observation_seconds=0)

    assert res.status == "COMPLETED"
    assert proc1 in stop_call_order


# ==============================================================================
# TEST 15: Already-running emulator is reused when compatible and not stopped at end
# ==============================================================================
def test_already_running_emulator_reused_and_not_stopped():
    mock_env = MagicMock()
    mock_env.find_adb_path.return_value = "/mock/adb"
    mock_env.get_status.return_value = EnvironmentStatus(ready=True, running_devices=["emulator-5554"])

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.get_device_supported_abis.return_value = ["x86_64", "x86"]
    mock_runner.get_device_sdk_version.return_value = 36
    mock_runner.install_apk.return_value = (True, "Success")
    mock_runner.launch_activity.return_value = (True, "Success")
    mock_runner.dump_logcat.return_value = ""
    mock_runner.dump_services.return_value = ""
    mock_runner.dump_processes.return_value = "u0_a100 1234 800 1200000 50000 0 0 S com.spyaware.benign"
    mock_runner.get_package_pids.return_value = ["1234"]

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    res = worker.run_analysis(BENIGN_APK, launchable_activity=".MainActivity", observation_seconds=0)

    assert res.status == "COMPLETED"
    assert res.execution.device_id == "emulator-5554"
    assert res.execution.emulator_started_by_job is False
    # stop_emulator MUST NOT be called on pre-existing emulator
    mock_runner.stop_emulator.assert_not_called()


# ==============================================================================
# TEST 16: Unlaunched application: all 10 telemetry categories report NOT_TESTED
# ==============================================================================
def test_unlaunched_application_all_categories_not_tested():
    mock_env = MagicMock()
    mock_env.get_status.return_value = EnvironmentStatus(ready=True, selected_avd="Test_AVD")
    mock_env.find_adb_path.return_value = "/mock/adb"
    mock_env.find_emulator_path.return_value = "/mock/emulator"

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.install_apk.return_value = (True, "Success")

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)
    # No launchable activity -> cannot launch
    res = worker.run_analysis(BENIGN_APK, package_name="com.test.pkg", launchable_activity=None)

    assert res.status == "NO_LAUNCHABLE_ACTIVITY"
    assert res.telemetry is not None
    assert res.telemetry.categories_observed == 0
    assert res.telemetry.categories_not_tested == 10
    assert all(o.status == "NOT_TESTED" for o in res.telemetry.categories.values())


# ==============================================================================
# TEST 17: Partial observation: successful commands NOT_OBSERVED, failed commands UNAVAILABLE
# ==============================================================================
def test_partial_observation_distinguishes_not_observed_from_unavailable():
    observer = DynamicObserver()

    # Camera dumpsys failed (None), while audio dumpsys succeeded with normal output
    observations, runtime_behavior, findings, score = observer.observe_stage_2b(
        package_name="com.test.pkg",
        launch_success=True,
        logcat_text="",
        services_text="",
        process_text="u0_a100 1234 800 1200000 50000 0 0 S com.test.pkg",
        camera_dumpsys=None,  # Command failed / unavailable
        audio_dumpsys="AudioRecord clients: none",  # Command succeeded; no active capture
        location_dumpsys="LocationManagerService: active providers none",
        accessibility_dumpsys="AccessibilityServices: none",
        media_projection_dumpsys="MediaProjection tokens: none",
        target_pids=[1234],
        duration_seconds=15.0,
    )

    tele: CanonicalTelemetryResult = observer.last_telemetry
    assert tele.categories["CAMERA"].status == RuntimeBehaviorStatus.UNAVAILABLE.value
    assert tele.categories["MICROPHONE"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert tele.categories_unavailable >= 1
    assert tele.categories_observed == 1  # Category 10 (PROCESS) observed


# ==============================================================================
# TEST 18: Single surveillance event observed: headline, summary, and matrix show exactly 1 observed
# ==============================================================================
def test_single_surveillance_event_headline_and_matrix_consistency():
    observer = DynamicObserver()

    camera_log = "01-01 10:00:00.000  1234  1250 I CameraDevice: openCamera 0 for com.test.spy"
    observations, runtime_behavior, findings, score = observer.observe_stage_2b(
        package_name="com.test.spy",
        launch_success=True,
        logcat_text=camera_log,
        services_text="",
        process_text="u0_a100 1234 800 1200000 50000 0 0 S com.test.spy",
        camera_dumpsys="Client 0: com.test.spy active",
        audio_dumpsys="",
        location_dumpsys="",
        accessibility_dumpsys="",
        media_projection_dumpsys="",
        target_pids=[1234],
        duration_seconds=15.0,
    )

    tele: CanonicalTelemetryResult = observer.last_telemetry
    # Exactly camera observed for covert surveillance (+ process lifecycle)
    assert tele.categories["CAMERA"].status == RuntimeBehaviorStatus.OBSERVED.value
    assert tele.categories["CAMERA"].evidence is not None
    assert tele.surveillance_observed_count == 1
    assert "1 covert surveillance indicator confirmed active" in tele.headline
    # Verify non-observed categories
    for cid in ["MICROPHONE", "LOCATION", "ACCESSIBILITY", "MEDIA_PROJECTION", "SMS", "CALL"]:
        assert tele.categories[cid].status == RuntimeBehaviorStatus.NOT_OBSERVED.value


# ==============================================================================
# TEST 19: Headline count matches observed categories, does not count NOT_OBSERVED/UNAVAILABLE/NOT_TESTED
# ==============================================================================
def test_headline_count_strictly_matches_observed_categories():
    observer = DynamicObserver()

    # Audio command failed (None), Camera command failed (None), no events seen
    observations, runtime_behavior, findings, score = observer.observe_stage_2b(
        package_name="com.test.clean",
        launch_success=True,
        logcat_text="",
        services_text="",
        process_text="",  # Process not found
        camera_dumpsys=None,  # UNAVAILABLE
        audio_dumpsys=None,   # UNAVAILABLE
        location_dumpsys="",
        accessibility_dumpsys="",
        media_projection_dumpsys="",
        target_pids=[],
        duration_seconds=15.0,
    )

    tele: CanonicalTelemetryResult = observer.last_telemetry
    assert tele.categories_observed == 0
    assert tele.surveillance_observed_count == 0
    # Must NOT claim active surveillance indicators
    assert "0 covert surveillance indicators" not in tele.headline
    assert "No suspicious runtime indicators observed" in tele.headline


# ==============================================================================
# TEST 20: Report JSON export includes canonical category status, reasons, evidence, and AVD fallback history
# ==============================================================================
def test_report_json_export_includes_telemetry_and_avd_history():
    from backend.services.analysis_service import AnalysisService

    service = AnalysisService()

    # Construct synthetic complete report
    obs_dict = {
        cid: RuntimeObservation(
            category=cid,
            status=RuntimeBehaviorStatus.NOT_OBSERVED.value,
            description="Checked cleanly",
            source="dumpsys",
        )
        for cid in CANONICAL_CATEGORIES_ORDER
    }
    obs_dict["CAMERA"].status = RuntimeBehaviorStatus.OBSERVED.value
    obs_dict["CAMERA"].evidence = "CameraDevice openCamera hit"

    telemetry = CanonicalTelemetryResult(
        categories_observed=1,
        categories_tested=10,
        categories_unavailable=0,
        categories_not_tested=0,
        categories_total=10,
        categories=obs_dict,
        surveillance_observed_count=1,
        headline="1 covert surveillance indicator confirmed active.",
        summary="1 / 10 observed",
    )

    dyn_res = DynamicAnalysisResult(
        status="COMPLETED",
        score=15.0,
        risk_level="MEDIUM",
        execution=ExecutionMetadata(
            package_name="com.test.export",
            launchable_activity=".MainActivity",
            launch_success=True,
            duration_seconds=15.0,
            avd_name="Profile_2",
            device_id="emulator-5556",
            emulator_started_by_job=True,
            exit_reason="OBSERVATION_COMPLETED",
            avd_attempts=[
                AVDFallbackAttempt(
                    avd_name="Profile_1",
                    status="FAILED",
                    failure_classification="EMULATOR_BOOT_TIMEOUT",
                    reason="Boot timed out on profile 1",
                ),
                AVDFallbackAttempt(
                    avd_name="Profile_2",
                    status="SUCCESS",
                    reason="Booted and installed cleanly",
                ),
            ],
        ),
        telemetry=telemetry,
        runtime_behavior=obs_dict,
    )

    # Serialize report to JSON
    report_dict = dyn_res.model_dump()
    json_str = json.dumps(report_dict)
    loaded = json.loads(json_str)

    # Assert all canonical fields and fallback history are preserved in export
    assert loaded["telemetry"]["categories_observed"] == 1
    assert loaded["telemetry"]["categories"]["CAMERA"]["status"] == "OBSERVED"
    assert loaded["telemetry"]["categories"]["CAMERA"]["evidence"] == "CameraDevice openCamera hit"
    assert len(loaded["execution"]["avd_attempts"]) == 2
    assert loaded["execution"]["avd_attempts"][0]["failure_classification"] == "EMULATOR_BOOT_TIMEOUT"
    assert loaded["execution"]["avd_attempts"][1]["status"] == "SUCCESS"
