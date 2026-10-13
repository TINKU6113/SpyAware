"""Comprehensive test suite for Dynamic Analysis and Network Analysis failure handling.

Covers:
1. Compatible ABI and successful installation.
2. INSTALL_FAILED_NO_MATCHING_ABIS (pre-check detection and ADB error message handling).
3. Installation failure followed by no launch attempt and no observation timer.
4. Launch failure after successful installation (duration = 0.0s, exit_reason="LAUNCH_FAILED").
5. Successful launch but no observed network traffic (disclaimer preserved, no hallucinated traffic).
6. Network capture unavailable (graceful UNAVAILABLE status without redundant emulator cycle).
7. Static network analysis succeeding while dynamic analysis fails (preserving static results, partial risk).
8. Missing or malformed runtime telemetry handled safely.
9. Guaranteed cleanup after each failure mode (force_stop, uninstall, stop_emulator).
10. ABI resolution in EnvironmentDiscovery, DynamicRunner, and extract_apk_abis.
"""

from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch
import zipfile
import pytest

from analyzers.dynamic.environment import EnvironmentDiscovery
from analyzers.dynamic.models import (
    DynamicAnalysisResult,
    EnvironmentStatus,
    ExecutionMetadata,
)
from analyzers.dynamic.runner import DynamicRunner
from analyzers.dynamic.worker import DynamicWorker, extract_apk_abis
from analyzers.network.models import NetworkAnalysisResult
from analyzers.network.worker import NetworkWorker
from backend.services.analysis_service import AnalysisService

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
BENIGN_APK = str(SAMPLES_DIR / "benign_sample.apk")


# ==============================================================================
# 1. COMPATIBLE ABI & SUCCESSFUL INSTALLATION
# ==============================================================================

def test_compatible_abi_and_successful_installation():
    """When ABI is compatible, DynamicWorker successfully installs, launches, and observes."""
    mock_env = MagicMock()
    mock_env.get_status.return_value = EnvironmentStatus(
        ready=True,
        selected_avd="Medium_Phone_API_36.1",
        available_avds=["Medium_Phone_API_36.1"],
    )
    mock_env.find_adb_path.return_value = "/mock/adb"
    mock_env.find_emulator_path.return_value = "/mock/emulator"
    mock_env.get_avd_supported_abis.return_value = ["x86_64"]
    mock_env.find_compatible_avd.return_value = "Medium_Phone_API_36.1"

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.get_device_supported_abis.return_value = ["x86_64", "x86"]
    mock_runner.install_apk.return_value = (True, "Success")
    mock_runner.launch_activity.return_value = (True, "Activity launched")
    mock_runner.dump_logcat.return_value = ""
    mock_runner.dump_services.return_value = ""
    mock_runner.dump_processes.return_value = ""
    mock_runner.get_package_pids.return_value = ["1234"]

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)

    with patch("analyzers.dynamic.worker.extract_apk_abis", return_value={"x86_64"}):
        res = worker.run_analysis(
            BENIGN_APK,
            package_name="com.test.app",
            launchable_activity=".MainActivity",
            observation_seconds=0,
        )

    assert res.status == "COMPLETED"
    assert res.execution.launch_success is True
    assert res.execution.exit_reason == "OBSERVATION_COMPLETED"
    assert res.execution.package_name == "com.test.app"
    mock_runner.install_apk.assert_called_once()
    mock_runner.launch_activity.assert_called_once()


# ==============================================================================
# 2. INSTALL_FAILED_NO_MATCHING_ABIS (PRE-CHECK AND ADB OUTPUT)
# ==============================================================================

def test_install_failed_no_matching_abis_pre_check():
    """Detect incompatible ABI before installation attempt and report explicit INCOMPATIBLE_ABI error."""
    mock_env = MagicMock()
    mock_env.get_status.return_value = EnvironmentStatus(
        ready=True,
        selected_avd="Medium_Phone_API_36.1",
        available_avds=["Medium_Phone_API_36.1"],
    )
    mock_env.find_adb_path.return_value = "/mock/adb"
    mock_env.find_emulator_path.return_value = "/mock/emulator"
    mock_env.get_avd_supported_abis.return_value = ["x86_64"]
    mock_env.find_compatible_avd.return_value = None

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.get_device_supported_abis.return_value = ["x86_64"]

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)

    # APK requires 32-bit armeabi, but running emulator only supports x86_64
    with patch("analyzers.dynamic.worker.extract_apk_abis", return_value={"armeabi"}):
        res = worker.run_analysis(
            BENIGN_APK,
            package_name="com.lema.lematcs2024",
            launchable_activity="org.cocos2dx.cpp.AppActivity",
            observation_seconds=10,
        )

    assert res.status == "FAILED"
    assert res.score == 0.0
    assert res.execution.launch_success is False
    assert res.execution.duration_seconds == 0.0
    assert res.execution.exit_reason == "INCOMPATIBLE_ABI"
    assert "INSTALL_FAILED_NO_MATCHING_ABIS" in res.error_message
    assert "armeabi" in res.error_message
    # Critical: install_apk and launch_activity must NOT have been called
    mock_runner.install_apk.assert_not_called()
    mock_runner.launch_activity.assert_not_called()


def test_install_failed_no_matching_abis_adb_error_handling():
    """When ADB install returns INSTALL_FAILED_NO_MATCHING_ABIS, classify as INCOMPATIBLE_ABI without launching."""
    mock_env = MagicMock()
    mock_env.get_status.return_value = EnvironmentStatus(
        ready=True,
        selected_avd="Medium_Phone_API_36.1",
        available_avds=["Medium_Phone_API_36.1"],
    )
    mock_env.find_adb_path.return_value = "/mock/adb"
    mock_env.find_emulator_path.return_value = "/mock/emulator"

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.get_device_supported_abis.return_value = []
    mock_runner.install_apk.return_value = (
        False,
        "Failure [INSTALL_FAILED_NO_MATCHING_ABIS: Failed to extract native libraries, res=-113]",
    )

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)

    with patch("analyzers.dynamic.worker.extract_apk_abis", return_value=set()):
        res = worker.run_analysis(
            BENIGN_APK,
            package_name="com.lema.lematcs2024",
            launchable_activity="org.cocos2dx.cpp.AppActivity",
            observation_seconds=15,
        )

    assert res.status == "FAILED"
    assert res.execution.launch_success is False
    assert res.execution.duration_seconds == 0.0
    assert res.execution.exit_reason == "INCOMPATIBLE_ABI"
    assert "INSTALL_FAILED_NO_MATCHING_ABIS" in res.error_message
    # Launch must NOT be attempted
    mock_runner.launch_activity.assert_not_called()


# ==============================================================================
# 3. INSTALLATION FAILURE FOLLOWED BY NO LAUNCH ATTEMPT & NO OBSERVATION TIMER
# ==============================================================================

def test_installation_failure_followed_by_no_launch_attempt():
    """General install failure (e.g. INSTALL_FAILED_DEXOPT) skips launch and observation entirely."""
    mock_env = MagicMock()
    mock_env.get_status.return_value = EnvironmentStatus(
        ready=True,
        selected_avd="Test_AVD",
        available_avds=["Test_AVD"],
    )
    mock_env.find_adb_path.return_value = "/mock/adb"
    mock_env.find_emulator_path.return_value = "/mock/emulator"

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.get_device_supported_abis.return_value = []
    mock_runner.install_apk.return_value = (False, "Failure [INSTALL_FAILED_DEXOPT]")

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)

    with patch("analyzers.dynamic.worker.extract_apk_abis", return_value=set()), \
         patch("time.sleep") as mock_sleep:

        res = worker.run_analysis(
            BENIGN_APK,
            package_name="com.test.dexopt",
            launchable_activity=".MainActivity",
            observation_seconds=15,
        )

    assert res.status == "FAILED"
    assert res.execution.launch_success is False
    assert res.execution.duration_seconds == 0.0
    assert res.execution.exit_reason == "INSTALL_FAILED"
    # Never called launch
    mock_runner.launch_activity.assert_not_called()
    # Observation sleep must NOT be called
    mock_sleep.assert_not_called()


# ==============================================================================
# 4. LAUNCH FAILURE AFTER SUCCESSFUL INSTALLATION
# ==============================================================================

def test_launch_failure_after_successful_installation():
    """When installation succeeds but launch_activity fails, exit_reason is LAUNCH_FAILED and duration is 0.0s."""
    mock_env = MagicMock()
    mock_env.get_status.return_value = EnvironmentStatus(
        ready=True,
        selected_avd="Test_AVD",
        available_avds=["Test_AVD"],
    )
    mock_env.find_adb_path.return_value = "/mock/adb"
    mock_env.find_emulator_path.return_value = "/mock/emulator"

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.get_device_supported_abis.return_value = []
    mock_runner.install_apk.return_value = (True, "Success")
    mock_runner.launch_activity.return_value = (
        False,
        "Error: Activity class does not exist / permission denial",
    )

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)

    with patch("analyzers.dynamic.worker.extract_apk_abis", return_value=set()), \
         patch("time.sleep") as mock_sleep:

        res = worker.run_analysis(
            BENIGN_APK,
            package_name="com.test.badlaunch",
            launchable_activity=".MissingActivity",
            observation_seconds=15,
        )

    assert res.status == "FAILED"
    assert res.execution.launch_success is False
    assert res.execution.duration_seconds == 0.0
    assert res.execution.exit_reason == "LAUNCH_FAILED"
    assert "Application launch failed" in res.error_message
    # Observation sleep must not run
    mock_sleep.assert_not_called()
    # Cleanup must still run
    mock_runner.force_stop.assert_called_once()
    mock_runner.uninstall_apk.assert_called_once()


# ==============================================================================
# 5. SUCCESSFUL LAUNCH BUT NO OBSERVED NETWORK TRAFFIC
# ==============================================================================

def test_successful_launch_but_no_observed_network_traffic():
    """When app launches but emits no socket traffic, report NOT_ATTRIBUTED without hallucinating traffic."""
    worker = NetworkWorker()
    mock_runner = worker.runner

    with patch.object(worker.env_discovery, "find_adb_path", return_value="/mock/adb"), \
         patch.object(worker.env_discovery, "find_emulator_path", return_value="/mock/emulator"), \
         patch.object(worker.env_discovery, "get_status", return_value=EnvironmentStatus(
             ready=True, selected_avd="Test_AVD", available_avds=["Test_AVD"], running_devices=["emulator-5554"],
         )), \
         patch.object(mock_runner, "get_first_online_device", return_value="emulator-5554"), \
         patch.object(mock_runner, "install_apk", return_value=(True, "Success")), \
         patch.object(mock_runner, "clear_logcat"), \
         patch.object(mock_runner, "launch_activity", return_value=(True, "Launched")), \
         patch.object(mock_runner, "get_package_pids", return_value=["1234"]), \
         patch.object(mock_runner, "dump_logcat", return_value=""), \
         patch.object(mock_runner, "force_stop"), \
         patch.object(mock_runner, "uninstall_apk"), \
         patch.object(worker.collector, "get_target_uid", return_value=10150), \
         patch.object(worker.collector, "poll_proc_net", return_value=[]), \
         patch("analyzers.network.worker.extract_apk_abis", return_value=set()):

        res = worker.run_analysis(BENIGN_APK, observation_seconds=0)

    assert res.status in ("COMPLETED", "NOT_ATTRIBUTED")
    assert res.attributed_events_count == 0
    assert len(res.events) == 0
    # Verified limitations and disclaimers are present
    assert any("absence of observed runtime network traffic" in lim.lower() for lim in res.limitations)
    # Never invent IPs or domains
    assert res.destination_breakdown == {}


# ==============================================================================
# 6. NETWORK CAPTURE UNAVAILABLE
# ==============================================================================

def test_network_capture_unavailable_when_dynamic_install_fails():
    """In AnalysisService, if dynamic analysis fails install/launch, network capture is marked UNAVAILABLE."""
    service = AnalysisService()

    # Create mock dynamic result that failed due to ABI incompatibility
    mock_dynamic_result = DynamicAnalysisResult(
        module="dynamic",
        stage="2B",
        status="FAILED",
        score=0.0,
        risk_level="LOW",
        execution=ExecutionMetadata(
            package_name="com.lema.lematcs2024",
            launchable_activity="org.cocos2dx.cpp.AppActivity",
            launch_success=False,
            duration_seconds=0.0,
            exit_reason="INCOMPATIBLE_ABI",
        ),
        observations=[],
        findings=[],
        error_message="APK requires native ABI(s) {'armeabi'} not supported by emulator: INSTALL_FAILED_NO_MATCHING_ABIS",
    )

    with patch.object(service.dynamic_worker, "run_analysis", return_value=mock_dynamic_result), \
         patch.object(service.network_worker, "run_analysis") as mock_network_run:

        report = service.analyze_apk_full(
            BENIGN_APK,
            original_filename="benign.apk",
            include_dynamic=True,
            include_network=True,
        )

    # Network analysis must NOT have been run redundantly
    mock_network_run.assert_not_called()
    assert report.network_details is not None
    assert report.network_details.status == "UNAVAILABLE"
    assert report.module_status["network"] == "UNAVAILABLE"
    assert report.module_scores.network is None
    assert "Application execution failed" in report.network_details.error_message


# ==============================================================================
# 7. STATIC ANALYSIS SUCCEEDS WHILE DYNAMIC ANALYSIS FAILS
# ==============================================================================

def test_static_network_analysis_succeeds_while_dynamic_fails():
    """Static analysis indicators are preserved even when dynamic emulator execution fails completely."""
    service = AnalysisService()

    # Fake dynamic failure
    mock_dyn = DynamicAnalysisResult(
        module="dynamic",
        stage="2B",
        status="FAILED",
        score=0.0,
        risk_level="LOW",
        execution=ExecutionMetadata(
            package_name="com.test.app",
            launch_success=False,
            duration_seconds=0.0,
            exit_reason="INCOMPATIBLE_ABI",
        ),
        observations=[],
        findings=[],
        error_message="INSTALL_FAILED_NO_MATCHING_ABIS",
    )

    with patch.object(service.dynamic_worker, "run_analysis", return_value=mock_dyn):
        report = service.analyze_apk_full(
            BENIGN_APK,
            original_filename="benign.apk",
            include_dynamic=True,
            include_network=True,
        )

    # Static analysis succeeded and is fully intact
    assert report.static_details is not None
    assert report.static_details.is_valid_apk is True
    assert report.module_scores.static is not None
    assert report.permission_details is not None
    assert report.module_scores.permissions is not None

    # Dynamic and network are marked unavailable / partial
    assert report.module_scores.dynamic is None
    assert report.module_scores.network is None
    assert report.analysis_status == "PARTIAL"
    assert report.overall_score is not None
    assert report.risk_level != "UNKNOWN"


# ==============================================================================
# 8. MISSING OR MALFORMED RUNTIME TELEMETRY
# ==============================================================================

def test_missing_or_malformed_runtime_telemetry():
    """Dynamic and Network workers handle empty logcat, missing /proc/net, and unparseable PIDs without crashing."""
    mock_env = MagicMock()
    mock_env.get_status.return_value = EnvironmentStatus(
        ready=True,
        selected_avd="Test_AVD",
        available_avds=["Test_AVD"],
    )
    mock_env.find_adb_path.return_value = "/mock/adb"
    mock_env.find_emulator_path.return_value = "/mock/emulator"

    mock_runner = MagicMock()
    mock_runner.get_first_online_device.return_value = "emulator-5554"
    mock_runner.get_device_supported_abis.return_value = []
    mock_runner.install_apk.return_value = (True, "Success")
    mock_runner.launch_activity.return_value = (True, "Success")
    # Malformed / empty telemetry returns
    mock_runner.dump_logcat.return_value = ""
    mock_runner.dump_services.return_value = None
    mock_runner.dump_processes.return_value = "corrupted non-ps data \x00\xff"
    mock_runner.get_package_pids.return_value = []

    worker = DynamicWorker(environment_discovery=mock_env, runner=mock_runner)

    with patch("analyzers.dynamic.worker.extract_apk_abis", return_value=set()):
        res = worker.run_analysis(
            BENIGN_APK,
            package_name="com.test.empty",
            launchable_activity=".MainActivity",
            observation_seconds=0,
        )

    assert res.status == "COMPLETED"
    assert res.execution.launch_success is True
    # Telemetry categories reflect canonical states without crashing
    assert all(r.status in ("NOT_OBSERVED", "OBSERVED", "UNAVAILABLE") for r in res.runtime_behavior.values())


# ==============================================================================
# 9. GUARANTEED CLEANUP AFTER EACH FAILURE MODE
# ==============================================================================

def test_guaranteed_cleanup_after_launch_failure_with_worker_started_emulator():
    """When worker starts an emulator and launch fails, both app uninstall and emulator shutdown are executed."""
    worker = DynamicWorker()
    mock_proc = MagicMock()
    mock_runner = worker.runner

    with patch.object(worker.env_discovery, "find_adb_path", return_value="/mock/adb"), \
         patch.object(worker.env_discovery, "find_emulator_path", return_value="/mock/emulator"), \
         patch.object(worker.env_discovery, "get_status", return_value=EnvironmentStatus(
             ready=True, selected_avd="Test_AVD", available_avds=["Test_AVD"], running_devices=[],
         )), \
         patch.object(mock_runner, "get_first_online_device", side_effect=[None, "emulator-5554"]), \
         patch.object(mock_runner, "start_emulator", return_value=mock_proc) as mock_start, \
         patch.object(mock_runner, "wait_for_boot", return_value=True), \
         patch.object(mock_runner, "install_apk", return_value=(True, "Success")), \
         patch.object(mock_runner, "launch_activity", return_value=(False, "Crash")), \
         patch.object(mock_runner, "force_stop") as mock_force_stop, \
         patch.object(mock_runner, "uninstall_apk") as mock_uninstall, \
         patch.object(mock_runner, "stop_emulator") as mock_stop, \
         patch("analyzers.dynamic.worker.extract_apk_abis", return_value=set()):

        res = worker.run_analysis(
            BENIGN_APK,
            package_name="com.test.crash",
            launchable_activity=".CrashActivity",
            observation_seconds=0,
        )

    assert res.status == "FAILED"
    mock_start.assert_called_once()
    mock_force_stop.assert_called_once()
    mock_uninstall.assert_called_once()
    mock_stop.assert_called_once_with(mock_proc, "/mock/adb", "emulator-5554")


# ==============================================================================
# 10. ABI RESOLUTION LOGIC TESTS
# ==============================================================================

def test_extract_apk_abis_from_zip():
    """extract_apk_abis extracts architectures from lib/<abi>/ paths in an APK."""
    with tempfile.NamedTemporaryFile(suffix=".apk") as tmp:
        with zipfile.ZipFile(tmp.name, "w") as zf:
            zf.writestr("classes.dex", b"dexcode")
            zf.writestr("lib/armeabi/libtest.so", b"elf")
            zf.writestr("lib/armeabi-v7a/libtest.so", b"elf")
            zf.writestr("AndroidManifest.xml", b"manifest")

        abis = extract_apk_abis(tmp.name)
        assert set(abis) == {"armeabi", "armeabi-v7a"}


def test_extract_apk_abis_pure_dex():
    """An APK with no native libraries returns an empty list (compatible with all ABIs)."""
    with tempfile.NamedTemporaryFile(suffix=".apk") as tmp:
        with zipfile.ZipFile(tmp.name, "w") as zf:
            zf.writestr("classes.dex", b"dexcode")
            zf.writestr("AndroidManifest.xml", b"manifest")

        abis = extract_apk_abis(tmp.name)
        assert abis == []


def test_environment_discovery_abi_config_parsing():
    """EnvironmentDiscovery parses config.ini and ini files for supported ABIs."""
    env = EnvironmentDiscovery()
    with tempfile.TemporaryDirectory() as tmpdir:
        avd_dir = Path(tmpdir)
        ini_file = avd_dir / "My_Test_AVD.ini"
        avd_folder = avd_dir / "My_Test_AVD.avd"
        avd_folder.mkdir()
        config_file = avd_folder / "config.ini"

        ini_file.write_text(f"path={avd_folder}\n")
        config_file.write_text("abi.type=x86_64\nhw.cpu.arch=x86_64\n")

        with patch("pathlib.Path.home", return_value=Path(tmpdir)):
            # Simulating home/.android/avd
            dot_android = Path(tmpdir) / ".android" / "avd"
            dot_android.mkdir(parents=True)
            ini_in_home = dot_android / "My_Test_AVD.ini"
            ini_in_home.write_text(f"path={avd_folder}\n")

            abis = env.get_avd_supported_abis("My_Test_AVD")
            assert "x86_64" in abis
            assert "x86" in abis

            # find_compatible_avd finds My_Test_AVD when x86_64 is required
            compat = env.find_compatible_avd(["x86_64"], available_avds=["My_Test_AVD"])
            assert compat == "My_Test_AVD"

            # find_compatible_avd returns None when armeabi is required and no ARM AVD exists
            compat_arm = env.find_compatible_avd(["armeabi"], available_avds=["My_Test_AVD"])
            assert compat_arm is None


def test_runner_device_supported_abis_parsing():
    """DynamicRunner queries getprop for abilist, abilist64, abilist32."""
    runner = DynamicRunner()
    mock_subprocess = MagicMock()
    mock_subprocess.return_value = MagicMock(
        returncode=0,
        stdout="x86_64,arm64-v8a,x86\n",
    )

    with patch("subprocess.run", mock_subprocess):
        abis = runner.get_device_supported_abis("/fake/adb", "emulator-5554")
        assert "x86_64" in abis
        assert "arm64-v8a" in abis
        assert "x86" in abis
