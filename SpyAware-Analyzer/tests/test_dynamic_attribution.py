"""Unit tests for Positive-Control Telemetry Attribution in Stage 2B.

Verifies that runtime surveillance indicators require strictly verified target
ownership (package name, target PID, active ServiceRecord/Client session)
and rejects generic framework messages or unrelated process telemetry.
"""

import pytest
from analyzers.dynamic.models import RuntimeBehaviorStatus
from analyzers.dynamic.observer import DynamicObserver


@pytest.fixture
def observer():
    return DynamicObserver()


def test_unrelated_process_microphone_framework_noise(observer):
    """A. Generic microphone framework message from unrelated daemon -> NOT_OBSERVED."""
    # Target package is com.benign.app (PID 2000), but logcat has startRecording from PID 1609 (daemon)
    unrelated_logcat = """
    10-09 01:48:14.795 I/aels    ( 1609): startRecordingInvocationStateUpdates
    10-09 01:48:14.796 D/AudioPolicyManager( 1609): startRecording(45) on input 23
    """
    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.benign.app",
        launch_success=True,
        logcat_text=unrelated_logcat,
        audio_dumpsys="No active sessions",
        target_pids=["2000"],
    )
    assert rb["microphone"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert not any(f.category == "DYNAMIC" and "Audio" in f.title for f in findings)
    assert score == 0.0


def test_target_owned_active_microphone_session(observer):
    """B. Target-owned active microphone session in dumpsys and target logcat -> OBSERVED."""
    target_audio_dumpsys = """
    RecordActivityMonitor dump time: 12:00:00 PM
    Active recording sessions:
    RecordActivityMonitor: uid:10150 pid:2341 package:com.positive.mic state:recording
    """
    target_logcat = """
    10-09 01:48:15.000  2341  2350 I AudioRecord: startRecording succeeded for com.positive.mic
    """
    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.positive.mic",
        launch_success=True,
        logcat_text=target_logcat,
        audio_dumpsys=target_audio_dumpsys,
        target_pids=["2341"],
    )
    assert rb["microphone"].status == RuntimeBehaviorStatus.OBSERVED.value
    assert "com.positive.mic" in rb["microphone"].evidence
    assert any("Audio" in f.title for f in findings)
    assert score >= 15.0


def test_unrelated_camera_framework_noise(observer):
    """C. Generic camera framework message without target ownership -> NOT_OBSERVED."""
    # Camera HAL / system daemon log from PID 2645, target is com.benign.app (PID 2000)
    unrelated_logcat = """
    10-09 01:48:40.450 W/android.camera2( 2645): userfaultfd: MOVE ioctl seems unsupported
    10-09 01:48:40.451 I/CameraService( 2645): CameraDevice client disconnected
    """
    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.benign.app",
        launch_success=True,
        logcat_text=unrelated_logcat,
        camera_dumpsys="Active Camera Clients: []",
        target_pids=["2000"],
    )
    assert rb["camera"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert not any("Camera" in f.title for f in findings)
    assert score == 0.0


def test_target_owned_active_camera_client(observer):
    """D. Target-owned active camera client in dumpsys -> OBSERVED."""
    dumpsys_camera = """
    Active Camera Clients:
    Client package name: com.positive.camera, device: 0, PID: 3412
    """
    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.positive.camera",
        launch_success=True,
        logcat_text="",
        camera_dumpsys=dumpsys_camera,
        target_pids=["3412"],
    )
    assert rb["camera"].status == RuntimeBehaviorStatus.OBSERVED.value
    assert "com.positive.camera" in rb["camera"].evidence
    assert score >= 15.0


def test_generic_location_provider_activity(observer):
    """E. Generic location provider activity without target listener -> NOT_OBSERVED."""
    generic_logcat = """
    10-09 01:48:20.000  1000  1050 D LocationManagerService: providerEnabledChanged: provider=gps enabled=true
    10-09 01:48:20.001  1000  1050 I FusedLocationHardware: GPS status change notification
    """
    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.benign.app",
        launch_success=True,
        logcat_text=generic_logcat,
        location_dumpsys="Location Providers: passive provider: []",
        target_pids=["2000"],
    )
    assert rb["location"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert not any("Location" in f.title or "Geolocation" in f.title for f in findings)
    assert score == 0.0


def test_target_owned_location_request(observer):
    """F. Target-owned location request in dumpsys -> OBSERVED."""
    target_loc_dumpsys = """
    Location Providers:
    passive provider:
      10199/com.positive.location[fused] Request[PASSIVE, minUpdateInterval=+1s]
    """
    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.positive.location",
        launch_success=True,
        logcat_text="",
        location_dumpsys=target_loc_dumpsys,
        target_pids=["5001"],
    )
    assert rb["location"].status == RuntimeBehaviorStatus.OBSERVED.value
    assert "com.positive.location" in rb["location"].evidence
    assert score >= 10.0


def test_target_owned_active_servicerecord(observer):
    """G. Target-owned active ServiceRecord in dumpsys -> OBSERVED."""
    target_services_dumpsys = """
    ACTIVITY MANAGER SERVICES (dumpsys activity services)
      * ServiceRecord{5c234 u0 com.positive.service/.MonitoringService}
        intent={cmp=com.positive.service/.MonitoringService}
        packageName=com.positive.service
        processName=com.positive.service
    """
    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.positive.service",
        launch_success=True,
        logcat_text="",
        services_text=target_services_dumpsys,
        target_pids=["6001"],
    )
    assert rb["background_service"].status == RuntimeBehaviorStatus.OBSERVED.value
    assert "MonitoringService" in rb["background_service"].evidence
    assert score >= 8.0


def test_permission_declaration_without_runtime_activity(observer):
    """H. Permission declaration without runtime activity -> NOT_OBSERVED."""
    # APK statically declared CAMERA, RECORD_AUDIO, ACCESS_FINE_LOCATION,
    # but runtime telemetry has no active clients or target calls.
    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.dormant.stalker",
        launch_success=True,
        logcat_text="ActivityManager: Displayed com.dormant.stalker/.MainActivity: +150ms",
        services_text="No active services",
        process_text="u0_a150 7001 500 1200000 40000 0 0 S com.dormant.stalker",
        camera_dumpsys="Active Camera Clients: []",
        audio_dumpsys="No active recording sessions",
        location_dumpsys="Location Providers: passive provider: []",
        accessibility_dumpsys="Bound services:{}",
        media_projection_dumpsys="Media Projection: null",
        target_pids=["7001"],
    )
    assert rb["camera"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert rb["microphone"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert rb["location"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert rb["accessibility"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert rb["media_projection"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert rb["background_service"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert rb["process"].status == RuntimeBehaviorStatus.OBSERVED.value
    assert rb["crash"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert score == 0.0


def test_unrelated_package_owns_telemetry(observer):
    """I. Telemetry owned by an unrelated application -> NOT_OBSERVED for target."""
    unrelated_camera_dumpsys = """
    Active Camera Clients:
    Client package name: com.other.camapp, device: 0, PID: 9876
    """
    unrelated_audio_dumpsys = """
    Active recording sessions:
    RecordActivityMonitor: uid:10200 pid:9877 package:com.other.voip state:recording
    """
    unrelated_sms_logcat = """
    10-09 01:48:28.310  1382  1390 I DialerRefresh( 1382): com.android.dialer.calllog.refresh filling Voicemail
    10-09 01:48:28.311  1382  1390 D SmsManager: com.android.mms sending background broadcast
    """
    obs, rb, findings, score = observer.observe_stage_2b(
        package_name="com.target.test",
        launch_success=True,
        logcat_text=unrelated_sms_logcat,
        camera_dumpsys=unrelated_camera_dumpsys,
        audio_dumpsys=unrelated_audio_dumpsys,
        target_pids=["5555"],
    )
    assert rb["camera"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert rb["microphone"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert rb["sms"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert rb["call"].status == RuntimeBehaviorStatus.NOT_OBSERVED.value
    assert score == 0.0
