"""Stage 2B Runtime Behavioral Observation tests for SpyAware-Analyzer.

Tests conservative runtime telemetry analysis across Camera, Microphone, Location,
Accessibility, Screen Capture, SMS, Calls, Background Services, Persistence, Processes,
and Crashes, verifying that runtime findings are derived strictly from runtime evidence
rather than static permission declarations.
"""

import pytest
from analyzers.dynamic.models import (
    DynamicAnalysisResult,
    RuntimeBehaviorCategory,
    RuntimeBehaviorStatus,
    RuntimeObservation,
)
from analyzers.dynamic.observer import DynamicObserver
from analyzers.dynamic.runner import DynamicRunner
from backend.models.analysis import Finding, Severity


@pytest.fixture
def observer():
    return DynamicObserver()


def test_stage2b_runtime_observation_model():
    """Validates schema structure and serialization of RuntimeObservation."""
    obs = RuntimeObservation(
        category=RuntimeBehaviorCategory.MICROPHONE.value,
        status=RuntimeBehaviorStatus.OBSERVED.value,
        description="Runtime audio recording observed.",
        evidence="AudioRecord: startRecording called by PID 4512",
        confidence=0.95,
        source="dumpsys:audio",
    )
    assert obs.category == "MICROPHONE"
    assert obs.status == "OBSERVED"
    assert obs.confidence == 0.95
    assert obs.source == "dumpsys:audio"
    assert "startRecording" in obs.evidence


def test_stage2b_camera_observed_from_dumpsys_and_logcat(observer):
    """Verifies that active camera client in dumpsys media.camera or logcat produces CAMERA OBSERVED."""
    dumpsys_camera = """
    == Service global info: ==
    Active Camera Clients:
    Client package name: com.stealth.cam, device: 0, PID: 3412
    """
    obs, runtime_behavior, findings, score = observer.observe_stage_2b(
        package_name="com.stealth.cam",
        launch_success=True,
        logcat_text="",
        camera_dumpsys=dumpsys_camera,
        duration_seconds=15.0,
    )

    cam_obs = runtime_behavior["camera"]
    assert cam_obs.status == "OBSERVED"
    assert "com.stealth.cam" in cam_obs.evidence
    assert cam_obs.source == "dumpsys:media.camera"
    assert score >= 15.0
    assert any(f.title == "Runtime Camera API Activity" for f in findings)


def test_stage2b_camera_not_observed_when_idle(observer):
    """Verifies CAMERA reports NOT_OBSERVED when camera service is idle."""
    dumpsys_camera = """
    Active Camera Clients:
    []
    """
    obs, runtime_behavior, findings, score = observer.observe_stage_2b(
        package_name="com.benign.app",
        launch_success=True,
        logcat_text="ActivityManager: Displayed com.benign.app/.MainActivity",
        camera_dumpsys=dumpsys_camera,
        duration_seconds=10.0,
    )

    cam_obs = runtime_behavior["camera"]
    assert cam_obs.status == "NOT_OBSERVED"
    assert cam_obs.evidence is None


def test_stage2b_microphone_observed_from_dumpsys(observer):
    """Verifies MICROPHONE reports OBSERVED when active recording session is detected."""
    dumpsys_audio = """
    RecordActivityMonitor dump time: 12:00:00 PM
    Active recording sessions:
    RecordActivityMonitor: uid:10150 pid:2341 package:com.audio.snoop state:recording
    """
    obs, runtime_behavior, findings, score = observer.observe_stage_2b(
        package_name="com.audio.snoop",
        launch_success=True,
        logcat_text="",
        audio_dumpsys=dumpsys_audio,
        duration_seconds=15.0,
    )

    mic_obs = runtime_behavior["microphone"]
    assert mic_obs.status == "OBSERVED"
    assert "com.audio.snoop" in mic_obs.evidence
    assert mic_obs.source == "dumpsys:audio"
    assert score >= 15.0


def test_stage2b_location_observed_and_not_observed(observer):
    """Verifies LOCATION reporting based on active provider requests."""
    dumpsys_location_active = """
    Location Providers:
    passive provider:
      10199/com.tracker.geo[fused] Request[PASSIVE, minUpdateInterval=+1s]
    """
    obs, runtime_behavior, findings, score = observer.observe_stage_2b(
        package_name="com.tracker.geo",
        launch_success=True,
        logcat_text="",
        location_dumpsys=dumpsys_location_active,
        duration_seconds=15.0,
    )
    assert runtime_behavior["location"].status == "OBSERVED"
    assert "dumpsys:location" in runtime_behavior["location"].source

    # Negative test
    obs, runtime_behavior_clean, _, _ = observer.observe_stage_2b(
        package_name="com.clean.app",
        launch_success=True,
        logcat_text="",
        location_dumpsys="Location Providers: passive provider: []",
        duration_seconds=15.0,
    )
    assert runtime_behavior_clean["location"].status == "NOT_OBSERVED"


def test_stage2b_accessibility_not_observed_solely_from_declaration(observer):
    """Verifies that an accessibility service is NOT reported as OBSERVED unless active in dumpsys."""
    # Manifest might declare BIND_ACCESSIBILITY_SERVICE, but dumpsys shows no bound services for this app
    dumpsys_accessibility_empty = """
    ACCESSIBILITY MANAGER (dumpsys accessibility)
    Bound services:{}
    Enabled services:{}
    """
    obs, runtime_behavior, findings, score = observer.observe_stage_2b(
        package_name="com.stalker.keylogger",
        launch_success=True,
        logcat_text="ActivityManager: Displayed com.stalker.keylogger/.MainActivity",
        accessibility_dumpsys=dumpsys_accessibility_empty,
        duration_seconds=15.0,
    )

    assert runtime_behavior["accessibility"].status == "NOT_OBSERVED"
    # Score should NOT receive accessibility penalty because it was not active at runtime
    assert not any("Accessibility" in f.title for f in findings)


def test_stage2b_accessibility_observed_when_bound_in_system(observer):
    """Verifies that when an accessibility service is genuinely bound in dumpsys, it is reported as OBSERVED."""
    dumpsys_accessibility_active = """
    ACCESSIBILITY MANAGER (dumpsys accessibility)
    Bound services:{com.stalker.keylogger/.KeylogService}
    Enabled services:{com.stalker.keylogger/.KeylogService}
    """
    obs, runtime_behavior, findings, score = observer.observe_stage_2b(
        package_name="com.stalker.keylogger",
        launch_success=True,
        logcat_text="",
        accessibility_dumpsys=dumpsys_accessibility_active,
        duration_seconds=15.0,
    )

    assert runtime_behavior["accessibility"].status == "OBSERVED"
    assert "com.stalker.keylogger" in runtime_behavior["accessibility"].evidence
    assert score >= 25.0


def test_stage2b_media_projection_observed_when_active(observer):
    """Verifies MEDIA_PROJECTION reports OBSERVED when active session is present."""
    dumpsys_mp_active = """
    MEDIA PROJECTION MANAGER (dumpsys media_projection)
    Media Projection: 
      MediaProjectionRecord{3b211 u0 com.stealth.screen/10123}
    """
    obs, runtime_behavior, findings, score = observer.observe_stage_2b(
        package_name="com.stealth.screen",
        launch_success=True,
        logcat_text="",
        media_projection_dumpsys=dumpsys_mp_active,
        duration_seconds=10.0,
    )

    assert runtime_behavior["media_projection"].status == "OBSERVED"
    assert score >= 25.0


def test_stage2b_background_services_running_vs_declared(observer):
    """Distinguishes declared services from actively running ServiceRecord instances."""
    dumpsys_services = """
    ACTIVITY MANAGER SERVICES (dumpsys activity services)
      * ServiceRecord{4a123 u0 com.spy.daemon/.LiveStreamService}
        intent={cmp=com.spy.daemon/.LiveStreamService}
        packageName=com.spy.daemon
    """
    obs, runtime_behavior, findings, score = observer.observe_stage_2b(
        package_name="com.spy.daemon",
        launch_success=True,
        logcat_text="",
        services_text=dumpsys_services,
        duration_seconds=10.0,
    )

    assert runtime_behavior["background_service"].status == "OBSERVED"
    assert "LiveStreamService" in runtime_behavior["background_service"].evidence
    assert score == 8.0

    # Negative test: No running services
    obs, runtime_clean, _, score_clean = observer.observe_stage_2b(
        package_name="com.spy.daemon",
        launch_success=True,
        logcat_text="",
        services_text="No active services found for package",
        duration_seconds=10.0,
    )
    assert runtime_clean["background_service"].status == "NOT_OBSERVED"
    assert score_clean == 0.0


def test_stage2b_process_observation(observer):
    """Captures PID and process names for the target package."""
    ps_output = """
    USER           PID  PPID        VSZ    RSS WCHAN            ADDR S NAME
    u0_a123       4580   820    2103400  84210 0                   0 S com.sample.target
    u0_a123       4601  4580    1800200  42100 0                   0 S com.sample.target:bg
    """
    obs, runtime_behavior, findings, score = observer.observe_stage_2b(
        package_name="com.sample.target",
        launch_success=True,
        logcat_text="",
        process_text=ps_output,
        duration_seconds=10.0,
    )

    proc_obs = runtime_behavior["process"]
    assert proc_obs.status == "OBSERVED"
    assert "4580" in proc_obs.evidence
    assert "4601" in proc_obs.evidence
    # Ordinary process execution is not penalized
    assert score == 0.0


def test_stage2b_clean_execution_all_not_observed(observer):
    """When a clean app runs without sensitive hardware usage, all categories are NOT_OBSERVED."""
    obs, runtime_behavior, findings, score = observer.observe_stage_2b(
        package_name="com.benign.calculator",
        launch_success=True,
        logcat_text="ActivityManager: Displayed com.benign.calculator/.MainActivity: +210ms",
        services_text="",
        process_text="u0_a100 3000 800 1200000 50000 0 0 S com.benign.calculator",
        camera_dumpsys="Active Camera Clients: []",
        audio_dumpsys="No recording sessions",
        location_dumpsys="Location Providers: passive provider: []",
        accessibility_dumpsys="Bound services:{}",
        media_projection_dumpsys="Media Projection: null",
        duration_seconds=15.0,
    )

    assert score == 0.0
    assert runtime_behavior["camera"].status == "NOT_OBSERVED"
    assert runtime_behavior["microphone"].status == "NOT_OBSERVED"
    assert runtime_behavior["location"].status == "NOT_OBSERVED"
    assert runtime_behavior["accessibility"].status == "NOT_OBSERVED"
    assert runtime_behavior["media_projection"].status == "NOT_OBSERVED"
    assert runtime_behavior["sms"].status == "NOT_OBSERVED"
    assert runtime_behavior["call"].status == "NOT_OBSERVED"
    assert runtime_behavior["background_service"].status == "NOT_OBSERVED"
    assert runtime_behavior["crash"].status == "NOT_OBSERVED"
    assert runtime_behavior["process"].status == "OBSERVED"


def test_stage2b_backwards_compatibility_wrapper(observer):
    """Verifies that observer.observe() returns exactly 3 values for Stage 2A compatibility."""
    ret = observer.observe(
        package_name="com.test.compat",
        launch_success=True,
        logcat_text="ActivityManager: Displayed com.test.compat/.MainActivity",
    )
    assert isinstance(ret, tuple)
    assert len(ret) == 3
    obs, findings, score = ret
    assert isinstance(obs, list)
    assert isinstance(findings, list)
    assert isinstance(score, float)
    assert len(observer.last_runtime_behavior) == 11
