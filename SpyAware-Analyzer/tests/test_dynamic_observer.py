"""Unit tests for DynamicObserver in SpyAware-Analyzer."""

import pytest
from analyzers.dynamic.observer import DynamicObserver
from backend.models.analysis import Severity


@pytest.fixture
def observer():
    return DynamicObserver()


def test_observer_launch_lifecycle_success(observer):
    """Observes successful application launch."""
    obs, findings, score = observer.observe(
        package_name="com.test.app",
        launch_success=True,
        logcat_text="ActivityManager: Displayed com.test.app/.MainActivity",
        duration_seconds=15.0,
    )
    assert any(o.type == "APPLICATION_STARTED" for o in obs)
    assert score == 0.0  # Launch alone is informational (score = 0)


def test_observer_launch_failure(observer):
    """Observes launch failure."""
    obs, findings, score = observer.observe(
        package_name="com.test.app",
        launch_success=False,
        logcat_text="",
        duration_seconds=5.0,
    )
    assert any(o.type == "APPLICATION_LAUNCH_FAILED" for o in obs)
    assert score == 0.0


def test_observer_application_crash(observer):
    """Detects fatal crashes without inflating surveillance score."""
    sample_logcat = """
    01-01 12:00:00.100  1000  1000 E AndroidRuntime: FATAL EXCEPTION: main
    01-01 12:00:00.101  1000  1000 E AndroidRuntime: Process: com.test.app, PID: 1234
    01-01 12:00:00.102  1000  1000 E AndroidRuntime: java.lang.NullPointerException
    """
    obs, findings, score = observer.observe(
        package_name="com.test.app",
        launch_success=True,
        logcat_text=sample_logcat,
        duration_seconds=10.0,
    )
    assert any(o.type == "APPLICATION_CRASHED" for o in obs)
    # A crash should not contribute to surveillance score by itself
    assert score == 0.0


def test_observer_surveillance_indicators(observer):
    """Detects camera, microphone, location, and accessibility runtime logs with conservative scoring."""
    sample_logcat = """
    01-01 12:00:00.000  1000  1000 I ActivityManager: Start proc 1234:com.covert.spy/u0a123 for activity
    01-01 12:00:01.000  1234  1250 I CameraDevice: openCamera 0 callback received
    01-01 12:00:02.000  1234  1250 D AudioRecord: startRecording called in background
    01-01 12:00:03.000  1234  1250 I LocationManager: requestLocationUpdates provider=gps
    01-01 12:00:04.000  1234  1250 I AccessibilityService: onAccessibilityEvent type=32
    """
    obs, findings, score = observer.observe(
        package_name="com.covert.spy",
        launch_success=True,
        logcat_text=sample_logcat,
        duration_seconds=20.0,
    )
    obs_types = [o.type for o in obs]
    assert "CAMERA_ACTIVITY_OBSERVED" in obs_types
    assert "AUDIO_ACTIVITY_OBSERVED" in obs_types
    assert "LOCATION_ACTIVITY_OBSERVED" in obs_types
    assert "ACCESSIBILITY_ACTIVITY_OBSERVED" in obs_types

    # Camera (15) + Audio (15) + Location (10) + Accessibility (25) = 65
    assert score == 65.0
    assert len(findings) == 4


def test_observer_active_background_services(observer):
    """Detects running background services from dumpsys output."""
    dumpsys_services = """
    ACTIVITY MANAGER SERVICES (dumpsys activity services)
      * ServiceRecord{3a123 u0 com.stealth.tracker/.BackgroundSurveillanceService}
        intent={cmp=com.stealth.tracker/.BackgroundSurveillanceService}
        packageName=com.stealth.tracker
        processName=com.stealth.tracker:remote
    """
    obs, findings, score = observer.observe(
        package_name="com.stealth.tracker",
        launch_success=True,
        logcat_text="",
        services_text=dumpsys_services,
        duration_seconds=15.0,
    )
    assert any(o.type == "RUNNING_SERVICES_DETECTED" for o in obs)
    assert score == 8.0
    assert any(f.title == "Active Background Service at Runtime" for f in findings)
