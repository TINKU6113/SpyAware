"""Tests for Milestone M8 — Dynamic & Surveillance Detection.

Verifies:
1. Honest status representation: OBSERVED, NOT_OBSERVED, UNAVAILABLE, NOT_TESTED.
2. Surveillance telemetry categories: CAMERA, MICROPHONE, LOCATION, ACCESSIBILITY, SCREEN, TELEPHONY, CLIPBOARD.
3. Robust failure containment when ADB / emulators are absent or unreachable.
4. Static risk preservation: unperformed dynamic execution never lowers or clears risk scores.
5. Absence of fabricated evidence when runtime monitoring fails or times out.
"""

from unittest.mock import MagicMock, patch
import pytest

from analyzers.dynamic.models import (
    DynamicAnalysisResult,
    EnvironmentStatus,
    RuntimeBehaviorCategory,
    RuntimeBehaviorStatus,
    RuntimeObservation,
)
from analyzers.dynamic.worker import DynamicWorker
from backend.models.analysis import RiskReport
from backend.services.analysis_service import AnalysisService
from risk_engine.engine import RiskEngine


def test_surveillance_telemetry_statuses_distinct():
    """All 4 behavioral statuses have clear semantic separation."""
    obs_observed = RuntimeObservation(
        category=RuntimeBehaviorCategory.CAMERA.value,
        status=RuntimeBehaviorStatus.OBSERVED.value,
        description="Active camera frame capture detected",
        confidence=1.0,
    )
    obs_not_observed = RuntimeObservation(
        category=RuntimeBehaviorCategory.MICROPHONE.value,
        status=RuntimeBehaviorStatus.NOT_OBSERVED.value,
        description="Audio record API was not invoked during observation",
        confidence=0.8,
    )
    obs_unavailable = RuntimeObservation(
        category=RuntimeBehaviorCategory.LOCATION.value,
        status=RuntimeBehaviorStatus.UNAVAILABLE.value,
        description="GPS location provider service was not initialized in test target",
        confidence=0.0,
    )
    obs_not_tested = RuntimeObservation(
        category=RuntimeBehaviorCategory.SMS.value,
        status=RuntimeBehaviorStatus.NOT_TESTED.value,
        description="Telephony events were not stimulated in this test profile",
        confidence=0.0,
    )

    assert obs_observed.status == "OBSERVED"
    assert obs_not_observed.status == "NOT_OBSERVED"
    assert obs_unavailable.status == "UNAVAILABLE"
    assert obs_not_tested.status == "NOT_TESTED"


def test_dynamic_failure_never_reduces_static_risk_score(tmp_path):
    """Dynamic analysis failure (UNAVAILABLE/FAILED) preserves static findings and score."""
    service = AnalysisService(reports_dir=tmp_path)
    service.dynamic_worker = MagicMock()
    service.dynamic_worker.run_analysis.return_value = DynamicAnalysisResult(
        status="UNAVAILABLE",
        score=0.0,
        risk_level="UNKNOWN",
        error_message="Host ADB daemon unreachable",
        limitations=["Dynamic testing was unavailable due to host ADB daemon error"],
    )

    report = service.analyze_apk_full(
        apk_path="samples/benign_sample.apk",
        original_filename="benign_sample.apk",
        include_dynamic=True,
        include_network=False,
    )

    # Static score must remain intact
    assert report.module_scores.static is not None
    assert report.module_scores.static >= 10.0
    # Dynamic score must be None
    assert report.module_scores.dynamic is None
    assert report.module_status["dynamic"] == "UNAVAILABLE"
    # Overall score must reflect static evidence, not zero
    assert report.overall_score >= 10.0
    assert any("Dynamic testing was unavailable" in lim for lim in report.limitations)


def test_no_fabricated_evidence_on_dynamic_timeout():
    """A timed out or aborted dynamic run generates no false positive surveillance findings."""
    worker = DynamicWorker()
    worker.runner = MagicMock()
    worker.runner.wait_for_boot.return_value = True
    worker.runner.install_apk.return_value = (False, "Command timed out after 15 seconds")
    worker.runner.reserve_emulator_port.return_value = 5554
    worker.runner.start_emulator.return_value = MagicMock(poll=MagicMock(return_value=None))
    worker.env_discovery = MagicMock()
    worker.env_discovery.find_adb_path.return_value = "/usr/bin/adb"
    worker.env_discovery.find_emulator_path.return_value = "/usr/bin/emulator"
    worker.env_discovery.get_status.return_value = EnvironmentStatus(
        adb_available=True,
        emulator_available=True,
        avdmanager_available=True,
        available_avds=["Test_AVD"],
        running_devices=[],
        ready=True,
    )

    res = worker.run_analysis(
        apk_path="samples/benign_sample.apk",
        package_name="com.spyaware.benign",
        launchable_activity=".MainActivity",
        observation_seconds=15,
    )

    assert res.status in ("FAILED", "TIMEOUT", "UNAVAILABLE", "ERROR")
    # Findings list must NOT fabricate spyware alerts
    assert len(res.findings) == 0


def test_surveillance_categories_coverage():
    """All required surveillance categories are supported in telemetry models."""
    expected_categories = [
        "CAMERA",
        "MICROPHONE",
        "LOCATION",
        "ACCESSIBILITY",
        "MEDIA_PROJECTION",
        "SMS",
        "CALL",
        "BACKGROUND_SERVICE",
        "PERSISTENCE",
        "PROCESS",
        "CRASH",
    ]
    enum_values = [c.value for c in RuntimeBehaviorCategory]
    for cat in expected_categories:
        assert cat in enum_values
