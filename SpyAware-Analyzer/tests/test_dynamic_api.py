"""API integration tests for Dynamic Analysis endpoints in SpyAware-Analyzer."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from analyzers.dynamic.models import (
    DynamicAnalysisResult,
    EnvironmentStatus,
    ExecutionMetadata,
    Observation,
)
from backend.main import app
from backend.models.analysis import Finding, Severity

client = TestClient(app)
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def test_api_dynamic_environment():
    """GET /api/dynamic/environment returns diagnostic status."""
    res = client.get("/api/dynamic/environment")
    assert res.status_code == 200
    data = res.json()
    assert "adb_available" in data
    assert "emulator_available" in data
    assert "ready" in data


@patch("backend.services.analysis_service.AnalysisService.analyze_dynamic_only")
def test_api_analyze_dynamic_endpoint(mock_analyze_dyn):
    """POST /api/analyze/dynamic accepts APK and returns dynamic report."""
    from backend.models.analysis import ModuleScores, RiskReport

    mock_report = RiskReport(
        analysis_id="test-dyn-id-1234",
        timestamp="2026-10-08T00:00:00Z",
        apk_filename="benign_sample.apk",
        overall_score=15.0,
        risk_level="LOW",
        module_scores=ModuleScores(static=None, permissions=None, dynamic=15.0),
        findings=[],
        summary="Dynamic test summary",
        dynamic_details=DynamicAnalysisResult(
            status="COMPLETED",
            score=15.0,
            risk_level="LOW",
            execution=ExecutionMetadata(package_name="com.spyaware.benign", launch_success=True),
            observations=[Observation(type="APPLICATION_STARTED", description="Launched")],
        ),
    )
    mock_analyze_dyn.return_value = mock_report

    apk_file = SAMPLES_DIR / "benign_sample.apk"
    with open(apk_file, "rb") as f:
        res = client.post(
            "/api/analyze/dynamic",
            files={"file": ("benign_sample.apk", f, "application/vnd.android.package-archive")},
        )
    assert res.status_code == 200
    data = res.json()
    assert data["analysis_id"] == "test-dyn-id-1234"
    assert data["module_scores"]["dynamic"] == 15.0
    assert data["dynamic_details"]["status"] == "COMPLETED"


@patch("analyzers.dynamic.worker.DynamicWorker.run_analysis")
def test_api_analyze_with_dynamic_flag(mock_worker_run):
    """POST /api/analyze?dynamic=true runs multi-module including dynamic."""
    mock_worker_run.return_value = DynamicAnalysisResult(
        status="COMPLETED",
        score=20.0,
        risk_level="LOW",
        execution=ExecutionMetadata(package_name="com.spyaware.benign", launch_success=True),
        observations=[Observation(type="APPLICATION_STARTED", description="App started")],
        findings=[
            Finding(
                category="DYNAMIC",
                severity=Severity.LOW,
                title="Dynamic Observation",
                description="Test dynamic finding",
                evidence="Log trace",
                score=20.0,
            )
        ],
    )

    apk_file = SAMPLES_DIR / "benign_sample.apk"
    with open(apk_file, "rb") as f:
        res = client.post(
            "/api/analyze?dynamic=true",
            files={"file": ("benign_sample.apk", f, "application/vnd.android.package-archive")},
        )
    assert res.status_code == 200
    data = res.json()
    assert data["module_scores"]["static"] is not None
    assert data["module_scores"]["permissions"] is not None
    assert data["module_scores"]["dynamic"] == 20.0
    assert data["dynamic_details"] is not None
    assert data["dynamic_details"]["status"] == "COMPLETED"
