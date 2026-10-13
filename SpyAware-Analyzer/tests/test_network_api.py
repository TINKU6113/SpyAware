"""Integration tests for Stage 2C network analysis API endpoints."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from analyzers.network.models import (
    NetworkAnalysisResult,
    NetworkAttributionStatus,
    NetworkBehaviorCategory,
    NetworkBehaviorStatus,
    NetworkObservation,
)
from backend.models.analysis import Finding, Severity

client = TestClient(app)
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def test_api_analyze_with_network_flag():
    """Tests POST /api/analyze with network=True query parameter."""
    apk_path = SAMPLES_DIR / "benign_sample.apk"
    if not apk_path.exists():
        pytest.skip("benign_sample.apk not built yet")

    mock_network_result = NetworkAnalysisResult(
        module="network",
        stage="2C",
        status="COMPLETED",
        score=0.0,
        risk_level="LOW",
        target_package="com.spyaware.benign",
        target_uid=10228,
        duration_seconds=5.0,
        total_events=1,
        attributed_events_count=0,
        unattributed_events_count=1,
        observations={
            NetworkBehaviorCategory.NETWORK_CONNECTION.value: NetworkObservation(
                category=NetworkBehaviorCategory.NETWORK_CONNECTION.value,
                status=NetworkBehaviorStatus.NOT_OBSERVED.value,
                description="No network connection observed",
            )
        },
        findings=[],
        limitations=[],
    )

    with patch(
        "backend.services.analysis_service.NetworkWorker.run_analysis",
        return_value=mock_network_result,
    ):
        with open(apk_path, "rb") as f:
            response = client.post(
                "/api/analyze?network=true",
                files={"file": ("benign_sample.apk", f, "application/vnd.android.package-archive")},
            )

        assert response.status_code == 200
        data = response.json()
        assert "network_details" in data
        assert data["network_details"] is not None
        assert data["network_details"]["module"] == "network"
        assert data["network_details"]["stage"] == "2C"
        assert data["module_scores"]["network"] == 0.0


def test_api_analyze_network_only_endpoint():
    """Tests POST /api/analyze/network endpoint."""
    apk_path = SAMPLES_DIR / "benign_sample.apk"
    if not apk_path.exists():
        pytest.skip("benign_sample.apk not built yet")

    mock_network_result = NetworkAnalysisResult(
        module="network",
        stage="2C",
        status="COMPLETED",
        score=25.0,
        risk_level="MEDIUM",
        target_package="com.spyaware.positive.network",
        target_uid=10229,
        duration_seconds=5.0,
        total_events=3,
        attributed_events_count=2,
        unattributed_events_count=1,
        observations={
            NetworkBehaviorCategory.NETWORK_CONNECTION.value: NetworkObservation(
                category=NetworkBehaviorCategory.NETWORK_CONNECTION.value,
                status=NetworkBehaviorStatus.OBSERVED.value,
                description="Active network socket connection",
                count=2,
            )
        },
        findings=[
            Finding(
                category="NETWORK",
                severity=Severity.LOW,
                title="Target Network Socket",
                description="Verified UID connection",
                evidence="10.0.2.2:80",
                score=5.0,
            )
        ],
        limitations=["Transport-level socket observation only"],
    )

    with patch(
        "backend.services.analysis_service.NetworkWorker.run_analysis",
        return_value=mock_network_result,
    ):
        with open(apk_path, "rb") as f:
            response = client.post(
                "/api/analyze/network",
                files={"file": ("benign_sample.apk", f, "application/vnd.android.package-archive")},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["overall_score"] == 25.0
        assert data["module_scores"]["network"] == 25.0
        assert data["network_details"]["status"] == "COMPLETED"
        assert len(data["network_details"]["findings"]) == 1
