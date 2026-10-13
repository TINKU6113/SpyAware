"""Integration tests for SpyAware-Analyzer REST API endpoints."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def test_api_health_endpoint():
    """GET /api/health returns 200, healthy status, and expected module states."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "SpyAware-Analyzer"
    assert data["modules"]["static"] == "AVAILABLE"
    assert data["modules"]["permissions"] == "AVAILABLE"
    assert data["modules"]["dynamic"] in (
        "AVAILABLE",
        "CONFIGURED",
        "UNAVAILABLE_EMULATOR_OFFLINE",
        "UNAVAILABLE_MISSING_DEPENDENCIES",
    )
    assert data["modules"]["network"] in (
        "AVAILABLE",
        "CONFIGURED",
        "UNAVAILABLE_EMULATOR_OFFLINE",
        "UNAVAILABLE_MISSING_DEPENDENCIES",
    )
    assert data["modules"]["dynamic"] != "COMING_SOON"
    assert data["modules"]["network"] != "COMING_SOON"
    assert data["modules"]["ble"] == "COMING_SOON"


def test_api_analyze_permissions_json():
    """POST /api/analyze/permissions with JSON payload."""
    payload = {
        "permissions": [
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
        ],
        "target_name": "TestTriad",
    }
    response = client.post("/api/analyze/permissions", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "analysis_id" in data
    assert data["overall_score"] >= 50.0
    assert data["risk_level"] in ("HIGH", "CRITICAL")
    assert data["module_scores"]["permissions"] is not None
    assert data["module_scores"]["static"] is None


def test_api_analyze_full_apk():
    """POST /api/analyze with APK upload returns full report and stores it."""
    apk_path = SAMPLES_DIR / "benign_sample.apk"
    with open(apk_path, "rb") as f:
        response = client.post(
            "/api/analyze",
            files={"file": ("benign_sample.apk", f, "application/vnd.android.package-archive")},
        )
    assert response.status_code == 200
    data = response.json()
    analysis_id = data["analysis_id"]
    assert data["apk_filename"] == "benign_sample.apk"
    assert data["overall_score"] < 25.0
    assert data["risk_level"] == "LOW"
    assert data["static_details"]["is_valid_apk"] is True

    # Retrieve report by ID
    get_res = client.get(f"/api/analysis/{analysis_id}")
    assert get_res.status_code == 200
    assert get_res.json()["analysis_id"] == analysis_id


def test_api_analyze_malformed_apk():
    """POST /api/analyze with malformed file rejects with HTTP 400 Bad Request."""
    corrupt_path = SAMPLES_DIR / "malformed_corrupt.apk"
    with open(corrupt_path, "rb") as f:
        response = client.post(
            "/api/analyze",
            files={"file": ("malformed_corrupt.apk", f, "application/octet-stream")},
        )
    assert response.status_code == 400
    assert "Invalid APK" in response.json()["detail"]


def test_api_get_nonexistent_analysis():
    """GET /api/analysis/{nonexistent} returns 404."""
    response = client.get("/api/analysis/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404


def test_api_analyze_sample_preset():
    """POST /api/analyze/sample/critical_stalkerware_sample returns critical analysis report."""
    response = client.post("/api/analyze/sample/critical_stalkerware_sample")
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "CRITICAL"
    assert data["overall_score"] >= 75.0

