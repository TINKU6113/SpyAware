"""Integration tests for M3 REST API endpoints.

Tests device discovery, installed-package listing/analysis, compatibility checks,
and Markdown export endpoints.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from analyzers.discovery.models import ConnectedDevice, DiscoveredPackage, DeviceState, DeviceType, ExtractedAPK
from analyzers.dynamic.compatibility import CompatibilityReport, CompatibilityStatus

client = TestClient(app)
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def test_api_list_devices_mocked():
    """GET /api/devices returns connected devices list."""
    mock_dev = ConnectedDevice(
        serial="emulator-5554",
        state=DeviceState.DEVICE,
        device_type=DeviceType.EMULATOR,
        model="Android SDK built for x86_64",
        product="sdk_gphone64_x86_64",
        api_level=36,
        supported_abis=["x86_64", "arm64-v8a"],
    )
    with patch("backend.services.analysis_service.DeviceDiscoveryManager.list_devices", return_value=[mock_dev]):
        response = client.get("/api/devices")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["serial"] == "emulator-5554"
        assert data[0]["api_level"] == 36
        assert "x86_64" in data[0]["supported_abis"]


def test_api_list_packages_mocked():
    """GET /api/devices/{serial}/packages returns package listing."""
    mock_pkg = DiscoveredPackage(
        package_name="com.spyaware.benign",
        base_apk_path="/data/app/~~xyz==/com.spyaware.benign-1/base.apk",
        is_system=False,
        is_split=False,
    )
    with patch("backend.services.analysis_service.DeviceDiscoveryManager.list_installed_packages", return_value=[mock_pkg]):
        response = client.get("/api/devices/emulator-5554/packages?include_system=false")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["package_name"] == "com.spyaware.benign"
        assert data[0]["is_system"] is False


def test_api_compatibility_check_valid():
    """POST /api/compatibility/check evaluates valid APK."""
    apk_path = SAMPLES_DIR / "benign_sample.apk"
    with open(apk_path, "rb") as f:
        response = client.post(
            "/api/compatibility/check",
            files={"file": ("benign_sample.apk", f, "application/vnd.android.package-archive")},
        )
    assert response.status_code == 200
    data = response.json()
    assert "overall_status" in data
    assert data["apk_package_name"] == "com.spyaware.benign"
    assert data["apk_min_sdk"] is not None
    assert isinstance(data["candidate_evaluations"], list)


def test_api_compatibility_check_corrupt():
    """POST /api/compatibility/check rejects corrupt file with 400."""
    corrupt_path = SAMPLES_DIR / "malformed_corrupt.apk"
    with open(corrupt_path, "rb") as f:
        response = client.post(
            "/api/compatibility/check",
            files={"file": ("malformed_corrupt.apk", f, "application/octet-stream")},
        )
    assert response.status_code == 400
    assert "Invalid APK" in response.json()["detail"]


def test_api_markdown_export():
    """GET /api/analysis/{analysis_id}/export/markdown returns Markdown text."""
    # First analyze benign sample to generate a report
    apk_path = SAMPLES_DIR / "benign_sample.apk"
    with open(apk_path, "rb") as f:
        analyze_res = client.post(
            "/api/analyze",
            files={"file": ("benign_sample.apk", f, "application/vnd.android.package-archive")},
        )
    assert analyze_res.status_code == 200
    analysis_id = analyze_res.json()["analysis_id"]

    # Export markdown
    export_res = client.get(f"/api/analysis/{analysis_id}/export/markdown")
    assert export_res.status_code == 200
    assert "text/markdown" in export_res.headers.get("content-type", "")
    assert f"# SpyAware Analysis Report: benign_sample.apk" in export_res.text
    assert f"`{analysis_id}`" in export_res.text
    assert "## Executive Summary" in export_res.text


def test_api_analyze_installed_package_endpoint():
    """POST /api/devices/{serial}/packages/{pkg}/analyze extracts and analyzes."""
    extracted = ExtractedAPK(
        package_name="com.spyaware.benign",
        base_apk_path=str(SAMPLES_DIR / "benign_sample.apk"),
        temp_directory=None,  # Don't delete sample dir
        success=True,
    )
    with patch("backend.services.analysis_service.DeviceDiscoveryManager.extract_package_apk", return_value=extracted):
        response = client.post(
            "/api/devices/emulator-5554/packages/com.spyaware.benign/analyze"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["apk_filename"] == "com.spyaware.benign.apk"
        assert data["overall_score"] < 25.0
