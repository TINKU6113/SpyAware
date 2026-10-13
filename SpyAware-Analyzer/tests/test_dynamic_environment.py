"""Unit tests for Dynamic Environment Discovery in SpyAware-Analyzer."""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from analyzers.dynamic.environment import EnvironmentDiscovery
from backend.main import app

client = TestClient(app)


def test_real_or_host_environment_status():
    """Environment discovery executes on current host without raising exceptions."""
    discovery = EnvironmentDiscovery()
    status = discovery.get_status()

    assert isinstance(status.adb_available, bool)
    assert isinstance(status.emulator_available, bool)
    assert isinstance(status.available_avds, list)
    assert isinstance(status.ready, bool)
    assert isinstance(status.message, str)


def test_endpoint_dynamic_environment():
    """GET /api/dynamic/environment returns 200 and valid schema."""
    response = client.get("/api/dynamic/environment")
    assert response.status_code == 200
    data = response.json()

    assert "adb_available" in data
    assert "emulator_available" in data
    assert "available_avds" in data
    assert "ready" in data
    assert "message" in data


def test_mocked_environment_missing_tools():
    """When adb or emulator are not found, reports ready=False gracefully."""
    discovery = EnvironmentDiscovery()
    with patch.object(discovery, "find_adb_path", return_value=None), \
         patch.object(discovery, "find_emulator_path", return_value=None), \
         patch.object(discovery, "list_available_avds", return_value=[]), \
         patch.object(discovery, "list_running_devices", return_value=[]):
        status = discovery.get_status()
        assert not status.ready
        assert not status.adb_available
        assert not status.emulator_available
        assert "not ready" in status.message.lower()


def test_mocked_environment_configured_avd():
    """Respects SPYAWARE_AVD_NAME when set in environment."""
    discovery = EnvironmentDiscovery()
    with patch.dict("os.environ", {"SPYAWARE_AVD_NAME": "Custom_SpyAware_AVD"}), \
         patch.object(discovery, "find_adb_path", return_value="/fake/adb"), \
         patch.object(discovery, "find_emulator_path", return_value="/fake/emulator"), \
         patch.object(discovery, "list_available_avds", return_value=["Custom_SpyAware_AVD", "Other_AVD"]):
        status = discovery.get_status()
        assert status.ready
        assert status.selected_avd == "Custom_SpyAware_AVD"
