"""Unit tests for ADB Device Discovery, Package Enumeration, and Safe APK Extraction (Milestone M3.2)."""

import subprocess
from unittest.mock import MagicMock, patch
import pytest

from analyzers.discovery.manager import DeviceDiscoveryManager
from analyzers.discovery.models import DeviceState, DeviceType


@pytest.fixture
def mock_env():
    env = MagicMock()
    env.find_adb_path.return_value = "/mock/bin/adb"
    return env


@pytest.fixture
def discovery_mgr(mock_env):
    return DeviceDiscoveryManager(env_discovery=mock_env)


def test_no_connected_devices(discovery_mgr):
    """Empty adb devices output returns empty device list."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["adb", "devices", "-l"],
            returncode=0,
            stdout="List of devices attached\n\n",
            stderr="",
        )
        devices = discovery_mgr.list_devices()
        assert len(devices) == 0


def test_single_authorized_emulator(discovery_mgr):
    """Detects and inspects single authorized emulator."""
    with patch("subprocess.run") as mock_run:
        # 1. adb devices -l
        mock_run.side_effect = [
            subprocess.CompletedProcess(
                args=["adb", "devices", "-l"],
                returncode=0,
                stdout="List of devices attached\nemulator-5554 device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64\n",
                stderr="",
            ),
            # getprop release & sdk
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="14\n34\n",
                stderr="",
            ),
            # getprop abis
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="x86_64,x86\nx86_64\n",
                stderr="",
            ),
            # emu avd name
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="Medium_Phone_API_36.1\nOK\n",
                stderr="",
            ),
        ]

        devices = discovery_mgr.list_devices()
        assert len(devices) == 1
        dev = devices[0]
        assert dev.serial == "emulator-5554"
        assert dev.state == DeviceState.DEVICE
        assert dev.is_authorized is True
        assert dev.is_online is True
        assert dev.device_type == DeviceType.EMULATOR
        assert dev.android_version == "14"
        assert dev.api_level == 34
        assert dev.abi == "x86_64"
        assert dev.avd_name == "Medium_Phone_API_36.1"


def test_multiple_devices_including_physical_and_unauthorized(discovery_mgr):
    """Distinguishes emulator from physical, and device from unauthorized."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = [
            subprocess.CompletedProcess(
                args=["adb", "devices", "-l"],
                returncode=0,
                stdout=(
                    "List of devices attached\n"
                    "emulator-5554 device product:sdk model:sdk\n"
                    "RFCW123456 unauthorized model:Pixel_8\n"
                    "192.168.1.100:5555 offline\n"
                ),
                stderr="",
            ),
            # props for emulator-5554
            subprocess.CompletedProcess(args=[], returncode=0, stdout="16\n36\n"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="x86_64\nx86_64\n"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="Medium_Phone_API_36.1\nOK\n"),
        ]

        devices = discovery_mgr.list_devices()
        assert len(devices) == 3

        emu = next(d for d in devices if d.serial == "emulator-5554")
        assert emu.is_authorized is True
        assert emu.device_type == DeviceType.EMULATOR

        phys_unauth = next(d for d in devices if d.serial == "RFCW123456")
        assert phys_unauth.is_authorized is False
        assert phys_unauth.state == DeviceState.UNAUTHORIZED
        assert phys_unauth.device_type == DeviceType.PHYSICAL

        offline = next(d for d in devices if d.serial == "192.168.1.100:5555")
        assert offline.is_online is False
        assert offline.state == DeviceState.OFFLINE


def test_list_installed_packages_success_with_splits(discovery_mgr):
    """Successfully enumerates packages and detects split APK installations."""
    with patch.object(discovery_mgr, "list_devices") as mock_list_dev:
        mock_list_dev.return_value = [
            MagicMock(serial="emulator-5554", is_authorized=True, is_online=True)
        ]

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                # pm list packages -f -3
                subprocess.CompletedProcess(
                    args=["adb", "-s", "emulator-5554", "shell", "pm", "list", "packages", "-f", "-3"],
                    returncode=0,
                    stdout=(
                        "package:/data/app/com.example.single-1/base.apk=com.example.single\n"
                        "package:/data/app/com.example.split-2/base.apk=com.example.split\n"
                    ),
                    stderr="",
                ),
                # pm path for single
                subprocess.CompletedProcess(
                    args=["adb", "-s", "emulator-5554", "shell", "pm", "path", "com.example.single"],
                    returncode=0,
                    stdout="package:/data/app/com.example.single-1/base.apk\n",
                    stderr="",
                ),
                # pm path for split
                subprocess.CompletedProcess(
                    args=["adb", "-s", "emulator-5554", "shell", "pm", "path", "com.example.split"],
                    returncode=0,
                    stdout=(
                        "package:/data/app/com.example.split-2/base.apk\n"
                        "package:/data/app/com.example.split-2/split_config.arm64_v8a.apk\n"
                        "package:/data/app/com.example.split-2/split_config.xxhdpi.apk\n"
                    ),
                    stderr="",
                ),
            ]

            packages = discovery_mgr.list_installed_packages("emulator-5554", include_system=False)
            assert len(packages) == 2

            single = next(p for p in packages if p.package_name == "com.example.single")
            assert single.is_split is False
            assert single.split_count == 0

            split = next(p for p in packages if p.package_name == "com.example.split")
            assert split.is_split is True
            assert split.split_count == 2
            assert len(split.split_apk_paths) == 2


def test_list_packages_rejects_unauthorized_device(discovery_mgr):
    """Refuses to query packages from unauthorized device."""
    with patch.object(discovery_mgr, "list_devices") as mock_list_dev:
        mock_list_dev.return_value = [
            MagicMock(serial="device-unauth", is_authorized=False, is_online=True)
        ]
        with pytest.raises(PermissionError, match="unauthorized"):
            discovery_mgr.list_installed_packages("device-unauth")


def test_extract_package_rejects_unsafe_package_name(discovery_mgr):
    """Rejects path traversal or malicious injection in package name."""
    extracted = discovery_mgr.extract_package_apk("emulator-5554", "../../etc/passwd")
    assert extracted.success is False
    assert "forbidden characters" in extracted.error_message


def test_extract_package_blocks_non_apk_path(discovery_mgr):
    """Blocks extraction if returned path points to databases or non-APK files."""
    with patch.object(discovery_mgr, "list_devices") as mock_list_dev:
        mock_list_dev.return_value = [
            MagicMock(serial="emulator-5554", is_authorized=True, is_online=True)
        ]

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="package:/data/data/com.example.app/databases/app.db\n",
                stderr="",
            )
            extracted = discovery_mgr.extract_package_apk("emulator-5554", "com.example.app")
            assert extracted.success is False
            assert "Security violation" in extracted.error_message


def test_extract_package_success(discovery_mgr, tmp_path):
    """Successfully pulls base APK and records split warnings."""
    with patch.object(discovery_mgr, "list_devices") as mock_list_dev:
        mock_list_dev.return_value = [
            MagicMock(serial="emulator-5554", is_authorized=True, is_online=True)
        ]

        with patch("subprocess.run") as mock_run:
            # First call: pm path
            def mock_subprocess(*args, **kwargs):
                cmd = args[0]
                if "pm" in cmd and "path" in cmd:
                    return subprocess.CompletedProcess(
                        args=cmd,
                        returncode=0,
                        stdout="package:/data/app/base.apk\npackage:/data/app/split_config.apk\n",
                    )
                elif "pull" in cmd:
                    # Create mock local file so existence check passes
                    dest_path = cmd[-1]
                    with open(dest_path, "wb") as f:
                        f.write(b"MOCK APK BINARY")
                    return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="Pulled", stderr="")
                return subprocess.CompletedProcess(args=cmd, returncode=0)

            mock_run.side_effect = mock_subprocess

            extracted = discovery_mgr.extract_package_apk(
                "emulator-5554", "com.example.app", output_dir=str(tmp_path)
            )
            assert extracted.success is True
            assert extracted.package_name == "com.example.app"
            assert extracted.is_split is True
            assert extracted.split_count == 1
            assert len(extracted.warnings) >= 1
            assert "split APK installation" in extracted.warnings[0]
