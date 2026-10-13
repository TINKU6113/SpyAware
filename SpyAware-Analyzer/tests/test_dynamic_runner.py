"""Unit tests for DynamicRunner in SpyAware-Analyzer."""

from unittest.mock import MagicMock, patch
import subprocess
import pytest

from analyzers.dynamic.runner import (
    BOOT_TIMEOUT_SECONDS,
    CLEANUP_TIMEOUT_SECONDS,
    EXECUTION_TIMEOUT_SECONDS,
    INSTALL_TIMEOUT_SECONDS,
    DynamicRunner,
)


@pytest.fixture
def runner():
    return DynamicRunner()


def test_runner_defaults(runner):
    """Verifies reasonable default safety timeouts."""
    assert runner.boot_timeout == BOOT_TIMEOUT_SECONDS == 90
    assert runner.install_timeout == INSTALL_TIMEOUT_SECONDS == 30
    assert runner.execution_timeout == EXECUTION_TIMEOUT_SECONDS == 60
    assert runner.cleanup_timeout == CLEANUP_TIMEOUT_SECONDS == 30


@patch("subprocess.run")
def test_get_first_online_device(mock_run, runner):
    """Correctly parses device IDs from adb devices output."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="List of devices attached\nemulator-5554\tdevice\nemulator-5556\toffline\n",
    )
    device_id = runner.get_first_online_device("/fake/adb")
    assert device_id == "emulator-5554"


@patch("subprocess.run")
def test_wait_for_boot_success(mock_run, runner):
    """Signals boot complete when getprop is 1 and package manager is active."""
    # First call: getprop sys.boot_completed -> "1"
    # Second call: pm path android -> "package:/system/framework/framework-res.apk"
    mock_run.side_effect = [
        MagicMock(returncode=0, stdout="1\n"),
        MagicMock(returncode=0, stdout="package:/system/framework/framework-res.apk\n"),
    ]
    booted = runner.wait_for_boot("/fake/adb", "emulator-5554")
    assert booted is True


@patch("subprocess.run")
def test_install_apk_success(mock_run, runner):
    """Runs adb install with -r -g arguments and reports success."""
    mock_run.return_value = MagicMock(returncode=0, stdout="Performing Streamed Install\nSuccess\n", stderr="")
    success, msg = runner.install_apk("/fake/adb", "/path/to/test.apk", "emulator-5554")
    assert success is True
    assert "Success" in msg

    # Verify command arguments passed
    called_args = mock_run.call_args[0][0]
    assert called_args == ["/fake/adb", "-s", "emulator-5554", "install", "-r", "-g", "/path/to/test.apk"]


@patch("subprocess.run")
def test_launch_activity_explicit(mock_run, runner):
    """Constructs correct am start arguments for explicit activity."""
    mock_run.return_value = MagicMock(returncode=0, stdout="Starting: Intent { cmp=com.test/.Main }\n", stderr="")
    success, msg = runner.launch_activity("/fake/adb", "com.test", ".Main", "emulator-5554")
    assert success is True
    called_args = mock_run.call_args[0][0]
    assert called_args == ["/fake/adb", "-s", "emulator-5554", "shell", "am", "start", "-n", "com.test/.Main"]


@patch("subprocess.run")
def test_launch_activity_monkey_fallback(mock_run, runner):
    """Uses monkey tool when activity_name is None."""
    mock_run.return_value = MagicMock(returncode=0, stdout="Events injected: 1\n", stderr="")
    success, msg = runner.launch_activity("/fake/adb", "com.test", None, "emulator-5554")
    assert success is True
    called_args = mock_run.call_args[0][0]
    assert called_args == [
        "/fake/adb",
        "-s",
        "emulator-5554",
        "shell",
        "monkey",
        "-p",
        "com.test",
        "-c",
        "android.intent.category.LAUNCHER",
        "1",
    ]
