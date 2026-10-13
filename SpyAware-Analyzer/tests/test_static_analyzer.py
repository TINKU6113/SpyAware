"""Unit tests for StaticAnalyzer in SpyAware-Analyzer."""

from pathlib import Path
import pytest
from analyzers.static.analyzer import StaticAnalyzer
from backend.models.analysis import Severity

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def static_analyzer():
    return StaticAnalyzer()


def test_nonexistent_apk_file(static_analyzer):
    """Attempting to analyze a non-existent file path handled safely."""
    res = static_analyzer.analyze(str(SAMPLES_DIR / "non_existent_file.apk"))
    assert not res.is_valid_apk
    assert "does not exist" in res.error_message
    assert res.score == 0.0


def test_malformed_corrupt_file(static_analyzer):
    """Attempting to analyze non-zip random data handled gracefully."""
    res = static_analyzer.analyze(str(SAMPLES_DIR / "malformed_corrupt.apk"))
    assert not res.is_valid_apk
    assert "not a valid ZIP/APK archive" in res.error_message
    assert res.score == 0.0


def test_malformed_missing_manifest(static_analyzer):
    """A valid zip archive missing AndroidManifest.xml is safely rejected."""
    res = static_analyzer.analyze(str(SAMPLES_DIR / "malformed_no_manifest.apk"))
    assert not res.is_valid_apk
    assert "does not contain AndroidManifest.xml" in res.error_message
    assert res.score == 0.0


def test_malformed_invalid_manifest_binary(static_analyzer):
    """An archive with corrupted binary manifest data handled without crash."""
    res = static_analyzer.analyze(str(SAMPLES_DIR / "malformed_invalid_manifest.apk"))
    assert not res.is_valid_apk
    assert res.error_message is not None
    assert res.score == 0.0


def test_benign_apk_analysis(static_analyzer):
    """Benign sample APK extracts package name and requested permissions cleanly."""
    res = static_analyzer.analyze(str(SAMPLES_DIR / "benign_sample.apk"))
    assert res.is_valid_apk
    assert res.package_name == "com.spyaware.benign"
    assert "android.permission.INTERNET" in res.requested_permissions
    assert res.score < 25.0


def test_suspicious_apk_analysis(static_analyzer):
    """Suspicious sample extracts surveillance permissions and DEX indicators."""
    res = static_analyzer.analyze(str(SAMPLES_DIR / "suspicious_surveillance_sample.apk"))
    assert res.is_valid_apk
    assert res.package_name == "com.spyaware.suspicious"
    assert "android.permission.CAMERA" in res.requested_permissions
    assert "android.permission.RECORD_AUDIO" in res.requested_permissions
    # Check that DEX indicators were detected
    assert len(res.camera_api_indicators) > 0
    assert len(res.microphone_api_indicators) > 0
    assert len(res.location_api_indicators) > 0
    assert res.score >= 40.0


def test_critical_stalkerware_apk_analysis(static_analyzer):
    """Critical stalkerware APK detects native libraries, shell strings, and accessibility."""
    res = static_analyzer.analyze(str(SAMPLES_DIR / "critical_stalkerware_sample.apk"))
    assert res.is_valid_apk
    assert res.package_name == "com.spyaware.stalkerware"
    assert len(res.native_libraries) > 0
    assert len(res.screen_capture_indicators) > 0
    assert len(res.suspicious_strings_urls) > 0
    assert res.score >= 50.0
