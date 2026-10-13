"""Unit tests for Permission Analyzer and combination rules in SpyAware-Analyzer."""

import pytest
from analyzers.permissions.analyzer import PermissionAnalyzer
from backend.models.analysis import Severity


@pytest.fixture
def analyzer():
    return PermissionAnalyzer()


def test_empty_permissions(analyzer):
    """Empty permission list yields 0 score and no findings."""
    result = analyzer.analyze([])
    assert result.score == 0.0
    assert len(result.findings) == 0
    assert len(result.individual_findings) == 0
    assert len(result.combination_findings) == 0


def test_benign_permissions(analyzer):
    """Benign standard permissions evaluate to a LOW score (< 25)."""
    benign_perms = [
        "android.permission.INTERNET",
        "android.permission.VIBRATE",
        "android.permission.POST_NOTIFICATIONS",
    ]
    result = analyzer.analyze(benign_perms)
    assert result.score < 25.0
    # INTERNET is scored as low baseline (4.0)
    assert result.score == 4.0
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.LOW


def test_suspicious_permissions_triad(analyzer):
    """Camera, Audio, Location, Boot, and Foreground trigger high/critical risk and combinations."""
    suspicious_perms = [
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.FOREGROUND_SERVICE",
    ]
    result = analyzer.analyze(suspicious_perms)
    assert result.score >= 50.0

    combo_titles = [f.title for f in result.combination_findings]
    # Check that Audio + Video combination fired
    assert any("Audio & Video Surveillance" in t for t in combo_titles)
    # Check that Situational Awareness combination fired
    assert any("Situational & Geolocation Surveillance" in t for t in combo_titles)
    # Check that Boot + Foreground combination fired
    assert any("Boot-Time Persistent Background Service" in t for t in combo_titles)


def test_very_suspicious_stalkerware_permissions(analyzer):
    """Accessibility + Overlay + Boot + Audio + Internet triggers CRITICAL risk (>= 75)."""
    very_suspicious_perms = [
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.RECORD_AUDIO",
        "android.permission.INTERNET",
    ]
    result = analyzer.analyze(very_suspicious_perms)
    assert result.score >= 75.0
    assert result.score <= 100.0

    combo_titles = [f.title for f in result.combination_findings]
    assert any("Accessibility & Screen Overlay" in t for t in combo_titles)
    assert any("Reboot Survival of Accessibility" in t for t in combo_titles)
    assert any("Exfiltration" in t for t in combo_titles)


def test_score_normalization_cap(analyzer):
    """Even an extreme list of permissions never exceeds 100.0."""
    giant_list = [
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_CONTACTS",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.INTERNET",
        "android.permission.FOREGROUND_SERVICE",
    ]
    result = analyzer.analyze(giant_list)
    assert result.score == 100.0


def test_permission_name_variations(analyzer):
    """Handles both full and short permission names seamlessly."""
    full = analyzer.analyze(["android.permission.RECORD_AUDIO"])
    short = analyzer.analyze(["RECORD_AUDIO"])
    assert full.score == short.score
    assert len(full.findings) == len(short.findings)
