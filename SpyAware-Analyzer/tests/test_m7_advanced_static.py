"""Tests for Milestone M7 — Advanced Static Analysis & Manifest Auditing.

Verifies the enhanced static detection rules:
- Unprotected Content Providers (STATIC_MANIFEST_UNPROTECTED_PROVIDER)
- Unverified Deep Links / App Links (STATIC_MANIFEST_UNVERIFIED_DEEP_LINK)
- Notification Listeners (STATIC_MANIFEST_NOTIFICATION_LISTENER)
- Device Administration Receivers (STATIC_MANIFEST_DEVICE_ADMIN)
- Background Location Permission (STATIC_PERM_BACKGROUND_LOCATION)
- Insecure WebView Configurations (STATIC_DEX_WEBVIEW_INSECURE_SETTINGS)
- Weak Cryptographic Ciphers & Hashes (STATIC_DEX_INSECURE_CIPHER_ALGORITHM)
- Clipboard Monitoring APIs (STATIC_DEX_CLIPBOARD_MONITORING)
- Native Anti-Debugging & Hooking Detection (STATIC_NATIVE_ANTI_DEBUGGING)
"""

from pathlib import Path
import pytest
from analyzers.static.analyzer import StaticAnalyzer
from backend.models.analysis import Severity
from samples.builder import build_and_sign_apk


@pytest.fixture
def static_analyzer():
    return StaticAnalyzer()


def test_unprotected_content_provider_detection(tmp_path, static_analyzer):
    """Detects exported ContentProvider lacking read/write permissions."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.provider">
    <application>
        <provider android:name="com.test.LeakyProvider" android:exported="true" android:authorities="com.test.leaky" />
        <provider android:name="com.test.ProtectedProvider" android:exported="true" android:permission="com.test.READ" android:authorities="com.test.protected" />
    </application>
</manifest>"""
    apk_path = tmp_path / "provider_test.apk"
    build_and_sign_apk(apk_path, "com.test.provider", manifest, [])

    res = static_analyzer.analyze(str(apk_path))
    assert res.is_valid_apk
    rule_ids = {f.rule_id for f in res.findings}
    assert "STATIC_MANIFEST_UNPROTECTED_PROVIDER" in rule_ids
    
    finding = next(f for f in res.findings if f.rule_id == "STATIC_MANIFEST_UNPROTECTED_PROVIDER")
    assert finding.severity == Severity.MEDIUM
    assert finding.score == 10.0
    assert "LeakyProvider" in finding.evidence
    assert "ProtectedProvider" not in finding.evidence


def test_unverified_deep_link_detection(tmp_path, static_analyzer):
    """Detects HTTP/HTTPS deep links configured without autoVerify='true'."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.deeplink">
    <application>
        <activity android:name="com.test.UnverifiedActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="https" android:host="example.com" />
            </intent-filter>
        </activity>
    </application>
</manifest>"""
    apk_path = tmp_path / "deeplink_test.apk"
    build_and_sign_apk(apk_path, "com.test.deeplink", manifest, [])

    res = static_analyzer.analyze(str(apk_path))
    assert res.is_valid_apk
    rule_ids = {f.rule_id for f in res.findings}
    assert "STATIC_MANIFEST_UNVERIFIED_DEEP_LINK" in rule_ids
    
    finding = next(f for f in res.findings if f.rule_id == "STATIC_MANIFEST_UNVERIFIED_DEEP_LINK")
    assert finding.severity == Severity.LOW
    assert finding.score == 5.0
    assert "UnverifiedActivity" in finding.evidence


def test_notification_listener_service_detection(tmp_path, static_analyzer):
    """Detects services requiring BIND_NOTIFICATION_LISTENER_SERVICE."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.notif">
    <application>
        <service android:name="com.test.NotificationSnooper"
                 android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE">
            <intent-filter>
                <action android:name="android.service.notification.NotificationListenerService" />
            </intent-filter>
        </service>
    </application>
</manifest>"""
    apk_path = tmp_path / "notif_test.apk"
    build_and_sign_apk(apk_path, "com.test.notif", manifest, [])

    res = static_analyzer.analyze(str(apk_path))
    assert res.is_valid_apk
    rule_ids = {f.rule_id for f in res.findings}
    assert "STATIC_MANIFEST_NOTIFICATION_LISTENER" in rule_ids
    
    finding = next(f for f in res.findings if f.rule_id == "STATIC_MANIFEST_NOTIFICATION_LISTENER")
    assert finding.severity == Severity.HIGH
    assert finding.score == 20.0
    assert "NotificationSnooper" in finding.evidence


def test_device_admin_receiver_detection(tmp_path, static_analyzer):
    """Detects receivers declaring BIND_DEVICE_ADMIN / DEVICE_ADMIN_ENABLED."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.admin">
    <application>
        <receiver android:name="com.test.AdminLocker"
                  android:permission="android.permission.BIND_DEVICE_ADMIN">
            <intent-filter>
                <action android:name="android.app.action.DEVICE_ADMIN_ENABLED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>"""
    apk_path = tmp_path / "admin_test.apk"
    build_and_sign_apk(apk_path, "com.test.admin", manifest, [])

    res = static_analyzer.analyze(str(apk_path))
    assert res.is_valid_apk
    rule_ids = {f.rule_id for f in res.findings}
    assert "STATIC_MANIFEST_DEVICE_ADMIN" in rule_ids
    
    finding = next(f for f in res.findings if f.rule_id == "STATIC_MANIFEST_DEVICE_ADMIN")
    assert finding.severity == Severity.HIGH
    assert finding.score == 20.0
    assert "AdminLocker" in finding.evidence


def test_background_location_permission_detection(tmp_path, static_analyzer):
    """Detects ACCESS_BACKGROUND_LOCATION permission declaration."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.bgloc">
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION" />
    <application />
</manifest>"""
    apk_path = tmp_path / "bgloc_test.apk"
    build_and_sign_apk(apk_path, "com.test.bgloc", manifest, [])

    res = static_analyzer.analyze(str(apk_path))
    assert res.is_valid_apk
    rule_ids = {f.rule_id for f in res.findings}
    assert "STATIC_PERM_BACKGROUND_LOCATION" in rule_ids
    
    finding = next(f for f in res.findings if f.rule_id == "STATIC_PERM_BACKGROUND_LOCATION")
    assert finding.severity == Severity.MEDIUM
    assert finding.score == 12.0


def test_insecure_webview_settings_detection(tmp_path, static_analyzer):
    """Detects insecure WebView configuration patterns in DEX bytecode."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.webview"><application /></manifest>"""
    dex_strings = ["setJavaScriptEnabled", "addJavascriptInterface", "Landroid/webkit/WebView;"]
    apk_path = tmp_path / "webview_test.apk"
    build_and_sign_apk(apk_path, "com.test.webview", manifest, dex_strings)

    res = static_analyzer.analyze(str(apk_path))
    assert res.is_valid_apk
    rule_ids = {f.rule_id for f in res.findings}
    assert "STATIC_DEX_WEBVIEW_INSECURE_SETTINGS" in rule_ids
    
    finding = next(f for f in res.findings if f.rule_id == "STATIC_DEX_WEBVIEW_INSECURE_SETTINGS")
    assert finding.severity == Severity.MEDIUM
    assert finding.score == 10.0


def test_weak_cryptographic_ciphers_and_hashes(tmp_path, static_analyzer):
    """Detects weak ciphers and digests (MD5, SHA-1, DES, RC4) in DEX bytecode."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.crypto"><application /></manifest>"""
    dex_strings = ["MD5", "DES/CBC/PKCS5Padding", "Ljavax/crypto/Cipher;"]
    apk_path = tmp_path / "crypto_test.apk"
    build_and_sign_apk(apk_path, "com.test.crypto", manifest, dex_strings)

    res = static_analyzer.analyze(str(apk_path))
    assert res.is_valid_apk
    rule_ids = {f.rule_id for f in res.findings}
    assert "STATIC_DEX_INSECURE_CIPHER_ALGORITHM" in rule_ids
    
    finding = next(f for f in res.findings if f.rule_id == "STATIC_DEX_INSECURE_CIPHER_ALGORITHM")
    assert finding.severity == Severity.LOW
    assert finding.score == 6.0


def test_clipboard_monitoring_detection(tmp_path, static_analyzer):
    """Detects ClipboardManager and clip change listener references in DEX."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.clipboard"><application /></manifest>"""
    dex_strings = ["ClipboardManager", "addPrimaryClipChangedListener"]
    apk_path = tmp_path / "clip_test.apk"
    build_and_sign_apk(apk_path, "com.test.clipboard", manifest, dex_strings)

    res = static_analyzer.analyze(str(apk_path))
    assert res.is_valid_apk
    rule_ids = {f.rule_id for f in res.findings}
    assert "STATIC_DEX_CLIPBOARD_MONITORING" in rule_ids
    
    finding = next(f for f in res.findings if f.rule_id == "STATIC_DEX_CLIPBOARD_MONITORING")
    assert finding.severity == Severity.MEDIUM
    assert finding.score == 10.0


def test_native_anti_debugging_detection(tmp_path, static_analyzer):
    """Detects TracerPid, /proc/self/status, or frida symbols in native libraries and DEX."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.antidebug"><application /></manifest>"""
    native_libs = {
        "lib/arm64-v8a/libsecurity.so": b"\x7fELF" + b"TracerPid\x00" + b"/proc/self/status\x00"
    }
    apk_path = tmp_path / "antidebug_test.apk"
    build_and_sign_apk(apk_path, "com.test.antidebug", manifest, [], native_libs=native_libs)

    res = static_analyzer.analyze(str(apk_path))
    assert res.is_valid_apk
    rule_ids = {f.rule_id for f in res.findings}
    assert "STATIC_NATIVE_ANTI_DEBUGGING" in rule_ids
    
    finding = next(f for f in res.findings if f.rule_id == "STATIC_NATIVE_ANTI_DEBUGGING")
    assert finding.severity == Severity.LOW
    assert finding.score == 6.0
