"""Transparent and configurable risk rules for SpyAware-Analyzer.

Defines:
1. Individual sensitive permission risk weights and indicators.
2. Permission combination rules that highlight surveillance patterns.
3. Static manifest and DEX indicator risk rules.
"""

from typing import Dict, List, Optional
from backend.models.analysis import Finding, Severity


class PermissionRule:
    def __init__(
        self,
        permission: str,
        short_name: str,
        severity: Severity,
        score: float,
        title: str,
        description: str,
        surveillance_aspect: str,
    ):
        self.permission = permission
        self.short_name = short_name
        self.severity = severity
        self.score = score
        self.title = title
        self.description = description
        self.surveillance_aspect = surveillance_aspect


# Registry of individual permission rules
# Keyed by standard Android permission name (e.g., android.permission.CAMERA)
# or short suffix (e.g., CAMERA)
INDIVIDUAL_PERMISSION_RULES: Dict[str, PermissionRule] = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": PermissionRule(
        permission="android.permission.BIND_ACCESSIBILITY_SERVICE",
        short_name="BIND_ACCESSIBILITY_SERVICE",
        severity=Severity.CRITICAL,
        score=35.0,
        title="Accessibility Service Binding Permission",
        description=(
            "Grants total inspection of screen UI, keystroke logging (keylogger capability), "
            "and programmatic tap injection without user interaction."
        ),
        surveillance_aspect="UI & Input Interception",
    ),
    "android.permission.SYSTEM_ALERT_WINDOW": PermissionRule(
        permission="android.permission.SYSTEM_ALERT_WINDOW",
        short_name="SYSTEM_ALERT_WINDOW",
        severity=Severity.HIGH,
        score=22.0,
        title="Overlay Window Permission (Draw Over Apps)",
        description=(
            "Allows rendering views on top of all other apps. Widely used in covert tapjacking, "
            "fake login phishing screens, and stealth overlay surveillance."
        ),
        surveillance_aspect="Covert Overlay / Tapjacking",
    ),
    "android.permission.READ_SMS": PermissionRule(
        permission="android.permission.READ_SMS",
        short_name="READ_SMS",
        severity=Severity.HIGH,
        score=20.0,
        title="Read Private SMS Messages",
        description=(
            "Provides access to incoming and stored SMS messages, including two-factor authentication "
            "verification codes and private conversations."
        ),
        surveillance_aspect="Communications Interception",
    ),
    "android.permission.RECEIVE_SMS": PermissionRule(
        permission="android.permission.RECEIVE_SMS",
        short_name="RECEIVE_SMS",
        severity=Severity.HIGH,
        score=20.0,
        title="Intercept Real-Time Incoming SMS",
        description=(
            "Allows interception of incoming SMS broadcasts prior to notification delivery, "
            "enabling silent theft of one-time SMS passcodes."
        ),
        surveillance_aspect="Communications Interception",
    ),
    "android.permission.READ_CALL_LOG": PermissionRule(
        permission="android.permission.READ_CALL_LOG",
        short_name="READ_CALL_LOG",
        severity=Severity.HIGH,
        score=18.0,
        title="Read Phone Call Log History",
        description=(
            "Exposes detailed call history, including incoming/outgoing phone numbers, call duration, "
            "timestamps, and missed call records."
        ),
        surveillance_aspect="Communications Interception",
    ),
    "android.permission.RECORD_AUDIO": PermissionRule(
        permission="android.permission.RECORD_AUDIO",
        short_name="RECORD_AUDIO",
        severity=Severity.HIGH,
        score=16.0,
        title="Microphone Audio Recording Access",
        description=(
            "Elevated risk capability to record ambient microphone audio and phone conversations "
            "in the background."
        ),
        surveillance_aspect="Audio Surveillance",
    ),
    "android.permission.CAMERA": PermissionRule(
        permission="android.permission.CAMERA",
        short_name="CAMERA",
        severity=Severity.HIGH,
        score=15.0,
        title="Device Camera Access",
        description=(
            "Elevated risk capability to capture still photos or record live video feeds from "
            "front/back device cameras."
        ),
        surveillance_aspect="Visual Surveillance",
    ),
    "android.permission.ACCESS_BACKGROUND_LOCATION": PermissionRule(
        permission="android.permission.ACCESS_BACKGROUND_LOCATION",
        short_name="ACCESS_BACKGROUND_LOCATION",
        severity=Severity.HIGH,
        score=15.0,
        title="Continuous Background Location Tracking",
        description=(
            "Allows silent continuous GPS tracking of the device even when the application is not "
            "actively open in the foreground."
        ),
        surveillance_aspect="Geolocation Tracking",
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": PermissionRule(
        permission="android.permission.REQUEST_INSTALL_PACKAGES",
        short_name="REQUEST_INSTALL_PACKAGES",
        severity=Severity.HIGH,
        score=15.0,
        title="Request Package Installation (Dropper Indicator)",
        description=(
            "Elevated risk capability allowing the application to prompt or stage installation of "
            "secondary APK payloads."
        ),
        surveillance_aspect="Payload Staging / Dropper",
    ),
    "android.permission.PACKAGE_USAGE_STATS": PermissionRule(
        permission="android.permission.PACKAGE_USAGE_STATS",
        short_name="PACKAGE_USAGE_STATS",
        severity=Severity.HIGH,
        score=14.0,
        title="App Usage Statistics Access",
        description=(
            "Special access permission that reveals timestamps and duration of all user activities "
            "across other applications."
        ),
        surveillance_aspect="Activity Monitoring",
    ),
    "android.permission.RECEIVE_BOOT_COMPLETED": PermissionRule(
        permission="android.permission.RECEIVE_BOOT_COMPLETED",
        short_name="RECEIVE_BOOT_COMPLETED",
        severity=Severity.MEDIUM,
        score=14.0,
        title="Device Boot Persistence Trigger",
        description=(
            "Elevated persistence indicator enabling the application to wake up and launch services "
            "immediately upon device startup."
        ),
        surveillance_aspect="Device Persistence",
    ),
    "android.permission.ACCESS_FINE_LOCATION": PermissionRule(
        permission="android.permission.ACCESS_FINE_LOCATION",
        short_name="ACCESS_FINE_LOCATION",
        severity=Severity.MEDIUM,
        score=12.0,
        title="Precise GPS Location Access",
        description=(
            "Moderate risk capability enabling precise geographic coordinate tracking via GNSS/GPS sensors."
        ),
        surveillance_aspect="Geolocation Tracking",
    ),
    "android.permission.READ_CONTACTS": PermissionRule(
        permission="android.permission.READ_CONTACTS",
        short_name="READ_CONTACTS",
        severity=Severity.MEDIUM,
        score=12.0,
        title="Read Address Book & Contacts",
        description=(
            "Moderate risk access to private address book entries, phone numbers, email addresses, "
            "and contact relationship details."
        ),
        surveillance_aspect="Contact Harvesting",
    ),
    "android.permission.QUERY_ALL_PACKAGES": PermissionRule(
        permission="android.permission.QUERY_ALL_PACKAGES",
        short_name="QUERY_ALL_PACKAGES",
        severity=Severity.MEDIUM,
        score=12.0,
        title="Query All Installed Packages",
        description=(
            "Allows the app to enumerate every installed package on the system, used for anti-virus evasion "
            "or target reconnaissance."
        ),
        surveillance_aspect="Target Reconnaissance",
    ),
    "android.permission.READ_EXTERNAL_STORAGE": PermissionRule(
        permission="android.permission.READ_EXTERNAL_STORAGE",
        short_name="READ_EXTERNAL_STORAGE",
        severity=Severity.MEDIUM,
        score=10.0,
        title="Read Shared Device Storage",
        description=(
            "Allows traversing and reading shared storage files, including photos, downloads, and sensitive documents."
        ),
        surveillance_aspect="Data Harvesting",
    ),
    "android.permission.READ_MEDIA_IMAGES": PermissionRule(
        permission="android.permission.READ_MEDIA_IMAGES",
        short_name="READ_MEDIA_IMAGES",
        severity=Severity.MEDIUM,
        score=10.0,
        title="Read Device Photo Media",
        description=(
            "Allows reading stored user photographs and image files from local storage."
        ),
        surveillance_aspect="Data Harvesting",
    ),
    "android.permission.ACCESS_COARSE_LOCATION": PermissionRule(
        permission="android.permission.ACCESS_COARSE_LOCATION",
        short_name="ACCESS_COARSE_LOCATION",
        severity=Severity.MEDIUM,
        score=8.0,
        title="Coarse Cell/WiFi Location Access",
        description=(
            "Allows estimating geographic location based on network cell towers and WiFi access points."
        ),
        surveillance_aspect="Geolocation Tracking",
    ),
    "android.permission.READ_PHONE_STATE": PermissionRule(
        permission="android.permission.READ_PHONE_STATE",
        short_name="READ_PHONE_STATE",
        severity=Severity.LOW,
        score=8.0,
        title="Read Cellular Phone State & Identifiers",
        description=(
            "Context-dependent indicator exposing cellular network status, ongoing calls, and telephony IDs."
        ),
        surveillance_aspect="Device Profiling",
    ),
    "android.permission.FOREGROUND_SERVICE": PermissionRule(
        permission="android.permission.FOREGROUND_SERVICE",
        short_name="FOREGROUND_SERVICE",
        severity=Severity.LOW,
        score=6.0,
        title="Foreground Service Execution",
        description=(
            "Context-dependent indicator allowing prolonged persistent background execution with an active notification."
        ),
        surveillance_aspect="Background Execution",
    ),
    "android.permission.INTERNET": PermissionRule(
        permission="android.permission.INTERNET",
        short_name="INTERNET",
        severity=Severity.LOW,
        score=4.0,
        title="Network & Internet Access",
        description=(
            "Standard permission required for network communication; indispensable channel for covert remote command/exfiltration."
        ),
        surveillance_aspect="Data Exfiltration",
    ),
}


class PermissionCombinationRule:
    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: Severity,
        score: float,
        description: str,
        required_permissions: List[str],
        one_of_permissions: Optional[List[List[str]]] = None,
    ):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.score = score
        self.description = description
        self.required_permissions = required_permissions
        self.one_of_permissions = one_of_permissions or []


# Combination rules: Patterns showing coordinated covert surveillance capability
COMBINATION_RULES: List[PermissionCombinationRule] = [
    PermissionCombinationRule(
        rule_id="COMBO_AUDIO_VIDEO",
        title="Combined Audio & Video Surveillance Capability",
        severity=Severity.HIGH,
        score=25.0,
        description=(
            "Simultaneous request for CAMERA and RECORD_AUDIO permissions provides dual-channel "
            "environmental recording capabilities characteristic of covert spyware."
        ),
        required_permissions=["CAMERA", "RECORD_AUDIO"],
    ),
    PermissionCombinationRule(
        rule_id="COMBO_FULL_SITUATIONAL_AWARENESS",
        title="Full Situational & Geolocation Surveillance Triad",
        severity=Severity.CRITICAL,
        score=32.0,
        description=(
            "App combines CAMERA, RECORD_AUDIO, and precise or coarse LOCATION permissions. "
            "This combination enables continuous physical tracking coupled with real-time room audio/visual capture."
        ),
        required_permissions=["CAMERA", "RECORD_AUDIO"],
        one_of_permissions=[["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION"]],
    ),
    PermissionCombinationRule(
        rule_id="COMBO_ACCESSIBILITY_OVERLAY",
        title="Stealth Accessibility & Screen Overlay Synergy",
        severity=Severity.CRITICAL,
        score=35.0,
        description=(
            "Combination of BIND_ACCESSIBILITY_SERVICE and SYSTEM_ALERT_WINDOW allows an app to both "
            "intercept user input/keystrokes and display deceptive invisible clickjacking overlays."
        ),
        required_permissions=["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"],
    ),
    PermissionCombinationRule(
        rule_id="COMBO_ACCESSIBILITY_BOOT",
        title="Persistent Reboot Survival of Accessibility Hooks",
        severity=Severity.CRITICAL,
        score=28.0,
        description=(
            "Accessibility privileges paired with RECEIVE_BOOT_COMPLETED ensure that keylogging and "
            "UI surveillance hooks re-engage immediately after the device reboots."
        ),
        required_permissions=["BIND_ACCESSIBILITY_SERVICE", "RECEIVE_BOOT_COMPLETED"],
    ),
    PermissionCombinationRule(
        rule_id="COMBO_BOOT_FOREGROUND",
        title="Automated Boot-Time Persistent Background Service",
        severity=Severity.MEDIUM,
        score=16.0,
        description=(
            "Application automatically starts background services upon device power-on without requiring "
            "direct user invocation."
        ),
        required_permissions=["RECEIVE_BOOT_COMPLETED", "FOREGROUND_SERVICE"],
    ),
    PermissionCombinationRule(
        rule_id="COMBO_SMS_EXFILTRATION",
        title="SMS / 2FA Interception with Remote Network Channel",
        severity=Severity.HIGH,
        score=24.0,
        description=(
            "Ability to read or intercept incoming SMS messages paired with INTERNET access creates a direct "
            "vector for remote 2FA and OTP authentication theft."
        ),
        required_permissions=["INTERNET"],
        one_of_permissions=[["READ_SMS", "RECEIVE_SMS"]],
    ),
    PermissionCombinationRule(
        rule_id="COMBO_SURVEILLANCE_EXFILTRATION",
        title="Covert Data Sensor Exfiltration Pipeline",
        severity=Severity.MEDIUM,
        score=15.0,
        description=(
            "Direct combination of sensitive sensor/data permissions (Camera, Audio, Location, Contacts, or Call Log) "
            "with INTERNET capability forms a complete covert exfiltration pathway."
        ),
        required_permissions=["INTERNET"],
        one_of_permissions=[
            [
                "CAMERA",
                "RECORD_AUDIO",
                "ACCESS_FINE_LOCATION",
                "ACCESS_COARSE_LOCATION",
                "READ_CONTACTS",
                "READ_CALL_LOG",
            ]
        ],
    ),
    PermissionCombinationRule(
        rule_id="COMBO_APP_USAGE_PERSISTENCE",
        title="App Activity Tracking with Auto-Start Persistence",
        severity=Severity.HIGH,
        score=20.0,
        description=(
            "Application monitors user usage statistics across third-party apps and persists across device reboots."
        ),
        required_permissions=["PACKAGE_USAGE_STATS", "RECEIVE_BOOT_COMPLETED"],
    ),
]


def normalize_permission_name(perm: str) -> str:
    """Extract standard permission suffix for uniform matching."""
    perm = perm.strip()
    if perm.startswith("android.permission."):
        return perm.replace("android.permission.", "")
    if "." in perm:
        return perm.split(".")[-1]
    return perm
