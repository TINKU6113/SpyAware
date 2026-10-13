"""Static APK Analyzer for SpyAware-Analyzer.

Extracts manifest metadata, components, permissions, exported flags,
DEX bytecode API indicators (camera, audio, location, SMS, contacts, screen capture, network),
native .so libraries, and suspicious strings/URLs without executing the APK.
"""

import hashlib
import logging
import os
import re
import zipfile
from typing import Any, Dict, List, Optional, Set, Tuple

# Suppress verbose androguard debug logs
try:
    from loguru import logger as loguru_logger
    loguru_logger.disable("androguard")
except Exception:
    pass

from analyzers.intake.validator import UniversalAPKIntake
from backend.models.analysis import (
    CertificateInfo,
    ExportedComponent,
    Finding,
    ManifestConfiguration,
    Severity,
    StaticAnalysisResult,
)
from risk_engine.engine import RiskEngine

# Androguard imports
try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
except ImportError:
    APK = None
    DEX = None


# Signature API patterns to detect in DEX strings / method references
CAMERA_PATTERNS = [
    r"Landroid/hardware/Camera",
    r"Landroid/hardware/camera2",
    r"android\.hardware\.Camera",
    r"android\.hardware\.camera2",
    r"CameraDevice",
    r"CameraManager",
    r"openCamera",
    r"takePicture",
]

MICROPHONE_PATTERNS = [
    r"Landroid/media/AudioRecord",
    r"Landroid/media/MediaRecorder",
    r"android\.media\.AudioRecord",
    r"android\.media\.MediaRecorder",
    r"AudioSource",
    r"startRecording",
    r"setAudioSource",
]

LOCATION_PATTERNS = [
    r"Landroid/location/LocationManager",
    r"android\.location\.LocationManager",
    r"FusedLocationProviderClient",
    r"requestLocationUpdates",
    r"getLastKnownLocation",
    r"LocationListener",
]

SMS_CALL_PATTERNS = [
    r"Landroid/telephony/SmsManager",
    r"android\.telephony\.SmsManager",
    r"sendTextMessage",
    r"sendMultipartTextMessage",
    r"android/provider/Telephony",
    r"android/provider/CallLog",
    r"android\.provider\.CallLog",
    r"TelephonyManager",
    r"getDeviceId",
    r"getImei",
]

CONTACTS_PATTERNS = [
    r"android/provider/ContactsContract",
    r"android\.provider\.ContactsContract",
    r"ContactsContract\$Contacts",
    r"ContactsContract\$CommonDataKinds",
]

SCREEN_CAPTURE_PATTERNS = [
    r"Landroid/media/projection/MediaProjection",
    r"android\.media\.projection\.MediaProjection",
    r"MediaProjectionManager",
    r"createVirtualDisplay",
    r"getMediaProjection",
]

NETWORK_PATTERNS = [
    r"Ljava/net/HttpURLConnection",
    r"Lokhttp3/OkHttpClient",
    r"Lretrofit2/Retrofit",
    r"android/net/ConnectivityManager",
    r"java/net/Socket",
    r"java/net/URL",
]

SUSPICIOUS_CMD_PATTERNS = [
    (r"/system/bin/sh", "Reference to system shell /system/bin/sh"),
    (r"/bin/sh", "Reference to /bin/sh"),
    (r"(?:/system/x?bin/)?\bsu\b", "Reference to su (superuser) binary"),
    (r"(?:/system/bin/)?chmod\s+[0-7]{3,4}", "Shell chmod permission modification"),
    (r"(?:/system/bin/)?pm\s+install", "Silent package manager install command"),
    (r"\bsetprop\s+[a-zA-Z0-9_\.\-]+", "System property modification command"),
]

DYNAMIC_CLASSLOADER_PATTERNS = [
    (r"DexClassLoader", "Dynamic DEX class loader (runtime code execution)"),
    (r"InMemoryDexClassLoader", "In-memory DEX class loader (anti-forensic execution)"),
]

# Precompiled combined regular expressions for high-throughput DEX scanning
COMBINED_CAMERA_RE = re.compile("|".join(CAMERA_PATTERNS))
COMBINED_MICROPHONE_RE = re.compile("|".join(MICROPHONE_PATTERNS))
COMBINED_LOCATION_RE = re.compile("|".join(LOCATION_PATTERNS))
COMBINED_SMS_CALL_RE = re.compile("|".join(SMS_CALL_PATTERNS))
COMBINED_CONTACTS_RE = re.compile("|".join(CONTACTS_PATTERNS))
COMBINED_SCREEN_CAPTURE_RE = re.compile("|".join(SCREEN_CAPTURE_PATTERNS))
COMBINED_NETWORK_RE = re.compile("|".join(NETWORK_PATTERNS))
COMPILED_SUSPICIOUS_CMD = [(re.compile(pat, re.IGNORECASE), desc) for pat, desc in SUSPICIOUS_CMD_PATTERNS]
COMPILED_DYNAMIC_LOADER = [(re.compile(pat), desc) for pat, desc in DYNAMIC_CLASSLOADER_PATTERNS]

# Standard benign URL prefixes to exclude from suspicious URL reports
BENIGN_URL_PATTERNS = [
    re.compile(r"^https?://schemas\.android\.com"),
    re.compile(r"^https?://www\.w3\.org"),
    re.compile(r"^https?://schemas\.xmlsoap\.org"),
    re.compile(r"^https?://github\.com"),
    re.compile(r"^https?://android\.googlesource\.com"),
    re.compile(r"^https?://.*\.googleapis\.com"),
    re.compile(r"^https?://.*\.google\.com"),
]

# Additional static indicator patterns (Milestone M3.3)
REFLECTION_PATTERNS = [
    r"Ljava/lang/reflect/Method;->invoke",
    r"Ljava/lang/Class;->forName",
    r"Ljava/lang/Class;->getMethod",
    r"Ljava/lang/Class;->getDeclaredMethod",
    r"Class\.forName",
    r"Method\.invoke",
]

RUNTIME_EXEC_PATTERNS = [
    r"Ljava/lang/Runtime;->exec",
    r"Ljava/lang/ProcessBuilder;",
    r"Runtime\.getRuntime\(\)\.exec",
]

DEVICE_ADMIN_PATTERNS = [
    r"Landroid/app/admin/DevicePolicyManager;",
    r"android\.app\.action\.DEVICE_ADMIN_ENABLED",
    r"DevicePolicyManager",
]

CRYPTO_ECB_PATTERNS = [
    r"AES/ECB",
    r"DES/ECB",
    r"DESede/ECB",
]

AWS_KEY_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
GOOGLE_API_KEY_RE = re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z ]*?)PRIVATE KEY-----")
GITHUB_PAT_RE = re.compile(r"\b(ghp_[A-Za-z0-9_]{36,40})\b")
SLACK_WEBHOOK_RE = re.compile(r"(https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+)")
JWT_RE = re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]+)\b")

COMBINED_REFLECTION_RE = re.compile("|".join(REFLECTION_PATTERNS))
COMBINED_RUNTIME_EXEC_RE = re.compile("|".join(RUNTIME_EXEC_PATTERNS))
COMBINED_DEVICE_ADMIN_RE = re.compile("|".join(DEVICE_ADMIN_PATTERNS))
COMBINED_CRYPTO_ECB_RE = re.compile("|".join(CRYPTO_ECB_PATTERNS))

WEBVIEW_INSECURE_PATTERNS = [
    r"setJavaScriptEnabled",
    r"setAllowFileAccess",
    r"setAllowUniversalAccessFromFileURLs",
    r"setAllowFileAccessFromFileURLs",
    r"addJavascriptInterface",
]

INSECURE_CIPHER_PATTERNS = [
    r"\bMD5\b",
    r"\bSHA-1\b",
    r"\bDES\b",
    r"\bRC4\b",
    r"DES/",
    r"DESede/",
    r"RC4/",
]

CLIPBOARD_MONITORING_PATTERNS = [
    r"ClipboardManager",
    r"addPrimaryClipChangedListener",
    r"getPrimaryClip",
    r"OnPrimaryClipChangedListener",
]

ANTI_DEBUG_PATTERNS = [
    r"TracerPid",
    r"/proc/self/status",
    r"frida-gadget",
    r"xposed\.installer",
    r"de\.robv\.android\.xposed",
]

COMBINED_WEBVIEW_RE = re.compile("|".join(WEBVIEW_INSECURE_PATTERNS))
COMBINED_INSECURE_CIPHER_RE = re.compile("|".join(INSECURE_CIPHER_PATTERNS), re.IGNORECASE)
COMBINED_CLIPBOARD_RE = re.compile("|".join(CLIPBOARD_MONITORING_PATTERNS))
COMBINED_ANTI_DEBUG_RE = re.compile("|".join(ANTI_DEBUG_PATTERNS), re.IGNORECASE)



def redact_secret(val: str) -> str:
    """Redacts discovered secret keys to prevent leaking sensitive credentials in reports."""
    if len(val) >= 12:
        return val[:4] + "...[REDACTED]..." + val[-4:]
    return "[REDACTED]"


def make_finding(
    category: str,
    severity: Severity,
    title: str,
    description: str,
    evidence: str,
    score: float,
    rule_id: Optional[str] = None,
    confidence: float = 1.0,
    evidence_source: str = "static",
    location: Optional[str] = None,
    security_impact: Optional[str] = None,
    false_positive_notes: Optional[str] = None,
    remediation: Optional[str] = None,
    detection_method: str = "pattern_match",
) -> Finding:
    """Constructs a deterministic, enriched Finding with a stable ID and separation of severity from confidence."""
    f_seed = f"{category}:{rule_id or title}:{evidence[:50]}"
    f_id = hashlib.sha256(f_seed.encode("utf-8", errors="ignore")).hexdigest()[:16]
    return Finding(
        category=category,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        score=score,
        finding_id=f_id,
        rule_id=rule_id,
        confidence=confidence,
        evidence_source=evidence_source,
        location=location,
        security_impact=security_impact,
        false_positive_notes=false_positive_notes,
        remediation=remediation,
        detection_method=detection_method,
    )


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicates findings that represent the same underlying technical indicator."""
    seen = set()
    deduped = []
    for f in findings:
        key = (f.rule_id or f.title, f.evidence[:60] if f.evidence else "")
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped



class StaticAnalyzer:
    """Performs comprehensive static analysis of an Android APK file."""

    def __init__(self):
        self.intake = UniversalAPKIntake()

    def analyze(
        self, apk_path: str, is_split: bool = False, split_count: int = 0
    ) -> StaticAnalysisResult:
        """Run full static analysis on the specified APK file path.
        
        Args:
            apk_path: Absolute or relative path to the APK file.
            is_split: Whether this APK represents a base package of a split APK installation.
            split_count: Number of split APK slices associated with this installation.
            
        Returns:
            StaticAnalysisResult object containing extracted metadata, indicators, and findings.
        """
        filename = os.path.basename(apk_path)

        # 1. Basic filesystem and zip validation
        if not os.path.exists(apk_path):
            return StaticAnalysisResult(
                apk_filename=filename,
                is_valid_apk=False,
                error_message="APK file does not exist on disk",
                findings=[
                    make_finding(
                        category="STATIC",
                        severity=Severity.LOW,
                        title="File Not Found",
                        description="The specified APK file could not be located.",
                        evidence=apk_path,
                        score=0.0,
                        rule_id="STATIC_FILE_NOT_FOUND",
                        confidence=1.0,
                        evidence_source="filesystem",
                        remediation="Verify the file path and ensure the APK exists on disk.",
                    )
                ],
                score=0.0,
                is_split=is_split,
                split_count=split_count,
            )

        try:
            if os.path.getsize(apk_path) == 0:
                return StaticAnalysisResult(
                    apk_filename=filename,
                    is_valid_apk=False,
                    error_message="Uploaded APK file is empty (0 bytes)",
                    findings=[
                        make_finding(
                            category="STATIC",
                            severity=Severity.LOW,
                            title="Empty Archive",
                            description="The provided APK file is empty (0 bytes).",
                            evidence=filename,
                            score=0.0,
                            rule_id="STATIC_EMPTY_FILE",
                            confidence=1.0,
                            evidence_source="filesystem",
                            remediation="Upload a valid, non-empty APK archive.",
                        )
                    ],
                    score=0.0,
                    is_split=is_split,
                    split_count=split_count,
                )
        except OSError:
            pass

        if not zipfile.is_zipfile(apk_path):
            return StaticAnalysisResult(
                apk_filename=filename,
                is_valid_apk=False,
                error_message="Uploaded file is not a valid ZIP/APK archive",
                findings=[
                    make_finding(
                        category="STATIC",
                        severity=Severity.LOW,
                        title="Invalid Archive Format",
                        description="Uploaded file lacks a valid ZIP header (PK\\x03\\x04).",
                        evidence=filename,
                        score=0.0,
                        rule_id="STATIC_INVALID_ZIP_ARCHIVE",
                        confidence=1.0,
                        evidence_source="zip_header",
                        remediation="Ensure the uploaded file is a valid Android application package (APK).",
                    )
                ],
                score=0.0,
                is_split=is_split,
                split_count=split_count,
            )

        # Inspect zip entries for security & AndroidManifest.xml
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                infolist = zf.infolist()
                namelist = [info.filename for info in infolist]

                # Check maximum entry count (zip bomb / resource exhaustion prevention, 50,000 entries max)
                if len(infolist) > 50000:
                    return StaticAnalysisResult(
                        apk_filename=filename,
                        is_valid_apk=False,
                        error_message="Archive contains excessive entries (maximum 50,000 allowed)",
                        score=0.0,
                        is_split=is_split,
                        split_count=split_count,
                    )

                # Check for path traversal attempts
                if any(
                    name.startswith("/")
                    or "../" in name
                    or "..\\" in name
                    or name == ".."
                    or name.startswith("../")
                    or "/../" in name
                    or name.endswith("/..")
                    for name in namelist
                ):
                    return StaticAnalysisResult(
                        apk_filename=filename,
                        is_valid_apk=False,
                        error_message="Archive contains insecure relative or absolute paths (path traversal)",
                        score=0.0,
                        is_split=is_split,
                        split_count=split_count,
                    )

                # Check for encrypted archive entries
                if any(info.flag_bits & 0x1 for info in infolist):
                    return StaticAnalysisResult(
                        apk_filename=filename,
                        is_valid_apk=False,
                        error_message="Encrypted archive entries detected; encrypted APKs are not supported",
                        score=0.0,
                        is_split=is_split,
                        split_count=split_count,
                    )

                # Check uncompressed expansion limit (zip bomb prevention, 500 MB max)
                total_uncompressed = sum(info.file_size for info in infolist)
                total_compressed = sum(info.compress_size for info in infolist)
                if total_uncompressed > 500 * 1024 * 1024:
                    return StaticAnalysisResult(
                        apk_filename=filename,
                        is_valid_apk=False,
                        error_message=f"Uncompressed APK contents exceed 500 MB limit ({total_uncompressed // (1024*1024)} MB)",
                        score=0.0,
                        is_split=is_split,
                        split_count=split_count,
                    )
                if total_compressed > 10240 and (total_uncompressed / max(1, total_compressed)) > 100:
                    return StaticAnalysisResult(
                        apk_filename=filename,
                        is_valid_apk=False,
                        error_message="Unreasonable compression ratio detected (potential zip bomb)",
                        score=0.0,
                        is_split=is_split,
                        split_count=split_count,
                    )

                if "AndroidManifest.xml" not in namelist:
                    return StaticAnalysisResult(
                        apk_filename=filename,
                        is_valid_apk=False,
                        error_message="Archive does not contain AndroidManifest.xml",
                        findings=[
                            make_finding(
                                category="STATIC",
                                severity=Severity.LOW,
                                title="Missing Android Manifest",
                                description="The archive lacks an AndroidManifest.xml file required for Android packages.",
                                evidence=filename,
                                score=0.0,
                                rule_id="STATIC_MISSING_MANIFEST",
                                confidence=1.0,
                                evidence_source="archive",
                                remediation="Ensure the uploaded file contains an AndroidManifest.xml binary XML file.",
                            )
                        ],
                        score=0.0,
                        is_split=is_split,
                        split_count=split_count,
                    )
        except Exception as e:
            return StaticAnalysisResult(
                apk_filename=filename,
                is_valid_apk=False,
                error_message=f"ZIP parsing error: {str(e)}",
                score=0.0,
                is_split=is_split,
                split_count=split_count,
            )

        # 2. Androguard APK parsing
        try:
            apk = APK(apk_path)
            if not apk.is_valid_APK():
                return StaticAnalysisResult(
                    apk_filename=filename,
                    is_valid_apk=False,
                    error_message="APK structure or binary AndroidManifest is invalid according to parser",
                    score=0.0,
                    is_split=is_split,
                    split_count=split_count,
                )
        except Exception as e:
            return StaticAnalysisResult(
                apk_filename=filename,
                is_valid_apk=False,
                error_message=f"APK parsing exception: {str(e)}",
                score=0.0,
                is_split=is_split,
                split_count=split_count,
            )

        # 3. Extract manifest metadata
        package_name = apk.get_package()
        app_name = apk.get_app_name()
        version_name = apk.get_androidversion_name()
        version_code = apk.get_androidversion_code()
        min_sdk = apk.get_min_sdk_version()
        target_sdk = apk.get_target_sdk_version()

        permissions = list(apk.get_permissions() or [])
        activities = list(apk.get_activities() or [])
        services = list(apk.get_services() or [])
        receivers = list(apk.get_receivers() or [])
        providers = list(apk.get_providers() or [])

        # Extract launchable/main activity
        main_activity = None
        try:
            main_activity = apk.get_main_activity()
        except Exception:
            main_activity = None
        if not main_activity and activities:
            for act in activities:
                if "main" in act.lower():
                    main_activity = act
                    break
            if not main_activity:
                main_activity = activities[0]

        # 4. Manifest component analysis & exported detection
        (
            exported_components,
            boot_receivers,
            accessibility_services,
            foreground_indicators,
            unprotected_providers,
            notification_listeners,
            device_admins,
            unverified_deep_links,
        ) = self._analyze_manifest_components(apk)
        unprotected_exported = [
            c for c in exported_components if c.exported and not c.permission
        ]

        # 5. Extract Certificates and Manifest Configuration
        cert_info = self._analyze_certificates(apk)
        manifest_cfg, is_split_manifest = self._extract_manifest_configuration(
            apk, permissions, len(exported_components), len(unprotected_exported)
        )

        effective_is_split = is_split or is_split_manifest
        effective_split_count = split_count if split_count > 0 else (1 if effective_is_split else 0)
        limitations: List[str] = []
        if effective_is_split:
            limitations.append(
                "Split APK installation: Only the base APK was analyzed. Split APK components "
                "(such as architecture-specific native libraries, localized resources, or dynamic feature splits) "
                "were not included in this analysis."
            )

        # 6. Native libraries (.so) and architecture detection
        native_libraries = [
            f for f in apk.get_files() if f.startswith("lib/") and f.endswith(".so")
        ]
        native_architectures = sorted(
            list({f.split("/")[1] for f in native_libraries if len(f.split("/")) >= 3})
        )

        # 7. DEX bytecode analysis (Multi-DEX, API signatures, and suspicious strings)
        (
            dex_findings_data,
            dex_file_count,
            dex_files_analyzed,
            dex_files_failed,
            is_multidex,
        ) = self._analyze_dex_files(apk)

        if dex_file_count == 0:
            limitations.append(
                "No DEX bytecode files were found in this APK archive (may be an asset pack, "
                "resource configuration split, or native-only application)."
            )
        elif dex_files_failed:
            limitations.append(
                f"Partial DEX analysis: {len(dex_files_failed)} of {dex_file_count} DEX file(s) failed to parse: "
                + ", ".join([f"{k} ({v})" for k, v in list(dex_files_failed.items())[:3]])
            )

        # 8. Aggregate Findings and Defensive Scoring
        findings: List[Finding] = []

        # Certificate security checks
        if cert_info.is_debug_key:
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.MEDIUM,
                    title="Application Signed with Debug Certificate",
                    description=(
                        "The APK is signed with an Android Debug certificate (CN=Android Debug). "
                        "Debug certificates are not meant for production releases and indicate an unverified test build."
                    ),
                    evidence=f"Issuer: {cert_info.issuer or 'Android Debug'}, Subject: {cert_info.subject or 'Android Debug'}",
                    score=10.0,
                    rule_id="STATIC_CERT_DEBUG_KEY",
                    confidence=1.0,
                    evidence_source="certificate",
                    location="META-INF/CERT.RSA",
                    security_impact="Allows attacker interception if private debug key is publicly known.",
                    remediation="Sign the application with a private production keystore prior to distribution.",
                )
            )
        elif not cert_info.is_signed:
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.HIGH,
                    title="Unsigned Application Package",
                    description=(
                        "The APK archive lacks cryptographic signatures. Android OS will refuse installation "
                        "unless signature verification is bypassed."
                    ),
                    evidence="No APK Signature Scheme (v1/v2/v3) detected",
                    score=15.0,
                    rule_id="STATIC_CERT_UNSIGNED",
                    confidence=1.0,
                    evidence_source="certificate",
                    location="META-INF",
                    security_impact="Integrity cannot be verified; package is susceptible to tampering.",
                    remediation="Cryptographically sign the APK using apksigner.",
                )
            )

        # Manifest configuration security checks
        if manifest_cfg.debuggable:
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.HIGH,
                    title="Debuggable Build Enabled (android:debuggable='true')",
                    description=(
                        "The application manifest explicitly enables android:debuggable. "
                        "This allows anyone with adb access to attach a debugger (JDWP), inject code, "
                        "and dump process memory and private app storage."
                    ),
                    evidence="android:debuggable='true' declared in <application>",
                    score=20.0,
                    rule_id="STATIC_MANIFEST_DEBUGGABLE",
                    confidence=1.0,
                    evidence_source="manifest",
                    location="<application android:debuggable='true'>",
                    security_impact="Allows debugger attachment, arbitrary memory reading, and sandbox data extraction.",
                    remediation="Set android:debuggable='false' in release builds.",
                )
            )

        if manifest_cfg.uses_cleartext_traffic is True:
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.MEDIUM,
                    title="Cleartext Traffic Permitted (android:usesCleartextTraffic='true')",
                    description=(
                        "Application explicitly allows unencrypted HTTP network communication, "
                        "exposing data transmissions to local Wi-Fi eavesdropping or network interception."
                    ),
                    evidence="android:usesCleartextTraffic='true' declared in <application>",
                    score=10.0,
                    rule_id="STATIC_MANIFEST_CLEARTEXT_TRAFFIC",
                    confidence=1.0,
                    evidence_source="manifest",
                    location="<application android:usesCleartextTraffic='true'>",
                    security_impact="Vulnerable to man-in-the-middle cleartext eavesdropping.",
                    remediation="Enforce HTTPS via Network Security Config and disable cleartext traffic.",
                )
            )

        # Accessibility Service in manifest
        if accessibility_services:
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.CRITICAL,
                    title="Accessibility Service Component Declared",
                    description=(
                        "Application registers an AccessibilityService component. "
                        "Stalkerware commonly uses accessibility services to log keystrokes, "
                        "intercept arbitrary app screen contents, and bypass user permissions."
                    ),
                    evidence=", ".join(accessibility_services),
                    score=30.0,
                    rule_id="STATIC_MANIFEST_ACCESSIBILITY_SERVICE",
                    confidence=1.0,
                    evidence_source="manifest",
                    location="<service android:permission='android.permission.BIND_ACCESSIBILITY_SERVICE'>",
                    security_impact="Total screen and keystroke visibility without standard permission prompts.",
                    remediation="Audit AccessibilityService requirement; ensure it conforms to Google Play accessibility policies.",
                )
            )

        # Boot completed receiver
        if boot_receivers:
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.MEDIUM,
                    title="Boot-Completed Broadcast Receiver (Persistence)",
                    description=(
                        "Receiver registered for BOOT_COMPLETED or QUICKBOOT_POWERON allows "
                        "the app to silently activate and re-establish surveillance services upon device startup."
                    ),
                    evidence=", ".join(boot_receivers),
                    score=14.0,
                    rule_id="STATIC_MANIFEST_BOOT_RECEIVER",
                    confidence=1.0,
                    evidence_source="manifest",
                    location="<receiver android:name='...'>",
                    security_impact="Automatic background persistence across device restarts.",
                    remediation="Avoid boot-triggered execution unless necessary for user-scheduled alarms or push notifications.",
                )
            )

        # Screen capture indicators
        if dex_findings_data["screen_capture"]:
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.HIGH,
                    title="Screen Capture / MediaProjection API Indicator",
                    description=(
                        "Observed MediaProjection or virtual display API references. Enables recording "
                        "real-time device screen activity and streaming to remote servers."
                    ),
                    evidence=", ".join(dex_findings_data["screen_capture"][:5]),
                    score=20.0,
                    rule_id="STATIC_DEX_SCREEN_CAPTURE",
                    confidence=0.9,
                    evidence_source="dex",
                    location="DEX Bytecode",
                    security_impact="Live screen mirroring or recording without user knowledge.",
                    remediation="Restrict MediaProjection API to legitimate screen casting features with user consent.",
                )
            )

        # Sensor and Hardware API indicators correlated with declared permissions
        has_cam_perm = any("CAMERA" in p for p in permissions)
        has_mic_perm = any("RECORD_AUDIO" in p for p in permissions)
        has_loc_perm = any("LOCATION" in p for p in permissions)
        has_sms_perm = any("SMS" in p or "RECEIVE_MMS" in p for p in permissions)
        has_phone_perm = any(
            "READ_PHONE_STATE" in p or "READ_CALL_LOG" in p or "PROCESS_OUTGOING_CALLS" in p
            for p in permissions
        )
        has_contacts_perm = any("CONTACTS" in p for p in permissions)

        # Microphone / audio recording indicators
        if dex_findings_data["microphone"]:
            if has_mic_perm:
                findings.append(
                    make_finding(
                        category="STATIC",
                        severity=Severity.HIGH,
                        title="Audio Recording API Reference",
                        description=(
                            "Observed AudioRecord or MediaRecorder audio source references in bytecode "
                            "corroborated by declared RECORD_AUDIO permission. Enables room audio capture."
                        ),
                        evidence=", ".join(dex_findings_data["microphone"][:5]),
                        score=16.0,
                        rule_id="STATIC_DEX_MICROPHONE",
                        confidence=0.95,
                        evidence_source="dex",
                        location="DEX Bytecode",
                        security_impact="Room audio recording and environmental eavesdropping.",
                        remediation="Ensure audio capture is accompanied by visible user notification and foreground service.",
                    )
                )
            else:
                findings.append(
                    make_finding(
                        category="STATIC",
                        severity=Severity.INFO,
                        title="Unpermissioned Audio Recording API Reference (DEX Bytecode / Library Stub)",
                        description=(
                            "Bytecode contains AudioRecord/MediaRecorder references, but the application does not request "
                            "the RECORD_AUDIO permission required to access audio hardware at runtime."
                        ),
                        evidence=", ".join(dex_findings_data["microphone"][:5]),
                        score=0.0,
                        rule_id="STATIC_DEX_MICROPHONE_STUB",
                        confidence=0.7,
                        evidence_source="dex",
                        location="DEX Bytecode",
                        false_positive_notes="Framework SDKs or third-party libraries may include uninvoked audio classes.",
                        remediation="Informational: Bytecode contains audio APIs without declared RECORD_AUDIO permission.",
                    )
                )

        # Camera API indicators
        if dex_findings_data["camera"]:
            if has_cam_perm:
                findings.append(
                    make_finding(
                        category="STATIC",
                        severity=Severity.HIGH,
                        title="Camera Hardware API Reference",
                        description=(
                            "Observed Camera or Camera2 framework API calls corroborated by declared CAMERA permission. "
                            "Enables photo capture or video recording."
                        ),
                        evidence=", ".join(dex_findings_data["camera"][:5]),
                        score=15.0,
                        rule_id="STATIC_DEX_CAMERA",
                        confidence=0.95,
                        evidence_source="dex",
                        location="DEX Bytecode",
                        security_impact="Silent image capture or video surveillance.",
                        remediation="Ensure camera hardware access is triggered only by explicit user action.",
                    )
                )
            else:
                findings.append(
                    make_finding(
                        category="STATIC",
                        severity=Severity.INFO,
                        title="Unpermissioned Camera API Reference (DEX Bytecode / Library Stub)",
                        description=(
                            "Bytecode contains Camera framework references, but the application does not request the "
                            "CAMERA permission required to access hardware at runtime."
                        ),
                        evidence=", ".join(dex_findings_data["camera"][:5]),
                        score=0.0,
                        rule_id="STATIC_DEX_CAMERA_STUB",
                        confidence=0.7,
                        evidence_source="dex",
                        location="DEX Bytecode",
                        false_positive_notes="Framework SDKs may contain camera references without runtime permission.",
                        remediation="Informational: Bytecode contains camera APIs without declared CAMERA permission.",
                    )
                )

        # Location API indicators
        if dex_findings_data["location"]:
            if has_loc_perm:
                findings.append(
                    make_finding(
                        category="STATIC",
                        severity=Severity.MEDIUM,
                        title="Geolocation Tracking API Reference",
                        description=(
                            "Observed LocationManager or FusedLocationProviderClient methods corroborated by declared location permissions. "
                            "Enables physical GPS coordinate tracking."
                        ),
                        evidence=", ".join(dex_findings_data["location"][:5]),
                        score=12.0,
                        rule_id="STATIC_DEX_LOCATION",
                        confidence=0.95,
                        evidence_source="dex",
                        location="DEX Bytecode",
                        security_impact="Physical GPS coordinate tracking and movement profiling.",
                        remediation="Minimize background location requests and prefer coarse location when possible.",
                    )
                )
            else:
                findings.append(
                    make_finding(
                        category="STATIC",
                        severity=Severity.INFO,
                        title="Unpermissioned Location API Reference (DEX Bytecode / Library Stub)",
                        description=(
                            "Bytecode contains Location framework references, but the application does not request "
                            "ACCESS_FINE_LOCATION or ACCESS_COARSE_LOCATION permissions."
                        ),
                        evidence=", ".join(dex_findings_data["location"][:5]),
                        score=0.0,
                        rule_id="STATIC_DEX_LOCATION_STUB",
                        confidence=0.7,
                        evidence_source="dex",
                        location="DEX Bytecode",
                        false_positive_notes="Ad networks or mapping SDK stubs may contain location classes without permission.",
                        remediation="Informational: Bytecode contains location APIs without declared location permissions.",
                    )
                )

        # SMS & Call Log API indicators
        if dex_findings_data["sms_call"]:
            if has_sms_perm or has_phone_perm:
                findings.append(
                    make_finding(
                        category="STATIC",
                        severity=Severity.HIGH,
                        title="Telephony & SMS Access API Reference",
                        description=(
                            "Observed SmsManager, TelephonyManager, or CallLog references corroborated by declared telephony permissions. "
                            "Enables SMS interception, 2FA theft, or call history harvesting."
                        ),
                        evidence=", ".join(dex_findings_data["sms_call"][:5]),
                        score=18.0,
                        rule_id="STATIC_DEX_SMS_CALL",
                        confidence=0.95,
                        evidence_source="dex",
                        location="DEX Bytecode",
                        security_impact="SMS interception, 2FA theft, or call log exfiltration.",
                        remediation="Use SMS Retriever API for phone number verification instead of broad telephony permissions.",
                    )
                )
            else:
                findings.append(
                    make_finding(
                        category="STATIC",
                        severity=Severity.INFO,
                        title="Unpermissioned Telephony/SMS API Reference (DEX Bytecode / Library Stub)",
                        description=(
                            "Bytecode contains TelephonyManager or SMS references, but the application does not declare telephony or SMS permissions."
                        ),
                        evidence=", ".join(dex_findings_data["sms_call"][:5]),
                        score=0.0,
                        rule_id="STATIC_DEX_SMS_CALL_STUB",
                        confidence=0.7,
                        evidence_source="dex",
                        location="DEX Bytecode",
                        false_positive_notes="Device utility or network state helpers may reference telephony APIs.",
                        remediation="Informational: Bytecode contains telephony APIs without declared permissions.",
                    )
                )

        # Contacts API indicators
        if dex_findings_data["contacts"]:
            if has_contacts_perm:
                findings.append(
                    make_finding(
                        category="STATIC",
                        severity=Severity.MEDIUM,
                        title="Contacts Contract API Reference",
                        description="Observed ContactsContract references corroborated by declared contacts permissions.",
                        evidence=", ".join(dex_findings_data["contacts"][:5]),
                        score=10.0,
                        rule_id="STATIC_DEX_CONTACTS",
                        confidence=0.95,
                        evidence_source="dex",
                        location="DEX Bytecode",
                        security_impact="Address book harvesting and social graph exfiltration.",
                        remediation="Avoid reading full contact database unless essential for core features.",
                    )
                )
            else:
                findings.append(
                    make_finding(
                        category="STATIC",
                        severity=Severity.INFO,
                        title="Unpermissioned Contacts API Reference (DEX Bytecode / Library Stub)",
                        description="Bytecode contains ContactsContract references, but the application does not request READ_CONTACTS permission.",
                        evidence=", ".join(dex_findings_data["contacts"][:5]),
                        score=0.0,
                        rule_id="STATIC_DEX_CONTACTS_STUB",
                        confidence=0.7,
                        evidence_source="dex",
                        location="DEX Bytecode",
                        false_positive_notes="Social sharing stubs may contain uninvoked contacts code.",
                        remediation="Informational: Bytecode contains contacts APIs without declared READ_CONTACTS permission.",
                    )
                )

        # Suspicious shell / root commands
        if dex_findings_data["suspicious_commands"]:
            evidence_str = "; ".join(
                [f"{c}: {desc}" for c, desc in dex_findings_data["suspicious_commands"][:6]]
            )
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.HIGH,
                    title="Shell Execution or Superuser Strings Detected",
                    description=(
                        "Bytecode contains commands or binary paths associated with root access, shell invocation, "
                        "or privilege escalation (/bin/sh, su, chmod, setprop)."
                    ),
                    evidence=evidence_str,
                    score=20.0,
                    rule_id="STATIC_DEX_ROOT_COMMANDS",
                    confidence=0.9,
                    evidence_source="dex",
                    location="DEX Bytecode",
                    security_impact="Command injection, root elevation, or arbitrary process execution.",
                    remediation="Remove root commands (su, chmod) and shell invocations (/bin/sh).",
                )
            )

        # Dynamic class loading
        if dex_findings_data["dynamic_classloaders"]:
            evidence_str = "; ".join(
                [f"{c}: {desc}" for c, desc in dex_findings_data["dynamic_classloaders"][:4]]
            )
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.LOW,
                    title="Dynamic Class Loading Capability (DexClassLoader)",
                    description=(
                        "Application references dynamic class loader APIs (DexClassLoader / InMemoryDexClassLoader). "
                        "Enables loading compiled bytecode at runtime."
                    ),
                    evidence=evidence_str,
                    score=10.0,
                    rule_id="STATIC_DEX_DYNAMIC_CLASSLOADER",
                    confidence=0.9,
                    evidence_source="dex",
                    location="DEX Bytecode",
                    security_impact="Remote code execution or evasion of static analysis via dynamic payload fetching.",
                    remediation="Bundle all application logic statically and avoid dynamic class loaders.",
                )
            )

        # Exported components without permission protection
        if unprotected_exported:
            sample_names = [f"{c.component_type}:{c.name}" for c in unprotected_exported[:5]]
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.MEDIUM,
                    title=f"Exported Components Without Permission ({len(unprotected_exported)})",
                    description=(
                        "Application exposes components to other apps on the device without requiring "
                        "a protective permission. Can allow unauthorized trigger or component hijacking."
                    ),
                    evidence=", ".join(sample_names),
                    score=8.0,
                    rule_id="STATIC_MANIFEST_UNPROTECTED_EXPORTED",
                    confidence=1.0,
                    evidence_source="manifest",
                    location="AndroidManifest.xml",
                    security_impact="Unauthorized intent invocation or component hijacking by third-party apps.",
                    remediation="Set android:exported='false' on internal components or enforce custom permission.",
                )
            )

        # Native libraries (.so)
        if native_libraries:
            arch_summary = f" (ABIs: {', '.join(native_architectures)})" if native_architectures else ""
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.INFO,
                    title=f"Native Shared Libraries Present ({len(native_libraries)}){arch_summary}",
                    description=(
                        "Application contains compiled native code (.so binaries). Native libraries "
                        "can execute arbitrary machine code and bypass standard Java bytecode inspection."
                    ),
                    evidence=", ".join(native_libraries[:8]),
                    score=0.0,
                    rule_id="STATIC_NATIVE_LIBRARIES",
                    confidence=1.0,
                    evidence_source="native",
                    location="lib/",
                    false_positive_notes="Legitimate apps use native libraries for game engines, audio processing, or cryptography.",
                    remediation="Informational: Native code detected; ensure binaries are compiled with modern security flags.",
                )
            )

        # Overlay capabilities
        overlay_capabilities = []
        if (
            "android.permission.SYSTEM_ALERT_WINDOW" in permissions
            or "SYSTEM_ALERT_WINDOW" in permissions
        ):
            overlay_capabilities.append("android.permission.SYSTEM_ALERT_WINDOW")
        if dex_findings_data["overlay_indicators"]:
            overlay_capabilities.extend(dex_findings_data["overlay_indicators"])

        if overlay_capabilities:
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.HIGH,
                    title="Overlay Window Capability Detected",
                    description=(
                        "Capabilities to display views over other applications. Used in stealth tapjacking "
                        "and phishing attacks."
                    ),
                    evidence=", ".join(overlay_capabilities[:5]),
                    score=15.0,
                    rule_id="STATIC_OVERLAY_WINDOW",
                    confidence=0.95,
                    evidence_source="manifest_dex",
                    location="SYSTEM_ALERT_WINDOW / WindowManager",
                    security_impact="Tapjacking, phishing overlay, or deceptive UI interception.",
                    remediation="Audit overlay usage to ensure it adheres to Android 12+ overlay restrictions.",
                )
            )

        # Check native libraries for dangerous C library imports
        native_dangerous_calls: List[str] = []
        if native_libraries:
            try:
                with zipfile.ZipFile(apk_path, "r") as zf:
                    for nlib in native_libraries[:10]:
                        try:
                            lib_bytes = zf.read(nlib)
                            found_syms = []
                            for sym in [b"system\x00", b"popen\x00", b"execve\x00", b"ptrace\x00"]:
                                if sym in lib_bytes:
                                    found_syms.append(sym[:-1].decode("latin1"))
                            if found_syms:
                                native_dangerous_calls.append(f"{os.path.basename(nlib)}: {', '.join(found_syms)}")
                        except Exception:
                            pass
            except Exception:
                pass

        if native_dangerous_calls:
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.MEDIUM,
                    title="Dangerous Function References in Native Libraries (.so)",
                    description="Native binary imports or references system command execution or debugging bypass APIs (system, popen, execve, ptrace).",
                    evidence=", ".join(native_dangerous_calls[:5]),
                    score=12.0,
                    rule_id="STATIC_NATIVE_DANGEROUS_IMPORTS",
                    confidence=0.90,
                    evidence_source="native_library",
                    remediation="Avoid invoking shell commands and anti-debugging routines in native C/C++ libraries.",
                )
            )

        # Reflection API references
        if dex_findings_data.get("reflection"):
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.LOW,
                    title="Reflection API Invocation Observed",
                    description="Bytecode references dynamic reflection (Method.invoke, Class.forName). While common in frameworks, reflection can be used to obfuscate surveillance calls.",
                    evidence=", ".join(dex_findings_data["reflection"][:5]),
                    score=6.0,
                    rule_id="STATIC_DEX_REFLECTION",
                    confidence=0.85,
                    evidence_source="dex",
                    remediation="Refactor dynamic reflection to direct type-safe API invocations.",
                )
            )

        # Runtime Command Execution
        if dex_findings_data.get("runtime_exec"):
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.HIGH,
                    title="Runtime Command Execution API (Runtime.exec / ProcessBuilder)",
                    description="Application references Runtime.exec or ProcessBuilder to launch external system commands.",
                    evidence=", ".join(dex_findings_data["runtime_exec"][:4]),
                    score=18.0,
                    rule_id="STATIC_DEX_RUNTIME_EXEC",
                    confidence=0.95,
                    evidence_source="dex",
                    remediation="Replace shell process execution with native Android platform APIs.",
                )
            )

        # Device Administration
        if dex_findings_data.get("device_admin"):
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.HIGH,
                    title="Device Administrator Management API Reference",
                    description="Application references DevicePolicyManager or declares a device administrator receiver, enabling device management or wipe permissions.",
                    evidence=", ".join(dex_findings_data["device_admin"][:4]),
                    score=20.0,
                    rule_id="STATIC_DEX_DEVICE_ADMIN",
                    confidence=0.95,
                    evidence_source="dex",
                    remediation="Remove DevicePolicyManager bindings unless providing enterprise MDM functionality.",
                )
            )

        # Insecure Crypto ECB Mode
        if dex_findings_data.get("crypto_ecb"):
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.MEDIUM,
                    title="Insecure Cryptographic Mode (ECB Cipher)",
                    description="Observed AES/ECB or DES/ECB cipher usage. Electronic Codebook mode fails to provide semantic security and leaks plaintext patterns.",
                    evidence=", ".join(dex_findings_data["crypto_ecb"][:4]),
                    score=12.0,
                    rule_id="STATIC_INSECURE_CRYPTO_ECB",
                    confidence=0.90,
                    evidence_source="dex",
                    remediation="Use AES/GCM/NoPadding with authenticated encryption.",
                )
            )

        # Hardcoded Secrets
        if dex_findings_data.get("hardcoded_secrets"):
            ev_str = "; ".join([f"{k}: {v}" for k, v in dex_findings_data["hardcoded_secrets"][:4]])
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.HIGH,
                    title="Hardcoded API Key or Cryptographic Secret Detected",
                    description="Bytecode contains hardcoded cloud API keys or private key structures. Secret values have been redacted.",
                    evidence=ev_str,
                    score=15.0,
                    rule_id="STATIC_SECRET_HARDCODED_KEY",
                    confidence=0.95,
                    evidence_source="dex",
                    remediation="Move API secrets and tokens to secure backend services or Android Keystore.",
                )
            )

        # Manifest backup configuration
        if manifest_cfg.allow_backup:
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.LOW,
                    title="Application Backup Enabled (android:allowBackup='true')",
                    description="Application enables adb backup, allowing extraction of private sandbox storage.",
                    evidence="android:allowBackup='true' declared in manifest",
                    score=2.0,
                    rule_id="STATIC_MANIFEST_BACKUP_ENABLED",
                    confidence=1.0,
                    evidence_source="manifest",
                    remediation="Set android:allowBackup='false' if sensitive user data is stored.",
                )
            )

        # Unprotected Content Providers
        if unprotected_providers:
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.MEDIUM,
                    title="Unprotected Content Provider Component Declared",
                    description=(
                        "Content provider is exported without requiring read or write permissions, "
                        "allowing any installed application on the device to query or manipulate provider data."
                    ),
                    evidence=", ".join(unprotected_providers[:5]),
                    score=10.0,
                    rule_id="STATIC_MANIFEST_UNPROTECTED_PROVIDER",
                    confidence=1.0,
                    evidence_source="manifest",
                    location="<provider android:exported='true'>",
                    security_impact="Unauthorized data extraction or database modification by untrusted apps.",
                    remediation="Set android:exported='false' or declare android:readPermission and android:writePermission.",
                )
            )

        # Unverified Deep Links / App Links
        if unverified_deep_links:
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.LOW,
                    title="Unverified Deep Link / App Link Configuration",
                    description=(
                        "Activity registers HTTP/HTTPS intent filter with VIEW and BROWSABLE without enabling "
                        "android:autoVerify='true'. Malicious apps can intercept links intended for this application."
                    ),
                    evidence=", ".join(unverified_deep_links[:5]),
                    score=5.0,
                    rule_id="STATIC_MANIFEST_UNVERIFIED_DEEP_LINK",
                    confidence=0.9,
                    evidence_source="manifest",
                    location="<intent-filter>",
                    security_impact="URL/intent hijacking and phishing via unverified app link handling.",
                    remediation="Enable android:autoVerify='true' and publish Digital Asset Links (assetlinks.json).",
                )
            )

        # Notification Listener Service
        if notification_listeners:
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.HIGH,
                    title="Notification Listener Service Declared",
                    description=(
                        "Application declares a NotificationListenerService requiring BIND_NOTIFICATION_LISTENER_SERVICE. "
                        "Enables reading, intercepting, and dismissing all notifications across the device, including 2FA codes."
                    ),
                    evidence=", ".join(notification_listeners[:5]),
                    score=20.0,
                    rule_id="STATIC_MANIFEST_NOTIFICATION_LISTENER",
                    confidence=1.0,
                    evidence_source="manifest",
                    location="<service android:permission='android.permission.BIND_NOTIFICATION_LISTENER_SERVICE'>",
                    security_impact="Notification eavesdropping, two-factor authentication bypass, and message interception.",
                    remediation="Audit notification listener requirement; stalkerware frequently uses this to steal chat alerts.",
                )
            )

        # Device Admin Receiver in Manifest
        if device_admins:
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.HIGH,
                    title="Device Administration Receiver Declared",
                    description=(
                        "Application registers a device administration receiver with BIND_DEVICE_ADMIN or DEVICE_ADMIN_ENABLED. "
                        "Enables remote lock, device wipe, or tamper resistance preventing uninstallation."
                    ),
                    evidence=", ".join(device_admins[:5]),
                    score=20.0,
                    rule_id="STATIC_MANIFEST_DEVICE_ADMIN",
                    confidence=1.0,
                    evidence_source="manifest",
                    location="<receiver android:permission='android.permission.BIND_DEVICE_ADMIN'>",
                    security_impact="Privileged administrative control, uninstallation resistance, and remote wipe capabilities.",
                    remediation="Remove DevicePolicyManager bindings unless providing enterprise MDM functionality.",
                )
            )

        # Background Location Permission
        if any("ACCESS_BACKGROUND_LOCATION" in p for p in permissions):
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.MEDIUM,
                    title="Background Location Access Requested",
                    description=(
                        "Application requests android.permission.ACCESS_BACKGROUND_LOCATION, "
                        "enabling persistent GPS tracking even when the app is closed or in the background."
                    ),
                    evidence="android.permission.ACCESS_BACKGROUND_LOCATION",
                    score=12.0,
                    rule_id="STATIC_PERM_BACKGROUND_LOCATION",
                    confidence=1.0,
                    evidence_source="permission",
                    location="<uses-permission android:name='android.permission.ACCESS_BACKGROUND_LOCATION'/>",
                    security_impact="Continuous background physical location tracking and movement surveillance.",
                    remediation="Prefer foreground-only location access and request background location only if strictly necessary.",
                )
            )

        # Insecure WebView Settings
        if dex_findings_data.get("webview_insecure"):
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.MEDIUM,
                    title="Insecure WebView Configuration Detected",
                    description=(
                        "Bytecode references potentially insecure WebView settings (e.g. setJavaScriptEnabled, "
                        "setAllowFileAccessFromFileURLs, setAllowUniversalAccessFromFileURLs, or addJavascriptInterface)."
                    ),
                    evidence=", ".join(dex_findings_data["webview_insecure"][:5]),
                    score=10.0,
                    rule_id="STATIC_DEX_WEBVIEW_INSECURE_SETTINGS",
                    confidence=0.85,
                    evidence_source="dex",
                    location="DEX Bytecode",
                    security_impact="Cross-site scripting (XSS), local file disclosure, or remote code execution via WebView bridges.",
                    remediation="Disable file access from file URLs, avoid addJavascriptInterface without @JavascriptInterface, and restrict JavaScript.",
                )
            )

        # Insecure Ciphers & Weak Hashes
        if dex_findings_data.get("insecure_ciphers"):
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.LOW,
                    title="Weak Cryptographic Cipher or Hash Algorithm",
                    description=(
                        "Bytecode references obsolete or vulnerable cryptographic algorithms (MD5, SHA-1, DES, RC4) "
                        "susceptible to collision or cryptanalytic attacks."
                    ),
                    evidence=", ".join(dex_findings_data["insecure_ciphers"][:5]),
                    score=6.0,
                    rule_id="STATIC_DEX_INSECURE_CIPHER_ALGORITHM",
                    confidence=0.85,
                    evidence_source="dex",
                    location="DEX Bytecode",
                    security_impact="Weak encryption can lead to data decryption by adversaries; weak hashes allow collision attacks.",
                    remediation="Migrate to modern algorithms: SHA-256/SHA-512 for hashing and AES-GCM for encryption.",
                )
            )

        # Clipboard Monitoring
        if dex_findings_data.get("clipboard_monitoring"):
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.MEDIUM,
                    title="Clipboard Access / Monitoring APIs Observed",
                    description=(
                        "Application references ClipboardManager or clip change listeners, "
                        "enabling clipboard monitoring or copying sensitive data such as passwords or tokens."
                    ),
                    evidence=", ".join(dex_findings_data["clipboard_monitoring"][:5]),
                    score=10.0,
                    rule_id="STATIC_DEX_CLIPBOARD_MONITORING",
                    confidence=0.90,
                    evidence_source="dex",
                    location="DEX Bytecode",
                    security_impact="Clipboard snooping, sensitive token theft, and password extraction.",
                    remediation="Avoid monitoring clipboard changes continuously; restrict clipboard access to explicit paste actions.",
                )
            )

        # Native / DEX Anti-Debugging & Hooking Detection
        native_anti_debug: List[str] = []
        if native_libraries:
            try:
                with zipfile.ZipFile(apk_path, "r") as zf:
                    for nlib in native_libraries[:10]:
                        try:
                            lib_bytes = zf.read(nlib)
                            found_syms = []
                            for sym in [b"TracerPid", b"/proc/self/status", b"frida", b"xposed", b"gum-js-loop"]:
                                if sym in lib_bytes:
                                    found_syms.append(sym.decode("latin1"))
                            if found_syms:
                                native_anti_debug.append(f"{os.path.basename(nlib)}: {', '.join(found_syms)}")
                        except Exception:
                            pass
            except Exception:
                pass
        anti_debug_all = native_anti_debug + list(dex_findings_data.get("anti_debug") or [])
        if anti_debug_all:
            findings.append(
                make_finding(
                    category="STATIC",
                    severity=Severity.LOW,
                    title="Anti-Debugging or Hooking Detection Technique",
                    description=(
                        "Application contains indicators of anti-debugging or hooking framework detection "
                        "(ptrace, TracerPid, /proc/self/status, frida, xposed) to hinder dynamic analysis."
                    ),
                    evidence=", ".join(anti_debug_all[:5]),
                    score=6.0,
                    rule_id="STATIC_NATIVE_ANTI_DEBUGGING",
                    confidence=0.85,
                    evidence_source="native_dex",
                    remediation="Document anti-tamper mechanisms and provide debuggable instrumentation builds for security auditing.",
                )
            )

        # Ensure all findings have stable IDs, rule IDs, and deduplication
        enriched_findings: List[Finding] = []
        for f in findings:
            if not f.finding_id:
                f_seed = f"{f.category}:{f.rule_id or f.title}:{f.evidence[:50]}"
                f.finding_id = hashlib.sha256(f_seed.encode("utf-8", errors="ignore")).hexdigest()[:16]
            if not f.rule_id:
                slug = re.sub(r"[^A-Z0-9]+", "_", f.title.upper()).strip("_")
                f.rule_id = f"STATIC_{slug[:30]}"
            enriched_findings.append(f)

        findings = deduplicate_findings(enriched_findings)

        # Run universal intake for hashes, framework, and split detection
        intake_res = self.intake.validate_and_intake(apk_path, is_split=is_split, split_count=split_count)

        # Calculate normalized static score (0 - 100)
        raw_score = sum(f.score for f in findings)
        normalized_static_score = min(100.0, round(raw_score, 1))

        all_suspicious_strings = (
            dex_findings_data["suspicious_urls"]
            + [f"{cmd}: {d}" for cmd, d in dex_findings_data["suspicious_commands"]]
            + [f"{cmd}: {d}" for cmd, d in dex_findings_data["dynamic_classloaders"]]
        )

        return StaticAnalysisResult(
            apk_filename=filename,
            package_name=package_name,
            app_name=app_name,
            version_name=version_name,
            version_code=str(version_code) if version_code is not None else None,
            min_sdk=str(min_sdk) if min_sdk is not None else None,
            target_sdk=str(target_sdk) if target_sdk is not None else None,
            requested_permissions=permissions,
            activities=activities,
            services=services,
            receivers=receivers,
            providers=providers,
            exported_components=exported_components,
            foreground_service_indicators=foreground_indicators,
            boot_completed_receivers=boot_receivers,
            accessibility_services=accessibility_services,
            overlay_capabilities=overlay_capabilities,
            camera_api_indicators=dex_findings_data["camera"],
            microphone_api_indicators=dex_findings_data["microphone"],
            location_api_indicators=dex_findings_data["location"],
            sms_call_api_indicators=dex_findings_data["sms_call"],
            contacts_api_indicators=dex_findings_data["contacts"],
            screen_capture_indicators=dex_findings_data["screen_capture"],
            network_api_indicators=dex_findings_data["network"],
            native_libraries=native_libraries,
            native_architectures=native_architectures,
            dex_file_count=dex_file_count,
            dex_files_analyzed=dex_files_analyzed,
            dex_files_failed=dex_files_failed,
            is_multidex=is_multidex,
            suspicious_strings_urls=all_suspicious_strings,
            findings=findings,
            score=normalized_static_score,
            is_valid_apk=True,
            error_message=None,
            launchable_activity=main_activity,
            certificate_info=cert_info,
            manifest_config=manifest_cfg,
            is_split=effective_is_split,
            split_count=effective_split_count,
            limitations=limitations,
            sha256=intake_res.hashes.sha256 if intake_res.hashes else None,
            sha1=intake_res.hashes.sha1 if intake_res.hashes else None,
            md5=intake_res.hashes.md5 if intake_res.hashes else None,
            file_size_bytes=intake_res.file_size_bytes,
            framework=intake_res.framework.framework.value if intake_res.framework else None,
            framework_details={"confidence": intake_res.framework.confidence, "evidence": intake_res.framework.evidence} if intake_res.framework else None,
            packing_info=intake_res.packing_info.model_dump() if intake_res.packing_info else None,
            max_sdk=str(intake_res.metadata.max_sdk) if (intake_res.metadata and intake_res.metadata.max_sdk is not None) else None,
        )

    def _analyze_certificates(self, apk: Any) -> CertificateInfo:
        """Inspects cryptographic signatures and extracts certificate validity, fingerprints, and signer info."""
        cert_info = CertificateInfo()
        try:
            cert_info.is_signed = bool(apk.is_signed())
            schemes: List[str] = []
            if apk.is_signed_v1():
                schemes.append("v1")
            if apk.is_signed_v2():
                schemes.append("v2")
            if apk.is_signed_v3():
                schemes.append("v3")
            cert_info.signature_schemes = schemes

            if not cert_info.is_signed:
                cert_info.verification_status = "NOT_SIGNED"
                cert_info.verification_details = "No cryptographic signature found on APK archive"
            else:
                cert_info.verification_status = "METADATA_EXTRACTED_UNVERIFIED"
                scheme_str = ", ".join(schemes) if schemes else "unknown"
                cert_info.verification_details = (
                    f"Signed with scheme(s): {scheme_str}. Certificate metadata extracted; "
                    "full root CA trust chain not validated against device trust store."
                )

            certs = apk.get_certificates()
            if certs:
                c = certs[0]
                issuer_str = c.issuer.human_friendly if hasattr(c.issuer, "human_friendly") else str(c.issuer)
                subject_str = c.subject.human_friendly if hasattr(c.subject, "human_friendly") else str(c.subject)
                cert_info.issuer = issuer_str
                cert_info.subject = subject_str
                cert_info.sha256_fingerprint = getattr(c, "sha256_fingerprint", None)
                cert_info.sha1_fingerprint = getattr(c, "sha1_fingerprint", None)
                serial_val = getattr(c, "serial_number", None)
                cert_info.serial_number = str(serial_val) if serial_val is not None else None
                cert_info.valid_from = str(getattr(c, "not_valid_before", "")) or None
                cert_info.valid_until = str(getattr(c, "not_valid_after", "")) or None
                cert_info.signature_algorithm = getattr(c, "signature_algo", None) or getattr(c, "signature_algorithm", None)

                combined = f"{issuer_str} {subject_str}".lower()
                if "android debug" in combined or ("debug" in combined and "android" in combined):
                    cert_info.is_debug_key = True
        except Exception:
            pass
        return cert_info

    def _extract_manifest_configuration(
        self, apk: Any, permissions: List[str], exported_count: int, unprotected_count: int
    ) -> Tuple[ManifestConfiguration, bool]:
        """Extracts application configuration flags, custom permissions, and split APK attributes from manifest XML."""
        manifest_cfg = ManifestConfiguration()
        manifest_cfg.exported_components_count = exported_count
        manifest_cfg.unprotected_exported_count = unprotected_count

        DANGEROUS_PERM_KEYWORDS = [
            "CAMERA", "RECORD_AUDIO", "LOCATION", "CONTACTS", "SMS", "CALL_LOG",
            "PHONE_STATE", "STORAGE", "SENSORS", "CALENDAR"
        ]
        manifest_cfg.dangerous_permissions_count = sum(
            1 for p in permissions if any(k in p for k in DANGEROUS_PERM_KEYWORDS)
        )

        is_split = False

        try:
            manifest_xml = apk.get_android_manifest_xml()
            if manifest_xml is None:
                return manifest_cfg, is_split

            split_attr = manifest_xml.get("split")
            is_feature = manifest_xml.get("isFeatureSplit")
            if split_attr or (is_feature and is_feature.lower() in ("true", "1")):
                is_split = True

            ns = {"android": "http://schemas.android.com/apk/res/android"}
            app_tag = manifest_xml.find("application")
            if app_tag is not None:
                dbg = app_tag.get(f"{{{ns['android']}}}debuggable")
                if dbg is not None:
                    manifest_cfg.debuggable = dbg.lower() in ("true", "1")

                bk = app_tag.get(f"{{{ns['android']}}}allowBackup")
                if bk is not None:
                    manifest_cfg.allow_backup = bk.lower() in ("true", "1")

                clr = app_tag.get(f"{{{ns['android']}}}usesCleartextTraffic")
                if clr is not None:
                    manifest_cfg.uses_cleartext_traffic = clr.lower() in ("true", "1")

                net_sec = app_tag.get(f"{{{ns['android']}}}networkSecurityConfig")
                if net_sec is not None:
                    manifest_cfg.network_security_config = str(net_sec)

                split_req = app_tag.get(f"{{{ns['android']}}}isSplitRequired")
                if split_req is not None and split_req.lower() in ("true", "1"):
                    is_split = True

            custom_perms_elems = manifest_xml.findall("permission")
            custom_perm_names = []
            for cp in custom_perms_elems:
                name_attr = cp.get(f"{{{ns['android']}}}name") or cp.get("name")
                if name_attr:
                    custom_perm_names.append(str(name_attr))
            manifest_cfg.custom_permissions = custom_perm_names
            manifest_cfg.has_custom_permissions = len(custom_perm_names) > 0
        except Exception:
            pass

        return manifest_cfg, is_split

    def _analyze_manifest_components(
        self, apk: Any
    ) -> Tuple[List[ExportedComponent], List[str], List[str], List[str], List[str], List[str], List[str], List[str]]:
        """Inspects Android manifest XML to extract exported flags, boot receivers, accessibility services,
        unprotected providers, notification listeners, device admin receivers, and unverified deep links."""
        exported_components: List[ExportedComponent] = []
        boot_receivers: List[str] = []
        accessibility_services: List[str] = []
        foreground_indicators: List[str] = []
        unprotected_providers: List[str] = []
        notification_listeners: List[str] = []
        device_admins: List[str] = []
        unverified_deep_links: List[str] = []

        manifest_xml = None
        try:
            manifest_xml = apk.get_android_manifest_xml()
        except Exception:
            manifest_xml = None

        if manifest_xml is None:
            # Fallback to androguard component lists
            for r in apk.get_receivers() or []:
                filters = apk.get_intent_filters("receiver", r) or {}
                actions = filters.get("action", [])
                if any("BOOT_COMPLETED" in a or "QUICKBOOT" in a for a in actions):
                    boot_receivers.append(r)
            return (
                exported_components,
                boot_receivers,
                accessibility_services,
                foreground_indicators,
                unprotected_providers,
                notification_listeners,
                device_admins,
                unverified_deep_links,
            )

        ns = {"android": "http://schemas.android.com/apk/res/android"}
        app_tag = manifest_xml.find("application")
        if app_tag is None:
            return (
                exported_components,
                boot_receivers,
                accessibility_services,
                foreground_indicators,
                unprotected_providers,
                notification_listeners,
                device_admins,
                unverified_deep_links,
            )

        component_tags = [
            ("activity", "activities"),
            ("service", "services"),
            ("receiver", "receivers"),
            ("provider", "providers"),
        ]

        for tag_name, _ in component_tags:
            for elem in app_tag.findall(tag_name):
                # Name
                comp_name = elem.get(f"{{{ns['android']}}}name") or elem.get("name") or "unknown"
                # Exported flag
                exported_attr = elem.get(f"{{{ns['android']}}}exported")
                permission_attr = elem.get(f"{{{ns['android']}}}permission")
                
                intent_filters = elem.findall("intent-filter")
                has_intent_filter = len(intent_filters) > 0

                # Pre-Android 12: exported is true by default if intent-filters exist
                is_exported = False
                if exported_attr is not None:
                    is_exported = exported_attr.lower() in ("true", "1")
                elif has_intent_filter:
                    is_exported = True

                exported_components.append(
                    ExportedComponent(
                        component_type=tag_name,
                        name=comp_name,
                        exported=is_exported,
                        permission=permission_attr,
                    )
                )

                # Check Boot Receivers and Device Admin in Receivers
                if tag_name == "receiver":
                    is_dev_admin = False
                    if permission_attr and "BIND_DEVICE_ADMIN" in permission_attr:
                        is_dev_admin = True
                    for ifilter in intent_filters:
                        for action in ifilter.findall("action"):
                            action_name = action.get(f"{{{ns['android']}}}name") or ""
                            if (
                                "BOOT_COMPLETED" in action_name
                                or "QUICKBOOT_POWERON" in action_name
                            ):
                                boot_receivers.append(comp_name)
                            if "DEVICE_ADMIN_ENABLED" in action_name:
                                is_dev_admin = True
                    if is_dev_admin:
                        device_admins.append(comp_name)

                # Check Accessibility Service and Notification Listener in Services
                if tag_name == "service":
                    # Check foregroundServiceType attribute if present
                    fg_type = elem.get(f"{{{ns['android']}}}foregroundServiceType")
                    if fg_type:
                        foreground_indicators.append(f"{comp_name} (type: {fg_type})")

                    is_notif_listener = False
                    if permission_attr and "BIND_NOTIFICATION_LISTENER_SERVICE" in permission_attr:
                        is_notif_listener = True

                    for ifilter in intent_filters:
                        for action in ifilter.findall("action"):
                            action_name = action.get(f"{{{ns['android']}}}name") or ""
                            if "AccessibilityService" in action_name:
                                accessibility_services.append(comp_name)
                            if "NotificationListenerService" in action_name:
                                is_notif_listener = True
                    if permission_attr and "BIND_ACCESSIBILITY_SERVICE" in permission_attr:
                        if comp_name not in accessibility_services:
                            accessibility_services.append(comp_name)
                    if is_notif_listener:
                        notification_listeners.append(comp_name)

                # Check Unprotected Content Providers
                if tag_name == "provider" and is_exported:
                    read_perm = elem.get(f"{{{ns['android']}}}readPermission") or elem.get("readPermission")
                    write_perm = elem.get(f"{{{ns['android']}}}writePermission") or elem.get("writePermission")
                    if not permission_attr and not read_perm and not write_perm:
                        unprotected_providers.append(comp_name)

                # Check Unverified Deep Links in Activities
                if tag_name == "activity":
                    for ifilter in intent_filters:
                        has_view = any("VIEW" in (act.get(f"{{{ns['android']}}}name") or "") for act in ifilter.findall("action"))
                        has_browsable = any("BROWSABLE" in (cat.get(f"{{{ns['android']}}}name") or "") for cat in ifilter.findall("category"))
                        has_http = any((d.get(f"{{{ns['android']}}}scheme") or "").lower() in ("http", "https") for d in ifilter.findall("data"))
                        if has_view and has_browsable and has_http:
                            auto_verify = (ifilter.get(f"{{{ns['android']}}}autoVerify") or ifilter.get("autoVerify") or "").lower()
                            if auto_verify != "true":
                                unverified_deep_links.append(comp_name)

        # Check permissions for FOREGROUND_SERVICE
        for perm in apk.get_permissions() or []:
            if "FOREGROUND_SERVICE" in perm:
                foreground_indicators.append(perm)

        return (
            exported_components,
            list(set(boot_receivers)),
            list(set(accessibility_services)),
            list(set(foreground_indicators)),
            list(set(unprotected_providers)),
            list(set(notification_listeners)),
            list(set(device_admins)),
            list(set(unverified_deep_links)),
        )

    def _analyze_dex_files(
        self, apk: Any
    ) -> Tuple[Dict[str, Any], int, List[str], Dict[str, str], bool]:
        """Scans all DEX bytecode files (multidex) and string tables for surveillance API indicators."""
        results = {
            "camera": set(),
            "microphone": set(),
            "location": set(),
            "sms_call": set(),
            "contacts": set(),
            "screen_capture": set(),
            "network": set(),
            "overlay_indicators": set(),
            "suspicious_commands": [],
            "dynamic_classloaders": [],
            "suspicious_urls": set(),
            "reflection": set(),
            "runtime_exec": set(),
            "device_admin": set(),
            "crypto_ecb": set(),
            "hardcoded_secrets": [],
            "webview_insecure": set(),
            "insecure_ciphers": set(),
            "clipboard_monitoring": set(),
            "anti_debug": set(),
        }
        dex_files_analyzed: List[str] = []
        dex_files_failed: Dict[str, str] = {}

        try:
            dex_names = list(apk.get_dex_names() or [])
        except Exception:
            dex_names = []

        url_regex = re.compile(r"https?://(?:[a-zA-Z0-9_\-\.]+|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:/[^\s\"'<>]*)?")
        ip_url_regex = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?")

        if dex_names:
            dex_file_count = len(dex_names)
            for dex_name in dex_names:
                try:
                    try:
                        info = apk.zip.getinfo(dex_name)
                        if info.file_size > 100 * 1024 * 1024:
                            dex_files_failed[dex_name] = f"DEX exceeds 100MB decompression limit ({info.file_size // (1024 * 1024)}MB)"
                            continue
                    except Exception:
                        pass
                    dex_bytes = apk.get_file(dex_name)
                    if not dex_bytes:
                        dex_files_failed[dex_name] = "Empty DEX file bytes"
                        continue
                    try:
                        dex = DEX(dex_bytes)
                        strings = list(dex.get_strings() or [])
                    except Exception:
                        strings = self._extract_raw_strings(dex_bytes)
                    dex_files_analyzed.append(dex_name)
                    self._scan_dex_strings(strings, results, url_regex, ip_url_regex)
                except Exception as e:
                    dex_files_failed[dex_name] = str(e)
        else:
            try:
                dex_items = list(apk.get_all_dex() or [])
            except Exception:
                dex_items = []
            dex_file_count = len(dex_items)
            for idx, dex_bytes in enumerate(dex_items):
                dex_name = f"classes{idx + 1 if idx > 0 else ''}.dex"
                try:
                    try:
                        dex = DEX(dex_bytes)
                        strings = list(dex.get_strings() or [])
                    except Exception:
                        strings = self._extract_raw_strings(dex_bytes)
                    dex_files_analyzed.append(dex_name)
                    self._scan_dex_strings(strings, results, url_regex, ip_url_regex)
                except Exception as e:
                    dex_files_failed[dex_name] = str(e)

        is_multidex = dex_file_count > 1

        dex_data = {
            "camera": sorted(list(results["camera"])),
            "microphone": sorted(list(results["microphone"])),
            "location": sorted(list(results["location"])),
            "sms_call": sorted(list(results["sms_call"])),
            "contacts": sorted(list(results["contacts"])),
            "screen_capture": sorted(list(results["screen_capture"])),
            "network": sorted(list(results["network"])),
            "overlay_indicators": sorted(list(results["overlay_indicators"])),
            "suspicious_commands": results["suspicious_commands"][:20],
            "dynamic_classloaders": results["dynamic_classloaders"][:20],
            "suspicious_urls": sorted(list(results["suspicious_urls"]))[:30],
            "reflection": sorted(list(results["reflection"]))[:20],
            "runtime_exec": sorted(list(results["runtime_exec"]))[:20],
            "device_admin": sorted(list(results["device_admin"]))[:20],
            "crypto_ecb": sorted(list(results["crypto_ecb"]))[:20],
            "hardcoded_secrets": results["hardcoded_secrets"][:20],
            "webview_insecure": sorted(list(results["webview_insecure"]))[:20],
            "insecure_ciphers": sorted(list(results["insecure_ciphers"]))[:20],
            "clipboard_monitoring": sorted(list(results["clipboard_monitoring"]))[:20],
            "anti_debug": sorted(list(results["anti_debug"]))[:20],
        }
        return dex_data, dex_file_count, dex_files_analyzed, dex_files_failed, is_multidex

    def _scan_dex_strings(
        self,
        strings: List[str],
        results: Dict[str, Any],
        url_regex: re.Pattern,
        ip_url_regex: re.Pattern,
    ) -> None:
        """Fast scanning of DEX string list using precompiled combined regexes."""
        for s in strings:
            if not s or len(s) < 3:
                continue

            # Ignore Android build tool compiler metadata strings (e.g. D8/R8 compilation mode headers)
            if s.startswith("~~D8") or s.startswith("~~R8"):
                continue

            if COMBINED_CAMERA_RE.search(s):
                results["camera"].add(s[:100])

            if COMBINED_MICROPHONE_RE.search(s):
                results["microphone"].add(s[:100])

            if COMBINED_LOCATION_RE.search(s):
                results["location"].add(s[:100])

            if COMBINED_SMS_CALL_RE.search(s):
                results["sms_call"].add(s[:100])

            if COMBINED_CONTACTS_RE.search(s):
                results["contacts"].add(s[:100])

            if COMBINED_SCREEN_CAPTURE_RE.search(s):
                results["screen_capture"].add(s[:100])

            if COMBINED_NETWORK_RE.search(s):
                results["network"].add(s[:100])

            if "TYPE_APPLICATION_OVERLAY" in s or "TYPE_SYSTEM_ALERT" in s:
                results["overlay_indicators"].add(s[:100])

            for rx, desc in COMPILED_SUSPICIOUS_CMD:
                if rx.search(s):
                    results["suspicious_commands"].append((s[:60], desc))
                    break

            for rx, desc in COMPILED_DYNAMIC_LOADER:
                if rx.search(s):
                    results["dynamic_classloaders"].append((s[:60], desc))
                    break

            if COMBINED_REFLECTION_RE.search(s):
                results["reflection"].add(s[:100])

            if COMBINED_RUNTIME_EXEC_RE.search(s):
                results["runtime_exec"].add(s[:100])

            if COMBINED_DEVICE_ADMIN_RE.search(s):
                results["device_admin"].add(s[:100])

            if COMBINED_CRYPTO_ECB_RE.search(s):
                results["crypto_ecb"].add(s[:100])

            if COMBINED_WEBVIEW_RE.search(s):
                results["webview_insecure"].add(s[:100])

            if COMBINED_INSECURE_CIPHER_RE.search(s):
                results["insecure_ciphers"].add(s[:100])

            if COMBINED_CLIPBOARD_RE.search(s):
                results["clipboard_monitoring"].add(s[:100])

            if COMBINED_ANTI_DEBUG_RE.search(s):
                results["anti_debug"].add(s[:100])

            m_aws = AWS_KEY_RE.search(s)
            if m_aws:
                results["hardcoded_secrets"].append(("AWS Access Key ID", redact_secret(m_aws.group(1))))

            m_g = GOOGLE_API_KEY_RE.search(s)
            if m_g:
                results["hardcoded_secrets"].append(("Google API Key", redact_secret(m_g.group(1))))

            if PRIVATE_KEY_RE.search(s):
                results["hardcoded_secrets"].append(("Private Key Block", "-----BEGIN PRIVATE KEY...[REDACTED]"))

            m_gh = GITHUB_PAT_RE.search(s)
            if m_gh:
                results["hardcoded_secrets"].append(("GitHub Personal Access Token", redact_secret(m_gh.group(1))))

            m_slack = SLACK_WEBHOOK_RE.search(s)
            if m_slack:
                results["hardcoded_secrets"].append(("Slack Webhook URL", redact_secret(m_slack.group(1))))

            m_jwt = JWT_RE.search(s)
            if m_jwt:
                results["hardcoded_secrets"].append(("JSON Web Token (JWT)", redact_secret(m_jwt.group(1))))

            if "http://" in s or "https://" in s:
                matches = url_regex.findall(s)
                for url in matches:
                    if any(b.match(url) for b in BENIGN_URL_PATTERNS):
                        continue
                    if ip_url_regex.match(url):
                        results["suspicious_urls"].add(f"[Raw IP Endpoint] {url}")
                    elif len(url) < 150:
                        results["suspicious_urls"].add(url)

    def _extract_raw_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        """Extracts ASCII strings from arbitrary byte data as a resilient fallback."""
        pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
        found = []
        for m in pattern.finditer(data):
            try:
                s = m.group(0).decode("utf-8", errors="ignore").strip()
                if len(s) >= min_len:
                    found.append(s)
            except Exception:
                pass
        return found
