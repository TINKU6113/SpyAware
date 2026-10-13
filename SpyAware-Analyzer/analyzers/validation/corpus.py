"""Controlled Deterministic Validation Corpus for SpyAware-Analyzer.

Milestone M4: Detection Validation and Analysis Accuracy.
Defines 12 deterministic test cases covering:
1. Benign manifest permissions.
2. Exported components with and without appropriate protection.
3. Backup-enabled applications.
4. Debug signing indicators.
5. Bytecode reflection.
6. Runtime code loading (DexClassLoader).
7. Shell command invocation (su, Runtime.exec).
8. Weak cryptographic configurations (ECB cipher mode).
9. Native library indicators (.so files across ABIs).
10. Embedded synthetic test credentials (with redaction verification).
11. Malformed APK archives (corrupted ZIP header/payload).
12. Unsupported or incomplete split APKs.

Uses synthetic secrets and controlled fixtures only.
Never labels a sample malicious solely because it requests a permission,
uses reflection, is obfuscated, or contains a native library.
"""

import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, List, Optional

from analyzers.validation.models import (
    ExpectedRuleMatch,
    ValidationCategory,
    ValidationTestCase,
)
from samples.builder import (
    build_and_sign_apk,
    ensure_debug_keystore,
    find_android_build_tools,
    sign_apk,
)

CORPUS_DIR = Path(__file__).resolve().parent.parent.parent / "samples" / "validation_corpus"


def ensure_test_release_keystore(keystore_path: Optional[Path] = None) -> Path:
    """Ensures a synthetic non-debug release keystore exists for non-debug test fixtures.
    
    Generates standard Android keypair with CN='SpyAware Security' to avoid triggering
    the debug certificate detection rule (STATIC_CERT_DEBUG_KEY).
    """
    ks = keystore_path or (CORPUS_DIR / "test_release.keystore")
    if ks.exists():
        return ks

    ks.parent.mkdir(parents=True, exist_ok=True)
    keytool = shutil.which("keytool") or "/usr/bin/keytool"
    if not (os.path.exists(keytool) and os.access(keytool, os.X_OK)):
        raise RuntimeError(f"keytool not found; cannot generate release keystore at {ks}")

    cmd = [
        keytool,
        "-genkeypair",
        "-v",
        "-keystore",
        str(ks),
        "-alias",
        "androiddebugkey",
        "-keyalg",
        "RSA",
        "-keysize",
        "2048",
        "-validity",
        "10000",
        "-dname",
        "CN=SpyAware Security, O=Synthetic Corp, C=US",
        "-storepass",
        "android",
        "-keypass",
        "android",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Failed to create release keystore: {res.stderr}")
    return ks


# Registry of the 12 validation corpus cases
VALIDATION_CORPUS_CASES: List[ValidationTestCase] = [
    ValidationTestCase(
        case_id="TC_01_BENIGN_PERMISSIONS",
        name="Benign Manifest Permissions Only",
        category=ValidationCategory.BENIGN_PERMISSIONS,
        description="App requests only benign manifest permissions (INTERNET, VIBRATE, ACCESS_NETWORK_STATE) without surveillance combinations.",
        fixture_filename="tc01_benign_permissions.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="RULE_PERM_INTERNET",
                min_severity="LOW",
                max_severity="LOW",
                evidence_source="AndroidManifest.xml",
                description="Network & Internet Access standard permission indicator",
            )
        ],
        prohibited_rules=[
            "COMBINATION_LOCATION_NETWORK_EXFILTRATION",
            "COMBINATION_AUDIO_SURVEILLANCE",
            "STATIC_DEX_CAMERA",
            "STATIC_DEX_MICROPHONE",
            "STATIC_DEX_ROOT_COMMANDS",
            "STATIC_CERT_DEBUG_KEY",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="manifest",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Evaluated statically from manifest declaration; runtime grant flow unexercised.",
    ),
    ValidationTestCase(
        case_id="TC_02_EXPORTED_COMPONENTS",
        name="Exported Components With vs Without Permission Protection",
        category=ValidationCategory.EXPORTED_COMPONENTS,
        description="App declares an unprotected exported service (android:exported=true without permission) alongside a protected activity.",
        fixture_filename="tc02_exported_components.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_MANIFEST_UNPROTECTED_EXPORTED",
                min_severity="MEDIUM",
                max_severity="MEDIUM",
                evidence_source="manifest",
                description="Exported component without protective permission requirement",
            )
        ],
        prohibited_rules=[
            "STATIC_CERT_DEBUG_KEY",
            "STATIC_DEX_CAMERA",
            "STATIC_DEX_ROOT_COMMANDS",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="manifest",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Manifest inspection checks component exposure; intent fuzzing requires runtime testing.",
    ),
    ValidationTestCase(
        case_id="TC_03_BACKUP_ENABLED",
        name="Backup Enabled Application (android:allowBackup=true)",
        category=ValidationCategory.BACKUP_ENABLED,
        description="Application enables ADB backup (android:allowBackup=true), creating private sandbox data extraction risk.",
        fixture_filename="tc03_backup_enabled.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_MANIFEST_BACKUP_ENABLED",
                min_severity="LOW",
                max_severity="LOW",
                evidence_source="manifest",
                description="Application backup enabled in manifest",
            )
        ],
        prohibited_rules=[
            "STATIC_DEX_ROOT_COMMANDS",
            "STATIC_CERT_DEBUG_KEY",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="manifest",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Configuration audit only; adb backup extraction not executed on device.",
    ),
    ValidationTestCase(
        case_id="TC_04_DEBUG_SIGNING",
        name="Debug Keystore Signing Indicator",
        category=ValidationCategory.DEBUG_SIGNING,
        description="Application is signed using standard Android debug certificate (CN=Android Debug, O=Android, C=US).",
        fixture_filename="tc04_debug_signing.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_CERT_DEBUG_KEY",
                min_severity="LOW",
                max_severity="LOW",
                evidence_source="certificate",
                description="Debug certificate signature detected",
            )
        ],
        prohibited_rules=[
            "STATIC_DEX_ROOT_COMMANDS",
            "STATIC_DEX_CAMERA",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="certificate",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Certificate metadata extracted; full device trust store chain not validated.",
    ),
    ValidationTestCase(
        case_id="TC_05_REFLECTION",
        name="Dynamic Bytecode Reflection (Class.forName / Method.invoke)",
        category=ValidationCategory.REFLECTION,
        description="Bytecode contains Java reflection APIs (Method.invoke, Class.forName). Reflection alone is common in frameworks and does not prove malice.",
        fixture_filename="tc05_reflection.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_DEX_REFLECTION",
                min_severity="LOW",
                max_severity="LOW",
                evidence_source="dex",
                description="Reflection API invocation detected in bytecode",
            )
        ],
        prohibited_rules=[
            "STATIC_DEX_ROOT_COMMANDS",
            "STATIC_CERT_DEBUG_KEY",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="dex",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Static string/call analysis; targets of reflection are not resolved without deobfuscation or runtime tracing.",
    ),
    ValidationTestCase(
        case_id="TC_06_RUNTIME_CODE_LOADING",
        name="Runtime Dynamic Code Loading (DexClassLoader)",
        category=ValidationCategory.RUNTIME_CODE_LOADING,
        description="Bytecode references DexClassLoader or InMemoryDexClassLoader for dynamic payload staging.",
        fixture_filename="tc06_runtime_code_loading.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_DEX_DYNAMIC_CLASSLOADER",
                min_severity="HIGH",
                max_severity="HIGH",
                evidence_source="dex",
                description="Dynamic class loader reference detected",
            )
        ],
        prohibited_rules=[
            "STATIC_CERT_DEBUG_KEY",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="dex",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Static signature scan; payload downloaded or unpacked at runtime is unobserved without dynamic execution.",
    ),
    ValidationTestCase(
        case_id="TC_07_SHELL_COMMANDS",
        name="Root and Shell Command Invocation (/system/bin/su, Runtime.exec)",
        category=ValidationCategory.SHELL_COMMANDS,
        description="Application references root binaries (/system/bin/su, su) and Runtime.exec/ProcessBuilder command execution.",
        fixture_filename="tc07_shell_commands.apk",
        expected_ground_truth="SUSPICIOUS",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_DEX_ROOT_COMMANDS",
                min_severity="HIGH",
                max_severity="HIGH",
                evidence_source="dex",
                description="Root binary invocation references",
            ),
            ExpectedRuleMatch(
                rule_id="STATIC_DEX_RUNTIME_EXEC",
                min_severity="HIGH",
                max_severity="HIGH",
                evidence_source="dex",
                description="Runtime.exec or ProcessBuilder execution",
            ),
        ],
        prohibited_rules=[
            "STATIC_CERT_DEBUG_KEY",
        ],
        expected_severity_range=("HIGH", "CRITICAL"),
        expected_evidence_source="dex",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Commands detected from static string tables; exit codes and actual execution unverified.",
    ),
    ValidationTestCase(
        case_id="TC_08_WEAK_CRYPTO",
        name="Insecure Cryptographic Mode (ECB Cipher)",
        category=ValidationCategory.WEAK_CRYPTO,
        description="Bytecode configures AES/ECB or DES/ECB ciphers lacking semantic security.",
        fixture_filename="tc08_weak_crypto.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_INSECURE_CRYPTO_ECB",
                min_severity="MEDIUM",
                max_severity="MEDIUM",
                evidence_source="dex",
                description="Insecure ECB cipher mode detection",
            )
        ],
        prohibited_rules=[
            "STATIC_CERT_DEBUG_KEY",
            "STATIC_DEX_ROOT_COMMANDS",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="dex",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Static cipher algorithm string matching; keystore operations not dynamically captured.",
    ),
    ValidationTestCase(
        case_id="TC_09_NATIVE_LIBRARIES",
        name="Native Shared Library Indicators (.so Binaries)",
        category=ValidationCategory.NATIVE_LIBRARIES,
        description="Package bundles compiled .so native libraries across ABIs. Native libraries alone produce 0.0 INFO findings.",
        fixture_filename="tc09_native_libraries.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_NATIVE_LIBRARIES",
                min_severity="INFO",
                max_severity="INFO",
                evidence_source="native",
                description="Native shared libraries bundled in APK",
            )
        ],
        prohibited_rules=[
            "STATIC_CERT_DEBUG_KEY",
            "STATIC_DEX_ROOT_COMMANDS",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="native",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Static ELF header inspection only; native disassembly and symbolic execution omitted.",
    ),
    ValidationTestCase(
        case_id="TC_10_EMBEDDED_CREDENTIALS",
        name="Hardcoded Synthetic Cloud API Credentials",
        category=ValidationCategory.EMBEDDED_CREDENTIALS,
        description="Bytecode contains hardcoded synthetic cloud API keys (AWS, Google, GitHub); pipeline must detect and redact them.",
        fixture_filename="tc10_embedded_credentials.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_SECRET_HARDCODED_KEY",
                min_severity="HIGH",
                max_severity="HIGH",
                evidence_source="dex",
                description="Hardcoded API keys detected in bytecode",
            )
        ],
        prohibited_rules=[
            "STATIC_CERT_DEBUG_KEY",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="dex",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Pattern matching against high-entropy regexes; secret validity not verified online.",
    ),
    ValidationTestCase(
        case_id="TC_11_MALFORMED_ARCHIVE",
        name="Malformed and Corrupt APK ZIP Archive",
        category=ValidationCategory.MALFORMED_ARCHIVE,
        description="Archive contains truncated ZIP headers and invalid records; pipeline must handle safely without crashing.",
        fixture_filename="tc11_malformed_corrupt.apk",
        expected_ground_truth="MALFORMED",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_INVALID_ZIP_ARCHIVE",
                min_severity="HIGH",
                max_severity="HIGH",
                evidence_source="archive",
                description="Invalid ZIP archive structure",
            )
        ],
        prohibited_rules=[],
        expected_severity_range=("HIGH", "CRITICAL"),
        expected_evidence_source="archive",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="File parsing aborted gracefully due to corrupt archive structure.",
        is_malformed_case=True,
    ),
    ValidationTestCase(
        case_id="TC_12_SPLIT_APKS",
        name="Incomplete Split APK Installation",
        category=ValidationCategory.SPLIT_APKS,
        description="Base APK analyzed from a split APK bundle without required feature/architecture splits present.",
        fixture_filename="tc12_split_base.apk",
        expected_ground_truth="INCOMPLETE",
        expected_rules=[],
        prohibited_rules=[
            "STATIC_CERT_DEBUG_KEY",
            "STATIC_DEX_ROOT_COMMANDS",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="manifest",
        dynamic_required=False,
        expected_limitations=[
            "Analyzed base APK from a split APK installation (3 splits detected)."
        ],
        limitations_notes="Split APK components (feature splits, density resources, native ABIs) unverified.",
        is_split_case=True,
        split_count=3,
    ),
    ValidationTestCase(
        case_id="TC_13_LEGIT_CAMERA_MIC",
        name="Legitimate Single-Purpose Camera Utility",
        category=ValidationCategory.LEGIT_CAMERA_MIC,
        description="Single-purpose offline camera utility declaring CAMERA permission without audio, network, or background persistence.",
        fixture_filename="tc13_legit_camera.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_DEX_CAMERA",
                min_severity="LOW",
                max_severity="HIGH",
                evidence_source="dex",
                description="Camera API reference in DEX bytecode",
            ),
        ],
        prohibited_rules=[
            "COMBINATION_AUDIO_SURVEILLANCE",
            "COMBINATION_LOCATION_NETWORK_EXFILTRATION",
            "STATIC_DEX_MICROPHONE",
            "STATIC_DEX_ROOT_COMMANDS",
            "STATIC_CERT_DEBUG_KEY",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="dex",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Hardware camera access without network exfiltration or audio pairing remains bounded at LOW risk.",
    ),
    ValidationTestCase(
        case_id="TC_14_LEGIT_LOCATION",
        name="Legitimate Location Navigation / Weather App",
        category=ValidationCategory.LEGIT_LOCATION,
        description="Local utility declaring ACCESS_FINE_LOCATION without background location, telephony, SMS, or boot triggers.",
        fixture_filename="tc14_legit_location.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_DEX_LOCATION",
                min_severity="LOW",
                max_severity="HIGH",
                evidence_source="dex",
                description="Location API reference in DEX bytecode",
            ),
        ],
        prohibited_rules=[
            "COMBINATION_LOCATION_NETWORK_EXFILTRATION",
            "STATIC_DEX_ROOT_COMMANDS",
            "STATIC_CERT_DEBUG_KEY",
        ],
        expected_severity_range=("LOW", "MEDIUM"),
        expected_evidence_source="dex",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Standard foreground location access without stealth exfiltration.",
    ),
    ValidationTestCase(
        case_id="TC_15_LEGIT_NETWORK",
        name="Legitimate Secure Network API Client",
        category=ValidationCategory.LEGIT_NETWORK,
        description="Application declaring INTERNET access with cleartext traffic disabled and standard public endpoints.",
        fixture_filename="tc15_legit_network.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="RULE_PERM_INTERNET",
                min_severity="LOW",
                max_severity="LOW",
                evidence_source="AndroidManifest.xml",
                description="Standard Internet permission",
            ),
        ],
        prohibited_rules=[
            "STATIC_MANIFEST_CLEARTEXT_TRAFFIC",
            "STATIC_DEX_ROOT_COMMANDS",
            "STATIC_CERT_DEBUG_KEY",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="manifest",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Clean HTTPS network traffic without cleartext or raw IP communication.",
    ),
    ValidationTestCase(
        case_id="TC_16_LEGIT_REFLECTION",
        name="Legitimate Framework & JSON Reflection (Gson/ORM)",
        category=ValidationCategory.LEGIT_REFLECTION,
        description="Application utilizing dynamic reflection for JSON deserialization and dependency injection.",
        fixture_filename="tc16_legit_reflection.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_DEX_REFLECTION",
                min_severity="LOW",
                max_severity="LOW",
                evidence_source="dex",
                description="Reflection API invocation observed",
            ),
        ],
        prohibited_rules=[
            "STATIC_DEX_ROOT_COMMANDS",
            "STATIC_DEX_RUNTIME_EXEC",
            "STATIC_CERT_DEBUG_KEY",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="dex",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Reflection for framework deserialization remains score 6.0 LOW severity.",
    ),
    ValidationTestCase(
        case_id="TC_17_LEGIT_DYNAMIC_CODE",
        name="Legitimate Dynamic Module Plugin Loader",
        category=ValidationCategory.LEGIT_DYNAMIC_CODE,
        description="Application referencing DexClassLoader for modular feature loading without surveillance APIs.",
        fixture_filename="tc17_legit_dynamic_code.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_DEX_DYNAMIC_CLASSLOADER",
                min_severity="HIGH",
                max_severity="HIGH",
                evidence_source="dex",
                description="Dynamic class loader reference detected",
            ),
        ],
        prohibited_rules=[
            "STATIC_DEX_ROOT_COMMANDS",
            "STATIC_DEX_CAMERA",
            "STATIC_CERT_DEBUG_KEY",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="dex",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Isolated dynamic classloader without multi-vector surveillance synergy.",
    ),
    ValidationTestCase(
        case_id="TC_18_LEGIT_NATIVE_LIB",
        name="Legitimate Game Engine Native Libraries",
        category=ValidationCategory.LEGIT_NATIVE_LIB,
        description="Application bundling compiled native shared libraries across arm64-v8a and x86_64 architectures.",
        fixture_filename="tc18_legit_native_lib.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_NATIVE_LIBRARIES",
                min_severity="INFO",
                max_severity="INFO",
                evidence_source="native",
                description="Native shared libraries bundled in APK",
            ),
        ],
        prohibited_rules=[
            "STATIC_NATIVE_DANGEROUS_IMPORTS",
            "STATIC_DEX_ROOT_COMMANDS",
            "STATIC_CERT_DEBUG_KEY",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="native",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Pure native rendering/audio libraries produce 0.0 INFO findings.",
    ),
    ValidationTestCase(
        case_id="TC_19_LEGIT_EXPORTED",
        name="Legitimate Exported Share Intent Target",
        category=ValidationCategory.LEGIT_EXPORTED,
        description="Application declaring an exported activity with an explicit android.intent.action.SEND intent filter for user sharing.",
        fixture_filename="tc19_legit_exported.apk",
        expected_ground_truth="BENIGN",
        expected_rules=[
            ExpectedRuleMatch(
                rule_id="STATIC_MANIFEST_UNPROTECTED_EXPORTED",
                min_severity="MEDIUM",
                max_severity="MEDIUM",
                evidence_source="manifest",
                description="Exported component without custom permission requirement",
            ),
        ],
        prohibited_rules=[
            "STATIC_DEX_ROOT_COMMANDS",
            "STATIC_DEX_CAMERA",
            "STATIC_CERT_DEBUG_KEY",
        ],
        expected_severity_range=("LOW", "LOW"),
        expected_evidence_source="manifest",
        dynamic_required=False,
        expected_limitations=[],
        limitations_notes="Exported share receiver has public intent filter for external app content sharing.",
    ),
]


def _build_tc01_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC01: Benign Manifest Permissions Only."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc01_benign_permissions"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.VIBRATE" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <application android:label="TC01 Benign App" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="false" />
    </application>
</manifest>"""
    dex_strings = ["Lcom/spyaware/test/tc01/MainActivity;", "onCreate", "finish"]
    build_and_sign_apk(output_path, "com.spyaware.test.tc01_benign_permissions", manifest, dex_strings)
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc02_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC02: Exported Components With vs Without Permission Protection."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc02_exported"
    android:versionCode="1"
    android:versionName="1.0">
    <permission android:name="com.spyaware.test.CUSTOM_PERM" android:protectionLevel="signature" />
    <application android:label="TC02 Exported App" android:allowBackup="false">
        <activity android:name=".ProtectedActivity"
            android:exported="true"
            android:permission="com.spyaware.test.CUSTOM_PERM" />
        <service android:name=".UnprotectedService"
            android:exported="true" />
        <receiver android:name=".PrivateReceiver"
            android:exported="false" />
    </application>
</manifest>"""
    dex_strings = ["ProtectedActivity", "UnprotectedService", "PrivateReceiver"]
    build_and_sign_apk(output_path, "com.spyaware.test.tc02_exported", manifest, dex_strings)
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc03_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC03: Backup Enabled Application."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc03_backup"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="TC03 Backup App" android:allowBackup="true">
        <activity android:name=".MainActivity" android:exported="false" />
    </application>
</manifest>"""
    dex_strings = ["BackupActivity"]
    build_and_sign_apk(output_path, "com.spyaware.test.tc03_backup", manifest, dex_strings)
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc04_apk(output_path: Path) -> Path:
    """Builds TC04: Debug Keystore Signing."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc04_debug"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="TC04 Debug App" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="false" />
    </application>
</manifest>"""
    dex_strings = ["DebugActivity"]
    # Signed with default debug keystore
    build_and_sign_apk(output_path, "com.spyaware.test.tc04_debug", manifest, dex_strings)
    return output_path


def _build_tc05_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC05: Bytecode Reflection."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc05_reflection"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="TC05 Reflection App" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="false" />
    </application>
</manifest>"""
    dex_strings = [
        "Ljava/lang/reflect/Method;->invoke",
        "Class.forName",
        "Ljava/lang/Class;->forName",
        "Method.invoke",
    ]
    build_and_sign_apk(output_path, "com.spyaware.test.tc05_reflection", manifest, dex_strings)
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc06_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC06: Runtime Dynamic Code Loading."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc06_dynamic_loader"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="TC06 Dynamic Loader App" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="false" />
    </application>
</manifest>"""
    dex_strings = [
        "Ldalvik/system/DexClassLoader;",
        "dalvik.system.DexClassLoader",
        "InMemoryDexClassLoader",
    ]
    build_and_sign_apk(output_path, "com.spyaware.test.tc06_dynamic_loader", manifest, dex_strings)
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc07_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC07: Shell Command Invocation."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc07_shell"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="TC07 Shell App" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="false" />
    </application>
</manifest>"""
    dex_strings = [
        "/system/bin/su",
        "su",
        "Ljava/lang/Runtime;->exec",
        "ProcessBuilder",
        "Runtime.getRuntime().exec",
    ]
    build_and_sign_apk(output_path, "com.spyaware.test.tc07_shell", manifest, dex_strings)
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc08_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC08: Insecure Cryptographic Mode (ECB)."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc08_weak_crypto"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="TC08 Weak Crypto App" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="false" />
    </application>
</manifest>"""
    dex_strings = [
        "AES/ECB",
        "DES/ECB/PKCS5Padding",
        "DESede/ECB",
    ]
    build_and_sign_apk(output_path, "com.spyaware.test.tc08_weak_crypto", manifest, dex_strings)
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc09_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC09: Native Shared Libraries."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc09_native"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="TC09 Native App" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="false" />
    </application>
</manifest>"""
    elf_header = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 56)
    native_libs = {
        "lib/arm64-v8a/libnative_test.so": elf_header,
        "lib/x86_64/libnative_test.so": elf_header,
    }
    dex_strings = ["NativeActivity"]
    build_and_sign_apk(
        output_path,
        "com.spyaware.test.tc09_native",
        manifest,
        dex_strings,
        native_libs=native_libs,
    )
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc10_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC10: Hardcoded Synthetic Cloud API Credentials."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc10_secrets"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="TC10 Secrets App" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="false" />
    </application>
</manifest>"""
    dex_strings = [
        "AKIAIOSFODNN7EXAMPLE",  # Synthetic AWS ID
        "AIzaSyD-TEST-FAKE-KEY-FOR-VALIDATION12",  # Synthetic Google key
        "ghp_FakeGitHubTestToken1234567890123456",  # Synthetic GitHub token
    ]
    build_and_sign_apk(output_path, "com.spyaware.test.tc10_secrets", manifest, dex_strings)
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc11_apk(output_path: Path) -> Path:
    """Builds TC11: Malformed and Corrupted Archive."""
    # Truncated corrupt zip header
    output_path.parent.mkdir(parents=True, exist_ok=True)
    corrupted_data = b"PK\x03\x04\x00\x00\x00\x00CORRUPT_PAYLOAD_NOT_A_VALID_ZIP_HEADER"
    output_path.write_bytes(corrupted_data)
    return output_path


def _build_tc12_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC12: Incomplete Split Base APK."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc12_split_base"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="TC12 Split Base" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="false" />
    </application>
</manifest>"""
    dex_strings = ["SplitBaseActivity"]
    build_and_sign_apk(output_path, "com.spyaware.test.tc12_split_base", manifest, dex_strings)
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc13_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC13: Legitimate Single-Purpose Camera Utility (no network, no mic)."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc13_camera"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-permission android:name="android.permission.CAMERA" />
    <application android:label="TC13 Camera App" android:allowBackup="false">
        <activity android:name=".CameraActivity" android:exported="false" />
    </application>
</manifest>"""
    dex_strings = [
        "Landroid/hardware/Camera;",
        "openCamera",
        "takePicture",
    ]
    build_and_sign_apk(output_path, "com.spyaware.test.tc13_camera", manifest, dex_strings)
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc14_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC14: Legitimate Location Navigation / Weather (no network)."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc14_location"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <application android:label="TC14 Location" android:allowBackup="false">
        <activity android:name=".LocationActivity" android:exported="false" />
    </application>
</manifest>"""
    dex_strings = [
        "Landroid/location/LocationManager;",
        "requestLocationUpdates",
        "getLastKnownLocation",
    ]
    build_and_sign_apk(output_path, "com.spyaware.test.tc14_location", manifest, dex_strings)
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc15_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC15: Legitimate Secure Network Client (no cleartext, benign endpoints)."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc15_network"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <application android:label="TC15 Network" android:allowBackup="false" android:usesCleartextTraffic="false">
        <activity android:name=".NetworkActivity" android:exported="false" />
    </application>
</manifest>"""
    dex_strings = [
        "https://api.github.com/v1",
        "https://example.com/api",
    ]
    build_and_sign_apk(output_path, "com.spyaware.test.tc15_network", manifest, dex_strings)
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc16_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC16: Legitimate Framework & JSON Reflection (Gson/ORM)."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc16_reflection"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="TC16 Reflection" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="false" />
    </application>
</manifest>"""
    dex_strings = [
        "com.google.gson.Gson",
        "com.google.gson.reflect.TypeToken",
        "Class.forName",
        "getDeclaredMethod",
        "Ljava/lang/reflect/Method;->invoke",
    ]
    build_and_sign_apk(output_path, "com.spyaware.test.tc16_reflection", manifest, dex_strings)
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc17_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC17: Legitimate Dynamic Module Plugin Loader."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc17_plugin_loader"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="TC17 Dynamic Loader" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="false" />
    </application>
</manifest>"""
    dex_strings = [
        "Ldalvik/system/DexClassLoader;",
        "dalvik.system.DexClassLoader",
        "PluginLoader",
    ]
    build_and_sign_apk(output_path, "com.spyaware.test.tc17_plugin_loader", manifest, dex_strings)
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc18_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC18: Legitimate Game Engine Native Libraries."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc18_native_game"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="TC18 Native Game" android:allowBackup="false">
        <activity android:name=".GameActivity" android:exported="false" />
    </application>
</manifest>"""
    elf_header = b"\x7fELF\x02\x01\x01\x00" + (b"\x00" * 56)
    native_libs = {
        "lib/arm64-v8a/libgame_engine.so": elf_header,
        "lib/x86_64/libgame_engine.so": elf_header,
    }
    dex_strings = ["GameActivity"]
    build_and_sign_apk(
        output_path,
        "com.spyaware.test.tc18_native_game",
        manifest,
        dex_strings,
        native_libs=native_libs,
    )
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def _build_tc19_apk(output_path: Path, release_ks: Path) -> Path:
    """Builds TC19: Legitimate Exported Share Intent Target."""
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.spyaware.test.tc19_exported_share"
    android:versionCode="1"
    android:versionName="1.0">
    <application android:label="TC19 Exported Share" android:allowBackup="false">
        <activity android:name=".ShareActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.SEND" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
    </application>
</manifest>"""
    dex_strings = ["ShareActivity"]
    build_and_sign_apk(output_path, "com.spyaware.test.tc19_exported_share", manifest, dex_strings)
    sign_apk(output_path, keystore_path=release_ks)
    return output_path


def build_validation_corpus(
    target_dir: Optional[Path] = None, force_rebuild: bool = False
) -> Dict[str, Path]:
    """Generates all deterministic validation APK fixtures in the corpus directory.
    
    Returns a dictionary mapping case_id to the created APK Path.
    """
    corpus_path = target_dir or CORPUS_DIR
    corpus_path.mkdir(parents=True, exist_ok=True)
    release_ks = ensure_test_release_keystore(corpus_path / "test_release.keystore")

    built_paths: Dict[str, Path] = {}

    builders = {
        "TC_01_BENIGN_PERMISSIONS": lambda p: _build_tc01_apk(p, release_ks),
        "TC_02_EXPORTED_COMPONENTS": lambda p: _build_tc02_apk(p, release_ks),
        "TC_03_BACKUP_ENABLED": lambda p: _build_tc03_apk(p, release_ks),
        "TC_04_DEBUG_SIGNING": _build_tc04_apk,
        "TC_05_REFLECTION": lambda p: _build_tc05_apk(p, release_ks),
        "TC_06_RUNTIME_CODE_LOADING": lambda p: _build_tc06_apk(p, release_ks),
        "TC_07_SHELL_COMMANDS": lambda p: _build_tc07_apk(p, release_ks),
        "TC_08_WEAK_CRYPTO": lambda p: _build_tc08_apk(p, release_ks),
        "TC_09_NATIVE_LIBRARIES": lambda p: _build_tc09_apk(p, release_ks),
        "TC_10_EMBEDDED_CREDENTIALS": lambda p: _build_tc10_apk(p, release_ks),
        "TC_11_MALFORMED_ARCHIVE": _build_tc11_apk,
        "TC_12_SPLIT_APKS": lambda p: _build_tc12_apk(p, release_ks),
        "TC_13_LEGIT_CAMERA_MIC": lambda p: _build_tc13_apk(p, release_ks),
        "TC_14_LEGIT_LOCATION": lambda p: _build_tc14_apk(p, release_ks),
        "TC_15_LEGIT_NETWORK": lambda p: _build_tc15_apk(p, release_ks),
        "TC_16_LEGIT_REFLECTION": lambda p: _build_tc16_apk(p, release_ks),
        "TC_17_LEGIT_DYNAMIC_CODE": lambda p: _build_tc17_apk(p, release_ks),
        "TC_18_LEGIT_NATIVE_LIB": lambda p: _build_tc18_apk(p, release_ks),
        "TC_19_LEGIT_EXPORTED": lambda p: _build_tc19_apk(p, release_ks),
    }

    for case in VALIDATION_CORPUS_CASES:
        out_file = corpus_path / case.fixture_filename
        if not force_rebuild and out_file.exists() and out_file.stat().st_size > 0:
            built_paths[case.case_id] = out_file
            continue

        builder_fn = builders.get(case.case_id)
        if builder_fn:
            builder_fn(out_file)
            built_paths[case.case_id] = out_file

    return built_paths
