"""Universal APK Intake, Validation, and Metadata Extraction Engine.

Implements Milestone M3.0 specifications for SpyAware-Analyzer:
- Safe archive validation and ZIP bomb / path traversal defenses.
- Cryptographic hash calculation (SHA-256, SHA-1, MD5).
- Comprehensive metadata and Android SDK level extraction.
- Native library ABI detection.
- Evidence-based framework and packer detection (Flutter, React Native, Unity, Java/Kotlin).
- Split-package detection.
- Structured, typed intake results with graceful error containment.
"""

import hashlib
import logging
import os
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Suppress noisy androguard logs
try:
    from loguru import logger as loguru_logger
    loguru_logger.disable("androguard")
except Exception:
    pass

try:
    from androguard.core.apk import APK
except ImportError:
    APK = None

from backend.models.analysis import CertificateInfo, ExportedComponent
from analyzers.intake.models import (
    APKHashes,
    APKIntakeResult,
    APKMetadata,
    FrameworkIndicator,
    FrameworkType,
    IntakeStatus,
    PackingIndicators,
    SplitPackageInfo,
)

logger = logging.getLogger("spyaware.intake")

DEFAULT_MAX_FILE_SIZE_BYTES = 150 * 1024 * 1024  # 150 MB
MAX_ZIP_ENTRIES = 50_000
MAX_UNCOMPRESSED_SIZE_BYTES = 1024 * 1024 * 1024  # 1 GB
MAX_DECOMPRESSION_RATIO = 100.0
RATIO_EVALUATION_THRESHOLD = 10 * 1024 * 1024  # 10 MB

KNOWN_PACKER_LIBRARIES = {
    "libprotectClass.so": "Qihoo 360",
    "libsecexe.so": "Bangcle / SecNeo",
    "libSecShell.so": "Bangcle",
    "libSecShell-x86.so": "Bangcle",
    "libshex.so": "Tencent Legu",
    "libtxcore.so": "Tencent Legu",
    "libbaiduprotect.so": "Baidu Protect",
    "libexec.so": "IJiami",
    "libmobisec.so": "Alibaba Mobisec",
    "libAPKProtect.so": "APKProtect",
    "libnqshield.so": "NQ Shield",
}

VALID_ABIS = {
    "arm64-v8a",
    "armeabi-v7a",
    "armeabi",
    "x86",
    "x86_64",
    "mips",
    "mips64",
    "riscv64",
}


class UniversalAPKIntake:
    """Universal APK intake validator, parser, and framework identifier."""

    def __init__(self, max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES):
        env_max = os.environ.get("SPYAWARE_MAX_UPLOAD_MB")
        if env_max:
            try:
                self.max_file_size_bytes = int(env_max) * 1024 * 1024
            except ValueError:
                self.max_file_size_bytes = max_file_size_bytes
        else:
            self.max_file_size_bytes = max_file_size_bytes

    def calculate_hashes(self, file_path: str) -> APKHashes:
        """Computes SHA-256, SHA-1, and MD5 hashes in streaming 64KB blocks."""
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1()
        md5 = hashlib.md5()

        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)

        return APKHashes(
            sha256=sha256.hexdigest(),
            sha1=sha1.hexdigest(),
            md5=md5.hexdigest(),
        )

    def validate_and_intake(
        self,
        file_path: str,
        is_split: bool = False,
        split_count: int = 0,
        split_names: Optional[List[str]] = None,
    ) -> APKIntakeResult:
        """Executes full universal intake validation, metadata extraction, and framework audit.
        
        Guarantees structured error containment without unhandled exceptions.
        """
        file_name = os.path.basename(file_path) if file_path else "unknown.apk"

        # 1. Existence and regular file validation
        if not file_path or not os.path.exists(file_path):
            return APKIntakeResult(
                status=IntakeStatus.NOT_FOUND,
                is_valid=False,
                file_path=file_path or "",
                file_name=file_name,
                errors=["APK file does not exist on disk."],
            )

        if not os.path.isfile(file_path):
            return APKIntakeResult(
                status=IntakeStatus.INVALID_ARCHIVE,
                is_valid=False,
                file_path=file_path,
                file_name=file_name,
                errors=["Specified path is a directory or special device, not a regular file."],
            )

        # 2. File size validation
        try:
            file_size = os.path.getsize(file_path)
        except OSError as e:
            return APKIntakeResult(
                status=IntakeStatus.CORRUPTED,
                is_valid=False,
                file_path=file_path,
                file_name=file_name,
                errors=[f"Failed to access file attributes: {str(e)}"],
            )

        if file_size == 0:
            return APKIntakeResult(
                status=IntakeStatus.EMPTY_FILE,
                is_valid=False,
                file_path=file_path,
                file_name=file_name,
                file_size_bytes=0,
                errors=["APK file is empty (0 bytes)."],
            )

        if file_size > self.max_file_size_bytes:
            max_mb = self.max_file_size_bytes // (1024 * 1024)
            actual_mb = file_size / (1024 * 1024)
            return APKIntakeResult(
                status=IntakeStatus.FILE_TOO_LARGE,
                is_valid=False,
                file_path=file_path,
                file_name=file_name,
                file_size_bytes=file_size,
                errors=[
                    f"APK file size ({actual_mb:.1f} MB) exceeds maximum allowed limit of {max_mb} MB."
                ],
            )

        # 3. Compute cryptographic hashes
        try:
            hashes = self.calculate_hashes(file_path)
        except Exception as e:
            return APKIntakeResult(
                status=IntakeStatus.CORRUPTED,
                is_valid=False,
                file_path=file_path,
                file_name=file_name,
                file_size_bytes=file_size,
                errors=[f"Failed to compute file hashes: {str(e)}"],
            )

        # 4. ZIP archive structure and security audit
        if not zipfile.is_zipfile(file_path):
            return APKIntakeResult(
                status=IntakeStatus.INVALID_ARCHIVE,
                is_valid=False,
                file_path=file_path,
                file_name=file_name,
                file_size_bytes=file_size,
                hashes=hashes,
                errors=["File is not a valid ZIP/APK archive (missing PK header)."],
            )

        warnings: List[str] = []
        errors: List[str] = []
        unsupported: List[str] = []
        archive_entries: List[zipfile.ZipInfo] = []
        entry_names: List[str] = []
        total_uncompressed = 0

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                archive_entries = zf.infolist()
                entry_names = [e.filename for e in archive_entries]

                # Entry count limit (Zip Bomb defense)
                if len(archive_entries) > MAX_ZIP_ENTRIES:
                    return APKIntakeResult(
                        status=IntakeStatus.ZIP_BOMB_DETECTED,
                        is_valid=False,
                        file_path=file_path,
                        file_name=file_name,
                        file_size_bytes=file_size,
                        hashes=hashes,
                        archive_entry_count=len(archive_entries),
                        errors=[
                            f"Archive contains {len(archive_entries)} entries, exceeding safety limit of {MAX_ZIP_ENTRIES}."
                        ],
                    )

                # Path traversal and encrypted entry inspection
                for info in archive_entries:
                    total_uncompressed += info.file_size
                    ename = info.filename

                    # Traversal detection
                    if (
                        ename.startswith("/")
                        or ename.startswith("\\")
                        or "../" in ename
                        or "..\\" in ename
                        or ename == ".."
                        or Path(ename).is_absolute()
                    ):
                        return APKIntakeResult(
                            status=IntakeStatus.PATH_TRAVERSAL,
                            is_valid=False,
                            file_path=file_path,
                            file_name=file_name,
                            file_size_bytes=file_size,
                            hashes=hashes,
                            archive_entry_count=len(archive_entries),
                            errors=[f"Archive contains unsafe path traversal entry: {ename}"],
                        )

                    # Encrypted entries
                    if info.flag_bits & 0x1:
                        errors.append(f"Archive entry '{ename}' is encrypted. Encrypted APKs cannot be statically analyzed.")
                        return APKIntakeResult(
                            status=IntakeStatus.INVALID_ARCHIVE,
                            is_valid=False,
                            file_path=file_path,
                            file_name=file_name,
                            file_size_bytes=file_size,
                            hashes=hashes,
                            archive_entry_count=len(archive_entries),
                            errors=errors,
                        )

                # Uncompressed size and compression ratio limits (Zip bomb defense)
                if total_uncompressed > MAX_UNCOMPRESSED_SIZE_BYTES:
                    return APKIntakeResult(
                        status=IntakeStatus.ZIP_BOMB_DETECTED,
                        is_valid=False,
                        file_path=file_path,
                        file_name=file_name,
                        file_size_bytes=file_size,
                        hashes=hashes,
                        archive_entry_count=len(archive_entries),
                        uncompressed_size_bytes=total_uncompressed,
                        errors=[
                            f"Uncompressed size ({total_uncompressed / (1024*1024):.1f} MB) exceeds safety limit of {MAX_UNCOMPRESSED_SIZE_BYTES / (1024*1024):.0f} MB."
                        ],
                    )

                ratio = (total_uncompressed / file_size) if file_size > 0 else 0.0
                if total_uncompressed > RATIO_EVALUATION_THRESHOLD and ratio > MAX_DECOMPRESSION_RATIO:
                    return APKIntakeResult(
                        status=IntakeStatus.ZIP_BOMB_DETECTED,
                        is_valid=False,
                        file_path=file_path,
                        file_name=file_name,
                        file_size_bytes=file_size,
                        hashes=hashes,
                        archive_entry_count=len(archive_entries),
                        uncompressed_size_bytes=total_uncompressed,
                        compression_ratio=ratio,
                        errors=[
                            f"Archive compression ratio ({ratio:.1f}:1) exceeds safety threshold of {MAX_DECOMPRESSION_RATIO}:1."
                        ],
                    )

        except zipfile.BadZipFile as e:
            return APKIntakeResult(
                status=IntakeStatus.CORRUPTED,
                is_valid=False,
                file_path=file_path,
                file_name=file_name,
                file_size_bytes=file_size,
                hashes=hashes,
                errors=[f"Corrupted or truncated ZIP archive: {str(e)}"],
            )

        # Check AndroidManifest.xml presence
        if "AndroidManifest.xml" not in entry_names:
            return APKIntakeResult(
                status=IntakeStatus.INVALID_ARCHIVE,
                is_valid=False,
                file_path=file_path,
                file_name=file_name,
                file_size_bytes=file_size,
                hashes=hashes,
                archive_entry_count=len(archive_entries),
                uncompressed_size_bytes=total_uncompressed,
                compression_ratio=(total_uncompressed / file_size) if file_size > 0 else 0.0,
                errors=["APK archive is missing required AndroidManifest.xml."],
            )

        # 5. Extract Native Library ABIs
        native_abis: Set[str] = set()
        has_native = False
        dex_files = [n for n in entry_names if re.match(r"^classes\d*\.dex$", n)]

        for name in entry_names:
            if name.startswith("lib/") and name.endswith(".so"):
                has_native = True
                parts = name.split("/")
                if len(parts) >= 3 and parts[1] in VALID_ABIS:
                    native_abis.add(parts[1])

        detected_abis = sorted(list(native_abis))

        # 6. Framework Detection
        framework_indicator = self._detect_framework(entry_names, detected_abis)

        # 7. Packer and Obfuscation Detection
        packing_info = self._detect_packing_and_obfuscation(entry_names)

        # 8. Split Package Detection
        split_info = self._detect_split_package(
            entry_names, file_name, is_split, split_count, split_names
        )

        # 9. Extract Metadata via Androguard (with resilient error containment)
        metadata, andro_warnings, andro_errors = self._extract_metadata(file_path, detected_abis)
        warnings.extend(andro_warnings)
        errors.extend(andro_errors)

        # Reconcile status
        if andro_errors:
            intake_status = IntakeStatus.MALFORMED_MANIFEST
            is_valid = False
        elif warnings:
            intake_status = IntakeStatus.VALID_WITH_WARNINGS
            is_valid = True
        else:
            intake_status = IntakeStatus.VALID
            is_valid = True

        return APKIntakeResult(
            status=intake_status,
            is_valid=is_valid,
            file_path=file_path,
            file_name=file_name,
            file_size_bytes=file_size,
            hashes=hashes,
            metadata=metadata,
            native_abis=detected_abis,
            has_native_libraries=has_native,
            framework=framework_indicator,
            split_info=split_info,
            packing_info=packing_info,
            dex_file_count=len(dex_files),
            dex_files=dex_files,
            archive_entry_count=len(archive_entries),
            uncompressed_size_bytes=total_uncompressed,
            compression_ratio=(total_uncompressed / file_size) if file_size > 0 else 0.0,
            warnings=warnings,
            errors=errors,
            unsupported_characteristics=unsupported,
        )

    def _detect_framework(
        self, entry_names: List[str], detected_abis: List[str]
    ) -> FrameworkIndicator:
        """Determines the core development framework based on verifiable archive evidence."""
        evidence: List[str] = []

        # Check Flutter
        has_libflutter = any("libflutter.so" in n for n in entry_names)
        has_flutter_assets = any(n.startswith("assets/flutter_assets") for n in entry_names)
        if has_libflutter or has_flutter_assets:
            if has_libflutter:
                evidence.append("libflutter.so native engine library present")
            if has_flutter_assets:
                evidence.append("assets/flutter_assets directory present")
            return FrameworkIndicator(
                framework=FrameworkType.FLUTTER,
                confidence=0.95,
                evidence=evidence,
                details="Flutter AOT cross-platform framework detected",
            )

        # Check React Native
        has_rn_jni = any("libreactnativejni.so" in n for n in entry_names)
        has_hermes = any("libhermes.so" in n for n in entry_names)
        has_rn_bundle = any("assets/index.android.bundle" in n for n in entry_names)
        if has_rn_jni or has_hermes or has_rn_bundle:
            if has_rn_jni:
                evidence.append("libreactnativejni.so JNI bridge present")
            if has_hermes:
                evidence.append("libhermes.so Hermes JS engine present")
            if has_rn_bundle:
                evidence.append("assets/index.android.bundle JavaScript bundle present")
            return FrameworkIndicator(
                framework=FrameworkType.REACT_NATIVE,
                confidence=0.95,
                evidence=evidence,
                details="React Native JavaScript framework detected",
            )

        # Check Unity
        has_unity_lib = any("libunity.so" in n or "libmain.so" in n for n in entry_names)
        has_unity_data = any(n.startswith("assets/bin/Data") for n in entry_names)
        if has_unity_lib and has_unity_data:
            evidence.append("libunity.so engine and assets/bin/Data structure present")
            return FrameworkIndicator(
                framework=FrameworkType.UNITY,
                confidence=0.95,
                evidence=evidence,
                details="Unity 3D Game Engine detected",
            )

        # Check Native Only vs Java/Kotlin
        has_dex = any(n.startswith("classes") and n.endswith(".dex") for n in entry_names)
        has_native = any(n.startswith("lib/") and n.endswith(".so") for n in entry_names)

        if has_dex:
            evidence.append(f"Standard Dalvik/ART executable DEX bytecode present")
            if has_native:
                evidence.append(f"Native JNI libraries present: {', '.join(detected_abis)}")
                details = "Java/Kotlin Android application with native JNI extensions"
            else:
                details = "Pure Java/Kotlin Android application without native binaries"
            return FrameworkIndicator(
                framework=FrameworkType.JAVA_KOTLIN,
                confidence=0.90,
                evidence=evidence,
                details=details,
            )

        if has_native and not has_dex:
            evidence.append("Native binaries present with no Dalvik bytecode")
            return FrameworkIndicator(
                framework=FrameworkType.NATIVE_ONLY,
                confidence=0.85,
                evidence=evidence,
                details="Native-only application",
            )

        return FrameworkIndicator(
            framework=FrameworkType.UNKNOWN,
            confidence=0.5,
            evidence=["No standard framework signature matched"],
            details="Unknown application framework",
        )

    def _detect_packing_and_obfuscation(self, entry_names: List[str]) -> PackingIndicators:
        """Detects known third-party APK packers and dynamic code loading structures."""
        packers_found: List[str] = []
        evidence: List[str] = []

        for entry in entry_names:
            base_name = os.path.basename(entry)
            if base_name in KNOWN_PACKER_LIBRARIES:
                packer = KNOWN_PACKER_LIBRARIES[base_name]
                packers_found.append(packer)
                evidence.append(f"Known packer library '{base_name}' ({packer}) detected")

        # Split or in-memory DEX or encrypted assets
        has_encrypted_assets = any(
            entry.endswith(".xapk") or entry.endswith(".sec") or entry.endswith(".dat")
            for entry in entry_names
            if entry.startswith("assets/")
        )
        if has_encrypted_assets:
            evidence.append("Encrypted or protected asset containers observed in assets/")

        is_packed = len(packers_found) > 0
        packer_name = ", ".join(sorted(set(packers_found))) if packers_found else None

        return PackingIndicators(
            is_packed=is_packed,
            packer_name=packer_name,
            has_dynamic_code_loading=False,  # Evaluated further in DEX analysis
            has_in_memory_dex=False,
            obfuscation_detected=is_packed,
            evidence=evidence,
        )

    def _detect_split_package(
        self,
        entry_names: List[str],
        file_name: str,
        is_split: bool,
        split_count: int,
        split_names: Optional[List[str]],
    ) -> SplitPackageInfo:
        """Identifies split APK and dynamic feature characteristics."""
        is_base = True
        split_detected = is_split or False
        splits = list(split_names) if split_names else []

        low_name = file_name.lower()
        if "split_" in low_name or "config." in low_name:
            split_detected = True
            is_base = False

        return SplitPackageInfo(
            is_split=split_detected,
            is_base_apk=is_base,
            split_count=split_count if split_count > 0 else len(splits),
            split_names=splits,
            missing_required_splits=split_detected and is_base and (split_count == 0),
            notes="Base APK of a split APK installation" if (split_detected and is_base) else None,
        )

    def _extract_metadata(
        self, file_path: str, detected_abis: List[str]
    ) -> Tuple[Optional[APKMetadata], List[str], List[str]]:
        """Parses AndroidManifest.xml and signature blocks using Androguard."""
        warnings: List[str] = []
        errors: List[str] = []

        if APK is None:
            warnings.append("Androguard library is not installed; metadata extraction is limited.")
            return None, warnings, errors

        try:
            apk = APK(file_path)
            if not apk.is_valid_APK():
                errors.append("Androguard failed to parse APK structure (corrupt or invalid header).")
                return None, warnings, errors

            # Package Name
            pkg = apk.get_package()
            app_name = apk.get_app_name()
            ver_name = apk.get_androidversion_name()
            ver_code = apk.get_androidversion_code()

            # SDK Levels
            min_sdk_raw = apk.get_min_sdk_version()
            target_sdk_raw = apk.get_target_sdk_version()
            max_sdk_raw = apk.get_max_sdk_version()

            min_sdk = self._parse_int_sdk(min_sdk_raw)
            target_sdk = self._parse_int_sdk(target_sdk_raw)
            max_sdk = self._parse_int_sdk(max_sdk_raw)

            # Permissions
            permissions = apk.get_permissions() or []

            # Components
            activities = apk.get_activities() or []
            services = apk.get_services() or []
            receivers = apk.get_receivers() or []
            providers = apk.get_providers() or []

            # Exported components & launchable activity
            exported_components: List[ExportedComponent] = []
            launchable_activity: Optional[str] = None

            try:
                main_act = apk.get_main_activity()
                if main_act:
                    launchable_activity = main_act
            except Exception:
                pass

            # Inspect manifest XML for component exported attributes
            try:
                xml = apk.get_android_manifest_xml()
                if xml is not None:
                    for comp_type, tag in [
                        ("activity", "activity"),
                        ("service", "service"),
                        ("receiver", "receiver"),
                        ("provider", "provider"),
                    ]:
                        for elem in xml.findall(f".//{tag}"):
                            name = elem.get("{http://schemas.android.com/apk/res/android}name")
                            if not name:
                                continue
                            exp_attr = elem.get("{http://schemas.android.com/apk/res/android}exported")
                            has_intent_filter = elem.find("intent-filter") is not None
                            permission = elem.get("{http://schemas.android.com/apk/res/android}permission")

                            is_exp = False
                            if exp_attr is not None:
                                is_exp = (exp_attr.lower() == "true")
                            elif has_intent_filter:
                                # Implicitly exported if targetSdk < 31, but flagged
                                is_exp = True

                            if is_exp:
                                exported_components.append(
                                    ExportedComponent(
                                        component_type=comp_type,
                                        name=name,
                                        exported=True,
                                        permission=permission,
                                    )
                                )
            except Exception as e:
                warnings.append(f"Partial manifest XML parsing error: {str(e)}")

            # Certificate Info
            cert_info = self._extract_certificates(apk)

            metadata = APKMetadata(
                package_name=pkg,
                app_name=app_name,
                version_name=ver_name,
                version_code=ver_code,
                min_sdk=min_sdk,
                target_sdk=target_sdk,
                max_sdk=max_sdk,
                permissions=permissions,
                activities=activities,
                services=services,
                receivers=receivers,
                providers=providers,
                exported_components=exported_components,
                launchable_activity=launchable_activity,
                certificate=cert_info,
            )
            return metadata, warnings, errors

        except Exception as e:
            errors.append(f"AndroidManifest parsing failed: {str(e)}")
            return None, warnings, errors

    def _parse_int_sdk(self, val: Any) -> Optional[int]:
        """Safely parses SDK level values (strings, integers, or float strings)."""
        if val is None:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            try:
                return int(float(str(val)))
            except (ValueError, TypeError):
                return None

    def _extract_certificates(self, apk: Any) -> CertificateInfo:
        """Extracts cryptographic signing information from APK signature blocks."""
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
                cert_info.verification_details = "No signature found on APK archive"
            else:
                cert_info.verification_status = "METADATA_EXTRACTED_UNVERIFIED"
                scheme_str = ", ".join(schemes) if schemes else "unknown"
                cert_info.verification_details = f"Signed with scheme(s): {scheme_str}"

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
