"""ABI- and Android-Version-Aware Compatibility Engine for SpyAware-Analyzer.

Implements Milestone M3.1 specifications:
- Evaluates minSdk, targetSdk, native ABIs, and host emulator/device architecture.
- Handles pure Java/Kotlin vs single-ABI vs multi-ABI APKs.
- Evaluates platform rules rather than naive equality.
- Evaluates split-package requirements.
- Ranks candidate environments using transparent, explainable scoring.
- Handles all canonical outcomes: COMPATIBLE, COMPATIBLE_WITH_WARNINGS, INCOMPATIBLE_ABI,
  INCOMPATIBLE_ANDROID_VERSION, REQUIRED_SPLIT_PACKAGES_MISSING,
  REQUIRED_CAPABILITY_UNAVAILABLE, COMPATIBILITY_UNKNOWN.
- Generates actionable setup instructions for missing environments.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from analyzers.dynamic.environment import EnvironmentDiscovery
from analyzers.dynamic.models import AVDInventory, AVDProfile, EnvironmentStatus
from analyzers.intake.models import APKIntakeResult, SplitPackageInfo


class CompatibilityStatus(str, Enum):
    COMPATIBLE = "COMPATIBLE"
    COMPATIBLE_WITH_WARNINGS = "COMPATIBLE_WITH_WARNINGS"
    INCOMPATIBLE_ABI = "INCOMPATIBLE_ABI"
    INCOMPATIBLE_ANDROID_VERSION = "INCOMPATIBLE_ANDROID_VERSION"
    REQUIRED_SPLIT_PACKAGES_MISSING = "REQUIRED_SPLIT_PACKAGES_MISSING"
    REQUIRED_CAPABILITY_UNAVAILABLE = "REQUIRED_CAPABILITY_UNAVAILABLE"
    COMPATIBILITY_UNKNOWN = "COMPATIBILITY_UNKNOWN"


class CandidateEnvironmentEvaluation(BaseModel):
    target_id: str = Field(..., description="Target identifier (AVD name or device serial)")
    target_type: str = Field(..., description="RUNNING_DEVICE, RUNNING_EMULATOR, CONFIGURED_AVD")
    display_name: str
    api_level: Optional[int] = None
    android_version: Optional[str] = None
    supported_abis: List[str] = Field(default_factory=list)
    is_running: bool = False
    is_booted: bool = False
    status: CompatibilityStatus
    rank_score: int = Field(0, description="Deterministic ranking score (higher is preferred)")
    rationale: str
    rejection_reason: Optional[str] = None
    warnings: List[str] = Field(default_factory=list)


class CompatibilityReport(BaseModel):
    overall_status: CompatibilityStatus
    apk_package_name: Optional[str] = None
    apk_min_sdk: Optional[int] = None
    apk_target_sdk: Optional[int] = None
    apk_native_abis: List[str] = Field(default_factory=list)
    is_pure_java: bool = True
    selected_target: Optional[CandidateEnvironmentEvaluation] = None
    candidate_evaluations: List[CandidateEnvironmentEvaluation] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    setup_instructions: Optional[str] = None


class CompatibilityEngine:
    """Evaluates dynamic execution compatibility between APKs and Android environments."""

    def __init__(self, env_discovery: Optional[EnvironmentDiscovery] = None):
        self.env_discovery = env_discovery or EnvironmentDiscovery()

    def evaluate(
        self,
        intake_result: Optional[APKIntakeResult] = None,
        min_sdk: Optional[int] = None,
        target_sdk: Optional[int] = None,
        native_abis: Optional[List[str]] = None,
        package_name: Optional[str] = None,
        preferred_avd: Optional[str] = None,
        split_info: Optional[SplitPackageInfo] = None,
    ) -> CompatibilityReport:
        """Evaluates compatibility across all discovered devices and configured AVDs."""
        # 1. Resolve inputs from intake result if provided
        if intake_result is not None:
            if not intake_result.is_valid:
                return CompatibilityReport(
                    overall_status=CompatibilityStatus.COMPATIBILITY_UNKNOWN,
                    errors=[f"Cannot evaluate compatibility on invalid APK: {', '.join(intake_result.errors)}"],
                    rationale="APK validation failed or manifest unreadable",
                )

            pkg = intake_result.metadata.package_name if intake_result.metadata else None
            m_sdk = intake_result.metadata.min_sdk if intake_result.metadata else None
            t_sdk = intake_result.metadata.target_sdk if intake_result.metadata else None
            abis = list(intake_result.native_abis)
            s_info = intake_result.split_info
        else:
            pkg = package_name
            m_sdk = min_sdk
            t_sdk = target_sdk
            abis = list(native_abis) if native_abis is not None else []
            s_info = split_info or SplitPackageInfo()

        is_pure_java = (len(abis) == 0)

        # 2. Check if metadata could not be extracted at all
        if m_sdk is None and t_sdk is None and (pkg is None or (intake_result and intake_result.metadata is None)):
            return CompatibilityReport(
                overall_status=CompatibilityStatus.COMPATIBILITY_UNKNOWN,
                apk_package_name=pkg,
                is_pure_java=is_pure_java,
                errors=["APK metadata (minSdk, targetSdk) could not be extracted"],
            )

        # 3. Check split package requirements
        if s_info.is_split and s_info.is_base_apk and s_info.split_count == 0:
            pass  # Will be flagged as warning in report

        # 4. Discover candidate environments
        inventory: AVDInventory = self.env_discovery.get_avd_inventory()
        running_states: Dict[str, str] = self.env_discovery.get_running_device_states()
        running_avds: Dict[str, str] = self.env_discovery.get_running_avds()

        candidates: List[CandidateEnvironmentEvaluation] = []

        # A. Evaluate running devices / emulators
        for serial, state in running_states.items():
            is_running_emu = serial.startswith("emulator-")
            target_type = "RUNNING_EMULATOR" if is_running_emu else "RUNNING_DEVICE"
            dev_avd = None
            for a_name, a_serial in running_avds.items():
                if a_serial == serial:
                    dev_avd = a_name
                    break

            # Query device api and abi
            api_level, device_abis, is_booted = self._query_device_properties(serial)

            cand = self._evaluate_single_target(
                target_id=serial,
                target_type=target_type,
                display_name=f"{dev_avd} ({serial})" if dev_avd else f"Device {serial}",
                api_level=api_level,
                supported_abis=device_abis,
                is_running=True,
                is_booted=is_booted,
                apk_min_sdk=m_sdk,
                apk_target_sdk=t_sdk,
                apk_abis=abis,
                is_pure_java=is_pure_java,
                preferred_avd=preferred_avd,
                avd_name=dev_avd,
            )
            candidates.append(cand)

        # B. Evaluate configured offline AVD profiles
        running_serials = set(running_states.keys())
        for prof in inventory.profiles:
            # Check if this AVD is already in running candidates
            is_already_running = False
            for c in candidates:
                if c.display_name.startswith(prof.name):
                    is_already_running = True
                    break

            if is_already_running:
                continue

            cand = self._evaluate_single_target(
                target_id=prof.name,
                target_type="CONFIGURED_AVD",
                display_name=prof.display_name or prof.name,
                api_level=prof.api_level,
                supported_abis=prof.abis,
                is_running=False,
                is_booted=False,
                apk_min_sdk=m_sdk,
                apk_target_sdk=t_sdk,
                apk_abis=abis,
                is_pure_java=is_pure_java,
                preferred_avd=preferred_avd,
                avd_name=prof.name,
                profile_ready=prof.ready,
            )
            candidates.append(cand)

        # 5. Check if host has NO candidate environments at all
        if not candidates:
            instructions = self._generate_setup_instructions(m_sdk, t_sdk, abis)
            return CompatibilityReport(
                overall_status=CompatibilityStatus.REQUIRED_CAPABILITY_UNAVAILABLE,
                apk_package_name=pkg,
                apk_min_sdk=m_sdk,
                apk_target_sdk=t_sdk,
                apk_native_abis=abis,
                is_pure_java=is_pure_java,
                candidate_evaluations=[],
                errors=["No Android emulators, devices, or AVD profiles are configured or running on the host."],
                setup_instructions=instructions,
            )

        # 6. Rank candidates
        candidates.sort(key=lambda c: c.rank_score, reverse=True)

        # Filter for compatible candidates
        compatible_candidates = [
            c for c in candidates
            if c.status in (CompatibilityStatus.COMPATIBLE, CompatibilityStatus.COMPATIBLE_WITH_WARNINGS)
        ]

        report_warnings: List[str] = []
        if s_info.is_split and s_info.is_base_apk and (s_info.missing_required_splits or s_info.split_count == 0):
            report_warnings.append(
                "Base APK of a split package installation detected without associated split APK slices; "
                "split dynamic components or architecture-specific libraries may be missing."
            )

        if compatible_candidates:
            selected = compatible_candidates[0]
            if s_info.is_split and s_info.missing_required_splits:
                overall_status = CompatibilityStatus.REQUIRED_SPLIT_PACKAGES_MISSING
            else:
                overall_status = selected.status
            instructions = None
        else:
            selected = None
            # Determine primary failure reason across candidates
            has_abi_failure = any(c.status == CompatibilityStatus.INCOMPATIBLE_ABI for c in candidates)
            has_version_failure = any(c.status == CompatibilityStatus.INCOMPATIBLE_ANDROID_VERSION for c in candidates)

            if has_abi_failure and not has_version_failure:
                overall_status = CompatibilityStatus.INCOMPATIBLE_ABI
            elif has_version_failure and not has_abi_failure:
                overall_status = CompatibilityStatus.INCOMPATIBLE_ANDROID_VERSION
            elif has_abi_failure and has_version_failure:
                overall_status = CompatibilityStatus.INCOMPATIBLE_ABI
            else:
                overall_status = CompatibilityStatus.REQUIRED_CAPABILITY_UNAVAILABLE

            instructions = self._generate_setup_instructions(m_sdk, t_sdk, abis)

        return CompatibilityReport(
            overall_status=overall_status,
            apk_package_name=pkg,
            apk_min_sdk=m_sdk,
            apk_target_sdk=t_sdk,
            apk_native_abis=abis,
            is_pure_java=is_pure_java,
            selected_target=selected,
            candidate_evaluations=candidates,
            warnings=report_warnings,
            setup_instructions=instructions,
        )

    def _evaluate_single_target(
        self,
        target_id: str,
        target_type: str,
        display_name: str,
        api_level: Optional[int],
        supported_abis: List[str],
        is_running: bool,
        is_booted: bool,
        apk_min_sdk: Optional[int],
        apk_target_sdk: Optional[int],
        apk_abis: List[str],
        is_pure_java: bool,
        preferred_avd: Optional[str] = None,
        avd_name: Optional[str] = None,
        profile_ready: bool = True,
    ) -> CandidateEnvironmentEvaluation:
        """Evaluates a single target environment against APK constraints."""
        warnings: List[str] = []
        rejection_reason: Optional[str] = None

        if not profile_ready and target_type == "CONFIGURED_AVD":
            return CandidateEnvironmentEvaluation(
                target_id=target_id,
                target_type=target_type,
                display_name=display_name,
                api_level=api_level,
                supported_abis=supported_abis,
                is_running=is_running,
                is_booted=is_booted,
                status=CompatibilityStatus.REQUIRED_CAPABILITY_UNAVAILABLE,
                rank_score=-100,
                rationale="AVD profile is not ready or emulator binary is missing",
                rejection_reason="AVD configuration unready",
            )

        # 1. API Level compatibility
        if apk_min_sdk is not None and api_level is not None:
            if api_level < apk_min_sdk:
                return CandidateEnvironmentEvaluation(
                    target_id=target_id,
                    target_type=target_type,
                    display_name=display_name,
                    api_level=api_level,
                    supported_abis=supported_abis,
                    is_running=is_running,
                    is_booted=is_booted,
                    status=CompatibilityStatus.INCOMPATIBLE_ANDROID_VERSION,
                    rank_score=-50,
                    rationale=f"Device API level ({api_level}) is lower than APK minSdkVersion ({apk_min_sdk})",
                    rejection_reason=f"Android version too old: API {api_level} < minSdk {apk_min_sdk}",
                )

        # 2. ABI Compatibility
        abi_compatible = False
        if is_pure_java:
            # Pure Java runs on any environment
            abi_compatible = True
        else:
            # APK contains native libraries
            if not supported_abis:
                warnings.append("Environment ABIs could not be verified.")
            else:
                # Check for deprecated armeabi
                if "armeabi" in apk_abis and "armeabi" not in supported_abis:
                    if len(apk_abis) == 1:
                        return CandidateEnvironmentEvaluation(
                            target_id=target_id,
                            target_type=target_type,
                            display_name=display_name,
                            api_level=api_level,
                            supported_abis=supported_abis,
                            is_running=is_running,
                            is_booted=is_booted,
                            status=CompatibilityStatus.INCOMPATIBLE_ABI,
                            rank_score=-50,
                            rationale=f"APK requires deprecated armeabi architecture, not supported by target ({supported_abis})",
                            rejection_reason=f"Incompatible ABI: target supports {supported_abis}, requires armeabi",
                        )

                # Check if at least one ABI is supported
                matching = [a for a in apk_abis if a in supported_abis]
                if matching:
                    abi_compatible = True
                else:
                    return CandidateEnvironmentEvaluation(
                        target_id=target_id,
                        target_type=target_type,
                        display_name=display_name,
                        api_level=api_level,
                        supported_abis=supported_abis,
                        is_running=is_running,
                        is_booted=is_booted,
                        status=CompatibilityStatus.INCOMPATIBLE_ABI,
                        rank_score=-50,
                        rationale=f"APK native ABIs ({apk_abis}) are not supported by target ({supported_abis})",
                        rejection_reason=f"Incompatible ABI: requires {apk_abis}, target supports {supported_abis}",
                    )

        # 3. Transparent scoring for compatible candidate
        rank_score = 100

        # Running bonuses
        if is_running:
            rank_score += 80
            if is_booted:
                rank_score += 40

        # Preferred AVD bonus
        if preferred_avd and (avd_name == preferred_avd or target_id == preferred_avd):
            rank_score += 60
        elif avd_name == "Medium_Phone_API_36.1" or target_id == "Medium_Phone_API_36.1":
            rank_score += 30

        # Proximity to targetSdk
        if apk_target_sdk is not None and api_level is not None:
            diff = abs(api_level - apk_target_sdk)
            rank_score += max(0, 30 - (diff * 2))

            if api_level < apk_target_sdk:
                warnings.append(
                    f"Target API level ({api_level}) is lower than targetSdkVersion ({apk_target_sdk}). "
                    "Application will run in compatibility mode."
                )
            elif diff >= 5:
                warnings.append(
                    f"Target API level ({api_level}) is significantly newer than targetSdkVersion ({apk_target_sdk})."
                )

        if is_pure_java:
            rationale = "Pure Java/Kotlin APK: compatible with target environment"
        else:
            matched_abis = [a for a in apk_abis if a in supported_abis]
            rationale = f"Compatible native ABI(s) matched: {', '.join(matched_abis)}"

        final_status = CompatibilityStatus.COMPATIBLE_WITH_WARNINGS if warnings else CompatibilityStatus.COMPATIBLE

        return CandidateEnvironmentEvaluation(
            target_id=target_id,
            target_type=target_type,
            display_name=display_name,
            api_level=api_level,
            supported_abis=supported_abis,
            is_running=is_running,
            is_booted=is_booted,
            status=final_status,
            rank_score=rank_score,
            rationale=rationale,
            warnings=warnings,
        )

    def _query_device_properties(self, serial: str) -> Tuple[Optional[int], List[str], bool]:
        """Queries an active device via adb for API level, supported ABIs, and boot status."""
        adb = self.env_discovery.find_adb_path()
        if not adb:
            return None, [], False

        api_level = None
        abis: List[str] = []
        is_booted = False

        try:
            import subprocess
            # Query boot completed
            r_boot = subprocess.run(
                [adb, "-s", serial, "shell", "getprop", "sys.boot_completed"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if r_boot.returncode == 0 and r_boot.stdout.strip() == "1":
                is_booted = True

            # Query API level
            r_api = subprocess.run(
                [adb, "-s", serial, "shell", "getprop", "ro.build.version.sdk"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if r_api.returncode == 0 and r_api.stdout.strip().isdigit():
                api_level = int(r_api.stdout.strip())

            # Query ABIs
            r_abis = subprocess.run(
                [adb, "-s", serial, "shell", "getprop", "ro.product.cpu.abilist"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if r_abis.returncode == 0 and r_abis.stdout.strip():
                abis = [a.strip() for a in r_abis.stdout.strip().split(",") if a.strip()]

            if not abis:
                r_abi = subprocess.run(
                    [adb, "-s", serial, "shell", "getprop", "ro.product.cpu.abi"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                if r_abi.returncode == 0 and r_abi.stdout.strip():
                    abis = [r_abi.stdout.strip()]

        except Exception:
            pass

        return api_level, abis, is_booted

    def _generate_setup_instructions(
        self,
        min_sdk: Optional[int],
        target_sdk: Optional[int],
        abis: List[str],
    ) -> str:
        """Constructs copy-paste setup instructions to provision a compatible emulator."""
        target_api = max(min_sdk or 30, target_sdk or 30, 30)
        target_abi = "x86_64"
        if abis and "x86_64" not in abis and "x86" not in abis:
            if "arm64-v8a" in abis:
                target_abi = "arm64-v8a"
            elif "armeabi-v7a" in abis:
                target_abi = "armeabi-v7a"

        pkg_name = f"system-images;android-{target_api};google_apis;{target_abi}"
        avd_name = f"SpyAware_API_{target_api}_{target_abi.replace('-', '_')}"

        return (
            f"# To provision a compatible Android Virtual Device, execute:\n"
            f"sdkmanager --install \"{pkg_name}\"\n"
            f"avdmanager create avd -n \"{avd_name}\" -k \"{pkg_name}\" --device \"pixel\"\n"
            f"# Then launch using:\n"
            f"emulator -avd \"{avd_name}\" -no-snapshot-load -gpu swiftshader_indirect"
        )
