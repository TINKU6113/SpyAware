"""Dynamic Analysis Worker Orchestrator for SpyAware-Analyzer.

Coordinates safe APK dynamic execution in the Android emulator, gathers runtime telemetry,
invokes the DynamicObserver, and formats structured analysis results.
"""

import os
import time
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from analyzers.dynamic.environment import EnvironmentDiscovery
from analyzers.dynamic.models import (
    AVDFallbackAttempt,
    AVDProfile,
    CANONICAL_CATEGORIES_ORDER,
    CANONICAL_CATEGORY_NAMES,
    CanonicalBehaviorDict,
    CanonicalTelemetryResult,
    DynamicAnalysisResult,
    ExecutionMetadata,
    Observation,
    RuntimeBehaviorStatus,
    RuntimeObservation,
)
from analyzers.dynamic.observer import DynamicObserver
from analyzers.dynamic.runner import AVDLock, DynamicRunner
from analyzers.static.analyzer import StaticAnalyzer
from backend.models.analysis import Finding, Severity
from risk_engine.engine import RiskEngine

DEFAULT_OBSERVATION_SECONDS = 15


def extract_apk_abis(apk_path: str) -> List[str]:
    """Inspects native library ABI directories inside an APK archive."""
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            abis = set()
            for name in z.namelist():
                parts = name.split("/")
                if len(parts) >= 3 and parts[0] == "lib" and parts[-1].endswith(".so"):
                    abis.add(parts[1])
            return sorted(list(abis))
    except Exception:
        return []


def _create_untested_telemetry(
    status: str = "NOT_TESTED",
    reason: str = "Application execution was not performed.",
    additional_findings: Optional[List[Finding]] = None,
) -> Tuple[CanonicalBehaviorDict, CanonicalTelemetryResult]:
    """Creates a canonical telemetry result model where all 10 categories share an authoritative status."""
    categories: Dict[str, RuntimeObservation] = {}
    for cid in CANONICAL_CATEGORIES_ORDER:
        categories[cid] = RuntimeObservation(
            category=cid,
            name=CANONICAL_CATEGORY_NAMES.get(cid, cid),
            status=status,
            description=f"{CANONICAL_CATEGORY_NAMES.get(cid, cid)} was not evaluated: {reason}",
            evidence=None,
            confidence=1.0 if status == RuntimeBehaviorStatus.NOT_TESTED.value else 0.0,
            source="telemetry",
            reason=reason,
        )
    cat_unavail = 10 if status == RuntimeBehaviorStatus.UNAVAILABLE.value else 0
    cat_not_tested = 10 if status == RuntimeBehaviorStatus.NOT_TESTED.value else 0
    res = CanonicalTelemetryResult(
        categories_observed=0,
        categories_tested=0,
        categories_unavailable=cat_unavail,
        categories_not_tested=cat_not_tested,
        categories_total=10,
        categories=categories,
        surveillance_observed_count=0,
        headline="Dynamic runtime observation was not executed.",
        summary=reason,
        additional_findings=additional_findings or [],
    )
    behavior_dict = CanonicalBehaviorDict(categories)
    return behavior_dict, res


class DynamicWorker:
    """Orchestrates an end-to-end dynamic analysis job."""

    def __init__(
        self,
        environment_discovery: Optional[EnvironmentDiscovery] = None,
        runner: Optional[DynamicRunner] = None,
        observer: Optional[DynamicObserver] = None,
        static_analyzer: Optional[StaticAnalyzer] = None,
    ):
        self.env_discovery = environment_discovery or EnvironmentDiscovery()
        self.runner = runner or DynamicRunner()
        self.observer = observer or DynamicObserver()
        self.static_analyzer = static_analyzer or StaticAnalyzer()

    def run_analysis(
        self,
        apk_path: str,
        package_name: Optional[str] = None,
        launchable_activity: Optional[str] = None,
        avd_name: Optional[str] = None,
        observation_seconds: int = DEFAULT_OBSERVATION_SECONDS,
    ) -> DynamicAnalysisResult:
        """Executes dynamic analysis on an APK within an isolated emulator.
        
        Args:
            apk_path: Path to the APK file on host.
            package_name: Optional package identifier (extracted via static analysis if omitted).
            launchable_activity: Optional main activity name (extracted via static analysis if omitted).
            avd_name: Optional AVD name to use.
            observation_seconds: Duration to observe the running application.
            
        Returns:
            DynamicAnalysisResult containing findings, observations, and runtime metadata.
        """
        start_time = time.time()
        standard_limitations = [
            "Dynamic analysis in Stage 2B uses live Android system telemetry (dumpsys, logcat, process tables).",
            "Frida dynamic binary instrumentation is not active on this host; observation relies on verified OS telemetry.",
            "Sandbox evasion mechanisms (e.g., emulator detection, delayed timers) may suppress malicious behavior.",
            "Synthetic UI exploration without automated monkey tap navigation does not traverse all deep code branches.",
            "Encrypted network payloads (TLS/HTTPS) are not inspected in Stage 2B (reserved for mitmproxy Stage 2C milestone).",
        ]

        # 1. Host file validation
        if not os.path.exists(apk_path):
            tele_dict, tele_obj = _create_untested_telemetry(
                status="NOT_TESTED",
                reason=f"Target APK does not exist at path: {apk_path}",
            )
            return DynamicAnalysisResult(
                status="FAILED",
                error_message=f"Target APK does not exist at path: {apk_path}",
                runtime_behavior=tele_dict,
                telemetry=tele_obj,
                limitations=standard_limitations,
            )

        # 2. Package & launchable activity discovery via Static Analysis
        apk_abis = extract_apk_abis(apk_path)
        min_sdk_int: Optional[int] = None
        target_sdk_int: Optional[int] = None

        static_res = None
        if not package_name:
            static_res = self.static_analyzer.analyze(apk_path)
            if not static_res.is_valid_apk:
                tele_dict, tele_obj = _create_untested_telemetry(
                    status="NOT_TESTED",
                    reason=f"Static verification failed: {static_res.error_message}",
                )
                return DynamicAnalysisResult(
                    status="FAILED",
                    error_message=f"Static verification failed: {static_res.error_message}",
                    runtime_behavior=tele_dict,
                    telemetry=tele_obj,
                    limitations=standard_limitations,
                )
            package_name = package_name or static_res.package_name
            if not apk_abis and static_res.native_architectures:
                apk_abis = static_res.native_architectures
            if not launchable_activity:
                launchable_activity = static_res.launchable_activity
                if not launchable_activity and static_res.activities:
                    for act in static_res.activities:
                        if "main" in act.lower():
                            launchable_activity = act
                            break
                    if not launchable_activity:
                        launchable_activity = static_res.activities[0]

        if not package_name:
            tele_dict, tele_obj = _create_untested_telemetry(
                status="NOT_TESTED",
                reason="Could not determine package name from APK manifest.",
            )
            return DynamicAnalysisResult(
                status="FAILED",
                error_message="Could not determine package name from APK manifest.",
                runtime_behavior=tele_dict,
                telemetry=tele_obj,
                limitations=standard_limitations,
            )

        if static_res is None:
            try:
                static_res = self.static_analyzer.analyze(apk_path)
            except Exception:
                pass

        if static_res:
            if static_res.min_sdk:
                try:
                    min_sdk_int = int(static_res.min_sdk)
                except (ValueError, TypeError):
                    pass
            if static_res.target_sdk:
                try:
                    target_sdk_int = int(static_res.target_sdk)
                except (ValueError, TypeError):
                    pass
            if not apk_abis and static_res.native_architectures:
                apk_abis = static_res.native_architectures

        # 3. Environment verification
        env_status = self.env_discovery.get_status()
        if not env_status.ready:
            tele_dict, tele_obj = _create_untested_telemetry(
                status="UNAVAILABLE",
                reason=f"Dynamic sandbox is not ready: {env_status.message}",
            )
            return DynamicAnalysisResult(
                status="UNAVAILABLE",
                score=0.0,
                risk_level="UNKNOWN",
                execution=ExecutionMetadata(
                    package_name=package_name,
                    launchable_activity=launchable_activity,
                    launch_success=False,
                    duration_seconds=0.0,
                    exit_reason="ENVIRONMENT_UNAVAILABLE",
                ),
                observations=[
                    Observation(
                        type="DYNAMIC_ENVIRONMENT_UNAVAILABLE",
                        severity=Severity.INFO,
                        description=f"Dynamic sandbox is not ready: {env_status.message}",
                    )
                ],
                findings=[],
                telemetry=tele_obj,
                runtime_behavior=tele_dict,
                limitations=standard_limitations,
                error_message=env_status.message,
            )

        adb_path = self.env_discovery.find_adb_path()
        emu_path = self.env_discovery.find_emulator_path()
        if not adb_path:
            tele_dict, tele_obj = _create_untested_telemetry(
                status="UNAVAILABLE",
                reason="adb binary not found or unavailable on host",
            )
            return DynamicAnalysisResult(
                status="UNAVAILABLE",
                score=0.0,
                risk_level="UNKNOWN",
                execution=ExecutionMetadata(
                    package_name=package_name,
                    launchable_activity=launchable_activity,
                    launch_success=False,
                    duration_seconds=0.0,
                    exit_reason="ADB_UNAVAILABLE",
                ),
                observations=[
                    Observation(
                        type="DYNAMIC_ENVIRONMENT_UNAVAILABLE",
                        severity=Severity.INFO,
                        description="adb binary not found or unavailable on host",
                    )
                ],
                findings=[],
                telemetry=tele_obj,
                runtime_behavior=tele_dict,
                limitations=standard_limitations,
                error_message="adb binary not found or unavailable on host",
            )

        preferred_target_avd = avd_name or env_status.selected_avd or (env_status.available_avds[0] if env_status.available_avds else None)

        device_id = None
        target_avd = preferred_target_avd
        emulator_proc = None
        emulator_started_by_job = False
        target_port = None
        avd_lock = None
        avd_attempts: List[AVDFallbackAttempt] = []

        try:
            # 4. Query ADB for already-connected devices and check if any matches configured AVD
            raw_states = (
                self.runner.get_device_states(adb_path)
                if hasattr(self.runner, "get_device_states")
                else None
            )
            device_states = raw_states if isinstance(raw_states, dict) else {}
            running_avd_map: Dict[str, str] = {}
            for serial, state in device_states.items():
                if isinstance(serial, str) and serial.startswith("emulator-"):
                    avd_on_dev = (
                        self.runner.get_device_avd_name(adb_path, serial)
                        if hasattr(self.runner, "get_device_avd_name")
                        else None
                    )
                    if isinstance(avd_on_dev, str) and avd_on_dev:
                        running_avd_map[avd_on_dev] = serial

            matched_serial = running_avd_map.get(preferred_target_avd) if preferred_target_avd else None
            online_device = self.runner.get_first_online_device(adb_path, prefer_emulator=True)
            active_device = matched_serial or (online_device if isinstance(online_device, str) else None)
            need_start_emulator = False

            if active_device and active_device.startswith("emulator-"):
                device_abis = self.runner.get_device_supported_abis(adb_path, active_device)
                device_api = None
                if hasattr(self.runner, "get_device_sdk_version"):
                    device_api = self.runner.get_device_sdk_version(adb_path, active_device)

                # Check ABI compatibility
                abi_compatible = True
                if apk_abis and device_abis and not any(abi in device_abis for abi in apk_abis):
                    abi_compatible = False

                # Check SDK compatibility
                sdk_compatible = True
                if min_sdk_int is not None and isinstance(device_api, int) and device_api < min_sdk_int:
                    sdk_compatible = False

                if not abi_compatible or not sdk_compatible:
                    # Active emulator is incompatible: check if an alternative compatible AVD exists
                    compat_avd = self.env_discovery.find_compatible_avd(apk_abis, env_status.available_avds)
                    if compat_avd and emu_path:
                        target_avd = compat_avd
                        need_start_emulator = True
                    else:
                        # Incompatible ABI and no alternative emulator
                        tele_dict, tele_obj = _create_untested_telemetry(
                            status="NOT_TESTED",
                            reason=(
                                f"Target APK requires native ABI(s) {apk_abis}, which are incompatible with "
                                f"active device ({active_device}) supported ABI(s) {device_abis}."
                            ),
                        )
                        return DynamicAnalysisResult(
                            status="FAILED",
                            score=0.0,
                            risk_level="UNKNOWN",
                            execution=ExecutionMetadata(
                                package_name=package_name,
                                launchable_activity=launchable_activity,
                                launch_success=False,
                                duration_seconds=0.0,
                                device_id=active_device,
                                exit_reason="INCOMPATIBLE_ABI",
                            ),
                            observations=[
                                Observation(
                                    type="ABI_INCOMPATIBLE",
                                    severity=Severity.INFO,
                                    description=(
                                        f"Target APK requires native ABI(s) {apk_abis}, which are incompatible with "
                                        f"active device ({active_device}) supported ABI(s) {device_abis}. "
                                        f"No compatible emulator is available."
                                    ),
                                )
                            ],
                            findings=[],
                            telemetry=tele_obj,
                            runtime_behavior=tele_dict,
                            error_message=(
                                f"ABI incompatibility: APK requires native architecture {apk_abis}, "
                                f"but active device ({active_device}) only supports {device_abis}. "
                                f"Installation cannot proceed (INSTALL_FAILED_NO_MATCHING_ABIS)."
                            ),
                            limitations=standard_limitations,
                        )
                else:
                    # Running emulator is compatible! Check if it's already booted or booting
                    if device_states.get(active_device) == "offline":
                        booted = self.runner.wait_for_boot(adb_path, device_id=active_device)
                        if booted:
                            device_id = active_device
                            emulator_started_by_job = False
                        else:
                            need_start_emulator = True
                    else:
                        device_id = active_device
                        emulator_started_by_job = False
            else:
                # Either no device online, or active device is a physical device (not an emulator)
                need_start_emulator = True

            # Pre-launch check: verify target AVD ABI compatibility if starting an emulator
            if need_start_emulator:
                if not emu_path:
                    tele_dict, tele_obj = _create_untested_telemetry(
                        status="UNAVAILABLE",
                        reason="Android emulator executable not found.",
                    )
                    return DynamicAnalysisResult(
                        status="UNAVAILABLE",
                        score=0.0,
                        risk_level="UNKNOWN",
                        error_message="Android emulator executable not found.",
                        runtime_behavior=tele_dict,
                        telemetry=tele_obj,
                        limitations=standard_limitations,
                    )

                # Collect candidate AVDs
                candidate_avd_names: List[str] = []
                if hasattr(self.env_discovery, "rank_compatible_avds"):
                    try:
                        ranked = self.env_discovery.rank_compatible_avds(
                            apk_min_sdk=min_sdk_int,
                            apk_target_sdk=target_sdk_int,
                            apk_abis=apk_abis,
                            preferred_avd=target_avd,
                        )
                        if isinstance(ranked, list):
                            for item in ranked:
                                if isinstance(item, tuple) and len(item) >= 1:
                                    p = item[0]
                                    name = p.name if hasattr(p, "name") else str(p)
                                    if name not in candidate_avd_names:
                                        candidate_avd_names.append(name)
                    except Exception:
                        pass

                if not candidate_avd_names:
                    # Fallback candidate pool
                    pool = []
                    if target_avd:
                        pool.append(target_avd)
                    if env_status.available_avds:
                        for a in env_status.available_avds:
                            if a not in pool:
                                pool.append(a)

                    if apk_abis:
                        compat_avd = self.env_discovery.find_compatible_avd(apk_abis, pool)
                        if compat_avd:
                            candidate_avd_names = [compat_avd]
                        else:
                            target_abis = self.env_discovery.get_avd_supported_abis(target_avd) if target_avd else []
                            if target_abis and not any(abi in target_abis for abi in apk_abis):
                                tele_dict, tele_obj = _create_untested_telemetry(
                                    status="NOT_TESTED",
                                    reason=f"Target APK requires native ABI(s) {apk_abis}, incompatible with configured AVD '{target_avd}' ({target_abis}).",
                                )
                                return DynamicAnalysisResult(
                                    status="FAILED",
                                    score=0.0,
                                    risk_level="UNKNOWN",
                                    execution=ExecutionMetadata(
                                        package_name=package_name,
                                        launchable_activity=launchable_activity,
                                        launch_success=False,
                                        duration_seconds=0.0,
                                        avd_name=target_avd,
                                        exit_reason="INCOMPATIBLE_ABI",
                                    ),
                                    observations=[
                                        Observation(
                                            type="ABI_INCOMPATIBLE",
                                            severity=Severity.INFO,
                                            description=(
                                                f"Target APK requires native ABI(s) {apk_abis}, which are incompatible with "
                                                f"configured AVD '{target_avd}' supported ABI(s) {target_abis}. "
                                                f"No compatible emulator is available."
                                            ),
                                        )
                                    ],
                                    findings=[],
                                    telemetry=tele_obj,
                                    runtime_behavior=tele_dict,
                                    error_message=(
                                        f"ABI incompatibility: APK requires native architecture {apk_abis}, "
                                        f"but configured AVD '{target_avd}' only supports {target_abis}. "
                                        f"Installation cannot proceed (INSTALL_FAILED_NO_MATCHING_ABIS)."
                                    ),
                                    limitations=standard_limitations,
                                )
                    else:
                        candidate_avd_names = pool

                if not candidate_avd_names:
                    tele_dict, tele_obj = _create_untested_telemetry(
                        status="UNAVAILABLE",
                        reason="No AVD available to launch.",
                    )
                    return DynamicAnalysisResult(
                        status="UNAVAILABLE",
                        score=0.0,
                        risk_level="UNKNOWN",
                        error_message="No active emulator running and no AVD available to launch.",
                        runtime_behavior=tele_dict,
                        telemetry=tele_obj,
                        limitations=standard_limitations,
                    )

                last_failure_reason = "STARTUP_FAILED"
                last_error_message = "Failed to launch candidate emulators."

                # Sequential candidate fallback loop
                for candidate in candidate_avd_names:
                    # Avoid starting duplicate instances of an already-running AVD
                    running_serial = running_avd_map.get(candidate)
                    if not running_serial and hasattr(self.runner, "find_running_avd"):
                        raw_find = self.runner.find_running_avd(adb_path, candidate)
                        if isinstance(raw_find, str) and raw_find.startswith("emulator-"):
                            running_serial = raw_find
                    if isinstance(running_serial, str) and running_serial.startswith("emulator-"):
                        avd_attempts.append(
                            AVDFallbackAttempt(
                                avd_name=candidate,
                                status="SKIPPED",
                                failure_classification="ALREADY_RUNNING",
                                reason=f"AVD '{candidate}' is already running on device {running_serial} and duplicate launch is not permitted.",
                            )
                        )
                        last_failure_reason = "ALREADY_RUNNING"
                        last_error_message = f"AVD '{candidate}' is already running on device {running_serial}."
                        continue

                    # 1. Acquire exclusive lock on target AVD
                    lock = AVDLock(candidate)
                    if not lock.acquire(timeout=0):
                        avd_attempts.append(
                            AVDFallbackAttempt(
                                avd_name=candidate,
                                status="SKIPPED",
                                failure_classification="AVD_LOCKED",
                                reason=f"AVD '{candidate}' is currently in use by another analysis job.",
                            )
                        )
                        last_failure_reason = "AVD_LOCKED"
                        last_error_message = f"AVD '{candidate}' is currently in use by another analysis job."
                        continue

                    # 2. Reserve an emulator console port
                    res_port = self.runner.reserve_emulator_port(adb_path)
                    if res_port is None:
                        avd_attempts.append(
                            AVDFallbackAttempt(
                                avd_name=candidate,
                                status="FAILED",
                                failure_classification="NO_PORTS_AVAILABLE",
                                reason="No emulator console ports available in range 5554-5584.",
                            )
                        )
                        lock.release()
                        last_failure_reason = "NO_PORTS_AVAILABLE"
                        last_error_message = "No emulator console ports available in range 5554-5584."
                        continue

                    target_port = res_port if isinstance(res_port, int) else 5554
                    target_device_id = f"emulator-{target_port}"

                    # 3. Start emulator
                    proc = self.runner.start_emulator(emu_path, candidate, port=target_port)
                    if proc is None:
                        avd_attempts.append(
                            AVDFallbackAttempt(
                                avd_name=candidate,
                                status="FAILED",
                                failure_classification="STARTUP_FAILED",
                                reason=f"Failed to start Android emulator for AVD '{candidate}'.",
                            )
                        )
                        self.runner.release_port_reservation(target_port)
                        target_port = None
                        lock.release()
                        last_failure_reason = "STARTUP_FAILED"
                        last_error_message = f"Failed to start Android emulator for AVD '{candidate}'."
                        continue

                    # 4. Wait for boot targeting explicit serial
                    booted = self.runner.wait_for_boot(
                        adb_path,
                        device_id=target_device_id,
                        emulator_proc=proc,
                    )
                    if not booted:
                        proc_exited = proc is not None and isinstance(proc.poll(), int)
                        exit_reason = "PROCESS_EXITED" if proc_exited else "BOOT_TIMEOUT"
                        err_msg = (
                            "Android emulator process exited unexpectedly during boot."
                            if proc_exited
                            else "Android emulator boot timed out."
                        )
                        avd_attempts.append(
                            AVDFallbackAttempt(
                                avd_name=candidate,
                                status="FAILED",
                                failure_classification=exit_reason,
                                reason=err_msg,
                            )
                        )
                        self.runner.stop_emulator(proc, adb_path, target_device_id)
                        self.runner.release_port_reservation(target_port)
                        target_port = None
                        lock.release()
                        last_failure_reason = exit_reason
                        last_error_message = err_msg
                        continue

                    # 5. Clear previous logs
                    self.runner.clear_logcat(adb_path, target_device_id)

                    # 6. Install APK
                    install_success, install_msg = self.runner.install_apk(adb_path, apk_path, target_device_id)
                    if not install_success:
                        is_abi_error = "INSTALL_FAILED_NO_MATCHING_ABIS" in install_msg
                        is_sdk_error = "INSTALL_FAILED_OLDER_SDK" in install_msg
                        exit_reason = "INCOMPATIBLE_ABI" if is_abi_error else ("INCOMPATIBLE_ANDROID_VERSION" if is_sdk_error else "INSTALL_FAILED")
                        err_desc = (
                            f"APK installation failed due to ABI incompatibility (INSTALL_FAILED_NO_MATCHING_ABIS). "
                            f"APK native architectures: {apk_abis or 'unknown'}. Device output: {install_msg}"
                            if is_abi_error
                            else (
                                f"APK installation failed due to Android version mismatch (INSTALL_FAILED_OLDER_SDK). "
                                f"APK minSdk: {min_sdk_int}. Device output: {install_msg}"
                                if is_sdk_error
                                else f"APK installation failed on device: {install_msg}"
                            )
                        )
                        avd_attempts.append(
                            AVDFallbackAttempt(
                                avd_name=candidate,
                                status="FAILED",
                                failure_classification=exit_reason,
                                reason=err_desc,
                            )
                        )
                        self.runner.stop_emulator(proc, adb_path, target_device_id)
                        self.runner.release_port_reservation(target_port)
                        target_port = None
                        lock.release()
                        last_failure_reason = exit_reason
                        last_error_message = err_desc
                        continue

                    # Succeeded!
                    avd_attempts.append(
                        AVDFallbackAttempt(
                            avd_name=candidate,
                            status="SUCCESS",
                            reason=f"Successfully installed APK on '{candidate}'.",
                        )
                    )
                    device_id = target_device_id
                    target_avd = candidate
                    emulator_proc = proc
                    emulator_started_by_job = True
                    avd_lock = lock
                    break

                if not device_id:
                    # All candidates failed
                    tele_dict, tele_obj = _create_untested_telemetry(
                        status="NOT_TESTED",
                        reason=f"Candidate emulator startup or installation failed: {last_error_message}",
                    )
                    stat = "TIMEOUT" if last_failure_reason == "BOOT_TIMEOUT" else (
                        "UNAVAILABLE" if last_failure_reason in ("AVD_LOCKED", "NO_PORTS_AVAILABLE") else "FAILED"
                    )
                    return DynamicAnalysisResult(
                        status=stat,
                        score=0.0,
                        risk_level="UNKNOWN",
                        execution=ExecutionMetadata(
                            package_name=package_name,
                            launchable_activity=launchable_activity,
                            launch_success=False,
                            duration_seconds=0.0,
                            avd_name=target_avd,
                            device_id=None,
                            emulator_started_by_job=True if last_failure_reason in ("BOOT_TIMEOUT", "PROCESS_EXITED", "INSTALL_FAILED") else False,
                            exit_reason=last_failure_reason,
                            avd_attempts=avd_attempts,
                        ),
                        observations=[
                            Observation(
                                type=last_failure_reason,
                                severity=Severity.INFO,
                                description=last_error_message,
                            )
                        ],
                        findings=[],
                        telemetry=tele_obj,
                        runtime_behavior=tele_dict,
                        error_message=last_error_message,
                        limitations=standard_limitations,
                    )
            else:
                # Active running emulator was reused
                self.runner.clear_logcat(adb_path, device_id)
                install_success, install_msg = self.runner.install_apk(adb_path, apk_path, device_id)
                if not install_success:
                    is_abi_error = "INSTALL_FAILED_NO_MATCHING_ABIS" in install_msg
                    is_sdk_error = "INSTALL_FAILED_OLDER_SDK" in install_msg
                    exit_reason = "INCOMPATIBLE_ABI" if is_abi_error else ("INCOMPATIBLE_ANDROID_VERSION" if is_sdk_error else "INSTALL_FAILED")
                    err_desc = (
                        f"APK installation failed due to ABI incompatibility (INSTALL_FAILED_NO_MATCHING_ABIS). "
                        f"APK native architectures: {apk_abis or 'unknown'}. Device output: {install_msg}"
                        if is_abi_error
                        else (
                            f"APK installation failed due to Android version mismatch (INSTALL_FAILED_OLDER_SDK). "
                            f"APK minSdk: {min_sdk_int}. Device output: {install_msg}"
                            if is_sdk_error
                            else f"APK installation failed on device: {install_msg}"
                        )
                    )
                    avd_attempts.append(
                        AVDFallbackAttempt(
                            avd_name=device_id,
                            status="FAILED",
                            failure_classification=exit_reason,
                            reason=err_desc,
                        )
                    )
                    tele_dict, tele_obj = _create_untested_telemetry(
                        status="NOT_TESTED",
                        reason=f"APK installation failed: {err_desc}",
                    )
                    return DynamicAnalysisResult(
                        status="FAILED",
                        score=0.0,
                        risk_level="UNKNOWN",
                        execution=ExecutionMetadata(
                            package_name=package_name,
                            launchable_activity=launchable_activity,
                            device_id=device_id,
                            avd_name=target_avd,
                            emulator_started_by_job=False,
                            exit_reason=exit_reason,
                            duration_seconds=0.0,
                            launch_success=False,
                            avd_attempts=avd_attempts,
                        ),
                        observations=[
                            Observation(
                                type="INSTALLATION_FAILED",
                                severity=Severity.INFO,
                                description=err_desc,
                            )
                        ],
                        findings=[],
                        telemetry=tele_obj,
                        runtime_behavior=tele_dict,
                        error_message=err_desc,
                        limitations=standard_limitations,
                    )
                else:
                    avd_attempts.append(
                        AVDFallbackAttempt(
                            avd_name=device_id,
                            status="SUCCESS",
                            reason=f"Installed successfully on running emulator {device_id}.",
                        )
                    )

            # 7. Check if launchable activity was found
            if not launchable_activity:
                tele_dict, tele_obj = _create_untested_telemetry(
                    status="NOT_TESTED",
                    reason="No launchable activity found in application manifest.",
                )
                return DynamicAnalysisResult(
                    status="NO_LAUNCHABLE_ACTIVITY",
                    score=0.0,
                    risk_level="UNKNOWN",
                    execution=ExecutionMetadata(
                        package_name=package_name,
                        launchable_activity=None,
                        launch_success=False,
                        device_id=device_id,
                        avd_name=target_avd,
                        emulator_started_by_job=emulator_started_by_job,
                        duration_seconds=0.0,
                        exit_reason="NO_LAUNCHABLE_ACTIVITY",
                        avd_attempts=avd_attempts,
                    ),
                    observations=[
                        Observation(
                            type="NO_LAUNCHABLE_ACTIVITY",
                            severity=Severity.INFO,
                            description="Application could not be automatically launched because no launchable activity was identified.",
                        )
                    ],
                    findings=[],
                    telemetry=tele_obj,
                    runtime_behavior=tele_dict,
                    limitations=standard_limitations,
                    error_message="No launchable activity found in application manifest.",
                )

            # 8. Launch Application
            launch_success, launch_msg = self.runner.launch_activity(
                adb_path, package_name, launchable_activity, device_id
            )
            if not launch_success:
                tele_dict, tele_obj = _create_untested_telemetry(
                    status="NOT_TESTED",
                    reason=f"Application launch failed: {launch_msg}",
                )
                return DynamicAnalysisResult(
                    status="FAILED",
                    score=0.0,
                    risk_level="UNKNOWN",
                    execution=ExecutionMetadata(
                        package_name=package_name,
                        launchable_activity=launchable_activity,
                        launch_success=False,
                        device_id=device_id,
                        avd_name=target_avd,
                        emulator_started_by_job=emulator_started_by_job,
                        duration_seconds=0.0,
                        exit_reason="LAUNCH_FAILED",
                        avd_attempts=avd_attempts,
                    ),
                    observations=[
                        Observation(
                            type="LAUNCH_FAILED",
                            severity=Severity.INFO,
                            description=f"Application failed to launch activity '{launchable_activity}': {launch_msg}",
                        )
                    ],
                    findings=[],
                    telemetry=tele_obj,
                    runtime_behavior=tele_dict,
                    error_message=f"Application launch failed: {launch_msg}",
                    limitations=standard_limitations,
                )

            initial_pids = self.runner.get_package_pids(adb_path, package_name, device_id)

            # 9. Observe execution for configured duration (timer starts AFTER launch)
            obs_start_time = time.time()
            if observation_seconds > 0:
                time.sleep(observation_seconds)
            duration = round(time.time() - obs_start_time, 1)

            # 10. Collect runtime telemetry
            logcat_text = self.runner.dump_logcat(adb_path, device_id)
            services_text = self.runner.dump_services(adb_path, package_name, device_id)
            process_text = self.runner.dump_processes(adb_path, package_name, device_id)
            camera_dumpsys = self.runner.dump_camera_service(adb_path, device_id)
            audio_dumpsys = self.runner.dump_audio_service(adb_path, device_id)
            location_dumpsys = self.runner.dump_location_service(adb_path, device_id)
            accessibility_dumpsys = self.runner.dump_accessibility_service(adb_path, device_id)
            media_projection_dumpsys = self.runner.dump_media_projection_service(adb_path, device_id)
            current_pids = self.runner.get_package_pids(adb_path, package_name, device_id)
            target_pids = list(set(initial_pids + current_pids))

            # 11. Run DynamicObserver Stage 2B analysis
            observations, runtime_behavior, findings, dynamic_score = self.observer.observe_stage_2b(
                package_name=package_name,
                launch_success=launch_success,
                logcat_text=logcat_text,
                services_text=services_text,
                process_text=process_text,
                camera_dumpsys=camera_dumpsys,
                audio_dumpsys=audio_dumpsys,
                location_dumpsys=location_dumpsys,
                accessibility_dumpsys=accessibility_dumpsys,
                media_projection_dumpsys=media_projection_dumpsys,
                target_pids=target_pids,
                duration_seconds=duration,
            )

            risk_level = RiskEngine.classify_risk_level(dynamic_score)

            return DynamicAnalysisResult(
                module="dynamic",
                stage="2B",
                status="COMPLETED",
                score=dynamic_score,
                risk_level=risk_level,
                execution=ExecutionMetadata(
                    package_name=package_name,
                    launchable_activity=launchable_activity,
                    launch_success=launch_success,
                    duration_seconds=duration,
                    avd_name=target_avd,
                    device_id=device_id,
                    emulator_started_by_job=emulator_started_by_job,
                    exit_reason="OBSERVATION_COMPLETED",
                    avd_attempts=avd_attempts,
                ),
                observations=observations,
                runtime_behavior=self.observer.last_runtime_behavior or CanonicalBehaviorDict(runtime_behavior),
                telemetry=self.observer.last_telemetry,
                findings=findings,
                limitations=standard_limitations,
                raw_logcat_snippet="\n".join(logcat_text.splitlines()[-50:]) if logcat_text else None,
            )

        finally:
            # Cleanup safely: stop app, uninstall, and shut down emulator if started
            if adb_path and device_id and package_name:
                try:
                    self.runner.force_stop(adb_path, package_name, device_id)
                except Exception:
                    pass
                try:
                    self.runner.uninstall_apk(adb_path, package_name, device_id)
                except Exception:
                    pass

            if emulator_started_by_job and emulator_proc:
                try:
                    self.runner.stop_emulator(emulator_proc, adb_path, device_id)
                except Exception:
                    pass

            if target_port is not None:
                try:
                    self.runner.release_port_reservation(target_port)
                except Exception:
                    pass

            if avd_lock and avd_lock.acquired:
                try:
                    avd_lock.release()
                except Exception:
                    pass
