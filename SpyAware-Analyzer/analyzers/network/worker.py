"""Stage 2C Network Analysis Worker Orchestrator.

Manages dynamic execution of APKs in the Android emulator sandbox specifically
for network socket observation, address decoding, and strict UID target attribution.
"""

import os
import subprocess
import time
from typing import List, Optional

from analyzers.dynamic.environment import EnvironmentDiscovery
from analyzers.dynamic.runner import AVDLock, DynamicRunner
from analyzers.dynamic.worker import extract_apk_abis
from analyzers.static.analyzer import StaticAnalyzer
from analyzers.network.collector import NetworkCollector
from analyzers.network.models import (
    NetworkAnalysisResult,
    NetworkAttributionStatus,
    NetworkEvent,
)
from analyzers.network.observer import NetworkObserver

DEFAULT_OBSERVATION_SECONDS = 10


def correlate_http_telemetry(
    events: List[NetworkEvent],
    logcat_text: str,
    target_package: Optional[str] = None,
    target_pids: Optional[List[int]] = None,
) -> None:
    """Correlates target application runtime logcat telemetry to verify HTTP protocol."""
    if not logcat_text or not events:
        return

    pid_strs = {str(p) for p in (target_pids or [])}
    http_lines: List[str] = []

    for line in logcat_text.splitlines():
        is_target_line = False
        if target_package and target_package in line:
            is_target_line = True
        elif "SpyAwareNetTest" in line:
            is_target_line = True
        elif pid_strs:
            for p in pid_strs:
                if f"({p})" in line or f" {p} " in line:
                    is_target_line = True
                    break

        if is_target_line:
            if any(term in line for term in ("http://", "HttpURLConnection", "HTTP/1.", "GET /", "POST /")):
                http_lines.append(line.strip())

    if not http_lines:
        return

    # Extract concise evidence snippet (without exposing payloads/secrets)
    snippet = http_lines[0]
    if len(snippet) > 120:
        snippet = snippet[:120] + "..."

    for ev in events:
        if ev.attribution_status == NetworkAttributionStatus.ATTRIBUTED and ev.remote_port in (80, 8080, 8765):
            ev.http_confirmed = True
            ev.protocol_evidence = f"HTTP communication verified via target application runtime telemetry: {snippet}"


class NetworkWorker:
    """Orchestrates an end-to-end network dynamic analysis run."""

    def __init__(
        self,
        environment_discovery: Optional[EnvironmentDiscovery] = None,
        runner: Optional[DynamicRunner] = None,
        collector: Optional[NetworkCollector] = None,
        observer: Optional[NetworkObserver] = None,
        static_analyzer: Optional[StaticAnalyzer] = None,
    ):
        self.env_discovery = environment_discovery or EnvironmentDiscovery()
        self.runner = runner or DynamicRunner()
        self.collector = collector or NetworkCollector()
        self.observer = observer or NetworkObserver()
        self.static_analyzer = static_analyzer or StaticAnalyzer()

    def run_analysis(
        self,
        apk_path: str,
        package_name: Optional[str] = None,
        launchable_activity: Optional[str] = None,
        avd_name: Optional[str] = None,
        observation_seconds: int = DEFAULT_OBSERVATION_SECONDS,
    ) -> NetworkAnalysisResult:
        """Executes APK in emulator sandbox and observes transport-level network behavior."""
        start_time = time.time()
        standard_limitations = [
            "Transport-level socket observation only; payload content is not decrypted.",
            "Ambient system DNS resolver traffic is not attributed to target UID without packet inspection.",
            "Attribution is strictly enforced via Linux kernel UID socket ownership.",
        ]

        # 1. Host file validation
        if not os.path.exists(apk_path):
            return NetworkAnalysisResult(
                status="FAILED",
                score=0.0,
                error_message=f"Target APK does not exist at path: {apk_path}",
                limitations=standard_limitations,
            )

        # 2. Package & launchable activity discovery
        apk_abis = extract_apk_abis(apk_path)
        if not package_name:
            static_res = self.static_analyzer.analyze(apk_path)
            if not static_res.is_valid_apk:
                return NetworkAnalysisResult(
                    status="FAILED",
                    score=0.0,
                    risk_level="UNKNOWN",
                    error_message=f"Static verification failed: {static_res.error_message}",
                    limitations=standard_limitations,
                )
            package_name = static_res.package_name
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
            return NetworkAnalysisResult(
                status="FAILED",
                score=0.0,
                risk_level="UNKNOWN",
                error_message="Could not determine package name from APK manifest.",
                limitations=standard_limitations,
            )

        # 3. Environment verification
        env_status = self.env_discovery.get_status()
        if not env_status.ready:
            return NetworkAnalysisResult(
                status="UNAVAILABLE",
                score=0.0,
                risk_level="UNKNOWN",
                target_package=package_name,
                error_message="Dynamic execution environment is not ready (missing adb, emulator, or AVD).",
                limitations=standard_limitations,
            )

        adb_path = self.env_discovery.find_adb_path()
        if not adb_path:
            return NetworkAnalysisResult(
                status="UNAVAILABLE",
                score=0.0,
                risk_level="UNKNOWN",
                target_package=package_name,
                error_message="ADB binary not found on host system.",
                limitations=standard_limitations,
            )

        # 4. Device discovery / selection & emulator lifecycle management
        device_id: Optional[str] = None
        emulator_proc: Optional[subprocess.Popen] = None
        emulator_started_by_job: bool = False
        target_port: Optional[int] = None
        avd_lock = None
        target_uid: Optional[int] = None
        target_pids: List[int] = []
        captured_events: List[NetworkEvent] = []

        try:
            active_device = self.runner.get_first_online_device(adb_path, prefer_emulator=True)
            need_start_emulator = False

            if active_device and active_device.startswith("emulator-"):
                device_abis = self.runner.get_device_supported_abis(adb_path, active_device)
                if apk_abis and device_abis and not any(abi in device_abis for abi in apk_abis):
                    compat_avd = self.env_discovery.find_compatible_avd(apk_abis, env_status.available_avds)
                    emu_path = self.env_discovery.find_emulator_path()
                    if compat_avd and emu_path:
                        target_avd = compat_avd
                        need_start_emulator = True
                    else:
                        return NetworkAnalysisResult(
                            status="UNAVAILABLE",
                            score=0.0,
                            risk_level="UNKNOWN",
                            target_package=package_name,
                            error_message=(
                                f"Runtime network capture unavailable: Target APK requires native architecture "
                                f"{apk_abis}, which is incompatible with device ({active_device}) supporting {device_abis} "
                                f"(INSTALL_FAILED_NO_MATCHING_ABIS)."
                            ),
                            limitations=standard_limitations,
                        )
                else:
                    device_id = active_device
                    emulator_started_by_job = False
            else:
                need_start_emulator = True

            if need_start_emulator:
                target_avd = avd_name or env_status.selected_avd or (env_status.available_avds[0] if env_status.available_avds else None)
                if not target_avd:
                    return NetworkAnalysisResult(
                        status="UNAVAILABLE",
                        score=0.0,
                        risk_level="UNKNOWN",
                        target_package=package_name,
                        error_message="No AVD available to launch emulator.",
                        limitations=standard_limitations,
                    )
                emu_path = self.env_discovery.find_emulator_path()
                if not emu_path:
                    return NetworkAnalysisResult(
                        status="UNAVAILABLE",
                        score=0.0,
                        risk_level="UNKNOWN",
                        target_package=package_name,
                        error_message="Emulator binary not found.",
                        limitations=standard_limitations,
                    )

                # Pre-launch check: verify target AVD ABI compatibility
                target_abis = self.env_discovery.get_avd_supported_abis(target_avd)
                if apk_abis and target_abis and not any(abi in target_abis for abi in apk_abis):
                    compat_avd = self.env_discovery.find_compatible_avd(apk_abis, env_status.available_avds)
                    if compat_avd:
                        target_avd = compat_avd
                    else:
                        return NetworkAnalysisResult(
                            status="UNAVAILABLE",
                            score=0.0,
                            risk_level="UNKNOWN",
                            target_package=package_name,
                            error_message=(
                                f"Runtime network capture unavailable: Target APK requires native architecture "
                                f"{apk_abis}, which is incompatible with configured AVD '{target_avd}' "
                                f"supporting {target_abis} (INSTALL_FAILED_NO_MATCHING_ABIS)."
                            ),
                            limitations=standard_limitations,
                        )

                # Avoid starting duplicate instances of an already-running AVD
                running_serial = None
                if hasattr(self.runner, "find_running_avd"):
                    raw_find = self.runner.find_running_avd(adb_path, target_avd)
                    if isinstance(raw_find, str) and raw_find.startswith("emulator-"):
                        running_serial = raw_find
                if running_serial:
                    return NetworkAnalysisResult(
                        status="UNAVAILABLE",
                        score=0.0,
                        risk_level="UNKNOWN",
                        target_package=package_name,
                        error_message=f"AVD '{target_avd}' is already running on device {running_serial} and duplicate launch is not permitted.",
                        limitations=standard_limitations,
                    )

                # Acquire exclusive lock on target AVD
                avd_lock = AVDLock(target_avd)
                if not avd_lock.acquire(timeout=0):
                    return NetworkAnalysisResult(
                        status="UNAVAILABLE",
                        score=0.0,
                        risk_level="UNKNOWN",
                        target_package=package_name,
                        error_message=f"AVD '{target_avd}' is currently in use by another analysis job.",
                        limitations=standard_limitations,
                    )

                res_port = self.runner.reserve_emulator_port(adb_path)
                if res_port is None:
                    return NetworkAnalysisResult(
                        status="UNAVAILABLE",
                        score=0.0,
                        risk_level="UNKNOWN",
                        target_package=package_name,
                        error_message="No emulator console ports available in range 5554-5584.",
                        limitations=standard_limitations,
                    )
                target_port = res_port if isinstance(res_port, int) else 5554
                target_device_id = f"emulator-{target_port}"
                device_id = target_device_id

                emulator_proc = self.runner.start_emulator(emu_path, target_avd, port=target_port)
                if emulator_proc is None:
                    return NetworkAnalysisResult(
                        status="FAILED",
                        score=0.0,
                        risk_level="UNKNOWN",
                        target_package=package_name,
                        error_message=f"Failed to start Android emulator for AVD '{target_avd}'.",
                        limitations=standard_limitations,
                    )
                emulator_started_by_job = True

                booted = self.runner.wait_for_boot(
                    adb_path,
                    device_id=target_device_id,
                    emulator_proc=emulator_proc,
                )
                if not booted:
                    proc_exited = emulator_proc is not None and isinstance(emulator_proc.poll(), int)
                    err_msg = (
                        "Android emulator process exited unexpectedly during boot."
                        if proc_exited
                        else "Emulator boot timed out."
                    )
                    return NetworkAnalysisResult(
                        status="FAILED" if proc_exited else "TIMEOUT",
                        score=0.0,
                        risk_level="UNKNOWN",
                        target_package=package_name,
                        error_message=err_msg,
                        limitations=standard_limitations,
                    )

                device_id = target_device_id

            if not device_id:
                return NetworkAnalysisResult(
                    status="UNAVAILABLE",
                    score=0.0,
                    risk_level="UNKNOWN",
                    target_package=package_name,
                    error_message="Failed to connect to online Android device/emulator.",
                    limitations=standard_limitations,
                )

            # 5. Install APK
            installed, install_msg = self.runner.install_apk(adb_path, apk_path, device_id=device_id)
            if not installed:
                return NetworkAnalysisResult(
                    status="UNAVAILABLE",
                    score=0.0,
                    risk_level="UNKNOWN",
                    target_package=package_name,
                    error_message=f"Runtime network capture unavailable: Application installation failed ({install_msg})",
                    limitations=standard_limitations,
                )

            # 6. Discover Target UID immediately after install
            target_uid = self.collector.get_target_uid(adb_path, package_name, device_id=device_id)

            # 7. Baseline poll before launch
            baseline_events = self.collector.poll_proc_net(
                adb_path=adb_path,
                target_uid=target_uid,
                target_package=package_name,
                device_id=device_id,
            )
            captured_events.extend(baseline_events)

            # Clear logcat buffer before target execution
            self.runner.clear_logcat(adb_path, device_id=device_id)

            # 8. Launch Activity
            launched, launch_msg = self.runner.launch_activity(
                adb_path=adb_path,
                package_name=package_name,
                activity_name=launchable_activity,
                device_id=device_id,
            )
            if not launched:
                return NetworkAnalysisResult(
                    status="UNAVAILABLE",
                    score=0.0,
                    risk_level="UNKNOWN",
                    target_package=package_name,
                    target_uid=target_uid,
                    target_pids=[],
                    duration_seconds=0.0,
                    error_message=f"Runtime network capture unavailable: Application launch failed ({launch_msg})",
                    limitations=standard_limitations,
                )

            # 9. Query PID
            pid_strs = self.runner.get_package_pids(adb_path, package_name, device_id=device_id)
            target_pids = [int(p) for p in pid_strs if p.isdigit()]

            # 10. Polling observation loop (timer starts AFTER launch)
            obs_start_time = time.time()
            poll_interval = 0.5
            end_time = time.time() + observation_seconds
            while time.time() < end_time:
                poll_events = self.collector.poll_proc_net(
                    adb_path=adb_path,
                    target_uid=target_uid,
                    target_package=package_name,
                    target_pids=target_pids,
                    device_id=device_id,
                )
                captured_events.extend(poll_events)
                time.sleep(poll_interval)

            # Capture runtime logcat telemetry and correlate HTTP activity
            logcat_text = self.runner.dump_logcat(adb_path, device_id=device_id, max_lines=2000)
            correlate_http_telemetry(captured_events, logcat_text, package_name, target_pids)

            duration = round(time.time() - obs_start_time, 2)

            # 12. Evaluate observations
            result = self.observer.evaluate(
                events=captured_events,
                target_package=package_name,
                target_uid=target_uid,
                target_pids=target_pids,
                duration_seconds=duration,
            )
            return result

        except Exception as e:
            return NetworkAnalysisResult(
                status="FAILED",
                score=0.0,
                target_package=package_name,
                target_uid=target_uid,
                target_pids=target_pids,
                error_message=f"Network analysis encountered an error: {str(e)}",
                limitations=standard_limitations,
            )
        finally:
            # 11. Cleanup safely: stop app, uninstall, and shut down emulator if started by this job
            if adb_path and device_id and package_name:
                try:
                    self.runner.force_stop(adb_path, package_name, device_id=device_id)
                except Exception:
                    pass
                try:
                    self.runner.uninstall_apk(adb_path, package_name, device_id=device_id)
                except Exception:
                    pass

            if emulator_started_by_job:
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
