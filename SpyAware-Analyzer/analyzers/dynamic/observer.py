"""Runtime Logcat, Dumpsys, and Process Observer for SpyAware-Analyzer (Stage 2B).

Audits live system telemetry (dumpsys, logcat, process tables) to distinguish
between statically declared capabilities and genuinely observed runtime behaviors
across Camera, Microphone, Location, Accessibility, Screen Capture, SMS, Calls,
Background Services, Persistence, Processes, and Crashes.
"""

import re
from typing import Dict, List, Optional, Set, Tuple

from analyzers.dynamic.models import (
    CANONICAL_CATEGORIES_ORDER,
    CANONICAL_CATEGORY_NAMES,
    CanonicalBehaviorDict,
    CanonicalTelemetryResult,
    Observation,
    RuntimeBehaviorCategory,
    RuntimeBehaviorStatus,
    RuntimeObservation,
)
from backend.models.analysis import Finding, Severity


# Conservative regex patterns matching runtime surveillance indicators in logcat
SURVEILLANCE_LOG_PATTERNS = [
    (
        "CAMERA",
        re.compile(r"(?:CameraDevice|openCamera|takePicture|CameraManager|android\.hardware\.Camera|camera2)", re.IGNORECASE),
        Severity.MEDIUM,
        "Runtime Camera API Activity",
        "Logcat contains references to camera framework or hardware device calls.",
        15.0,
    ),
    (
        "AUDIO",
        re.compile(r"(?:AudioRecord|MediaRecorder.*audio|setAudioSource|startRecording)", re.IGNORECASE),
        Severity.MEDIUM,
        "Runtime Audio Recording Activity",
        "Logcat contains references to audio recording initialization or recording start.",
        15.0,
    ),
    (
        "LOCATION",
        re.compile(r"(?:LocationManager|FusedLocationProvider|requestLocationUpdates|getLastKnownLocation)", re.IGNORECASE),
        Severity.LOW,
        "Runtime Geolocation Request Activity",
        "Logcat contains references to location updates or GPS provider queries.",
        10.0,
    ),
    (
        "SMS_TELEPHONY",
        re.compile(r"(?:SmsManager|sendTextMessage|TelephonyManager.*get(?:Imei|DeviceId)|CallLog)", re.IGNORECASE),
        Severity.MEDIUM,
        "Runtime Telephony or SMS Activity",
        "Logcat contains references to telephony state querying or SMS messaging APIs.",
        15.0,
    ),
    (
        "ACCESSIBILITY",
        re.compile(r"(?:AccessibilityService|AccessibilityNodeInfo|onAccessibilityEvent)", re.IGNORECASE),
        Severity.HIGH,
        "Runtime Accessibility Interaction",
        "Logcat indicates accessibility service bindings, window introspection, or UI events.",
        25.0,
    ),
    (
        "SCREEN_CAPTURE",
        re.compile(r"(?:MediaProjection|createVirtualDisplay)", re.IGNORECASE),
        Severity.HIGH,
        "Runtime Screen Capture / Virtual Display",
        "Logcat indicates MediaProjection manager usage or virtual display creation.",
        25.0,
    ),
]

CRASH_PATTERNS = [
    re.compile(r"FATAL EXCEPTION", re.IGNORECASE),
    re.compile(r"AndroidRuntime:\s+FATAL", re.IGNORECASE),
    re.compile(r"Process\s+[\w\.]+\s+has died", re.IGNORECASE),
    re.compile(r"SIGSEGV|SIGBUS", re.IGNORECASE),
]


class DynamicObserver:
    """Parses logcat and system dumpsys outputs to detect runtime behaviors."""

    def __init__(self):
        self.last_runtime_behavior: Dict[str, RuntimeObservation] = {}
        self.last_telemetry: Optional[CanonicalTelemetryResult] = None

    @staticmethod
    def _extract_line_pid(line: str) -> Optional[str]:
        """Extracts the originating process ID from standard Android logcat formats."""
        m1 = re.match(r"^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+(\d+)\s+", line.strip())
        if m1:
            return m1.group(1)
        m2 = re.search(r"\(\s*(\d+)\s*\):", line)
        if m2:
            return m2.group(1)
        return None

    @classmethod
    def _is_target_logcat_line(
        cls, line: str, pkg: str, known_pids: Set[str]
    ) -> bool:
        """Determines if a logcat line belongs to the analyzed target application."""
        if not pkg and not known_pids:
            return False

        line_pid = cls._extract_line_pid(line)
        if line_pid and line_pid in known_pids:
            return True

        if pkg and pkg in line:
            return True

        return False

    def observe(
        self,
        package_name: Optional[str],
        launch_success: bool,
        logcat_text: str,
        services_text: Optional[str] = None,
        process_text: Optional[str] = None,
        duration_seconds: float = 0.0,
        target_pids: Optional[List[str]] = None,
    ) -> Tuple[List[Observation], List[Finding], float]:
        """Backwards-compatible wrapper returning (observations, findings, score)."""
        observations, runtime_behavior, findings, score = self.observe_stage_2b(
            package_name=package_name,
            launch_success=launch_success,
            logcat_text=logcat_text,
            services_text=services_text,
            process_text=process_text,
            target_pids=target_pids,
            duration_seconds=duration_seconds,
        )
        self.last_runtime_behavior = runtime_behavior
        return observations, findings, score

    def analyze_crash_attribution(
        self,
        logcat_text: str,
        package_name: Optional[str],
        target_pids: Optional[List[str]] = None,
        process_text: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], str]:
        """Correlates crash telemetry specifically to the analyzed package and its processes.
        
        A crash is classified as OBSERVED only when there is strong, unambiguous evidence
        associating the crash event with the target package name, target PID, or target component.
        
        Events from other applications, system_server, or normal force-stop cleanup are excluded.
        
        Returns:
            Tuple of (crash_observed: bool, evidence: Optional[str], description: str)
        """
        if not package_name:
            return False, None, "Target package identifier unavailable for crash correlation."

        if not logcat_text or not logcat_text.strip():
            return False, None, "No logcat output available for crash analysis."

        pkg = package_name.strip()
        known_pids = set(str(p).strip() for p in (target_pids or []) if str(p).strip().isdigit())
        if process_text:
            for l in process_text.splitlines():
                if pkg in l:
                    parts = l.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        known_pids.add(parts[1])

        lines = logcat_text.splitlines()
        num_lines = len(lines)

        # Cleanup / non-crash indicator patterns that must never be classified as crashes
        cleanup_indicators = [
            "force stopping",
            "force stop",
            "force-stop",
            "am force-stop",
            "am uninstall",
            "stop com.",
            "has died: empty",
            "has died: cch",
            "has died: cached",
            "has died: background",
            "has died: prcp",
        ]

        # Scan logcat lines
        for i, line in enumerate(lines):
            line_str = line.strip()
            line_lower = line_str.lower()

            # Skip explicit cleanup / maintenance actions
            if any(c in line_lower for c in cleanup_indicators):
                continue

            # -----------------------------------------------------
            # Pattern 1: AndroidRuntime FATAL EXCEPTION
            # -----------------------------------------------------
            if "fatal exception" in line_lower or "androidruntime: fatal" in line_lower:
                block_window = lines[i : min(num_lines, i + 8)]
                
                target_matched = False
                unrelated_proc = False
                crashed_identity = None

                for block_line in block_window:
                    proc_match = re.search(r"Process:\s*([^\s,]+)", block_line)
                    pid_match = re.search(r"PID:\s*(\d+)", block_line)
                    
                    if proc_match:
                        proc_name = proc_match.group(1).strip()
                        if proc_name == pkg or proc_name.startswith(f"{pkg}:"):
                            target_matched = True
                            crashed_identity = f"Process: {proc_name}"
                            break
                        else:
                            unrelated_proc = True
                            break

                    if pid_match and pid_match.group(1) in known_pids:
                        target_matched = True
                        crashed_identity = f"PID: {pid_match.group(1)} ({pkg})"
                        break

                if target_matched:
                    evidence_parts = [line_str]
                    if crashed_identity:
                        evidence_parts.append(crashed_identity)
                    if len(block_window) > 2:
                        for bl in block_window[1:4]:
                            if any(k in bl for k in ["Exception", "Error", "Caused by"]):
                                evidence_parts.append(bl.strip())
                                break
                    return (
                        True,
                        " | ".join(evidence_parts),
                        f"Unhandled fatal runtime exception confirmed in target application ({pkg}).",
                    )

                if unrelated_proc:
                    continue

                # Check if stack trace explicitly names a component of target package
                component_match = False
                for block_line in block_window:
                    if f"ComponentInfo{{{pkg}/" in block_line or f"at {pkg}." in block_line:
                        component_match = True
                        break

                if component_match:
                    evidence_parts = [line_str]
                    if len(block_window) > 1:
                        evidence_parts.append(block_window[1].strip())
                    return (
                        True,
                        " | ".join(p for p in evidence_parts if p),
                        f"Target application component ({pkg}) triggered an unhandled fatal exception.",
                    )

            # -----------------------------------------------------
            # Pattern 2: ActivityManager / Process Death
            # -----------------------------------------------------
            if ("activitymanager" in line_lower or "activitytaskmanager" in line_lower) and pkg in line:
                crash_death_match = re.search(
                    r"Process\s+([^\s]+)\s+\(pid\s+(\d+)\)\s+has died:\s*(crash|abort|fatal|segv)",
                    line,
                    re.IGNORECASE,
                )
                if crash_death_match:
                    proc_name = crash_death_match.group(1).strip()
                    if proc_name == pkg or proc_name.startswith(f"{pkg}:"):
                        return (
                            True,
                            line_str,
                            f"ActivityManager confirmed process termination due to crash for '{pkg}'.",
                        )

                kill_crash_match = re.search(
                    r"Killing\s+(\d+):([^\s/]+).*(?:crash|fatal|abort)",
                    line,
                    re.IGNORECASE,
                )
                if kill_crash_match:
                    proc_name = kill_crash_match.group(2).strip()
                    if proc_name == pkg or proc_name.startswith(f"{pkg}:"):
                        return (
                            True,
                            line_str,
                            f"ActivityManager terminated target process '{pkg}' following fatal error.",
                        )

                if re.search(r"Application\s+([^\s]+)\s+has crashed", line, re.IGNORECASE):
                    if pkg in line:
                        return (
                            True,
                            line_str,
                            f"ActivityManager recorded application crash for '{pkg}'.",
                        )

            # -----------------------------------------------------
            # Pattern 3: Native Tombstone / DEBUG (SIGSEGV/SIGBUS/SIGABRT)
            # -----------------------------------------------------
            if ("debug" in line_lower or "fatal signal" in line_lower) and any(
                s in line for s in ["SIGSEGV", "SIGBUS", "SIGABRT", "SIGFPE", "signal"]
            ):
                debug_window = lines[max(0, i - 4) : min(num_lines, i + 6)]
                is_target_tombstone = False
                for d_line in debug_window:
                    if f">>> {pkg} <<<" in d_line or f">>> {pkg}:" in d_line or f"({pkg})" in d_line:
                        is_target_tombstone = True
                        break
                    for pid in known_pids:
                        if f"pid: {pid}" in d_line.lower() or f"tid: {pid}" in d_line.lower() or f"thread {pid}" in d_line.lower():
                            if pkg in d_line or f">>> {pkg} <<<" in d_line:
                                is_target_tombstone = True
                                break

                if is_target_tombstone:
                    return (
                        True,
                        line_str,
                        f"Target process '{pkg}' terminated by fatal native signal.",
                    )

        return (
            False,
            None,
            f"No fatal exceptions or process crashes were observed for target package '{pkg}'.",
        )

    def observe_stage_2b(
        self,
        package_name: Optional[str],
        launch_success: bool,
        logcat_text: Optional[str] = "",
        services_text: Optional[str] = None,
        process_text: Optional[str] = None,
        camera_dumpsys: Optional[str] = None,
        audio_dumpsys: Optional[str] = None,
        location_dumpsys: Optional[str] = None,
        accessibility_dumpsys: Optional[str] = None,
        media_projection_dumpsys: Optional[str] = None,
        target_pids: Optional[List[str]] = None,
        duration_seconds: float = 0.0,
        source_statuses: Optional[Dict[str, str]] = None,
    ) -> Tuple[List[Observation], Dict[str, RuntimeObservation], List[Finding], float]:
        """Comprehensive Stage 2B observation evaluating all 10 canonical runtime behavioral categories.

        Returns single authoritative state per category (OBSERVED, NOT_OBSERVED, UNAVAILABLE, NOT_TESTED)
        and populates self.last_telemetry as canonical single source of truth.
        """
        pkg = package_name or ""
        observations: List[Observation] = []
        findings: List[Finding] = []
        runtime_behavior = CanonicalBehaviorDict()
        raw_score = 0.0
        statuses = source_statuses or {}
        time_str = f"{duration_seconds:.1f}s window" if duration_seconds > 0 else None

        # Collect target process IDs for strict logcat correlation
        known_pids: Set[str] = set(str(p).strip() for p in (target_pids or []) if str(p).strip().isdigit())
        if process_text and pkg:
            for l in process_text.splitlines():
                if pkg in l:
                    parts = l.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        known_pids.add(parts[1])

        # Also extract target PIDs from logcat process start lines if available
        if pkg and logcat_text:
            start_proc_pat = re.compile(r"Start proc\s+(\d+):" + re.escape(pkg), re.IGNORECASE)
            for l in logcat_text.splitlines():
                sp_match = start_proc_pat.search(l)
                if sp_match:
                    known_pids.add(sp_match.group(1))

        # ---------------------------------------------------------
        # 1. Lifecycle observation
        # ---------------------------------------------------------
        if launch_success:
            observations.append(
                Observation(
                    type="APPLICATION_STARTED",
                    severity=Severity.INFO,
                    description=f"Application '{pkg or 'target'}' launched successfully and ran for {duration_seconds:.1f}s.",
                )
            )
        else:
            observations.append(
                Observation(
                    type="APPLICATION_LAUNCH_FAILED",
                    severity=Severity.LOW,
                    description="Application process or activity did not launch successfully.",
                )
            )

        # ---------------------------------------------------------
        # 2. Crash Detection with Strict Target Attribution
        # ---------------------------------------------------------
        crash_observed, crash_evidence, crash_desc = self.analyze_crash_attribution(
            logcat_text=logcat_text or "",
            package_name=pkg,
            target_pids=target_pids,
            process_text=process_text or "",
        )

        additional_findings: List[Finding] = []
        if crash_observed:
            observations.append(
                Observation(
                    type="APPLICATION_CRASHED",
                    severity=Severity.MEDIUM,
                    description=crash_desc,
                    evidence=crash_evidence,
                )
            )
            crash_finding = Finding(
                category="DYNAMIC",
                severity=Severity.MEDIUM,
                title="Application Crashed at Runtime",
                description=crash_desc,
                evidence=crash_evidence or "Logcat stack trace",
                score=0.0,
            )
            additional_findings.append(crash_finding)
            runtime_behavior["CRASH"] = RuntimeObservation(
                category="CRASH",
                name="Application Stability & Crash Attribution",
                status=RuntimeBehaviorStatus.OBSERVED.value,
                description=crash_desc,
                evidence=crash_evidence,
                timestamp=time_str,
                confidence=1.0,
                source="logcat",
                reason="Fatal exception or process termination attributed to target",
            )
        else:
            runtime_behavior["CRASH"] = RuntimeObservation(
                category="CRASH",
                name="Application Stability & Crash Attribution",
                status=RuntimeBehaviorStatus.NOT_OBSERVED.value,
                description=crash_desc,
                evidence=None,
                timestamp=time_str,
                confidence=1.0,
                source="logcat",
                reason="No crashes or uncaught exceptions observed for target",
            )

        # If application was NOT launched, all 10 canonical categories are NOT_TESTED
        if not launch_success:
            for cat_id in CANONICAL_CATEGORIES_ORDER:
                runtime_behavior[cat_id] = RuntimeObservation(
                    category=cat_id,
                    name=CANONICAL_CATEGORY_NAMES[cat_id],
                    status=RuntimeBehaviorStatus.NOT_TESTED.value,
                    description=f"{CANONICAL_CATEGORY_NAMES[cat_id]} was not evaluated because application was not launched.",
                    evidence=None,
                    timestamp=None,
                    confidence=1.0,
                    source="telemetry",
                    reason="Application launch not completed; runtime observation not executed.",
                )

            canonical_categories = {cid: runtime_behavior[cid] for cid in CANONICAL_CATEGORIES_ORDER}
            self.last_telemetry = CanonicalTelemetryResult(
                categories_observed=0,
                categories_tested=0,
                categories_unavailable=0,
                categories_not_tested=10,
                categories_total=10,
                categories=canonical_categories,
                surveillance_observed_count=0,
                headline="Application was not launched; runtime telemetry was not tested.",
                summary="0 / 0 tested categories observed (10 not tested).",
                additional_findings=additional_findings,
            )
            self.last_runtime_behavior = runtime_behavior
            return observations, runtime_behavior, findings, 0.0

        # =========================================================
        # 1. PROCESS (Runtime Process Lifecycle)
        # =========================================================
        pids: List[str] = []
        process_lines: List[str] = []
        if process_text and pkg:
            for l in process_text.splitlines():
                if pkg in l:
                    process_lines.append(l.strip())
                    parts = l.split()
                    if len(parts) >= 2:
                        pids.append(parts[1])

        status_override = statuses.get("PROCESS")
        if status_override == RuntimeBehaviorStatus.UNAVAILABLE.value or process_text is None:
            runtime_behavior["PROCESS"] = RuntimeObservation(
                category="PROCESS",
                name=CANONICAL_CATEGORY_NAMES["PROCESS"],
                status=RuntimeBehaviorStatus.UNAVAILABLE.value,
                description="Process table (ps -A) could not be queried or command failed.",
                evidence=None,
                timestamp=time_str,
                confidence=0.5,
                source="ps",
                reason="ps -A query command failed or process table was unavailable",
            )
        elif status_override == RuntimeBehaviorStatus.NOT_TESTED.value:
            runtime_behavior["PROCESS"] = RuntimeObservation(
                category="PROCESS",
                name=CANONICAL_CATEGORY_NAMES["PROCESS"],
                status=RuntimeBehaviorStatus.NOT_TESTED.value,
                description="Process table auditing was not evaluated during this analysis.",
                evidence=None,
                timestamp=time_str,
                confidence=1.0,
                source="ps",
                reason="Category was not tested",
            )
        elif process_lines:
            runtime_behavior["PROCESS"] = RuntimeObservation(
                category="PROCESS",
                name=CANONICAL_CATEGORY_NAMES["PROCESS"],
                status=RuntimeBehaviorStatus.OBSERVED.value,
                description=f"Application process is active on device (PIDs: {', '.join(pids)}).",
                evidence="; ".join(process_lines[:2]),
                timestamp=time_str,
                confidence=1.0,
                source="ps",
                reason=f"Active process table entry matched package name (PID(s): {', '.join(pids)})",
                details={"pids": pids},
            )
        else:
            runtime_behavior["PROCESS"] = RuntimeObservation(
                category="PROCESS",
                name=CANONICAL_CATEGORY_NAMES["PROCESS"],
                status=RuntimeBehaviorStatus.NOT_OBSERVED.value,
                description="Application process was not found in the active process table at sampling time.",
                evidence=None,
                timestamp=time_str,
                confidence=0.90,
                source="ps",
                reason="Process table sampled successfully; package not present in running processes",
            )

        # =========================================================
        # 2. BACKGROUND_SERVICE (Active Background Services)
        # =========================================================
        service_lines: List[str] = []
        if services_text and pkg and pkg in services_text:
            for l in services_text.splitlines():
                if pkg in l and ("ServiceRecord" in l or "app=ProcessRecord" in l or "packageName=" in l):
                    service_lines.append(l.strip())

        status_override = statuses.get("BACKGROUND_SERVICE")
        if status_override == RuntimeBehaviorStatus.UNAVAILABLE.value or services_text is None:
            runtime_behavior["BACKGROUND_SERVICE"] = RuntimeObservation(
                category="BACKGROUND_SERVICE",
                name=CANONICAL_CATEGORY_NAMES["BACKGROUND_SERVICE"],
                status=RuntimeBehaviorStatus.UNAVAILABLE.value,
                description="dumpsys activity services could not be queried or command failed.",
                evidence=None,
                timestamp=time_str,
                confidence=0.5,
                source="dumpsys:activity.services",
                reason="dumpsys command failed or was not accessible",
            )
        elif status_override == RuntimeBehaviorStatus.NOT_TESTED.value:
            runtime_behavior["BACKGROUND_SERVICE"] = RuntimeObservation(
                category="BACKGROUND_SERVICE",
                name=CANONICAL_CATEGORY_NAMES["BACKGROUND_SERVICE"],
                status=RuntimeBehaviorStatus.NOT_TESTED.value,
                description="Background services auditing was not evaluated during this analysis.",
                evidence=None,
                timestamp=time_str,
                confidence=1.0,
                source="dumpsys:activity.services",
                reason="Category was not tested",
            )
        elif service_lines:
            evidence_str = "; ".join(service_lines[:2])
            observations.append(
                Observation(
                    type="RUNNING_SERVICES_DETECTED",
                    severity=Severity.LOW,
                    description=f"Active background service components detected in dumpsys ({len(service_lines)} entries).",
                    evidence=evidence_str,
                )
            )
            findings.append(
                Finding(
                    category="DYNAMIC",
                    severity=Severity.LOW,
                    title="Active Background Service at Runtime",
                    description=(
                        "The application maintained active service components in Android system state "
                        "during runtime observation."
                    ),
                    evidence=evidence_str,
                    score=8.0,
                )
            )
            raw_score += 8.0
            runtime_behavior["BACKGROUND_SERVICE"] = RuntimeObservation(
                category="BACKGROUND_SERVICE",
                name=CANONICAL_CATEGORY_NAMES["BACKGROUND_SERVICE"],
                status=RuntimeBehaviorStatus.OBSERVED.value,
                description="Active background service components verified in Android system state.",
                evidence=evidence_str,
                timestamp=time_str,
                confidence=1.0,
                source="dumpsys:activity.services",
                reason=f"Found {len(service_lines)} active ServiceRecord entries in ActivityManager",
            )
        else:
            runtime_behavior["BACKGROUND_SERVICE"] = RuntimeObservation(
                category="BACKGROUND_SERVICE",
                name=CANONICAL_CATEGORY_NAMES["BACKGROUND_SERVICE"],
                status=RuntimeBehaviorStatus.NOT_OBSERVED.value,
                description="No running background service components were detected in Android system state.",
                evidence=None,
                timestamp=time_str,
                confidence=1.0,
                source="dumpsys:activity.services",
                reason="dumpsys activity services queried successfully; no active ServiceRecords for target",
            )

        # =========================================================
        # 3. CAMERA (Camera / Video Capture)
        # =========================================================
        camera_observed = False
        camera_evidence = None
        camera_source = "dumpsys:media.camera"

        if camera_dumpsys and pkg:
            for l in camera_dumpsys.splitlines():
                l_lower = l.lower()
                is_target_cam = (
                    pkg in l
                    or any(f"pid: {pid}" in l_lower or f"pid:{pid}" in l_lower for pid in known_pids)
                )
                if is_target_cam and any(
                    k in l_lower for k in ["client package", "client name", "client:", "active camera client", "device:"]
                ):
                    camera_observed = True
                    camera_evidence = l.strip()
                    camera_source = "dumpsys:media.camera"
                    break

        if not camera_observed and logcat_text:
            cam_pat = re.compile(
                r"(?:CameraDevice|openCamera|takePicture|CameraManager\.openCamera|android\.hardware\.Camera|startPreview)",
                re.IGNORECASE,
            )
            for l in logcat_text.splitlines():
                if self._is_target_logcat_line(l, pkg, known_pids) and cam_pat.search(l):
                    camera_observed = True
                    camera_evidence = l.strip()
                    camera_source = "logcat"
                    break

        status_override = statuses.get("CAMERA")
        if status_override == RuntimeBehaviorStatus.UNAVAILABLE.value or (camera_dumpsys is None and not logcat_text):
            runtime_behavior["CAMERA"] = RuntimeObservation(
                category="CAMERA",
                name=CANONICAL_CATEGORY_NAMES["CAMERA"],
                status=RuntimeBehaviorStatus.UNAVAILABLE.value,
                description="Camera telemetry source failed or was not accessible.",
                evidence=None,
                timestamp=time_str,
                confidence=0.5,
                source="dumpsys:media.camera",
                reason="dumpsys media.camera and logcat could not be queried reliably",
            )
        elif status_override == RuntimeBehaviorStatus.NOT_TESTED.value:
            runtime_behavior["CAMERA"] = RuntimeObservation(
                category="CAMERA",
                name=CANONICAL_CATEGORY_NAMES["CAMERA"],
                status=RuntimeBehaviorStatus.NOT_TESTED.value,
                description="Camera telemetry was not evaluated during this analysis.",
                evidence=None,
                timestamp=time_str,
                confidence=1.0,
                source="dumpsys:media.camera",
                reason="Category was not tested",
            )
        elif camera_observed:
            observations.append(
                Observation(
                    type="CAMERA_ACTIVITY_OBSERVED",
                    severity=Severity.MEDIUM,
                    description="Runtime Camera API Activity: Target application interacted with camera framework or hardware device.",
                    evidence=camera_evidence,
                )
            )
            findings.append(
                Finding(
                    category="DYNAMIC",
                    severity=Severity.MEDIUM,
                    title="Runtime Camera API Activity",
                    description="Target application interacted with camera framework or hardware device.",
                    evidence=camera_evidence or "Camera client hit",
                    score=15.0,
                )
            )
            raw_score += 15.0
            runtime_behavior["CAMERA"] = RuntimeObservation(
                category="CAMERA",
                name=CANONICAL_CATEGORY_NAMES["CAMERA"],
                status=RuntimeBehaviorStatus.OBSERVED.value,
                description="Runtime camera hardware or framework interaction was observed.",
                evidence=camera_evidence,
                timestamp=time_str,
                confidence=0.95,
                source=camera_source,
                reason="Active camera client or CameraManager connection identified at runtime",
            )
        else:
            runtime_behavior["CAMERA"] = RuntimeObservation(
                category="CAMERA",
                name=CANONICAL_CATEGORY_NAMES["CAMERA"],
                status=RuntimeBehaviorStatus.NOT_OBSERVED.value,
                description="No active camera hardware or service connections were detected during runtime observation.",
                evidence=None,
                timestamp=time_str,
                confidence=0.95,
                source="dumpsys:media.camera",
                reason="dumpsys media.camera queried successfully; no active clients for target package",
            )

        # =========================================================
        # 4. MICROPHONE (Microphone / Audio Capture)
        # =========================================================
        audio_observed = False
        audio_evidence = None
        audio_source = "dumpsys:audio"

        if audio_dumpsys and pkg:
            for l in audio_dumpsys.splitlines():
                l_lower = l.lower()
                is_target_audio = (
                    f"package:{pkg}" in l_lower
                    or f"package: {pkg}" in l_lower
                    or f"client: {pkg}" in l_lower
                    or f"package={pkg}" in l_lower
                    or (pkg in l and "record" in l_lower)
                    or any(f"pid:{pid}" in l_lower or f"pid: {pid}" in l_lower for pid in known_pids)
                )
                if is_target_audio and any(
                    k in l_lower for k in ["recordactivitymonitor", "recording session", "state:recording", "source:mic", "audiorecord"]
                ):
                    audio_observed = True
                    audio_evidence = l.strip()
                    audio_source = "dumpsys:audio"
                    break

        if not audio_observed and logcat_text:
            audio_pat = re.compile(
                r"(?:AudioRecord.*(?:startRecording|read|getState)|startRecording|MediaRecorder.*(?:start|setAudioSource)|AudioSource\.MIC)",
                re.IGNORECASE,
            )
            for l in logcat_text.splitlines():
                if self._is_target_logcat_line(l, pkg, known_pids) and audio_pat.search(l):
                    audio_observed = True
                    audio_evidence = l.strip()
                    audio_source = "logcat"
                    break

        status_override = statuses.get("MICROPHONE")
        if status_override == RuntimeBehaviorStatus.UNAVAILABLE.value or (audio_dumpsys is None and not logcat_text):
            runtime_behavior["MICROPHONE"] = RuntimeObservation(
                category="MICROPHONE",
                name=CANONICAL_CATEGORY_NAMES["MICROPHONE"],
                status=RuntimeBehaviorStatus.UNAVAILABLE.value,
                description="Audio telemetry source failed or was not accessible.",
                evidence=None,
                timestamp=time_str,
                confidence=0.5,
                source="dumpsys:audio",
                reason="dumpsys audio and logcat could not be queried reliably",
            )
        elif status_override == RuntimeBehaviorStatus.NOT_TESTED.value:
            runtime_behavior["MICROPHONE"] = RuntimeObservation(
                category="MICROPHONE",
                name=CANONICAL_CATEGORY_NAMES["MICROPHONE"],
                status=RuntimeBehaviorStatus.NOT_TESTED.value,
                description="Audio recording telemetry was not evaluated during this analysis.",
                evidence=None,
                timestamp=time_str,
                confidence=1.0,
                source="dumpsys:audio",
                reason="Category was not tested",
            )
        elif audio_observed:
            observations.append(
                Observation(
                    type="AUDIO_ACTIVITY_OBSERVED",
                    severity=Severity.MEDIUM,
                    description="Runtime Audio Recording Activity: Target application initialized audio recording or started active microphone session.",
                    evidence=audio_evidence,
                )
            )
            findings.append(
                Finding(
                    category="DYNAMIC",
                    severity=Severity.MEDIUM,
                    title="Runtime Audio Recording Activity",
                    description="Target application initialized audio recording or started active microphone session.",
                    evidence=audio_evidence or "Audio recording hit",
                    score=15.0,
                )
            )
            raw_score += 15.0
            runtime_behavior["MICROPHONE"] = RuntimeObservation(
                category="MICROPHONE",
                name=CANONICAL_CATEGORY_NAMES["MICROPHONE"],
                status=RuntimeBehaviorStatus.OBSERVED.value,
                description="Runtime audio recording initialization or active microphone session was observed.",
                evidence=audio_evidence,
                timestamp=time_str,
                confidence=0.95,
                source=audio_source,
                reason="AudioRecord or MediaRecorder recording session detected at runtime",
            )
        else:
            runtime_behavior["MICROPHONE"] = RuntimeObservation(
                category="MICROPHONE",
                name=CANONICAL_CATEGORY_NAMES["MICROPHONE"],
                status=RuntimeBehaviorStatus.NOT_OBSERVED.value,
                description="No audio recording sessions or microphone device activations were detected during runtime observation.",
                evidence=None,
                timestamp=time_str,
                confidence=0.95,
                source="dumpsys:audio",
                reason="dumpsys audio queried successfully; no active recording sessions for target",
            )

        # =========================================================
        # 5. LOCATION (Location Tracking)
        # =========================================================
        location_observed = False
        location_evidence = None
        location_source = "dumpsys:location"

        if location_dumpsys and pkg:
            for l in location_dumpsys.splitlines():
                l_lower = l.lower()
                is_target_loc = (
                    pkg in l
                    or any(f"pid:{pid}" in l_lower or f"pid: {pid}" in l_lower for pid in known_pids)
                )
                if is_target_loc and any(k in l_lower for k in ["request[", "listener", "provider", "registration["]):
                    location_observed = True
                    location_evidence = l.strip()
                    location_source = "dumpsys:location"
                    break

        if not location_observed and logcat_text:
            loc_pat = re.compile(
                r"(?:requestLocationUpdates|LocationListener|getLastKnownLocation|FusedLocationProviderClient)",
                re.IGNORECASE,
            )
            for l in logcat_text.splitlines():
                if self._is_target_logcat_line(l, pkg, known_pids) and loc_pat.search(l):
                    location_observed = True
                    location_evidence = l.strip()
                    location_source = "logcat"
                    break

        status_override = statuses.get("LOCATION")
        if status_override == RuntimeBehaviorStatus.UNAVAILABLE.value or (location_dumpsys is None and not logcat_text):
            runtime_behavior["LOCATION"] = RuntimeObservation(
                category="LOCATION",
                name=CANONICAL_CATEGORY_NAMES["LOCATION"],
                status=RuntimeBehaviorStatus.UNAVAILABLE.value,
                description="Location telemetry source failed or was not accessible.",
                evidence=None,
                timestamp=time_str,
                confidence=0.5,
                source="dumpsys:location",
                reason="dumpsys location and logcat could not be queried reliably",
            )
        elif status_override == RuntimeBehaviorStatus.NOT_TESTED.value:
            runtime_behavior["LOCATION"] = RuntimeObservation(
                category="LOCATION",
                name=CANONICAL_CATEGORY_NAMES["LOCATION"],
                status=RuntimeBehaviorStatus.NOT_TESTED.value,
                description="Location telemetry was not evaluated during this analysis.",
                evidence=None,
                timestamp=time_str,
                confidence=1.0,
                source="dumpsys:location",
                reason="Category was not tested",
            )
        elif location_observed:
            observations.append(
                Observation(
                    type="LOCATION_ACTIVITY_OBSERVED",
                    severity=Severity.LOW,
                    description="Runtime Geolocation Request Activity: Target application requested location updates or queried GPS provider.",
                    evidence=location_evidence,
                )
            )
            findings.append(
                Finding(
                    category="DYNAMIC",
                    severity=Severity.LOW,
                    title="Runtime Geolocation Request Activity",
                    description="Target application requested location updates or queried GPS provider.",
                    evidence=location_evidence or "Location request hit",
                    score=10.0,
                )
            )
            raw_score += 10.0
            runtime_behavior["LOCATION"] = RuntimeObservation(
                category="LOCATION",
                name=CANONICAL_CATEGORY_NAMES["LOCATION"],
                status=RuntimeBehaviorStatus.OBSERVED.value,
                description="Runtime location provider registration or GPS update requests were observed.",
                evidence=location_evidence,
                timestamp=time_str,
                confidence=0.90,
                source=location_source,
                reason="Active location provider request or geofence listener registered at runtime",
            )
        else:
            runtime_behavior["LOCATION"] = RuntimeObservation(
                category="LOCATION",
                name=CANONICAL_CATEGORY_NAMES["LOCATION"],
                status=RuntimeBehaviorStatus.NOT_OBSERVED.value,
                description="No active location provider updates or GPS queries were detected during runtime observation.",
                evidence=None,
                timestamp=time_str,
                confidence=0.90,
                source="dumpsys:location",
                reason="dumpsys location queried successfully; no active requests or listeners for target",
            )

        # =========================================================
        # 6. ACCESSIBILITY (Accessibility Service Abuse)
        # =========================================================
        accessibility_observed = False
        accessibility_evidence = None
        accessibility_source = "dumpsys:accessibility"

        if accessibility_dumpsys and pkg:
            for l in accessibility_dumpsys.splitlines():
                if any(k in l for k in ["tracking=[", "windows:[", "focusedWindow:"]):
                    continue
                if (
                    f"Bound services:{{{pkg}/" in l
                    or f"Bound services:{{Service[{pkg}/" in l
                    or f"component={{{pkg}/" in l
                    or f"ComponentInfo{{{pkg}/" in l
                    or (f"ServiceRecord{{" in l and f"{pkg}/" in l)
                    or f"Service[component={{{pkg}/" in l
                    or f"Bound services:{{{pkg}." in l
                    or f"Enabled services:{{{pkg}/" in l
                    or f"Enabled services:{{{pkg}." in l
                ):
                    accessibility_observed = True
                    accessibility_evidence = l.strip()
                    accessibility_source = "dumpsys:accessibility"
                    break

        if not accessibility_observed and logcat_text:
            acc_pat = re.compile(
                r"(?:AccessibilityService|onAccessibilityEvent|AccessibilityNodeInfo|performGlobalAction)",
                re.IGNORECASE,
            )
            for l in logcat_text.splitlines():
                if self._is_target_logcat_line(l, pkg, known_pids) and acc_pat.search(l):
                    accessibility_observed = True
                    accessibility_evidence = l.strip()
                    accessibility_source = "logcat"
                    break

        status_override = statuses.get("ACCESSIBILITY")
        if status_override == RuntimeBehaviorStatus.UNAVAILABLE.value or (accessibility_dumpsys is None and not logcat_text):
            runtime_behavior["ACCESSIBILITY"] = RuntimeObservation(
                category="ACCESSIBILITY",
                name=CANONICAL_CATEGORY_NAMES["ACCESSIBILITY"],
                status=RuntimeBehaviorStatus.UNAVAILABLE.value,
                description="Accessibility telemetry source failed or was not accessible.",
                evidence=None,
                timestamp=time_str,
                confidence=0.5,
                source="dumpsys:accessibility",
                reason="dumpsys accessibility could not be queried reliably",
            )
        elif status_override == RuntimeBehaviorStatus.NOT_TESTED.value:
            runtime_behavior["ACCESSIBILITY"] = RuntimeObservation(
                category="ACCESSIBILITY",
                name=CANONICAL_CATEGORY_NAMES["ACCESSIBILITY"],
                status=RuntimeBehaviorStatus.NOT_TESTED.value,
                description="Accessibility service auditing was not evaluated during this analysis.",
                evidence=None,
                timestamp=time_str,
                confidence=1.0,
                source="dumpsys:accessibility",
                reason="Category was not tested",
            )
        elif accessibility_observed:
            observations.append(
                Observation(
                    type="ACCESSIBILITY_ACTIVITY_OBSERVED",
                    severity=Severity.HIGH,
                    description="Runtime Accessibility Interaction: Target accessibility service actively bound or handled UI events.",
                    evidence=accessibility_evidence,
                )
            )
            findings.append(
                Finding(
                    category="DYNAMIC",
                    severity=Severity.HIGH,
                    title="Runtime Accessibility Interaction",
                    description="Target accessibility service actively bound or handled UI events.",
                    evidence=accessibility_evidence or "Accessibility service bound",
                    score=25.0,
                )
            )
            raw_score += 25.0
            runtime_behavior["ACCESSIBILITY"] = RuntimeObservation(
                category="ACCESSIBILITY",
                name=CANONICAL_CATEGORY_NAMES["ACCESSIBILITY"],
                status=RuntimeBehaviorStatus.OBSERVED.value,
                description="Accessibility service component actively bound and verified at runtime.",
                evidence=accessibility_evidence,
                timestamp=time_str,
                confidence=1.0,
                source=accessibility_source,
                reason="Service component bound and capturing user UI events in AccessibilityManager",
            )
        else:
            runtime_behavior["ACCESSIBILITY"] = RuntimeObservation(
                category="ACCESSIBILITY",
                name=CANONICAL_CATEGORY_NAMES["ACCESSIBILITY"],
                status=RuntimeBehaviorStatus.NOT_OBSERVED.value,
                description="No active or bound accessibility services were registered by this application at runtime.",
                evidence=None,
                timestamp=time_str,
                confidence=1.0,
                source="dumpsys:accessibility",
                reason="dumpsys accessibility queried successfully; no active Bound services for target",
            )

        # =========================================================
        # 7. MEDIA_PROJECTION (Screen Capture / MediaProjection)
        # =========================================================
        mp_observed = False
        mp_evidence = None
        mp_source = "dumpsys:media_projection"

        if media_projection_dumpsys and pkg and pkg in media_projection_dumpsys:
            for l in media_projection_dumpsys.splitlines():
                if pkg in l and any(k in l.lower() for k in ["mediaprojection", "mediaprojectionrecord", "session"]):
                    mp_observed = True
                    mp_evidence = l.strip()
                    mp_source = "dumpsys:media_projection"
                    break

        if not mp_observed and logcat_text:
            mp_pat = re.compile(r"(?:MediaProjection|createVirtualDisplay|getMediaProjection)", re.IGNORECASE)
            for l in logcat_text.splitlines():
                if self._is_target_logcat_line(l, pkg, known_pids) and mp_pat.search(l):
                    mp_observed = True
                    mp_evidence = l.strip()
                    mp_source = "logcat"
                    break

        status_override = statuses.get("MEDIA_PROJECTION")
        if status_override == RuntimeBehaviorStatus.UNAVAILABLE.value or (media_projection_dumpsys is None and not logcat_text):
            runtime_behavior["MEDIA_PROJECTION"] = RuntimeObservation(
                category="MEDIA_PROJECTION",
                name=CANONICAL_CATEGORY_NAMES["MEDIA_PROJECTION"],
                status=RuntimeBehaviorStatus.UNAVAILABLE.value,
                description="Screen capture telemetry source failed or was not accessible.",
                evidence=None,
                timestamp=time_str,
                confidence=0.5,
                source="dumpsys:media_projection",
                reason="dumpsys media_projection could not be queried reliably",
            )
        elif status_override == RuntimeBehaviorStatus.NOT_TESTED.value:
            runtime_behavior["MEDIA_PROJECTION"] = RuntimeObservation(
                category="MEDIA_PROJECTION",
                name=CANONICAL_CATEGORY_NAMES["MEDIA_PROJECTION"],
                status=RuntimeBehaviorStatus.NOT_TESTED.value,
                description="MediaProjection screen capture was not evaluated during this analysis.",
                evidence=None,
                timestamp=time_str,
                confidence=1.0,
                source="dumpsys:media_projection",
                reason="Category was not tested",
            )
        elif mp_observed:
            observations.append(
                Observation(
                    type="SCREEN_CAPTURE_ACTIVITY_OBSERVED",
                    severity=Severity.HIGH,
                    description="Runtime Screen Capture / Virtual Display: Target application initiated MediaProjection or virtual display session.",
                    evidence=mp_evidence,
                )
            )
            findings.append(
                Finding(
                    category="DYNAMIC",
                    severity=Severity.HIGH,
                    title="Runtime Screen Capture / Virtual Display",
                    description="Target application initiated MediaProjection or virtual display session.",
                    evidence=mp_evidence or "Screen capture session hit",
                    score=25.0,
                )
            )
            raw_score += 25.0
            runtime_behavior["MEDIA_PROJECTION"] = RuntimeObservation(
                category="MEDIA_PROJECTION",
                name=CANONICAL_CATEGORY_NAMES["MEDIA_PROJECTION"],
                status=RuntimeBehaviorStatus.OBSERVED.value,
                description="Runtime screen capture or virtual display projection session observed.",
                evidence=mp_evidence,
                timestamp=time_str,
                confidence=1.0,
                source=mp_source,
                reason="Active MediaProjectionRecord session token active in system service",
            )
        else:
            runtime_behavior["MEDIA_PROJECTION"] = RuntimeObservation(
                category="MEDIA_PROJECTION",
                name=CANONICAL_CATEGORY_NAMES["MEDIA_PROJECTION"],
                status=RuntimeBehaviorStatus.NOT_OBSERVED.value,
                description="No active MediaProjection or screen streaming sessions were observed.",
                evidence=None,
                timestamp=time_str,
                confidence=1.0,
                source="dumpsys:media_projection",
                reason="dumpsys media_projection queried successfully; no active projection sessions",
            )

        # =========================================================
        # 8. SMS (SMS Telephony & Interception)
        # =========================================================
        sms_observed = False
        sms_evidence = None
        if logcat_text:
            sms_pat = re.compile(
                r"(?:SmsManager.*sendTextMessage|sendTextMessage|TelephonyManager.*get(?:Imei|DeviceId|SubscriberId)|Telephony\.Sms)",
                re.IGNORECASE,
            )
            for l in logcat_text.splitlines():
                if self._is_target_logcat_line(l, pkg, known_pids) and sms_pat.search(l):
                    sms_observed = True
                    sms_evidence = l.strip()
                    break

        status_override = statuses.get("SMS")
        if status_override == RuntimeBehaviorStatus.UNAVAILABLE.value or logcat_text is None:
            runtime_behavior["SMS"] = RuntimeObservation(
                category="SMS",
                name=CANONICAL_CATEGORY_NAMES["SMS"],
                status=RuntimeBehaviorStatus.UNAVAILABLE.value,
                description="SMS & Telephony telemetry source failed or was not accessible.",
                evidence=None,
                timestamp=time_str,
                confidence=0.5,
                source="logcat",
                reason="logcat buffer could not be queried or was unavailable",
            )
        elif status_override == RuntimeBehaviorStatus.NOT_TESTED.value:
            runtime_behavior["SMS"] = RuntimeObservation(
                category="SMS",
                name=CANONICAL_CATEGORY_NAMES["SMS"],
                status=RuntimeBehaviorStatus.NOT_TESTED.value,
                description="SMS & Telephony telemetry was not evaluated during this analysis.",
                evidence=None,
                timestamp=time_str,
                confidence=1.0,
                source="logcat",
                reason="Category was not tested",
            )
        elif sms_observed:
            observations.append(
                Observation(
                    type="SMS_TELEPHONY_ACTIVITY_OBSERVED",
                    severity=Severity.MEDIUM,
                    description="Runtime Telephony or SMS Activity: Target application queried telephony identity or dispatched SMS messaging APIs.",
                    evidence=sms_evidence,
                )
            )
            findings.append(
                Finding(
                    category="DYNAMIC",
                    severity=Severity.MEDIUM,
                    title="Runtime Telephony or SMS Activity",
                    description="Target application queried telephony identity or dispatched SMS messaging APIs.",
                    evidence=sms_evidence or "SMS API hit",
                    score=15.0,
                )
            )
            raw_score += 15.0
            runtime_behavior["SMS"] = RuntimeObservation(
                category="SMS",
                name=CANONICAL_CATEGORY_NAMES["SMS"],
                status=RuntimeBehaviorStatus.OBSERVED.value,
                description="Runtime telephony state querying or SMS messaging API calls detected in logcat.",
                evidence=sms_evidence,
                timestamp=time_str,
                confidence=0.90,
                source="logcat",
                reason="SmsManager or TelephonyManager query call matched in logcat trace",
            )
        else:
            runtime_behavior["SMS"] = RuntimeObservation(
                category="SMS",
                name=CANONICAL_CATEGORY_NAMES["SMS"],
                status=RuntimeBehaviorStatus.NOT_OBSERVED.value,
                description="No runtime SMS dispatch or telephony access activity was detected.",
                evidence=None,
                timestamp=time_str,
                confidence=0.95,
                source="logcat",
                reason="logcat buffer monitored; no SMS dispatch or telephony identity queries observed",
            )

        # =========================================================
        # 9. PERSISTENCE (Persistence & Boot Receivers)
        # =========================================================
        persist_observed = False
        persist_evidence = None
        if logcat_text:
            boot_pat = re.compile(r"(?:BOOT_COMPLETED|LOCKED_BOOT_COMPLETED|JobScheduler.*schedule)", re.IGNORECASE)
            for l in logcat_text.splitlines():
                if self._is_target_logcat_line(l, pkg, known_pids) and boot_pat.search(l):
                    persist_observed = True
                    persist_evidence = l.strip()
                    break

        status_override = statuses.get("PERSISTENCE")
        if status_override == RuntimeBehaviorStatus.UNAVAILABLE.value or logcat_text is None:
            runtime_behavior["PERSISTENCE"] = RuntimeObservation(
                category="PERSISTENCE",
                name=CANONICAL_CATEGORY_NAMES["PERSISTENCE"],
                status=RuntimeBehaviorStatus.UNAVAILABLE.value,
                description="Persistence telemetry source failed or was not accessible.",
                evidence=None,
                timestamp=time_str,
                confidence=0.5,
                source="logcat",
                reason="logcat buffer could not be queried or was unavailable",
            )
        elif status_override == RuntimeBehaviorStatus.NOT_TESTED.value:
            runtime_behavior["PERSISTENCE"] = RuntimeObservation(
                category="PERSISTENCE",
                name=CANONICAL_CATEGORY_NAMES["PERSISTENCE"],
                status=RuntimeBehaviorStatus.NOT_TESTED.value,
                description="Persistence receivers were not evaluated during this analysis.",
                evidence=None,
                timestamp=time_str,
                confidence=1.0,
                source="logcat",
                reason="Category was not tested",
            )
        elif persist_observed:
            runtime_behavior["PERSISTENCE"] = RuntimeObservation(
                category="PERSISTENCE",
                name=CANONICAL_CATEGORY_NAMES["PERSISTENCE"],
                status=RuntimeBehaviorStatus.OBSERVED.value,
                description="Runtime boot-completion receiver or scheduled persistence trigger was observed.",
                evidence=persist_evidence,
                timestamp=time_str,
                confidence=0.90,
                source="logcat",
                reason="BOOT_COMPLETED receiver or JobScheduler task invocation detected in logcat",
            )
        else:
            runtime_behavior["PERSISTENCE"] = RuntimeObservation(
                category="PERSISTENCE",
                name=CANONICAL_CATEGORY_NAMES["PERSISTENCE"],
                status=RuntimeBehaviorStatus.NOT_OBSERVED.value,
                description="No boot-completion or persistence trigger invocations were observed during the execution window.",
                evidence=None,
                timestamp=time_str,
                confidence=0.95,
                source="logcat",
                reason="logcat buffer monitored; no boot receivers or JobScheduler registrations triggered",
            )

        # =========================================================
        # 10. CALL (Call Activity & Telephony)
        # =========================================================
        call_observed = False
        call_evidence = None
        if logcat_text:
            call_pat = re.compile(r"(?:ACTION_CALL|placeCall|TelecomManager.*placeCall|CallLog\.Calls)", re.IGNORECASE)
            for l in logcat_text.splitlines():
                if self._is_target_logcat_line(l, pkg, known_pids) and call_pat.search(l):
                    call_observed = True
                    call_evidence = l.strip()
                    break

        status_override = statuses.get("CALL")
        if status_override == RuntimeBehaviorStatus.UNAVAILABLE.value or logcat_text is None:
            runtime_behavior["CALL"] = RuntimeObservation(
                category="CALL",
                name=CANONICAL_CATEGORY_NAMES["CALL"],
                status=RuntimeBehaviorStatus.UNAVAILABLE.value,
                description="Call activity telemetry source failed or was not accessible.",
                evidence=None,
                timestamp=time_str,
                confidence=0.5,
                source="logcat",
                reason="logcat buffer could not be queried or was unavailable",
            )
        elif status_override == RuntimeBehaviorStatus.NOT_TESTED.value:
            runtime_behavior["CALL"] = RuntimeObservation(
                category="CALL",
                name=CANONICAL_CATEGORY_NAMES["CALL"],
                status=RuntimeBehaviorStatus.NOT_TESTED.value,
                description="Call activity telemetry was not evaluated during this analysis.",
                evidence=None,
                timestamp=time_str,
                confidence=1.0,
                source="logcat",
                reason="Category was not tested",
            )
        elif call_observed:
            observations.append(
                Observation(
                    type="CALL_ACTIVITY_OBSERVED",
                    severity=Severity.MEDIUM,
                    description="Runtime Phone Call Activity: Target application initiated phone call action or queried call log records.",
                    evidence=call_evidence,
                )
            )
            findings.append(
                Finding(
                    category="DYNAMIC",
                    severity=Severity.MEDIUM,
                    title="Runtime Phone Call Activity",
                    description="Target application initiated phone call action or queried call log records.",
                    evidence=call_evidence or "Phone call API hit",
                    score=15.0,
                )
            )
            raw_score += 15.0
            runtime_behavior["CALL"] = RuntimeObservation(
                category="CALL",
                name=CANONICAL_CATEGORY_NAMES["CALL"],
                status=RuntimeBehaviorStatus.OBSERVED.value,
                description="Runtime phone call initiation or call log querying was observed.",
                evidence=call_evidence,
                timestamp=time_str,
                confidence=0.90,
                source="logcat",
                reason="ACTION_CALL or CallLog query matched in logcat trace",
            )
        else:
            runtime_behavior["CALL"] = RuntimeObservation(
                category="CALL",
                name=CANONICAL_CATEGORY_NAMES["CALL"],
                status=RuntimeBehaviorStatus.NOT_OBSERVED.value,
                description="No phone call requests or telephony dialer interactions were observed.",
                evidence=None,
                timestamp=time_str,
                confidence=0.95,
                source="logcat",
                reason="logcat buffer monitored; no outbound calls or call log queries detected",
            )

        # ---------------------------------------------------------
        # Canonical Telemetry Aggregation
        # ---------------------------------------------------------
        canonical_categories: Dict[str, RuntimeObservation] = {
            cid: runtime_behavior[cid] for cid in CANONICAL_CATEGORIES_ORDER
        }

        cat_observed_count = sum(
            1 for o in canonical_categories.values() if o.status == RuntimeBehaviorStatus.OBSERVED.value
        )
        cat_tested_count = sum(
            1 for o in canonical_categories.values()
            if o.status in (RuntimeBehaviorStatus.OBSERVED.value, RuntimeBehaviorStatus.NOT_OBSERVED.value)
        )
        cat_unavailable_count = sum(
            1 for o in canonical_categories.values() if o.status == RuntimeBehaviorStatus.UNAVAILABLE.value
        )
        cat_not_tested_count = sum(
            1 for o in canonical_categories.values() if o.status == RuntimeBehaviorStatus.NOT_TESTED.value
        )

        # Surveillance categories are categories 1-9 (excluding benign process lifecycle)
        surveillance_observed = sum(
            1 for cid in CANONICAL_CATEGORIES_ORDER
            if cid != "PROCESS" and canonical_categories[cid].status == RuntimeBehaviorStatus.OBSERVED.value
        )

        if surveillance_observed > 0:
            headline = (
                f"{surveillance_observed} covert surveillance indicator"
                f"{'s' if surveillance_observed > 1 else ''} confirmed active during runtime observation."
            )
        elif cat_observed_count > 0:
            headline = (
                f"{cat_observed_count} runtime telemetry category observed active (Process Lifecycle). "
                "No covert surveillance indicators detected."
            )
        else:
            headline = "No suspicious runtime indicators observed during the execution window."

        canonical_telemetry = CanonicalTelemetryResult(
            categories_observed=cat_observed_count,
            categories_tested=cat_tested_count,
            categories_unavailable=cat_unavailable_count,
            categories_not_tested=cat_not_tested_count,
            categories_total=10,
            categories=canonical_categories,
            surveillance_observed_count=surveillance_observed,
            headline=headline,
            summary=(
                f"{cat_observed_count} / {cat_tested_count} tested categories observed active at runtime "
                f"({cat_unavailable_count} unavailable, {cat_not_tested_count} not tested)."
            ),
            additional_findings=additional_findings,
        )

        self.last_telemetry = canonical_telemetry
        self.last_runtime_behavior = runtime_behavior
        final_score = min(100.0, round(raw_score, 1))

        return observations, runtime_behavior, findings, final_score
