"""Analysis orchestration service for SpyAware-Analyzer.

Manages APK file validation, running analyzers, computing overall risk,
persisting JSON reports to disk, and retrieving historical analyses.
"""

import json
import logging
import os
import shutil
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import ValidationError

from analyzers.discovery.manager import DeviceDiscoveryManager
from analyzers.discovery.models import ConnectedDevice, DiscoveredPackage
from analyzers.dynamic.compatibility import CompatibilityEngine, CompatibilityReport
from analyzers.dynamic.environment import EnvironmentDiscovery
from analyzers.dynamic.models import DynamicAnalysisResult, EnvironmentStatus
from analyzers.dynamic.worker import DynamicWorker
from analyzers.network.models import NetworkAnalysisResult
from analyzers.network.worker import NetworkWorker
from analyzers.permissions.analyzer import PermissionAnalyzer
from analyzers.static.analyzer import StaticAnalyzer
from backend.models.analysis import (
    Finding,
    ModuleScores,
    PermissionAnalysisResult,
    RiskReport,
    StaticAnalysisResult,
)
from risk_engine.engine import RiskEngine
from backend.models.comparison import AnalysisComparisonReport
from backend.services.comparison_service import ComparisonService

logger = logging.getLogger(__name__)

REPORTS_DIR = Path(__file__).resolve().parent.parent.parent / "reports"
MAX_UPLOAD_MB = int(os.environ.get("SPYAWARE_MAX_UPLOAD_MB", "150"))
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_MB * 1024 * 1024  # 150 MB default max APK size


def get_max_upload_bytes() -> int:
    """Return maximum upload size in bytes based on SPYAWARE_MAX_UPLOAD_MB environment variable."""
    return int(os.environ.get("SPYAWARE_MAX_UPLOAD_MB", "150")) * 1024 * 1024


class InvalidAPKError(ValueError):
    """Raised when an APK file is invalid, corrupted, or unparseable."""
    pass


class CorruptedReportError(Exception):
    """Raised when a saved report file exists on disk but is malformed, truncated, or structurally invalid."""
    pass


class AnalysisService:
    """Coordinates static, permission, dynamic, network, and risk analysis workflows."""

    def __init__(self, reports_dir: Optional[Path] = None):
        self.reports_dir = reports_dir or REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.static_analyzer = StaticAnalyzer()
        self.permission_analyzer = PermissionAnalyzer()
        self.dynamic_worker = DynamicWorker()
        self.network_worker = NetworkWorker()
        self.risk_engine = RiskEngine()
        self.discovery_manager = DeviceDiscoveryManager(env_discovery=self.dynamic_worker.env_discovery)
        self.compatibility_engine = CompatibilityEngine(env_discovery=self.dynamic_worker.env_discovery)
        self.comparison_service = ComparisonService()
        self._cached_env_status: Optional[EnvironmentStatus] = None
        self._cached_env_time: float = 0.0
        self._emulator_execution_lock = threading.RLock()

    def get_dynamic_environment(self, force_refresh: bool = False) -> EnvironmentStatus:
        """Returns host discovery diagnostics for Android emulator and adb with lightweight caching."""
        now = time.time()
        if not force_refresh and self._cached_env_status is not None and (now - self._cached_env_time < 5.0):
            return self._cached_env_status
        status = self.dynamic_worker.env_discovery.get_status()
        self._cached_env_status = status
        self._cached_env_time = now
        return status

    def _get_profile_duration(self, profile: Optional[str]) -> int:
        """Maps an execution profile to its dynamic observation / network capture duration in seconds."""
        norm = (profile or "").upper()
        if norm == "QUICK":
            return 5
        elif norm == "EXTENDED":
            return 30
        return 15

    def analyze_apk_full(
        self,
        apk_path: str,
        original_filename: str,
        include_dynamic: bool = False,
        include_network: bool = False,
        avd_name: Optional[str] = None,
        is_split: bool = False,
        split_count: int = 0,
        split_names: Optional[List[str]] = None,
        analysis_profile: str = "STANDARD",
    ) -> RiskReport:
        """Runs static analysis, permission analysis, and optionally dynamic/network analysis."""
        start_time = time.time()
        analysis_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()
        module_status: Dict[str, str] = {}
        module_errors: Dict[str, Optional[str]] = {}
        limitations: List[str] = []

        norm_profile = analysis_profile.upper() if analysis_profile else "STANDARD"
        if norm_profile not in ("QUICK", "STANDARD", "EXTENDED", "STATIC_ONLY"):
            norm_profile = "STANDARD"

        if norm_profile == "STATIC_ONLY":
            include_dynamic = False
            include_network = False

        obs_seconds = self._get_profile_duration(norm_profile)

        # Evaluate execution compatibility
        compatibility_result = None
        try:
            compatibility_result = self.evaluate_apk_compatibility(apk_path, preferred_avd=avd_name)
            if compatibility_result and compatibility_result.warnings:
                for w in compatibility_result.warnings:
                    if w not in limitations:
                        limitations.append(w)
        except Exception as e:
            logger.warning("Compatibility evaluation failed: %s", e)

        if is_split:
            limitations.append(
                f"Analyzed base APK from a split APK installation ({split_count} splits detected). "
                f"Dynamic features, split DEX code, or architecture-specific native libraries located in split APKs were not evaluated."
            )

        # 1. Run static analysis
        try:
            static_result: StaticAnalysisResult = self.static_analyzer.analyze(
                apk_path, is_split=is_split, split_count=split_count
            )
            if not static_result.is_valid_apk:
                raise InvalidAPKError(static_result.error_message or "Invalid or corrupted APK file")
            module_status["static"] = "COMPLETED"
            module_errors["static"] = None
        except InvalidAPKError:
            raise
        except Exception as e:
            logger.error("Static analysis failed: %s", e)
            raise InvalidAPKError(f"APK parsing failed: {e}") from e

        if static_result.limitations:
            limitations.extend(static_result.limitations)

        # 2. Extract permissions and run permission analysis
        try:
            declared_perms = static_result.requested_permissions
            perm_result: PermissionAnalysisResult = self.permission_analyzer.analyze(declared_perms)
            module_status["permissions"] = "COMPLETED"
            module_errors["permissions"] = None
        except Exception as e:
            logger.error("Permission analysis failed: %s", e)
            module_status["permissions"] = "FAILED"
            module_errors["permissions"] = str(e)
            perm_result = PermissionAnalysisResult(
                package_name=static_result.package_name,
                requested_permissions=[],
                findings=[],
                score=0.0,
                risk_level="UNKNOWN",
                category_breakdown={},
            )

        # 3. Dynamic Analysis if requested
        dynamic_result: Optional[DynamicAnalysisResult] = None
        dynamic_score: Optional[float] = None
        dynamic_findings: List[Finding] = []

        if include_dynamic:
            try:
                with self._emulator_execution_lock:
                    dynamic_result = self.dynamic_worker.run_analysis(
                        apk_path=apk_path,
                        package_name=static_result.package_name,
                        launchable_activity=static_result.launchable_activity,
                        avd_name=avd_name,
                        observation_seconds=obs_seconds,
                    )
                if dynamic_result.status == "COMPLETED":
                    dynamic_score = dynamic_result.score
                    dynamic_findings = dynamic_result.findings
                    module_status["dynamic"] = "COMPLETED"
                    module_errors["dynamic"] = None
                else:
                    dynamic_score = None
                    dynamic_findings = []
                    module_status["dynamic"] = dynamic_result.status
                    module_errors["dynamic"] = dynamic_result.error_message or f"Dynamic analysis status: {dynamic_result.status}"
                    if dynamic_result.limitations:
                        limitations.extend(dynamic_result.limitations)
            except Exception as e:
                module_status["dynamic"] = "FAILED"
                module_errors["dynamic"] = str(e)
        else:
            module_status["dynamic"] = "NOT_REQUESTED"
            module_errors["dynamic"] = None

        # 4. Network Analysis if requested
        network_result: Optional[NetworkAnalysisResult] = None
        network_score: Optional[float] = None
        network_findings: List[Finding] = []

        if include_network:
            # If dynamic analysis was also requested and failed during execution,
            # runtime network analysis cannot run because application execution is unavailable.
            if include_dynamic and dynamic_result and dynamic_result.status != "COMPLETED":
                fail_reason = dynamic_result.error_message or f"Dynamic analysis status: {dynamic_result.status}"
                network_result = NetworkAnalysisResult(
                    module="network",
                    stage="2C",
                    status="UNAVAILABLE",
                    score=0.0,
                    risk_level="UNKNOWN",
                    target_package=static_result.package_name,
                    error_message=f"Runtime network capture unavailable: Application execution failed ({fail_reason})",
                    limitations=[
                        "Runtime network analysis requires successful emulator installation and execution.",
                        "Static network indicators (if any) are evaluated independently in the static analysis module.",
                        "Absence of runtime capture does not indicate absence of network capability.",
                    ],
                )
                network_score = None
                network_findings = []
                module_status["network"] = "UNAVAILABLE"
                module_errors["network"] = network_result.error_message
            else:
                try:
                    with self._emulator_execution_lock:
                        network_result = self.network_worker.run_analysis(
                            apk_path=apk_path,
                            package_name=static_result.package_name,
                            launchable_activity=static_result.launchable_activity,
                            avd_name=avd_name,
                            capture_seconds=obs_seconds,
                        )
                    if network_result.status in ("COMPLETED", "NOT_ATTRIBUTED"):
                        network_score = network_result.score
                        network_findings = network_result.findings
                        module_status["network"] = network_result.status
                        module_errors["network"] = None
                    else:
                        network_score = None
                        network_findings = []
                        module_status["network"] = network_result.status
                        module_errors["network"] = network_result.error_message or f"Network analysis status: {network_result.status}"
                except Exception as e:
                    module_status["network"] = "FAILED"
                    module_errors["network"] = str(e)
        else:
            module_status["network"] = "NOT_REQUESTED"
            module_errors["network"] = None

        module_status["ble"] = "NOT_IMPLEMENTED"
        module_errors["ble"] = None

        # 5. Aggregate findings across active modules
        combined_findings: List[Finding] = (
            static_result.findings + perm_result.findings + dynamic_findings + network_findings
        )

        # 6. Compute risk score
        module_scores_dict = {
            "static": static_result.score if module_status["static"] == "COMPLETED" else None,
            "permissions": perm_result.score if module_status["permissions"] == "COMPLETED" else None,
            "dynamic": dynamic_score,
            "network": network_score,
            "ble": None,
        }

        risk_output = self.risk_engine.calculate_overall_risk(
            module_scores=module_scores_dict,
            findings=combined_findings,
            telemetry=dynamic_result.telemetry if dynamic_result else None,
        )

        # Resolve overall analysis status
        has_failed_requested = False
        if include_dynamic and module_status.get("dynamic") != "COMPLETED":
            has_failed_requested = True
        if include_network and module_status.get("network") not in ("COMPLETED", "NOT_ATTRIBUTED"):
            has_failed_requested = True
        if module_status.get("permissions") != "COMPLETED":
            has_failed_requested = True
        if static_result.dex_files_failed:
            has_failed_requested = True

        active_scores = [v for v in module_scores_dict.values() if v is not None]
        if not active_scores:
            analysis_status = "INCONCLUSIVE"
        elif has_failed_requested:
            analysis_status = "PARTIAL"
        else:
            meaningful_findings = [f for f in combined_findings if f.score > 0]
            if risk_output["overall_score"] == 0.0 and len(meaningful_findings) == 0:
                analysis_status = "COMPLETED_CLEAN"
            else:
                analysis_status = "COMPLETED_WITH_FINDINGS"

        module_scores = ModuleScores(
            static=static_result.score if module_status["static"] == "COMPLETED" else None,
            permissions=perm_result.score if module_status["permissions"] == "COMPLETED" else None,
            dynamic=dynamic_score,
            network=network_score,
            ble=None,
        )

        report = RiskReport(
            analysis_id=analysis_id,
            timestamp=now_iso,
            apk_filename=original_filename,
            overall_score=risk_output["overall_score"],
            risk_level=risk_output["risk_level"],
            analysis_status=analysis_status,
            module_scores=module_scores,
            module_status=module_status,
            module_errors=module_errors,
            findings=combined_findings,
            summary=risk_output["summary"],
            is_split=is_split or static_result.is_split,
            split_count=split_count if split_count > 0 else static_result.split_count,
            split_names=split_names or [],
            dex_file_count=static_result.dex_file_count,
            dex_files_analyzed=static_result.dex_files_analyzed,
            limitations=limitations + [lim for lim in static_result.limitations if lim not in limitations],
            certificate_info=static_result.certificate_info,
            manifest_config=static_result.manifest_config,
            static_details=static_result,
            permission_details=perm_result,
            dynamic_details=dynamic_result,
            network_details=network_result,
            sha256=static_result.sha256,
            framework=static_result.framework,
            native_abis=static_result.native_architectures,
            has_native_libraries=len(static_result.native_libraries) > 0,
            coverage_percent=risk_output.get("coverage_percent"),
            confidence_score=risk_output.get("confidence_score"),
            correlation_summary=risk_output.get("correlation_summary"),
            compatibility_details=compatibility_result,
            analysis_profile=norm_profile,
            duration_seconds=round(time.time() - start_time, 2),
            export_markdown_url=f"/api/analysis/{analysis_id}/export/markdown",
            export_json_url=f"/api/analysis/{analysis_id}",
        )

        # Persist report
        self.save_report(report)
        return report

    def analyze_network_only(
        self, apk_path: str, original_filename: str, avd_name: Optional[str] = None
    ) -> RiskReport:
        """Runs dynamic network analysis only in emulator sandbox."""
        start_time = time.time()
        analysis_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()
        module_status = {
            "static": "NOT_REQUESTED",
            "permissions": "NOT_REQUESTED",
            "dynamic": "NOT_REQUESTED",
            "network": "PENDING",
            "ble": "NOT_IMPLEMENTED",
        }
        module_errors: Dict[str, Optional[str]] = {"network": None}

        # Validate APK first
        static_res = self.static_analyzer.analyze(apk_path)
        if not static_res.is_valid_apk:
            raise InvalidAPKError(static_res.error_message or "Invalid or corrupted APK file")

        with self._emulator_execution_lock:
            network_result = self.network_worker.run_analysis(
                apk_path=apk_path,
                package_name=static_res.package_name,
                launchable_activity=static_res.launchable_activity,
                avd_name=avd_name,
            )

        is_completed = network_result.status in ("COMPLETED", "NOT_ATTRIBUTED")
        network_score = network_result.score if is_completed else None
        network_findings = network_result.findings if is_completed else []

        module_status["network"] = network_result.status
        if not is_completed:
            module_errors["network"] = network_result.error_message or f"Network analysis failed: {network_result.status}"
            analysis_status = "INCONCLUSIVE" if network_result.status in ("UNAVAILABLE", "TIMEOUT", "NO_TARGET_UID") else "FAILED"
        else:
            meaningful = [f for f in network_findings if f.score > 0]
            analysis_status = "COMPLETED_CLEAN" if (network_score == 0.0 and len(meaningful) == 0) else "COMPLETED_WITH_FINDINGS"

        module_scores_dict = {
            "static": None,
            "permissions": None,
            "dynamic": None,
            "network": network_score,
            "ble": None,
        }

        risk_output = self.risk_engine.calculate_overall_risk(
            module_scores=module_scores_dict,
            findings=network_findings,
        )

        module_scores = ModuleScores(
            static=None,
            permissions=None,
            dynamic=None,
            network=network_score,
            ble=None,
        )

        report = RiskReport(
            analysis_id=analysis_id,
            timestamp=now_iso,
            apk_filename=original_filename,
            overall_score=risk_output["overall_score"],
            risk_level=risk_output["risk_level"],
            analysis_status=analysis_status,
            module_scores=module_scores,
            module_status=module_status,
            module_errors=module_errors,
            findings=network_findings,
            summary=risk_output["summary"],
            static_details=None,
            permission_details=None,
            dynamic_details=None,
            network_details=network_result,
            analysis_profile="NETWORK_ONLY",
            duration_seconds=round(time.time() - start_time, 2),
            export_markdown_url=f"/api/analysis/{analysis_id}/export/markdown",
            export_json_url=f"/api/analysis/{analysis_id}",
        )

        self.save_report(report)
        return report

    def analyze_dynamic_only(
        self, apk_path: str, original_filename: str, avd_name: Optional[str] = None
    ) -> RiskReport:
        """Runs dynamic analysis only in emulator sandbox."""
        start_time = time.time()
        analysis_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()
        module_status = {
            "static": "NOT_REQUESTED",
            "permissions": "NOT_REQUESTED",
            "dynamic": "PENDING",
            "network": "NOT_REQUESTED",
            "ble": "NOT_IMPLEMENTED",
        }
        module_errors: Dict[str, Optional[str]] = {"dynamic": None}

        # Validate APK first
        static_res = self.static_analyzer.analyze(apk_path)
        if not static_res.is_valid_apk:
            raise InvalidAPKError(static_res.error_message or "Invalid or corrupted APK file")

        with self._emulator_execution_lock:
            dynamic_result = self.dynamic_worker.run_analysis(
                apk_path=apk_path,
                package_name=static_res.package_name,
                launchable_activity=static_res.launchable_activity,
                avd_name=avd_name,
            )

        is_completed = dynamic_result.status == "COMPLETED"
        dynamic_score = dynamic_result.score if is_completed else None
        dynamic_findings = dynamic_result.findings if is_completed else []

        module_status["dynamic"] = dynamic_result.status
        if not is_completed:
            module_errors["dynamic"] = dynamic_result.error_message or f"Dynamic analysis failed: {dynamic_result.status}"
            analysis_status = "INCONCLUSIVE" if dynamic_result.status in ("UNAVAILABLE", "TIMEOUT", "NO_LAUNCHABLE_ACTIVITY") else "FAILED"
        else:
            meaningful = [f for f in dynamic_findings if f.score > 0]
            analysis_status = "COMPLETED_CLEAN" if (dynamic_score == 0.0 and len(meaningful) == 0) else "COMPLETED_WITH_FINDINGS"

        module_scores_dict = {
            "static": None,
            "permissions": None,
            "dynamic": dynamic_score,
            "network": None,
            "ble": None,
        }

        risk_output = self.risk_engine.calculate_overall_risk(
            module_scores=module_scores_dict,
            findings=dynamic_findings,
        )

        module_scores = ModuleScores(
            static=None,
            permissions=None,
            dynamic=dynamic_score,
            network=None,
            ble=None,
        )

        report = RiskReport(
            analysis_id=analysis_id,
            timestamp=now_iso,
            apk_filename=original_filename,
            overall_score=risk_output["overall_score"],
            risk_level=risk_output["risk_level"],
            analysis_status=analysis_status,
            module_scores=module_scores,
            module_status=module_status,
            module_errors=module_errors,
            findings=dynamic_findings,
            summary=risk_output["summary"],
            static_details=None,
            permission_details=None,
            dynamic_details=dynamic_result,
            analysis_profile="DYNAMIC_ONLY",
            duration_seconds=round(time.time() - start_time, 2),
            export_markdown_url=f"/api/analysis/{analysis_id}/export/markdown",
            export_json_url=f"/api/analysis/{analysis_id}",
        )

        self.save_report(report)
        return report

    def analyze_static_only(self, apk_path: str, original_filename: str) -> RiskReport:
        """Runs static analysis only."""
        start_time = time.time()
        analysis_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()

        static_result: StaticAnalysisResult = self.static_analyzer.analyze(apk_path)
        if not static_result.is_valid_apk:
            raise InvalidAPKError(static_result.error_message or "Invalid or corrupted APK file")

        compatibility_result = None
        try:
            compatibility_result = self.evaluate_apk_compatibility(apk_path)
        except Exception:
            pass

        module_status = {
            "static": "COMPLETED",
            "permissions": "NOT_REQUESTED",
            "dynamic": "NOT_REQUESTED",
            "network": "NOT_REQUESTED",
            "ble": "NOT_IMPLEMENTED",
        }
        module_errors: Dict[str, Optional[str]] = {"static": None}

        module_scores_dict = {
            "static": static_result.score,
            "permissions": None,
            "dynamic": None,
            "network": None,
            "ble": None,
        }

        risk_output = self.risk_engine.calculate_overall_risk(
            module_scores=module_scores_dict,
            findings=static_result.findings,
        )

        meaningful = [f for f in static_result.findings if f.score > 0]
        analysis_status = (
            "COMPLETED_CLEAN"
            if (risk_output["overall_score"] == 0.0 and len(meaningful) == 0)
            else "COMPLETED_WITH_FINDINGS"
        )

        module_scores = ModuleScores(
            static=static_result.score,
            permissions=None,
            dynamic=None,
            network=None,
            ble=None,
        )

        report = RiskReport(
            analysis_id=analysis_id,
            timestamp=now_iso,
            apk_filename=original_filename,
            overall_score=risk_output["overall_score"],
            risk_level=risk_output["risk_level"],
            analysis_status=analysis_status,
            module_scores=module_scores,
            module_status=module_status,
            module_errors=module_errors,
            findings=static_result.findings,
            summary=risk_output["summary"],
            is_split=static_result.is_split,
            split_count=static_result.split_count,
            split_names=[],
            dex_file_count=static_result.dex_file_count,
            dex_files_analyzed=static_result.dex_files_analyzed,
            certificate_info=static_result.certificate_info,
            manifest_config=static_result.manifest_config,
            limitations=static_result.limitations,
            static_details=static_result,
            permission_details=None,
            sha256=static_result.sha256,
            framework=static_result.framework,
            native_abis=static_result.native_architectures,
            has_native_libraries=len(static_result.native_libraries) > 0,
            coverage_percent=risk_output.get("coverage_percent"),
            confidence_score=risk_output.get("confidence_score"),
            correlation_summary=risk_output.get("correlation_summary"),
            compatibility_details=compatibility_result,
            analysis_profile="STATIC_ONLY",
            duration_seconds=round(time.time() - start_time, 2),
            export_markdown_url=f"/api/analysis/{analysis_id}/export/markdown",
            export_json_url=f"/api/analysis/{analysis_id}",
        )

        self.save_report(report)
        return report

    def analyze_permissions_only(
        self, permissions: List[str], target_name: str = "manual_permissions_input"
    ) -> RiskReport:
        """Runs permission analysis on a provided list of permissions."""
        start_time = time.time()
        analysis_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()

        perm_result: PermissionAnalysisResult = self.permission_analyzer.analyze(permissions)

        module_status = {
            "static": "NOT_REQUESTED",
            "permissions": "COMPLETED",
            "dynamic": "NOT_REQUESTED",
            "network": "NOT_REQUESTED",
            "ble": "NOT_IMPLEMENTED",
        }
        module_errors: Dict[str, Optional[str]] = {"permissions": None}

        module_scores_dict = {
            "static": None,
            "permissions": perm_result.score,
            "dynamic": None,
            "network": None,
            "ble": None,
        }

        risk_output = self.risk_engine.calculate_overall_risk(
            module_scores=module_scores_dict,
            findings=perm_result.findings,
        )

        meaningful = [f for f in perm_result.findings if f.score > 0]
        analysis_status = (
            "COMPLETED_CLEAN"
            if (risk_output["overall_score"] == 0.0 and len(meaningful) == 0)
            else "COMPLETED_WITH_FINDINGS"
        )

        module_scores = ModuleScores(
            static=None,
            permissions=perm_result.score,
            dynamic=None,
            network=None,
            ble=None,
        )

        report = RiskReport(
            analysis_id=analysis_id,
            timestamp=now_iso,
            apk_filename=target_name,
            overall_score=risk_output["overall_score"],
            risk_level=risk_output["risk_level"],
            analysis_status=analysis_status,
            module_scores=module_scores,
            module_status=module_status,
            module_errors=module_errors,
            findings=perm_result.findings,
            summary=risk_output["summary"],
            static_details=None,
            permission_details=perm_result,
            analysis_profile="PERMISSIONS_ONLY",
            duration_seconds=round(time.time() - start_time, 2),
            export_markdown_url=f"/api/analysis/{analysis_id}/export/markdown",
            export_json_url=f"/api/analysis/{analysis_id}",
        )

        self.save_report(report)
        return report

    def save_report(self, report: RiskReport) -> None:
        """Saves a risk report to local JSON file under reports/."""
        report_file = self.reports_dir / f"{report.analysis_id}.json"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))

    def get_report_by_id(self, analysis_id: str) -> Optional[RiskReport]:
        """Safely loads a previously saved risk report.

        Returns None if the report file does not exist.
        Raises CorruptedReportError if the report file exists but is corrupted, truncated,
        or structurally invalid.
        """
        sanitized_id = os.path.basename(analysis_id.strip())
        report_file = self.reports_dir / f"{sanitized_id}.json"
        if not report_file.exists() or not report_file.is_file():
            return None

        try:
            with open(report_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
            logger.error("Failed to read/parse report file for %s: %s", sanitized_id, e)
            raise CorruptedReportError(f"Report '{sanitized_id}' is corrupted or unreadable JSON") from e

        if not isinstance(data, dict):
            raise CorruptedReportError(f"Report '{sanitized_id}' content is not a valid JSON object")

        try:
            return RiskReport.model_validate(data)
        except (ValidationError, Exception) as e:
            logger.error("Validation failed for report %s: %s", sanitized_id, e)
            raise CorruptedReportError(f"Report '{sanitized_id}' contains invalid or incomplete report schema") from e

    def list_reports(self, limit: int = 50) -> List[dict]:
        """Lists recent analysis report metadata, safely skipping corrupt or invalid files."""
        items = []
        files = sorted(
            self.reports_dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for f in files:
            if len(items) >= limit:
                break
            try:
                with open(f, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                if not isinstance(data, dict):
                    continue

                analysis_id = data.get("analysis_id")
                timestamp = data.get("timestamp")
                apk_filename = data.get("apk_filename")
                overall_score = data.get("overall_score")
                risk_level = data.get("risk_level")

                # Verify all required summary metadata fields are present and valid
                if not analysis_id or not timestamp or not apk_filename:
                    continue
                if risk_level is None or overall_score is None:
                    continue
                if not isinstance(overall_score, (int, float)):
                    continue

                items.append({
                    "analysis_id": str(analysis_id),
                    "timestamp": str(timestamp),
                    "apk_filename": str(apk_filename),
                    "overall_score": float(overall_score),
                    "risk_level": str(risk_level),
                })
            except Exception:
                continue
        return items

    def list_connected_devices(self) -> List[ConnectedDevice]:
        """Lists connected ADB devices with connection state and architecture properties."""
        return self.discovery_manager.list_devices()

    def list_device_packages(
        self, serial: str, include_system: bool = False
    ) -> List[DiscoveredPackage]:
        """Lists installed packages on target authorized device using explicit ADB serial targeting."""
        return self.discovery_manager.list_installed_packages(serial, include_system=include_system)

    def analyze_installed_package(
        self,
        serial: str,
        package_name: str,
        include_dynamic: bool = False,
        include_network: bool = False,
        avd_name: Optional[str] = None,
        analysis_profile: str = "STANDARD",
    ) -> RiskReport:
        """Safely pulls accessible APK for an installed package and executes multi-module analysis."""
        extracted = self.discovery_manager.extract_package_apk(serial, package_name)
        try:
            if not extracted.success:
                raise InvalidAPKError(extracted.error_message or "Failed to extract package APK from device")

            report = self.analyze_apk_full(
                apk_path=extracted.base_apk_path,
                original_filename=f"{package_name}.apk",
                include_dynamic=include_dynamic,
                include_network=include_network,
                avd_name=avd_name,
                is_split=extracted.is_split,
                split_count=extracted.split_count,
                analysis_profile=analysis_profile,
            )
            if extracted.warnings:
                for w in extracted.warnings:
                    if w not in report.limitations:
                        report.limitations.append(w)
            if extracted.is_split and (extracted.split_count == 0 or len(extracted.split_apk_paths) == 0):
                split_lim = (
                    "Package is a split APK installation analyzed without split slices; "
                    "dynamic features and architecture-specific native components may be missing or fail at runtime."
                )
                if split_lim not in report.limitations:
                    report.limitations.append(split_lim)
            return report
        finally:
            if extracted and extracted.temp_directory and os.path.exists(extracted.temp_directory):
                try:
                    shutil.rmtree(extracted.temp_directory, ignore_errors=True)
                except Exception:
                    pass

    def evaluate_apk_compatibility(
        self, apk_path: str, preferred_avd: Optional[str] = None
    ) -> CompatibilityReport:
        """Evaluates execution compatibility of an APK file against configured host AVDs and running emulators."""
        intake_res = self.static_analyzer.intake.validate_and_intake(apk_path)
        if not intake_res.is_valid:
            raise InvalidAPKError(intake_res.error_message or "Invalid or corrupted APK file")
        return self.compatibility_engine.evaluate(
            intake_result=intake_res,
            preferred_avd=preferred_avd,
        )

    def generate_markdown_report(self, report: RiskReport) -> str:
        """Generates a comprehensive, human-readable Markdown export of analysis results."""
        md = []
        md.append(f"# SpyAware Analysis Report: {report.apk_filename}")
        md.append(f"**Analysis ID**: `{report.analysis_id}`  ")
        md.append(f"**Timestamp**: {report.timestamp}  ")
        md.append(f"**Overall Risk**: **{report.risk_level}** ({report.overall_score:.1f}/100)  ")
        md.append(f"**Analysis Status**: `{report.analysis_status}`  ")
        if report.sha256:
            md.append(f"**SHA-256**: `{report.sha256}`  ")
        if report.framework:
            md.append(f"**Framework**: `{report.framework}`  ")
        if report.native_abis:
            md.append(f"**Native ABIs**: {', '.join(report.native_abis)}  ")
        if report.analysis_profile:
            md.append(f"**Analysis Profile**: `{report.analysis_profile}`  ")
        if report.duration_seconds is not None:
            md.append(f"**Execution Duration**: {report.duration_seconds:.2f}s  ")
        md.append("")
        if report.compatibility_details:
            cd = report.compatibility_details
            st = getattr(cd, "overall_status", None) or getattr(cd, "status", "UNKNOWN")
            status_val = st.value if hasattr(st, "value") else str(st)
            md.append("## Android Execution Compatibility")
            md.append(f"- **Compatibility Status**: `{status_val}`")
            sel = getattr(cd, "selected_target", None)
            if sel:
                disp = getattr(sel, "display_name", getattr(sel, "target_id", "Default Target"))
                api = getattr(sel, "api_level", None)
                api_str = f" (API {api})" if api else ""
                md.append(f"- **Selected Environment**: {disp}{api_str}")
            if getattr(cd, "apk_native_abis", None):
                md.append(f"- **APK Required ABIs**: {', '.join(cd.apk_native_abis)}")
            if getattr(cd, "warnings", None):
                for w in cd.warnings:
                    md.append(f"- *Compatibility Notice*: {w}")
            md.append("")
        md.append("## Executive Summary")
        md.append(report.summary)
        md.append("")
        md.append("## Module Risk Scores")
        md.append(f"- **Static Analysis**: {report.module_scores.static if report.module_scores.static is not None else 'N/A'}")
        md.append(f"- **Permission Analysis**: {report.module_scores.permissions if report.module_scores.permissions is not None else 'N/A'}")
        md.append(f"- **Dynamic Analysis**: {report.module_scores.dynamic if report.module_scores.dynamic is not None else 'N/A'}")
        md.append(f"- **Network Analysis**: {report.module_scores.network if report.module_scores.network is not None else 'N/A'}")
        md.append("")
        if report.coverage_percent is not None:
            conf_str = f"{report.confidence_score:.2f}" if report.confidence_score is not None else "N/A"
            md.append(f"**Analysis Coverage**: {report.coverage_percent:.1f}% | **Confidence Score**: {conf_str}")
            md.append("")
        if report.correlation_summary:
            md.append("## Correlated Surveillance Evidence")
            for cat, status in report.correlation_summary.items():
                md.append(f"- **{cat}**: `{status}`")
            md.append("")
        if report.findings:
            md.append(f"## Key Security Findings ({len(report.findings)})")
            for i, f in enumerate(report.findings[:35], 1):
                rule = f" [`{f.rule_id}`]" if f.rule_id else ""
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                md.append(f"### {i}. [{sev}] {f.title}{rule}")
                md.append(f"- **Description**: {f.description}")
                md.append(f"- **Evidence Source**: `{f.evidence_source}` | **Confidence**: {f.confidence:.2f}")
                md.append(f"- **Evidence**: `{f.evidence}`")
                if f.remediation:
                    md.append(f"- **Remediation**: {f.remediation}")
                md.append("")
        if report.limitations:
            md.append("## Analysis Limitations")
            for lim in report.limitations:
                md.append(f"- {lim}")
            md.append("")
        md.append("---")
        md.append(f"*{report.disclaimer}*")
        return "\n".join(md)

    def compare_analyses(
        self, base_analysis_id: str, target_analysis_id: str
    ) -> Optional[AnalysisComparisonReport]:
        """Compares two historical analysis reports by ID, returning structured differences."""
        base_report = self.get_report_by_id(base_analysis_id)
        if not base_report:
            return None
        target_report = self.get_report_by_id(target_analysis_id)
        if not target_report:
            return None
        return self.comparison_service.compare_analyses(base_report, target_report)

    def generate_comparison_markdown(
        self, comp_report: AnalysisComparisonReport
    ) -> str:
        """Renders an AnalysisComparisonReport as human-readable Markdown."""
        return self.comparison_service.generate_markdown_report(comp_report)


