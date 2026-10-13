"""FastAPI API routes for SpyAware-Analyzer.

Provides endpoints for health checks, static analysis, permission analysis,
combined full analysis, and analysis report retrieval.
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from backend.models.analysis import RiskReport
from backend.models.comparison import AnalysisComparisonReport, ComparisonRequest
from backend.services.analysis_service import (
    AnalysisService,
    CorruptedReportError,
    InvalidAPKError,
    MAX_UPLOAD_SIZE_BYTES,
    get_max_upload_bytes,
)

from analyzers.dynamic.models import AVDInventory, EnvironmentStatus
from analyzers.dynamic.compatibility import CompatibilityReport
from analyzers.discovery.models import ConnectedDevice, DiscoveredPackage

router = APIRouter(prefix="/api", tags=["SpyAware Analyzer"])
analysis_service = AnalysisService()


class PermissionListPayload(BaseModel):
    permissions: List[str]
    target_name: Optional[str] = "Manual Permissions Input"


@router.get("/health")
def health_check():
    """Health check endpoint indicating platform status, module readiness, and runtime capabilities."""
    env_status = analysis_service.get_dynamic_environment()

    def _resolve_runtime_status(env: EnvironmentStatus) -> str:
        if env.running_devices:
            return "AVAILABLE"
        elif env.ready:
            return "CONFIGURED"
        elif env.adb_available and env.emulator_available:
            return "UNAVAILABLE_EMULATOR_OFFLINE"
        else:
            return "UNAVAILABLE_MISSING_DEPENDENCIES"

    dynamic_status = _resolve_runtime_status(env_status)
    network_status = _resolve_runtime_status(env_status)

    return {
        "status": "healthy",
        "service": "SpyAware-Analyzer",
        "version": "1.0.0",
        "description": "Android Covert Surveillance Analysis Platform",
        "modules": {
            "static": "AVAILABLE",
            "permissions": "AVAILABLE",
            "dynamic": dynamic_status,
            "network": network_status,
            "ble": "COMING_SOON",
        },
        "capabilities": {
            "static": {
                "implemented": True,
                "status": "AVAILABLE",
                "description": "Static DEX bytecode and manifest component inspection",
            },
            "permissions": {
                "implemented": True,
                "status": "AVAILABLE",
                "description": "Manifest permission and synergistic combination analysis",
            },
            "dynamic": {
                "implemented": True,
                "status": dynamic_status,
                "description": "Stage 2B Android runtime behavioral observation",
                "runtime_ready": env_status.ready,
                "live_device": bool(env_status.running_devices),
            },
            "network": {
                "implemented": True,
                "status": network_status,
                "description": "Stage 2C kernel socket telemetry and C2 destination attribution",
                "runtime_ready": env_status.ready,
                "live_device": bool(env_status.running_devices),
            },
            "ble": {
                "implemented": False,
                "status": "COMING_SOON",
                "description": "Bluetooth Low Energy surveillance beacon tracking",
            },
        },
        "environment": {
            "adb_available": env_status.adb_available,
            "emulator_available": env_status.emulator_available,
            "avd_available": bool(env_status.available_avds),
            "running_devices": env_status.running_devices,
            "ready": env_status.ready,
            "message": env_status.message,
        },
    }


@router.get("/dynamic/environment", response_model=EnvironmentStatus)
def get_dynamic_environment_endpoint():
    """Diagnostic endpoint checking availability of adb, emulator, and AVDs."""
    return analysis_service.get_dynamic_environment()


def _save_upload_to_temp(file: UploadFile) -> str:
    """Safely saves an uploaded file to a temporary location, enforcing size limits."""
    filename = file.filename or "uploaded.apk"
    # Basic filename sanitization
    safe_suffix = os.path.splitext(filename)[1].lower()
    if safe_suffix not in (".apk", ".zip"):
        safe_suffix = ".apk"

    fd, temp_path = tempfile.mkstemp(prefix="spyaware_upload_", suffix=safe_suffix)
    bytes_written = 0

    try:
        with os.fdopen(fd, "wb") as out_f:
            while True:
                chunk = file.file.read(1024 * 1024)  # 1MB chunks
                if not chunk:
                    break
                bytes_written += len(chunk)
                max_bytes = get_max_upload_bytes()
                if bytes_written > max_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File exceeds maximum allowed upload size of {max_bytes // (1024 * 1024)} MB",
                    )
                out_f.write(chunk)

        if bytes_written == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded APK file is empty (0 bytes).",
            )
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise

    return temp_path


@router.post("/analyze", response_model=RiskReport)
async def analyze_full_apk(
    file: UploadFile = File(...),
    dynamic: bool = False,
    network: bool = False,
    avd: Optional[str] = None,
    is_split: bool = False,
    split_count: int = 0,
    split_names: Optional[str] = None,
    profile: Optional[str] = "STANDARD",
):
    """Upload and run full multi-module analysis on an Android APK.
    
    Executes:
    1. Static manifest & DEX bytecode indicator analysis
    2. Dedicated permission analysis (individual & synergistic combinations)
    3. Multi-module bounded risk scoring & report generation
    (Optionally executes dynamic analysis if dynamic=True, network analysis if network=True)
    """
    original_filename = file.filename or "unknown.apk"
    temp_path = None
    try:
        temp_path = _save_upload_to_temp(file)
        parsed_splits = [s.strip() for s in split_names.split(",") if s.strip()] if split_names else []
        report = analysis_service.analyze_apk_full(
            apk_path=temp_path,
            original_filename=original_filename,
            include_dynamic=dynamic,
            include_network=network,
            avd_name=avd,
            is_split=is_split,
            split_count=split_count,
            split_names=parsed_splits,
            analysis_profile=profile or "STANDARD",
        )
        return report
    except InvalidAPKError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid APK file: {str(e)}",
        )
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


@router.post("/analyze/static", response_model=RiskReport)
async def analyze_static_only_endpoint(file: UploadFile = File(...)):
    """Run static analysis only on an uploaded Android APK."""
    original_filename = file.filename or "unknown.apk"
    temp_path = None
    try:
        temp_path = _save_upload_to_temp(file)
        report = analysis_service.analyze_static_only(
            apk_path=temp_path, original_filename=original_filename
        )
        return report
    except InvalidAPKError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid APK file: {str(e)}",
        )
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


@router.post("/analyze/dynamic", response_model=RiskReport)
async def analyze_dynamic_only_endpoint(
    file: UploadFile = File(...),
    avd: Optional[str] = None,
):
    """Run dynamic emulator execution analysis only on an uploaded Android APK."""
    original_filename = file.filename or "unknown.apk"
    temp_path = None
    try:
        temp_path = _save_upload_to_temp(file)
        report = analysis_service.analyze_dynamic_only(
            apk_path=temp_path, original_filename=original_filename, avd_name=avd
        )
        return report
    except InvalidAPKError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid APK file: {str(e)}",
        )
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


@router.post("/analyze/network", response_model=RiskReport)
async def analyze_network_only_endpoint(
    file: UploadFile = File(...),
    avd: Optional[str] = None,
):
    """Run dynamic network socket analysis only on an uploaded Android APK."""
    original_filename = file.filename or "unknown.apk"
    temp_path = None
    try:
        temp_path = _save_upload_to_temp(file)
        report = analysis_service.analyze_network_only(
            apk_path=temp_path, original_filename=original_filename, avd_name=avd
        )
        return report
    except InvalidAPKError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid APK file: {str(e)}",
        )
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


@router.post("/analyze/permissions", response_model=RiskReport)
async def analyze_permissions_endpoint(
    request: Request,
    file: Optional[UploadFile] = None,
):
    """Run dedicated permission analysis on an APK upload OR raw permission list.
    
    Accepts either multipart APK file upload OR JSON body containing permission strings.
    """
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        body = await request.json()
        permissions = body.get("permissions", [])
        if not permissions and not isinstance(permissions, list):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="JSON body must contain a 'permissions' array.",
            )
        target_name = body.get("target_name", "Manual Permissions Input")
        return analysis_service.analyze_permissions_only(
            permissions=permissions, target_name=target_name
        )

    # Check multipart file upload
    if file is not None and file.filename:
        original_filename = file.filename
        temp_path = None
        try:
            temp_path = _save_upload_to_temp(file)
            static_res = analysis_service.static_analyzer.analyze(temp_path)
            if not static_res.is_valid_apk:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid APK file: {static_res.error_message or 'Corrupt or unparseable APK'}",
                )
            perms = static_res.requested_permissions
            report = analysis_service.analyze_permissions_only(
                permissions=perms, target_name=original_filename
            )
            return report
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    # Check form-data without file parameter (e.g., direct form upload)
    try:
        form = await request.form()
        uploaded = form.get("file")
        if uploaded and hasattr(uploaded, "filename") and uploaded.filename:
            temp_path = None
            try:
                temp_path = _save_upload_to_temp(uploaded)
                static_res = analysis_service.static_analyzer.analyze(temp_path)
                if not static_res.is_valid_apk:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid APK file: {static_res.error_message or 'Corrupt or unparseable APK'}",
                    )
                perms = static_res.requested_permissions
                return analysis_service.analyze_permissions_only(
                    permissions=perms, target_name=uploaded.filename
                )
            finally:
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except OSError:
                        pass
    except HTTPException:
        raise
    except Exception:
        pass

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Either an APK file upload or a JSON permission list must be provided.",
    )


@router.get("/analysis/{analysis_id}", response_model=RiskReport)
def get_analysis_report(analysis_id: str):
    """Retrieve a previously generated analysis report by ID."""
    safe_id = os.path.basename(analysis_id.strip())
    try:
        report = analysis_service.get_report_by_id(safe_id)
    except CorruptedReportError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis report '{safe_id}' is corrupted or unreadable",
        )
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis report '{safe_id}' not found",
        )
    return report


@router.get("/analyses")
def list_recent_analyses(limit: int = 20):
    """List recently completed analysis reports."""
    return analysis_service.list_reports(limit=limit)


@router.post("/analyze/sample/{sample_name}", response_model=RiskReport)
def analyze_sample_preset(sample_name: str):
    """Run full analysis on one of the pre-bundled synthetic sample APKs."""
    samples_dir = Path(__file__).resolve().parent.parent.parent / "samples"
    safe_name = os.path.basename(sample_name)
    if not safe_name.endswith(".apk"):
        safe_name = f"{safe_name}.apk"
    target_path = samples_dir / safe_name
    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample APK '{safe_name}' not found in samples directory",
        )
    is_network_sample = safe_name.lower() == "network_positive_sample.apk"
    try:
        return analysis_service.analyze_apk_full(
            str(target_path),
            safe_name,
            include_network=is_network_sample,
        )
    except InvalidAPKError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid sample APK: {str(e)}",
        )


@router.get("/dynamic/inventory", response_model=AVDInventory)
def get_dynamic_inventory():
    """Retrieve full inventory of configured AVD profiles, supported ABIs, and installed system images."""
    return analysis_service.dynamic_worker.env_discovery.get_avd_inventory()


@router.get("/devices", response_model=List[ConnectedDevice])
def list_connected_devices():
    """List connected ADB devices with authorization state, model, and ABI architecture."""
    return analysis_service.list_connected_devices()


@router.get("/devices/{serial}/packages", response_model=List[DiscoveredPackage])
def list_device_packages(serial: str, include_system: bool = False):
    """Enumerate installed packages on target authorized device using explicit ADB serial targeting."""
    safe_serial = os.path.basename(serial.strip())
    try:
        return analysis_service.list_device_packages(serial=safe_serial, include_system=include_system)
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except ConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e),
        )
    except TimeoutError as e:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=str(e),
        )
    except RuntimeError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)


@router.post("/devices/{serial}/packages/{package_name}/analyze", response_model=RiskReport)
def analyze_installed_package_endpoint(
    serial: str,
    package_name: str,
    dynamic: bool = False,
    network: bool = False,
    avd: Optional[str] = None,
    profile: Optional[str] = "STANDARD",
):
    """Safely extracts an installed package APK from an authorized device and executes analysis."""
    safe_serial = os.path.basename(serial.strip())
    safe_package = os.path.basename(package_name.strip())
    try:
        return analysis_service.analyze_installed_package(
            serial=safe_serial,
            package_name=safe_package,
            include_dynamic=dynamic,
            include_network=network,
            avd_name=avd,
            analysis_profile=profile or "STANDARD",
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except ConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e),
        )
    except TimeoutError as e:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=str(e),
        )
    except InvalidAPKError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to analyze device package: {str(e)}",
        )
    except RuntimeError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal error analyzing package '{safe_package}': {str(e)}",
        )


@router.post("/compatibility/check", response_model=CompatibilityReport)
async def check_apk_compatibility(
    file: UploadFile = File(...),
    avd: Optional[str] = None,
):
    """Evaluate execution compatibility of an APK file against configured host AVDs and running emulators."""
    temp_path = None
    try:
        temp_path = _save_upload_to_temp(file)
        return analysis_service.evaluate_apk_compatibility(
            apk_path=temp_path, preferred_avd=avd
        )
    except InvalidAPKError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid APK file for compatibility check: {str(e)}",
        )
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


@router.get("/analysis/{analysis_id}/export/markdown", response_class=PlainTextResponse)
def export_analysis_markdown(analysis_id: str):
    """Export a comprehensive human-readable Markdown analysis report."""
    safe_id = os.path.basename(analysis_id.strip())
    try:
        report = analysis_service.get_report_by_id(safe_id)
    except CorruptedReportError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis report '{safe_id}' is corrupted or unreadable",
        )
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis report '{safe_id}' not found",
        )
    md_content = analysis_service.generate_markdown_report(report)
    return PlainTextResponse(content=md_content, media_type="text/markdown")


@router.post("/analyses/compare", response_model=AnalysisComparisonReport)
def compare_analyses(request: ComparisonRequest):
    """Compares two historical analysis reports by ID, identifying finding and risk score deltas."""
    safe_base = os.path.basename(request.base_analysis_id.strip())
    safe_target = os.path.basename(request.target_analysis_id.strip())

    try:
        base_rep = analysis_service.get_report_by_id(safe_base)
        if not base_rep:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Base analysis report '{safe_base}' not found",
            )
        target_rep = analysis_service.get_report_by_id(safe_target)
        if not target_rep:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target analysis report '{safe_target}' not found",
            )
        return analysis_service.comparison_service.compare_analyses(base_rep, target_rep)
    except CorruptedReportError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Corrupted report encountered during comparison: {str(e)}",
        )


@router.get("/analyses/compare/{base_id}/{target_id}/export/markdown", response_class=PlainTextResponse)
def export_comparison_markdown(base_id: str, target_id: str):
    """Export a comprehensive Markdown diff report comparing two historical analyses."""
    safe_base = os.path.basename(base_id.strip())
    safe_target = os.path.basename(target_id.strip())

    try:
        base_rep = analysis_service.get_report_by_id(safe_base)
        if not base_rep:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Base analysis report '{safe_base}' not found",
            )
        target_rep = analysis_service.get_report_by_id(safe_target)
        if not target_rep:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target analysis report '{safe_target}' not found",
            )
        comp = analysis_service.comparison_service.compare_analyses(base_rep, target_rep)
        md = analysis_service.generate_comparison_markdown(comp)
        return PlainTextResponse(content=md, media_type="text/markdown")
    except CorruptedReportError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Corrupted report encountered during comparison: {str(e)}",
        )



