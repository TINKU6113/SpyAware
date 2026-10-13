"""Pydantic models for ADB device discovery, package enumeration, and safe APK extraction.

Part of Milestone M3.2 (Installed-Application Discovery).
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DeviceState(str, Enum):
    DEVICE = "device"
    OFFLINE = "offline"
    UNAUTHORIZED = "unauthorized"
    AUTHORIZING = "authorizing"
    RECOVERY = "recovery"
    MISSING = "missing"
    UNKNOWN = "unknown"


class DeviceType(str, Enum):
    EMULATOR = "EMULATOR"
    PHYSICAL = "PHYSICAL"
    UNKNOWN = "UNKNOWN"


class ConnectedDevice(BaseModel):
    serial: str = Field(..., description="Unique ADB device serial identifier")
    state: DeviceState = Field(DeviceState.DEVICE, description="ADB connection status")
    is_authorized: bool = Field(True, description="Whether device is authorized for ADB commands")
    is_online: bool = Field(True, description="Whether device is currently reachable")
    device_type: DeviceType = Field(DeviceType.UNKNOWN, description="EMULATOR or PHYSICAL")
    model: Optional[str] = None
    product: Optional[str] = None
    android_version: Optional[str] = None
    api_level: Optional[int] = None
    abi: Optional[str] = None
    supported_abis: List[str] = Field(default_factory=list)
    avd_name: Optional[str] = None


class DiscoveredPackage(BaseModel):
    package_name: str
    app_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    is_system: bool = False
    is_split: bool = False
    base_apk_path: Optional[str] = None
    split_apk_paths: List[str] = Field(default_factory=list)
    split_count: int = 0
    apk_size_bytes: Optional[int] = None
    extraction_permitted: bool = True
    extraction_error: Optional[str] = None


class ExtractedAPK(BaseModel):
    package_name: str
    base_apk_path: str
    split_apk_paths: List[str] = Field(default_factory=list)
    is_split: bool = False
    split_count: int = 0
    temp_directory: Optional[str] = None
    warnings: List[str] = Field(default_factory=list)
    success: bool = True
    error_message: Optional[str] = None
