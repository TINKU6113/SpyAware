"""Pydantic data models for universal APK intake, validation, and metadata extraction.

Part of Milestone M3.0 (Universal APK Intake and Validation).
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.models.analysis import CertificateInfo, ExportedComponent


class IntakeStatus(str, Enum):
    VALID = "VALID"
    VALID_WITH_WARNINGS = "VALID_WITH_WARNINGS"
    INVALID_ARCHIVE = "INVALID_ARCHIVE"
    MALFORMED_MANIFEST = "MALFORMED_MANIFEST"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    ZIP_BOMB_DETECTED = "ZIP_BOMB_DETECTED"
    CORRUPTED = "CORRUPTED"
    EMPTY_FILE = "EMPTY_FILE"
    NOT_FOUND = "NOT_FOUND"


class FrameworkType(str, Enum):
    JAVA_KOTLIN = "JAVA_KOTLIN"
    FLUTTER = "FLUTTER"
    REACT_NATIVE = "REACT_NATIVE"
    UNITY = "UNITY"
    NATIVE_ONLY = "NATIVE_ONLY"
    HYBRID = "HYBRID"
    UNKNOWN = "UNKNOWN"


class FrameworkIndicator(BaseModel):
    framework: FrameworkType = FrameworkType.UNKNOWN
    confidence: float = Field(1.0, description="Confidence metric (0.0 to 1.0)")
    evidence: List[str] = Field(default_factory=list, description="Files or strings proving framework usage")
    details: Optional[str] = None


class APKHashes(BaseModel):
    sha256: str
    sha1: str
    md5: str


class APKMetadata(BaseModel):
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    max_sdk: Optional[int] = None
    permissions: List[str] = Field(default_factory=list)
    activities: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    receivers: List[str] = Field(default_factory=list)
    providers: List[str] = Field(default_factory=list)
    exported_components: List[ExportedComponent] = Field(default_factory=list)
    launchable_activity: Optional[str] = None
    certificate: Optional[CertificateInfo] = None


class SplitPackageInfo(BaseModel):
    is_split: bool = False
    is_base_apk: bool = True
    split_count: int = 0
    split_names: List[str] = Field(default_factory=list)
    missing_required_splits: bool = False
    notes: Optional[str] = None


class PackingIndicators(BaseModel):
    is_packed: bool = False
    packer_name: Optional[str] = None
    has_dynamic_code_loading: bool = False
    has_in_memory_dex: bool = False
    obfuscation_detected: bool = False
    evidence: List[str] = Field(default_factory=list)


class APKIntakeResult(BaseModel):
    status: IntakeStatus
    is_valid: bool = True
    file_path: str
    file_name: str
    file_size_bytes: int = 0
    hashes: Optional[APKHashes] = None
    metadata: Optional[APKMetadata] = None
    native_abis: List[str] = Field(default_factory=list)
    has_native_libraries: bool = False
    framework: FrameworkIndicator = Field(default_factory=FrameworkIndicator)
    split_info: SplitPackageInfo = Field(default_factory=SplitPackageInfo)
    packing_info: PackingIndicators = Field(default_factory=PackingIndicators)
    dex_file_count: int = 0
    dex_files: List[str] = Field(default_factory=list)
    archive_entry_count: int = 0
    uncompressed_size_bytes: int = 0
    compression_ratio: float = 0.0
    parser_name: str = "SpyAware Universal Intake v3.0"
    parser_version: str = "3.0.0"
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    unsupported_characteristics: List[str] = Field(default_factory=list)

    @property
    def error_message(self) -> Optional[str]:
        return "; ".join(self.errors) if self.errors else None

