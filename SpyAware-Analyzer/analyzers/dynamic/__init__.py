"""Dynamic Analysis Package for SpyAware-Analyzer (Stage 2A).

Provides Android emulator and ADB runtime sandboxing, lifecycle monitoring,
logcat indicator observation, and environment diagnostics.
"""

from analyzers.dynamic.environment import EnvironmentDiscovery
from analyzers.dynamic.models import (
    DynamicAnalysisResult,
    EnvironmentStatus,
    ExecutionMetadata,
    Observation,
)
from analyzers.dynamic.observer import DynamicObserver
from analyzers.dynamic.runner import DynamicRunner
from analyzers.dynamic.worker import DynamicWorker

__all__ = [
    "DynamicWorker",
    "DynamicRunner",
    "DynamicObserver",
    "EnvironmentDiscovery",
    "DynamicAnalysisResult",
    "EnvironmentStatus",
    "ExecutionMetadata",
    "Observation",
]
