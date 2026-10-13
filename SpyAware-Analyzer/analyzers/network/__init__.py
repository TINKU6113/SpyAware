"""Network analysis module for SpyAware-Analyzer (Stage 2C Milestone 1).

Performs network socket observation, address decoding, and strict UID-to-package
target attribution without packet decryption or TLS interception.
"""

from analyzers.network.models import (
    NetworkAnalysisResult,
    NetworkAttributionStatus,
    NetworkBehaviorCategory,
    NetworkBehaviorStatus,
    NetworkEvent,
    NetworkObservation,
)
from analyzers.network.collector import NetworkCollector
from analyzers.network.observer import NetworkObserver
from analyzers.network.worker import NetworkWorker

__all__ = [
    "NetworkAnalysisResult",
    "NetworkAttributionStatus",
    "NetworkBehaviorCategory",
    "NetworkBehaviorStatus",
    "NetworkEvent",
    "NetworkObservation",
    "NetworkCollector",
    "NetworkObserver",
    "NetworkWorker",
]
