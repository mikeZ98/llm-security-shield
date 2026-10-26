"""Core security engine: configuration, heuristics, token vault and orchestration."""

from llm_security_shield.core.config import AuditLogLevel, ShieldSettings
from llm_security_shield.core.engine import (
    Detector,
    DetectorFailureError,
    SecurityShieldEngine,
    ShieldBlockedError,
    risk_score,
)
from llm_security_shield.core.sanitizer import HeuristicSanitizer, ThreatCategory, threat_of
from llm_security_shield.core.vault import (
    TokenVault,
    VaultError,
    VaultFullError,
    VaultIntegrityError,
)

__all__ = [
    "AuditLogLevel",
    "Detector",
    "DetectorFailureError",
    "HeuristicSanitizer",
    "SecurityShieldEngine",
    "ShieldBlockedError",
    "ShieldSettings",
    "ThreatCategory",
    "TokenVault",
    "VaultError",
    "VaultFullError",
    "VaultIntegrityError",
    "risk_score",
    "threat_of",
]
