"""Runtime configuration, loaded from ``SHIELD_*`` environment variables.

Unlike the schemas, settings are not ``strict``: environment values always arrive as
strings (lists as JSON), so lax coercion is required. Bounds are enforced explicitly.
"""

from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from llm_security_shield.core.sanitizer import ThreatCategory
from llm_security_shield.schemas import Severity

AuditLogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class ShieldSettings(BaseSettings):
    """Validated, immutable shield configuration."""

    model_config = SettingsConfigDict(
        env_prefix="SHIELD_", extra="forbid", frozen=True, validate_default=True
    )

    injection_risk_threshold: float = Field(default=0.7, gt=0.0, le=1.0)
    """Aggregate risk score at or above which a prompt is blocked."""

    block_on_severity: Severity | None = Severity.CRITICAL
    """Block on any single finding at or above this severity; ``None`` disables."""

    enabled_threats: frozenset[ThreatCategory] = frozenset(ThreatCategory)
    """Threat families the heuristic sanitizer reports. Must not be empty."""

    max_input_chars: int = Field(default=32_000, ge=1, le=1_000_000)
    """Inputs longer than this are rejected unscanned (OWASP LLM10)."""

    vault_ttl_seconds: int = Field(default=900, ge=1, le=86_400)
    vault_max_entries: int = Field(default=10_000, ge=1, le=1_000_000)

    audit_log_level: AuditLogLevel = "INFO"
    """Level at which per-request audit events are emitted."""

    @field_validator("enabled_threats")
    @classmethod
    def _require_threats(cls, value: frozenset[ThreatCategory]) -> frozenset[ThreatCategory]:
        if not value:
            raise ValueError("at least one threat category must be enabled")
        return value

    @field_validator("audit_log_level", mode="before")
    @classmethod
    def _upper_level(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value
