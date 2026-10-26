"""HTTP-layer configuration, loaded from ``SHIELD_API_*`` environment variables.

Like :class:`~llm_security_shield.core.config.ShieldSettings`, not ``strict``: environment
values always arrive as strings (collections as JSON).
"""

import posixpath
from pathlib import Path
from typing import Final

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

API_PREFIX: Final = "/v1/shield"
_MIB: Final = 1024 * 1024


def normalize_path(path: str) -> str:
    """Collapse ``..``, ``.`` and duplicate slashes so prefix checks cannot be sidestepped."""
    return "/" + posixpath.normpath(path or "/").lstrip("/")


def path_under(path: str, prefix: str) -> bool:
    """Whether normalized ``path`` equals ``prefix`` or lies below it (``/`` matches all)."""
    base = prefix.rstrip("/")
    return not base or path == base or path.startswith(base + "/")


class ApiSettings(BaseSettings):
    """Validated, immutable middleware and endpoint configuration."""

    model_config = SettingsConfigDict(
        env_prefix="SHIELD_API_", extra="forbid", frozen=True, validate_default=True
    )

    api_key: SecretStr | None = None
    """Required by every ``/v1/shield`` endpoint except health; enables deanonymization."""

    protected_path_prefixes: tuple[str, ...] = ("/",)
    """Requests under these prefixes are inspected and their responses redacted."""

    excluded_path_prefixes: tuple[str, ...] = (API_PREFIX, "/docs", "/redoc", "/openapi.json")
    """Never inspected. The shield's own API must stay excluded: it handles raw prompts and PII."""

    prompt_fields: frozenset[str] | None = None
    """JSON/form/query keys holding prompt text; ``None`` scans every string value."""

    response_fields: frozenset[str] | None = None
    """JSON keys whose string values are redacted; ``None`` redacts every string value."""

    scan_requests: bool = True
    redact_responses: bool = True

    max_request_bytes: int = Field(default=_MIB, ge=1, le=64 * _MIB)
    max_response_bytes: int = Field(default=4 * _MIB, ge=1, le=256 * _MIB)
    max_stream_buffer_bytes: int = Field(default=64 * 1024, ge=1024, le=16 * _MIB)
    """Largest partial SSE event or line held back while waiting for its delimiter."""

    max_sessions: int = Field(default=1_000, ge=1, le=1_000_000)
    sandbox_roots: tuple[str, ...] = ()
    tool_policy_file: Path | None = None

    @field_validator("api_key")
    @classmethod
    def _key_strength(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < 32:  # noqa: PLR2004
            raise ValueError("api_key must be at least 32 characters")
        return value

    @field_validator("protected_path_prefixes", "excluded_path_prefixes")
    @classmethod
    def _absolute_prefixes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if bad := [p for p in value if not p.startswith("/")]:
            raise ValueError(f"path prefixes must start with '/': {bad}")
        return value

    @field_validator("prompt_fields", "response_fields")
    @classmethod
    def _lower_fields(cls, value: frozenset[str] | None) -> frozenset[str] | None:
        return None if value is None else frozenset(v.lower() for v in value)

    def is_protected(self, path: str) -> bool:
        """Whether requests to ``path`` are inspected and their responses redacted."""
        normalized = normalize_path(path)
        return any(path_under(normalized, p) for p in self.protected_path_prefixes) and not any(
            path_under(normalized, p) for p in self.excluded_path_prefixes
        )
