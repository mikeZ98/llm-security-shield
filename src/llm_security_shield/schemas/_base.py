"""Shared base model and primitives used by every schema in the package."""

from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ShieldModel(BaseModel):
    """Immutable, strictly validated base for every schema in the package."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class OwaspCategory(StrEnum):
    """OWASP Top 10 for LLM Applications (2025) risk identifiers."""

    PROMPT_INJECTION = "LLM01"
    SENSITIVE_INFORMATION_DISCLOSURE = "LLM02"
    SUPPLY_CHAIN = "LLM03"
    DATA_AND_MODEL_POISONING = "LLM04"
    IMPROPER_OUTPUT_HANDLING = "LLM05"
    EXCESSIVE_AGENCY = "LLM06"
    SYSTEM_PROMPT_LEAKAGE = "LLM07"
    VECTOR_AND_EMBEDDING_WEAKNESSES = "LLM08"
    MISINFORMATION = "LLM09"
    UNBOUNDED_CONSUMPTION = "LLM10"


class Severity(StrEnum):
    """Ordered severity scale; compare with :attr:`rank`, not string order."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric position on the scale (``LOW`` is 0)."""
        return list(Severity).index(self)


class TextSpan(ShieldModel):
    """Half-open ``[start, end)`` character range within an inspected text."""

    start: int = Field(ge=0)
    end: int = Field(ge=0)

    @model_validator(mode="after")
    def _check_order(self) -> Self:
        if self.end <= self.start:
            raise ValueError("span end must be greater than start")
        return self
