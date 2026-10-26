"""Prompt-injection and jailbreak detection results (OWASP LLM01, LLM07)."""

from typing import Annotated

from pydantic import Field, StringConstraints

from llm_security_shield.schemas._base import OwaspCategory, Severity, ShieldModel, TextSpan

RuleId = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
]


class DetectionFinding(ShieldModel):
    """A single detector hit against an inspected text."""

    rule_id: RuleId
    category: OwaspCategory
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    description: str = Field(min_length=1, max_length=256)
    span: TextSpan | None = None


class DetectionResult(ShieldModel):
    """Aggregate verdict of all detectors run over one text."""

    findings: tuple[DetectionFinding, ...] = ()
    risk_score: float = Field(ge=0.0, le=1.0)
    blocked: bool

    @property
    def max_severity(self) -> Severity | None:
        """Highest severity among the findings, or ``None`` when there are none."""
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)
