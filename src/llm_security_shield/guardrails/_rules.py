"""Shared building blocks for guardrail rules and their findings."""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from llm_security_shield.core.sanitizer import ThreatCategory
from llm_security_shield.schemas import DetectionFinding, Severity, TextSpan

_HIDDEN_PAYLOAD_BOOST = 0.05
_MAX_DESCRIPTION = 256


@dataclass(frozen=True, slots=True)
class PatternRule:
    """A regex rule whose ``rule_id`` is ``<threat>.<name>``, so ``threat_of`` works."""

    name: str
    threat: ThreatCategory
    severity: Severity
    confidence: float
    description: str
    pattern: re.Pattern[str]

    @property
    def rule_id(self) -> str:
        return f"{self.threat}.{self.name}"

    def match(self, text: str) -> DetectionFinding | None:
        """Finding for the first match in ``text``, or ``None``."""
        if (found := self.pattern.search(text)) is None:
            return None
        return finding(self, TextSpan(start=found.start(), end=found.end()))


def finding(rule: PatternRule, span: TextSpan | None) -> DetectionFinding:
    """Finding for ``rule`` at ``span`` (``None`` when it matched a transformed text)."""
    return DetectionFinding(
        rule_id=rule.rule_id,
        category=rule.threat.owasp,
        severity=rule.severity,
        confidence=rule.confidence,
        description=rule.description,
        span=span,
    )


def scan_rules(rules: Iterable[PatternRule], text: str) -> list[DetectionFinding]:
    """First-match findings of every rule in ``rules``."""
    return [hit for rule in rules if (hit := rule.match(text)) is not None]


def enabled_rules(
    rules: Iterable[PatternRule], enabled: Iterable[ThreatCategory] | None
) -> tuple[PatternRule, ...]:
    """Rules whose threat family is enabled (all when ``enabled`` is ``None``)."""
    allowed = frozenset(ThreatCategory if enabled is None else enabled)
    return tuple(rule for rule in rules if rule.threat in allowed)


def wrap_hidden(
    rule_id: str,
    threat: ThreatCategory,
    inner: Sequence[DetectionFinding],
    *,
    label: str,
    floor: Severity = Severity.LOW,
) -> DetectionFinding:
    """Summarize findings uncovered only after a transformation (decoding, de-leeting)."""
    hidden_ids = ", ".join(sorted({f.rule_id for f in inner}))
    severity = max((floor, *(f.severity for f in inner)), key=lambda s: s.rank)
    return DetectionFinding(
        rule_id=rule_id,
        category=threat.owasp,
        severity=severity,
        confidence=round(min(1.0, max(f.confidence for f in inner) + _HIDDEN_PAYLOAD_BOOST), 4),
        description=f"{label} triggers: {hidden_ids}"[:_MAX_DESCRIPTION],
    )


def ordered(findings: Iterable[DetectionFinding]) -> tuple[DetectionFinding, ...]:
    """De-duplicate on ``(rule_id, span)`` and order by position, then rule id."""
    unique = {(f.rule_id, f.span): f for f in findings}
    return tuple(
        sorted(
            unique.values(),
            key=lambda f: (f.span is None, f.span.start if f.span else 0, f.rule_id),
        )
    )
