"""Asynchronous security engine: orchestrates detectors and enforces policy.

Ports & adapters: the engine depends only on the :class:`Detector` port. Adapters such as
:class:`~llm_security_shield.core.sanitizer.HeuristicSanitizer` plug in at construction.
"""

import asyncio
import logging
import math
from collections.abc import Iterable, Sequence
from typing import Protocol

from llm_security_shield.core.config import ShieldSettings
from llm_security_shield.core.sanitizer import HeuristicSanitizer
from llm_security_shield.schemas import DetectionFinding, DetectionResult, OwaspCategory, Severity

_audit = logging.getLogger("llm_security_shield.audit")


class Detector(Protocol):
    """Port for anything that inspects text and reports findings."""

    @property
    def name(self) -> str:
        """Stable identifier used in audit events."""
        ...

    async def detect(self, text: str) -> Sequence[DetectionFinding]:
        """Return findings for ``text``; must not mutate shared state."""
        ...


class ShieldBlockedError(Exception):
    """Raised by :meth:`SecurityShieldEngine.enforce` when a prompt is blocked."""

    def __init__(self, result: DetectionResult) -> None:
        super().__init__("prompt blocked by security policy")
        self.result = result


class DetectorFailureError(Exception):
    """Raised when a detector fails; the engine fails closed instead of allowing."""


def risk_score(findings: Iterable[DetectionFinding]) -> float:
    """Noisy-OR of finding confidences: independent signals compound, bounded in [0, 1].

    Confidences are sorted first so the result does not depend on detector order.
    """
    miss = math.prod(1.0 - c for c in sorted(f.confidence for f in findings))
    return round(1.0 - miss, 4)


def _input_too_large(limit: int) -> DetectionFinding:
    return DetectionFinding(
        rule_id="consumption.input_too_large",
        category=OwaspCategory.UNBOUNDED_CONSUMPTION,
        severity=Severity.CRITICAL,
        confidence=1.0,
        description=f"input exceeds {limit} characters and was not scanned",
    )


class SecurityShieldEngine:
    """Runs all detectors concurrently and turns their findings into a verdict."""

    def __init__(
        self, settings: ShieldSettings, detectors: Sequence[Detector] | None = None
    ) -> None:
        self._settings = settings
        self._detectors: tuple[Detector, ...] = (
            (HeuristicSanitizer(settings.enabled_threats),)
            if detectors is None
            else tuple(detectors)
        )
        self._audit_level = logging.getLevelNamesMapping()[settings.audit_log_level]

    @property
    def settings(self) -> ShieldSettings:
        """The configuration this engine enforces."""
        return self._settings

    async def inspect(self, text: str) -> DetectionResult:
        """Scan ``text`` with every detector and return an immutable verdict."""
        if len(text) > self._settings.max_input_chars:
            findings: tuple[DetectionFinding, ...] = (
                _input_too_large(self._settings.max_input_chars),
            )
        else:
            findings = await self._run_detectors(text)
        result = DetectionResult(
            findings=findings, risk_score=risk_score(findings), blocked=self._blocks(findings)
        )
        self._emit_audit(result)
        return result

    async def enforce(self, text: str) -> DetectionResult:
        """Like :meth:`inspect`, but raise :class:`ShieldBlockedError` when blocked."""
        result = await self.inspect(text)
        if result.blocked:
            raise ShieldBlockedError(result)
        return result

    async def _run_detectors(self, text: str) -> tuple[DetectionFinding, ...]:
        try:
            async with asyncio.TaskGroup() as group:
                tasks = [group.create_task(d.detect(text)) for d in self._detectors]
        except* Exception as failures:
            raise DetectorFailureError("detector failed; refusing to pass input") from failures
        unique = {(f.rule_id, f.span): f for task in tasks for f in task.result()}
        return tuple(
            sorted(
                unique.values(),
                key=lambda f: (f.span is None, f.span.start if f.span else 0, f.rule_id),
            )
        )

    def _blocks(self, findings: Sequence[DetectionFinding]) -> bool:
        if risk_score(findings) >= self._settings.injection_risk_threshold:
            return True
        floor = self._settings.block_on_severity
        return floor is not None and any(f.severity.rank >= floor.rank for f in findings)

    def _emit_audit(self, result: DetectionResult) -> None:
        """Log the verdict only; inspected text never reaches the audit log."""
        _audit.log(
            self._audit_level,
            "shield.inspect blocked=%s risk=%.4f rules=%s",
            result.blocked,
            result.risk_score,
            ",".join(f.rule_id for f in result.findings) or "-",
        )
