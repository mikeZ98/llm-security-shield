"""Composite guardrail pipeline: a high-priority ``Detector`` for the security engine.

"High priority" means: the pipeline is placed first in the engine's detector list, runs
its guards in order and short-circuits once a finding reaches ``short_circuit_on``
(critical by default), so a decisive hit is not delayed by the remaining guards.
"""

import asyncio
from collections.abc import Iterable, Sequence
from typing import Protocol

from llm_security_shield.core import Detector, HeuristicSanitizer, SecurityShieldEngine
from llm_security_shield.core.config import ShieldSettings
from llm_security_shield.core.sanitizer import ThreatCategory
from llm_security_shield.guardrails._rules import ordered
from llm_security_shield.guardrails.jailbreak_defense import JailbreakDefense
from llm_security_shield.guardrails.system_override_filter import (
    DEFAULT_RESERVED_DELIMITERS,
    SystemOverrideFilter,
)
from llm_security_shield.schemas import DetectionFinding, Severity


class TextGuard(Protocol):
    """A synchronous text guard the pipeline can compose."""

    @property
    def name(self) -> str:
        """Stable identifier."""
        ...

    def scan(self, text: str) -> Sequence[DetectionFinding]:
        """Findings for ``text``."""
        ...


class GuardrailPipeline:
    """Runs text guards in order as one ``Detector``."""

    name = "guardrail-pipeline"

    def __init__(
        self, guards: Sequence[TextGuard], *, short_circuit_on: Severity | None = Severity.CRITICAL
    ) -> None:
        if not guards:
            raise ValueError("a pipeline needs at least one guard")
        self._guards = tuple(guards)
        self._short_circuit_on = short_circuit_on

    @classmethod
    def default(
        cls,
        enabled: Iterable[ThreatCategory] | None = None,
        *,
        canaries: Iterable[str] = (),
        reserved_delimiters: Iterable[str] = DEFAULT_RESERVED_DELIMITERS,
    ) -> "GuardrailPipeline":
        """Structural checks first (cheap, often critical), then jailbreak unfolding."""
        threats = frozenset(ThreatCategory if enabled is None else enabled)
        return cls(
            (
                SystemOverrideFilter(
                    threats, canaries=canaries, reserved_delimiters=reserved_delimiters
                ),
                JailbreakDefense(threats),
            )
        )

    @property
    def guards(self) -> tuple[TextGuard, ...]:
        """The composed guards, in execution order."""
        return self._guards

    async def detect(self, text: str) -> tuple[DetectionFinding, ...]:
        """Run the pipeline off the event loop."""
        return await asyncio.to_thread(self.scan, text)

    def scan(self, text: str) -> tuple[DetectionFinding, ...]:
        """Findings from each guard in turn, stopping early on a decisive finding."""
        found: list[DetectionFinding] = []
        floor = self._short_circuit_on
        for guard in self._guards:
            found += guard.scan(text)
            if floor is not None and any(f.severity.rank >= floor.rank for f in found):
                break
        return ordered(found)


def default_detectors(
    settings: ShieldSettings,
    *,
    canaries: Iterable[str] = (),
    reserved_delimiters: Iterable[str] = DEFAULT_RESERVED_DELIMITERS,
) -> tuple[Detector, ...]:
    """The guardrail pipeline (first, high priority) followed by the core sanitizer."""
    return (
        GuardrailPipeline.default(
            settings.enabled_threats, canaries=canaries, reserved_delimiters=reserved_delimiters
        ),
        HeuristicSanitizer(settings.enabled_threats),
    )


def build_engine(
    settings: ShieldSettings,
    *,
    canaries: Iterable[str] = (),
    reserved_delimiters: Iterable[str] = DEFAULT_RESERVED_DELIMITERS,
) -> SecurityShieldEngine:
    """A :class:`SecurityShieldEngine` with guardrails plugged in."""
    return SecurityShieldEngine(
        settings,
        default_detectors(settings, canaries=canaries, reserved_delimiters=reserved_delimiters),
    )
