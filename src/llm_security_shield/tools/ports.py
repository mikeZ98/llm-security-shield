"""Ports implemented by the tool adapters; the API layer depends only on these."""

from collections.abc import Sequence
from typing import Protocol

from llm_security_shield.schemas import RedactionResult, ToolCall, ToolCallDecision


class Redactor(Protocol):
    """Reversibly replaces PII in text with vault tokens (OWASP LLM02)."""

    def anonymize(self, text: str) -> RedactionResult:
        """Return ``text`` with every detected entity replaced by a token."""
        ...

    def deanonymize(self, text: str) -> str:
        """Restore the original values of every live token in ``text``."""
        ...


class ToolCallGuard(Protocol):
    """Decides whether model-proposed tool calls may run (OWASP LLM06)."""

    def evaluate(self, call: ToolCall) -> ToolCallDecision:
        """Decide a single call in isolation."""
        ...

    def evaluate_all(self, calls: Sequence[ToolCall]) -> tuple[ToolCallDecision, ...]:
        """Decide one request's calls together, enforcing per-request call limits."""
        ...
