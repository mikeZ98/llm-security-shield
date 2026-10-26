"""Tool-call policy schemas (OWASP LLM06 Excessive Agency)."""

from enum import StrEnum
from typing import Annotated, Self

from pydantic import Field, JsonValue, StringConstraints, model_validator

from llm_security_shield.schemas._base import OwaspCategory, ShieldModel

ToolName = Annotated[
    str, StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$")
]


class PolicyAction(StrEnum):
    """What the guard does with a matching tool call."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ToolCall(ShieldModel):
    """A tool invocation proposed by the model."""

    name: ToolName
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    call_id: str | None = Field(default=None, min_length=1, max_length=128)


class ToolRule(ShieldModel):
    """Policy for one tool. ``allowed_arguments=None`` permits any argument names."""

    name: ToolName
    action: PolicyAction
    allowed_arguments: frozenset[str] | None = None
    max_calls_per_request: int | None = Field(default=None, ge=1)


class ToolPolicy(ShieldModel):
    """Complete tool-call policy. Unlisted tools fall back to ``default_action``."""

    default_action: PolicyAction = PolicyAction.DENY
    rules: tuple[ToolRule, ...] = ()

    @model_validator(mode="after")
    def _check_unique_names(self) -> Self:
        names = [r.name for r in self.rules]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"duplicate tool rules: {duplicates}")
        return self

    def rule_for(self, name: str) -> ToolRule | None:
        """Return the rule for ``name``, or ``None`` when the default applies."""
        return next((r for r in self.rules if r.name == name), None)


class ToolCallDecision(ShieldModel):
    """Outcome of evaluating one :class:`ToolCall` against a :class:`ToolPolicy`."""

    tool_name: ToolName
    action: PolicyAction
    reason: str = Field(min_length=1, max_length=256)
    category: OwaspCategory = OwaspCategory.EXCESSIVE_AGENCY

    @property
    def allowed(self) -> bool:
        """Whether the call may run without further approval."""
        return self.action is PolicyAction.ALLOW
