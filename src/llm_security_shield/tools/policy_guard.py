"""Tool-call policy guard (OWASP LLM06 Excessive Agency).

Decisions are deny-by-default: an unlisted tool gets the policy's ``default_action``
(``DENY`` unless configured otherwise), and every argument is inspected regardless of
the rule's action. Reasons name the offending argument but never echo its value.

Path containment resolves symlinks of existing path components, but a check-then-use
race (TOCTOU) remains possible; tools should still open files relative to a sandbox fd.
"""

from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final
from urllib.parse import unquote

from pydantic import JsonValue

from llm_security_shield.schemas import (
    PolicyAction,
    ToolCall,
    ToolCallDecision,
    ToolPolicy,
)

if TYPE_CHECKING:
    from llm_security_shield.tools.ports import ToolCallGuard

#: Shell metacharacters that chain, pipe, substitute or redirect commands.
SHELL_METACHARACTERS: Final = frozenset(";|&$`<>\n\r\x00")

DEFAULT_COMMAND_ARGUMENTS: Final = frozenset({"command", "cmd", "args", "argv", "shell", "script"})
DEFAULT_PATH_ARGUMENTS: Final = frozenset(
    {
        "path",
        "paths",
        "file",
        "filename",
        "filepath",
        "file_path",
        "dir",
        "directory",
        "cwd",
        "source",
        "src",
        "destination",
        "dest",
        "dst",
        "target",
    }
)


def _strings_by_key(arguments: dict[str, JsonValue]) -> Iterator[tuple[str, str]]:
    """Yield ``(nearest enclosing key, string)`` for every string at any depth.

    Iterative, so hostile nesting cannot exhaust the interpreter stack.
    """
    stack: list[tuple[str, JsonValue]] = list(arguments.items())
    while stack:
        key, value = stack.pop()
        if isinstance(value, str):
            yield key.lower(), value
        elif isinstance(value, list):
            stack.extend((key, item) for item in value)
        elif isinstance(value, dict):
            stack.extend(value.items())


def _path_syntax_violation(candidate: str) -> str | None:
    if "\x00" in candidate:
        return "NUL byte in path"
    if "\\" in candidate:
        return "backslash separator in path"
    if candidate.startswith("~"):
        return "home-directory expansion in path"
    return None


class ToolPolicyGuard:
    """``ToolCallGuard`` adapter enforcing a :class:`ToolPolicy` plus argument hygiene."""

    def __init__(
        self,
        policy: ToolPolicy,
        *,
        sandbox_roots: Iterable[str | Path] = (),
        command_arguments: Iterable[str] = DEFAULT_COMMAND_ARGUMENTS,
        path_arguments: Iterable[str] = DEFAULT_PATH_ARGUMENTS,
    ) -> None:
        roots = [Path(root) for root in sandbox_roots]
        if relative := [str(root) for root in roots if not root.is_absolute()]:
            raise ValueError(f"sandbox roots must be absolute: {relative}")
        self._policy = policy
        self._roots = tuple(root.resolve() for root in roots)
        self._command_arguments = frozenset(name.lower() for name in command_arguments)
        self._path_arguments = frozenset(name.lower() for name in path_arguments)

    @property
    def policy(self) -> ToolPolicy:
        """The policy being enforced."""
        return self._policy

    def evaluate(self, call: ToolCall) -> ToolCallDecision:
        """Decide a single call in isolation (call-count limits need :meth:`evaluate_all`)."""
        rule = self._policy.rule_for(call.name)
        if rule is None:
            action = self._policy.default_action
            if action is PolicyAction.DENY:
                return self._deny(call, "tool is not in the policy (deny by default)")
            basis = "default policy"
        else:
            if rule.action is PolicyAction.DENY:
                return self._deny(call, "tool is denied by policy")
            if rule.allowed_arguments is not None and (
                extra := sorted(set(call.arguments) - rule.allowed_arguments)
            ):
                return self._deny(call, f"arguments not permitted: {', '.join(extra)}"[:256])
            action = rule.action
            basis = "tool rule"
        if violation := self._inspect_arguments(call.arguments):
            return self._deny(call, violation)
        return ToolCallDecision(
            tool_name=call.name, action=action, reason=f"{action.value} by {basis}"
        )

    def evaluate_all(self, calls: Sequence[ToolCall]) -> tuple[ToolCallDecision, ...]:
        """Decide one request's calls in order, enforcing ``max_calls_per_request``."""
        seen: Counter[str] = Counter()
        decisions: list[ToolCallDecision] = []
        for call in calls:
            seen[call.name] += 1
            rule = self._policy.rule_for(call.name)
            limit = rule.max_calls_per_request if rule is not None else None
            if limit is not None and seen[call.name] > limit:
                decisions.append(self._deny(call, f"exceeds {limit} call(s) per request"))
            else:
                decisions.append(self.evaluate(call))
        return tuple(decisions)

    def _inspect_arguments(self, arguments: dict[str, JsonValue]) -> str | None:
        for key, value in _strings_by_key(arguments):
            if key in self._command_arguments and not SHELL_METACHARACTERS.isdisjoint(value):
                return f"shell metacharacters in argument '{key}'"
            if key in self._path_arguments and (problem := self._path_violation(value)):
                return f"{problem} in argument '{key}'"
        return None

    def _path_violation(self, value: str) -> str | None:
        """Check the raw and percent-decoded forms, since a tool may decode either."""
        if not self._roots:
            return "filesystem access is not permitted"
        for candidate in dict.fromkeys((value, unquote(value))):
            if problem := _path_syntax_violation(candidate) or self._escapes_sandbox(candidate):
                return problem
        return None

    def _escapes_sandbox(self, candidate: str) -> str | None:
        """Relative paths are anchored at the first sandbox root."""
        path = Path(candidate)
        try:
            resolved = (path if path.is_absolute() else self._roots[0] / path).resolve()
        except (OSError, RuntimeError):
            return "unresolvable path"
        if any(resolved.is_relative_to(root) for root in self._roots):
            return None
        return "path escapes the sandbox"

    @staticmethod
    def _deny(call: ToolCall, reason: str) -> ToolCallDecision:
        return ToolCallDecision(tool_name=call.name, action=PolicyAction.DENY, reason=reason)


if TYPE_CHECKING:

    def _conforms(adapter: ToolPolicyGuard) -> ToolCallGuard:
        return adapter
