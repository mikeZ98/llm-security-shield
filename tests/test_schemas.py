"""Schema contracts: strict, frozen, extra-forbidding models with validated formats."""

import json

import pytest
from pydantic import ValidationError

from llm_security_shield.schemas import (
    DetectionFinding,
    DetectionResult,
    OwaspCategory,
    PiiEntity,
    PolicyAction,
    RedactionResult,
    Severity,
    ShieldError,
    ShieldErrorResponse,
    TextSpan,
    ToolCall,
    ToolCallDecision,
    ToolPolicy,
    ToolRule,
)


def _finding(severity: Severity = Severity.HIGH, rule_id: str = "jailbreak.x") -> DetectionFinding:
    return DetectionFinding(
        rule_id=rule_id,
        category=OwaspCategory.PROMPT_INJECTION,
        severity=severity,
        confidence=0.9,
        description="d",
    )


class TestTextSpan:
    def test_valid_span(self) -> None:
        assert TextSpan(start=0, end=3).end == 3

    @pytest.mark.parametrize(("start", "end"), [(5, 5), (5, 4), (-1, 2)])
    def test_rejects_empty_reversed_or_negative(self, start: int, end: int) -> None:
        with pytest.raises(ValidationError):
            TextSpan(start=start, end=end)

    def test_strict_mode_rejects_coercion(self) -> None:
        with pytest.raises(ValidationError):
            TextSpan.model_validate({"start": "1", "end": 2})

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            TextSpan.model_validate({"start": 0, "end": 1, "length": 1})

    def test_frozen(self) -> None:
        span = TextSpan(start=0, end=3)
        with pytest.raises(ValidationError):
            span.start = 1  # type: ignore[misc]


class TestSeverity:
    def test_rank_order(self) -> None:
        ranks = [s.rank for s in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
        assert ranks == [0, 1, 2, 3]


class TestDetection:
    def test_max_severity(self) -> None:
        result = DetectionResult(
            findings=(_finding(Severity.MEDIUM), _finding(Severity.CRITICAL, "jailbreak.y")),
            risk_score=0.9,
            blocked=True,
        )
        assert result.max_severity is Severity.CRITICAL

    def test_max_severity_none_without_findings(self) -> None:
        assert DetectionResult(risk_score=0.0, blocked=False).max_severity is None

    @pytest.mark.parametrize("score", [-0.1, 1.01])
    def test_risk_score_bounds(self, score: float) -> None:
        with pytest.raises(ValidationError):
            DetectionResult(risk_score=score, blocked=False)

    @pytest.mark.parametrize("rule_id", ["Bad Rule", "", ".leading", "x" * 65])
    def test_rule_id_format(self, rule_id: str) -> None:
        with pytest.raises(ValidationError):
            _finding(rule_id=rule_id)

    def test_json_mode_accepts_enum_values(self) -> None:
        payload = {
            "findings": [
                {
                    "rule_id": "a",
                    "category": "LLM01",
                    "severity": "low",
                    "confidence": 0.1,
                    "description": "d",
                }
            ],
            "risk_score": 0.1,
            "blocked": False,
        }
        result = DetectionResult.model_validate_json(json.dumps(payload))
        assert result.findings[0].category is OwaspCategory.PROMPT_INJECTION


class TestRedaction:
    def test_redacted_result(self) -> None:
        result = RedactionResult(
            redacted_text="mail [REDACTED_EMAIL_ADDRESS_1]",
            entities=(
                PiiEntity(entity_type="EMAIL_ADDRESS", span=TextSpan(start=5, end=20), score=1.0),
            ),
            tokens=("[REDACTED_EMAIL_ADDRESS_1]",),
        )
        assert result.redacted

    def test_unredacted_result(self) -> None:
        assert not RedactionResult(redacted_text="plain").redacted

    def test_tokens_must_appear_in_text(self) -> None:
        with pytest.raises(ValidationError, match="tokens absent"):
            RedactionResult(redacted_text="nothing here", tokens=("[REDACTED_PERSON_1]",))

    @pytest.mark.parametrize(
        "token", ["[redacted_person]", "[REDACTED_]", "REDACTED_PERSON", "[REDACTED_PERSON]x"]
    )
    def test_invalid_token_format(self, token: str) -> None:
        with pytest.raises(ValidationError):
            RedactionResult(redacted_text=token, tokens=(token,))

    def test_entity_type_format(self) -> None:
        with pytest.raises(ValidationError):
            PiiEntity(entity_type="email", span=TextSpan(start=0, end=1), score=0.5)


class TestTools:
    def test_tool_call_arguments_are_json(self) -> None:
        call = ToolCall(name="search", arguments={"q": "x", "n": [1, None, {"a": True}]})
        assert call.arguments["n"] == [1, None, {"a": True}]

    @pytest.mark.parametrize("name", ["1bad", "", "has space", "x" * 129])
    def test_tool_name_format(self, name: str) -> None:
        with pytest.raises(ValidationError):
            ToolCall(name=name)

    def test_policy_defaults_to_deny(self) -> None:
        assert ToolPolicy().default_action is PolicyAction.DENY

    def test_policy_rejects_duplicate_rules(self) -> None:
        with pytest.raises(ValidationError, match="duplicate tool rules"):
            ToolPolicy(
                rules=(
                    ToolRule(name="a", action=PolicyAction.ALLOW),
                    ToolRule(name="a", action=PolicyAction.DENY),
                )
            )

    def test_rule_lookup(self) -> None:
        policy = ToolPolicy.model_validate_json(
            '{"rules": [{"name": "search", "action": "allow", "allowed_arguments": ["q"]}]}'
        )
        rule = policy.rule_for("search")
        assert rule is not None
        assert rule.allowed_arguments == frozenset({"q"})
        assert policy.rule_for("rm") is None

    def test_max_calls_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            ToolRule(name="a", action=PolicyAction.ALLOW, max_calls_per_request=0)

    @pytest.mark.parametrize(
        ("action", "allowed"),
        [
            (PolicyAction.ALLOW, True),
            (PolicyAction.DENY, False),
            (PolicyAction.REQUIRE_APPROVAL, False),
        ],
    )
    def test_decision_allowed(self, action: PolicyAction, allowed: bool) -> None:
        decision = ToolCallDecision(tool_name="t", action=action, reason="r")
        assert decision.allowed is allowed
        assert decision.category is OwaspCategory.EXCESSIVE_AGENCY


class TestErrors:
    def test_serialization_uses_enum_values(self) -> None:
        response = ShieldErrorResponse(
            error=ShieldError(
                code="prompt_injection",
                message="blocked",
                categories=(OwaspCategory.PROMPT_INJECTION, OwaspCategory.SYSTEM_PROMPT_LEAKAGE),
            )
        )
        dumped = response.model_dump(mode="json")
        assert dumped["error"]["categories"] == ["LLM01", "LLM07"]
        assert dumped["error"]["request_id"] is None

    def test_unknown_code_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ShieldError.model_validate({"code": "nope", "message": "m"})

    def test_message_length_bounded(self) -> None:
        with pytest.raises(ValidationError):
            ShieldError(code="internal_error", message="x" * 257)
