"""Settings validation and the async engine: scoring, blocking, fail-closed and audit."""

import logging
from collections.abc import Sequence

import pytest
from pydantic import ValidationError

from llm_security_shield.core import (
    DetectorFailureError,
    HeuristicSanitizer,
    SecurityShieldEngine,
    ShieldBlockedError,
    ShieldSettings,
    ThreatCategory,
    risk_score,
)
from llm_security_shield.schemas import DetectionFinding, OwaspCategory, Severity
from tests.support import INJECTION


def _finding(confidence: float, severity: Severity = Severity.LOW) -> DetectionFinding:
    return DetectionFinding(
        rule_id=f"test.c{int(confidence * 100)}",
        category=OwaspCategory.PROMPT_INJECTION,
        severity=severity,
        confidence=confidence,
        description="d",
    )


class _StaticDetector:
    name = "static"

    def __init__(self, findings: Sequence[DetectionFinding]) -> None:
        self._findings = tuple(findings)

    async def detect(self, _text: str) -> tuple[DetectionFinding, ...]:
        return self._findings


class _FailingDetector:
    name = "failing"

    async def detect(self, _text: str) -> tuple[DetectionFinding, ...]:
        raise RuntimeError("detector crashed")


class TestSettings:
    def test_defaults(self, settings: ShieldSettings) -> None:
        assert settings.injection_risk_threshold == 0.7
        assert settings.enabled_threats == frozenset(ThreatCategory)
        assert settings.audit_log_level == "INFO"

    def test_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SHIELD_INJECTION_RISK_THRESHOLD", "0.5")
        monkeypatch.setenv("SHIELD_ENABLED_THREATS", '["jailbreak", "obfuscation"]')
        monkeypatch.setenv("SHIELD_AUDIT_LOG_LEVEL", "warning")
        monkeypatch.setenv("SHIELD_BLOCK_ON_SEVERITY", "high")
        settings = ShieldSettings()
        assert settings.injection_risk_threshold == 0.5
        assert settings.enabled_threats == {ThreatCategory.JAILBREAK, ThreatCategory.OBFUSCATION}
        assert settings.audit_log_level == "WARNING"
        assert settings.block_on_severity is Severity.HIGH

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("SHIELD_INJECTION_RISK_THRESHOLD", "0"),
            ("SHIELD_INJECTION_RISK_THRESHOLD", "1.5"),
            ("SHIELD_ENABLED_THREATS", "[]"),
            ("SHIELD_ENABLED_THREATS", '["telepathy"]'),
            ("SHIELD_VAULT_TTL_SECONDS", "0"),
            ("SHIELD_MAX_INPUT_CHARS", "0"),
            ("SHIELD_AUDIT_LOG_LEVEL", "LOUD"),
        ],
    )
    def test_invalid_environment(
        self, monkeypatch: pytest.MonkeyPatch, key: str, value: str
    ) -> None:
        monkeypatch.setenv(key, value)
        with pytest.raises(ValidationError):
            ShieldSettings()

    def test_unknown_keyword_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ShieldSettings(unknown=1)  # type: ignore[call-arg]

    def test_frozen(self, settings: ShieldSettings) -> None:
        with pytest.raises(ValidationError):
            settings.max_input_chars = 1  # type: ignore[misc]


class TestRiskScore:
    def test_empty_is_zero(self) -> None:
        assert risk_score([]) == 0.0

    def test_noisy_or(self) -> None:
        assert risk_score([_finding(0.5), _finding(0.5)]) == 0.75

    def test_order_independent(self) -> None:
        findings = [_finding(0.3), _finding(0.55), _finding(0.9)]
        assert risk_score(findings) == risk_score(list(reversed(findings)))


class TestEngine:
    async def test_blocks_injection(self, settings: ShieldSettings) -> None:
        result = await SecurityShieldEngine(settings).inspect(INJECTION)
        assert result.blocked
        assert result.risk_score >= settings.injection_risk_threshold

    async def test_allows_benign(self, settings: ShieldSettings) -> None:
        result = await SecurityShieldEngine(settings).inspect("What's the weather in Paris?")
        assert not result.blocked
        assert result.findings == ()

    async def test_enforce(self, settings: ShieldSettings) -> None:
        engine = SecurityShieldEngine(settings)
        assert not (await engine.enforce("hello")).blocked
        with pytest.raises(ShieldBlockedError) as caught:
            await engine.enforce(INJECTION)
        assert caught.value.result.blocked

    async def test_oversized_input_rejected_unscanned(self) -> None:
        engine = SecurityShieldEngine(ShieldSettings(max_input_chars=10), [_FailingDetector()])
        result = await engine.inspect("x" * 11)
        assert result.blocked
        (finding,) = result.findings
        assert finding.category is OwaspCategory.UNBOUNDED_CONSUMPTION

    async def test_detector_failure_fails_closed(self, settings: ShieldSettings) -> None:
        engine = SecurityShieldEngine(settings, [HeuristicSanitizer(), _FailingDetector()])
        with pytest.raises(DetectorFailureError):
            await engine.inspect("hi")

    async def test_severity_floor_blocks_low_scores(self) -> None:
        weak_critical = _StaticDetector([_finding(0.1, Severity.CRITICAL)])
        strict = SecurityShieldEngine(ShieldSettings(), [weak_critical])
        assert (await strict.inspect("x")).blocked
        lenient = SecurityShieldEngine(ShieldSettings(block_on_severity=None), [weak_critical])
        assert not (await lenient.inspect("x")).blocked

    async def test_findings_deduplicated_across_detectors(self, settings: ShieldSettings) -> None:
        engine = SecurityShieldEngine(settings, [HeuristicSanitizer(), HeuristicSanitizer()])
        single = SecurityShieldEngine(settings)
        assert (await engine.inspect(INJECTION)).findings == (
            await single.inspect(INJECTION)
        ).findings

    def test_settings_property(self, settings: ShieldSettings) -> None:
        assert SecurityShieldEngine(settings).settings is settings

    async def test_audit_log_never_contains_prompt(self, caplog: pytest.LogCaptureFixture) -> None:
        engine = SecurityShieldEngine(ShieldSettings(audit_log_level="DEBUG"))
        with caplog.at_level(logging.DEBUG, logger="llm_security_shield.audit"):
            await engine.inspect("SECRET-PAYLOAD " + INJECTION)
            await engine.inspect("clean")
        blocked, clean = (r.getMessage() for r in caplog.records)
        assert "blocked=True" in blocked
        assert "instruction_override.ignore_previous" in blocked
        assert "SECRET" not in blocked
        assert clean.endswith("rules=-")
        assert caplog.records[0].levelno == logging.DEBUG
