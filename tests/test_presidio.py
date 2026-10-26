"""Presidio adapter: offline PII redaction, token reuse and exact deanonymization."""

import re
import socket
from types import SimpleNamespace
from typing import Any

import pytest
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from pytest_socket import SocketBlockedError

from llm_security_shield.core import TokenVault
from llm_security_shield.tools import (
    SUPPORTED_ENTITIES,
    ModelNotInstalledError,
    PresidioAnonymizer,
    build_analyzer,
)
from llm_security_shield.tools.presidio import _OfflineEmailRecognizer, _resolve_overlaps

SAMPLE = (
    "Hi, I'm John Smith from Berlin. Email john.smith@example.com, call +1 (212) 555-0198. "
    "Card 4111 1111 1111 1111, IBAN DE89 3704 0044 0532 0130 00, server 192.168.10.5. "
    "John Smith again. My social security number is 536-22-1234."
)
SECRETS = (
    "John Smith",
    "Berlin",
    "john.smith@example.com",
    "555-0198",
    "4111 1111 1111 1111",
    "DE89",
    "192.168.10.5",
    "536-22-1234",
)
TOKEN = re.compile(r"\[REDACTED_[A-Z_]+_\d+\]")


def test_redacts_every_supported_entity(anonymizer: PresidioAnonymizer) -> None:
    result = anonymizer.anonymize(SAMPLE)
    assert {e.entity_type for e in result.entities} == SUPPORTED_ENTITIES
    for secret in SECRETS:
        assert secret not in result.redacted_text


def test_entity_spans_refer_to_original(anonymizer: PresidioAnonymizer) -> None:
    result = anonymizer.anonymize(SAMPLE)
    by_type = {e.entity_type: SAMPLE[e.span.start : e.span.end] for e in result.entities}
    assert by_type["EMAIL_ADDRESS"] == "john.smith@example.com"
    assert by_type["US_SSN"] == "536-22-1234"


def test_repeated_entity_reuses_token(anonymizer: PresidioAnonymizer) -> None:
    result = anonymizer.anonymize(SAMPLE)
    assert result.redacted_text.count("[REDACTED_PERSON_1]") == 2
    assert len(set(result.tokens)) == len(result.tokens)
    assert all(TOKEN.fullmatch(t) for t in result.tokens)


def test_full_deanonymization(anonymizer: PresidioAnonymizer) -> None:
    result = anonymizer.anonymize(SAMPLE)
    assert anonymizer.deanonymize(result.redacted_text) == SAMPLE


def test_deanonymize_leaves_foreign_tokens(anonymizer: PresidioAnonymizer) -> None:
    anonymizer.anonymize(SAMPLE)
    text = "said [REDACTED_PERSON_1] and [REDACTED_FOO_7]"
    assert anonymizer.deanonymize(text) == "said John Smith and [REDACTED_FOO_7]"


@pytest.mark.parametrize("text", ["", "The weather is nice today."])
def test_nothing_to_redact(anonymizer: PresidioAnonymizer, text: str) -> None:
    result = anonymizer.anonymize(text)
    assert result.redacted_text == text
    assert not result.redacted


def test_entity_subset(vault: TokenVault, analyzer: AnalyzerEngine) -> None:
    only_email = PresidioAnonymizer(vault, analyzer=analyzer, entities={"EMAIL_ADDRESS"})
    result = only_email.anonymize(SAMPLE)
    assert {e.entity_type for e in result.entities} == {"EMAIL_ADDRESS"}
    assert "John Smith" in result.redacted_text


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"entities": {"SECRET_SAUCE"}}, "unsupported entities"),
        ({"entities": set()}, "at least one entity"),
        ({"score_threshold": 1.5}, "score_threshold"),
    ],
)
def test_invalid_configuration(
    vault: TokenVault, analyzer: AnalyzerEngine, options: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        PresidioAnonymizer(vault, analyzer=analyzer, **options)


def test_default_engines_are_built(vault: TokenVault) -> None:
    redactor = PresidioAnonymizer(vault)
    assert "[REDACTED_EMAIL_ADDRESS_1]" in redactor.anonymize("mail a@example.org").redacted_text


def test_dummy_operator_calls_do_not_pollute_vault(
    vault: TokenVault, analyzer: AnalyzerEngine
) -> None:
    """Older Presidio releases call custom lambdas with a dummy value during validation."""

    class DummyCallingAnonymizer:
        def __init__(self) -> None:
            self._real = AnonymizerEngine()  # type: ignore[no-untyped-call]

        def anonymize(self, **kwargs: Any) -> Any:
            for config in kwargs["operators"].values():
                assert config.params["lambda"]("PII") == ""
            return self._real.anonymize(**kwargs)

    redactor = PresidioAnonymizer(vault, analyzer=analyzer, anonymizer=DummyCallingAnonymizer())  # type: ignore[arg-type]
    result = redactor.anonymize("reach me at jane@example.org")
    assert "[REDACTED_EMAIL_ADDRESS_1]" in result.redacted_text
    assert len(vault) == len(result.tokens)
    assert vault.detokenize(result.redacted_text) == "reach me at jane@example.org"


def test_overlaps_resolved_by_score_then_length() -> None:
    def result(entity: str, start: int, end: int, score: float) -> SimpleNamespace:
        return SimpleNamespace(entity_type=entity, start=start, end=end, score=score)

    kept = _resolve_overlaps(
        [
            result("PERSON", 0, 20, 0.85),
            result("EMAIL_ADDRESS", 6, 20, 1.0),
            result("LOCATION", 25, 30, 0.85),
            result("PERSON", 25, 31, 0.85),
        ]
    )
    assert [(r.entity_type, r.start) for r in kept] == [("EMAIL_ADDRESS", 6), ("PERSON", 25)]


@pytest.mark.parametrize(
    ("address", "valid"), [("john@example.com", True), ("john@localhost", False)]
)
def test_offline_email_validation(address: str, valid: bool) -> None:
    assert _OfflineEmailRecognizer().validate_result(address) is valid


def test_refuses_to_download_missing_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("llm_security_shield.tools.presidio.spacy.util.is_package", lambda _: False)
    with pytest.raises(ModelNotInstalledError, match="en_core_web_sm"):
        build_analyzer()


def test_suite_is_hermetic() -> None:
    """pytest-socket must reject outbound sockets; the analyzer above loaded without one."""
    with (
        pytest.raises(SocketBlockedError),
        pytest.warns(UserWarning, match="tried to use socket"),
    ):
        socket.create_connection(("example.com", 443), timeout=1)
