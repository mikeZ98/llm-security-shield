"""Presidio PII adapter: detects entities and swaps them for reversible vault tokens.

Strictly offline. The spaCy model is the pinned ``en_core_web_sm`` wheel and must already
be installed (Presidio would otherwise try to download it), and email validation uses
tldextract's bundled suffix-list snapshot instead of fetching the list over HTTP.
"""

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, Final

import spacy
import tldextract
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import (
    CreditCardRecognizer,
    EmailRecognizer,
    IbanRecognizer,
    IpRecognizer,
    PhoneRecognizer,
    SpacyRecognizer,
    UsSsnRecognizer,
)
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig, RecognizerResult

from llm_security_shield.core.vault import TokenVault
from llm_security_shield.schemas import PiiEntity, RedactionResult, TextSpan

if TYPE_CHECKING:
    from llm_security_shield.tools.ports import Redactor

SPACY_MODEL: Final = "en_core_web_sm"
LANGUAGE: Final = "en"
SUPPORTED_ENTITIES: Final = frozenset(
    {
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "IBAN_CODE",
        "CREDIT_CARD",
        "US_SSN",
        "PERSON",
        "LOCATION",
        "IP_ADDRESS",
    }
)
#: Presidio scores phone numbers at 0.4; a higher default would let them through.
DEFAULT_SCORE_THRESHOLD: Final = 0.4


class ModelNotInstalledError(RuntimeError):
    """Raised instead of letting Presidio download a missing spaCy model."""


class _OfflineEmailRecognizer(EmailRecognizer):
    """Email recognizer whose domain check never touches the network."""

    _extractor = tldextract.TLDExtract(
        cache_dir=None, suffix_list_urls=(), fallback_to_snapshot=True
    )

    def validate_result(self, pattern_text: str) -> bool:
        return self._extractor(pattern_text).fqdn != ""


def build_analyzer() -> AnalyzerEngine:
    """Build an English analyzer limited to :data:`SUPPORTED_ENTITIES` (~1s; share it)."""
    if not spacy.util.is_package(SPACY_MODEL):
        raise ModelNotInstalledError(f"spaCy model {SPACY_MODEL!r} is not installed; run 'uv sync'")
    nlp_engine = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": LANGUAGE, "model_name": SPACY_MODEL}],
        }
    ).create_engine()
    registry = RecognizerRegistry(supported_languages=[LANGUAGE])
    for recognizer in (
        _OfflineEmailRecognizer(),
        PhoneRecognizer(),
        IbanRecognizer(),
        CreditCardRecognizer(),
        UsSsnRecognizer(),
        IpRecognizer(),
        SpacyRecognizer(supported_entities=["PERSON", "LOCATION"]),
    ):
        registry.add_recognizer(recognizer)
    return AnalyzerEngine(nlp_engine=nlp_engine, registry=registry, supported_languages=[LANGUAGE])


def _resolve_overlaps(results: Iterable[Any]) -> list[Any]:
    """Keep the strongest non-overlapping results: highest score, then longest span.

    Ties break on position and entity type, so the outcome is deterministic.
    """
    ranked = sorted(results, key=lambda r: (-r.score, -(r.end - r.start), r.start, r.entity_type))
    kept: list[Any] = []
    for result in ranked:
        if all(result.end <= k.start or result.start >= k.end for k in kept):
            kept.append(result)
    return sorted(kept, key=lambda r: r.start)


class PresidioAnonymizer:
    """``Redactor`` adapter over Presidio Analyzer and Anonymizer with a :class:`TokenVault`."""

    def __init__(
        self,
        vault: TokenVault,
        *,
        entities: Iterable[str] = SUPPORTED_ENTITIES,
        score_threshold: float = DEFAULT_SCORE_THRESHOLD,
        analyzer: AnalyzerEngine | None = None,
        anonymizer: AnonymizerEngine | None = None,
    ) -> None:
        self._entities = frozenset(entities)
        if unknown := self._entities - SUPPORTED_ENTITIES:
            raise ValueError(f"unsupported entities: {sorted(unknown)}")
        if not self._entities:
            raise ValueError("at least one entity type is required")
        if not 0.0 <= score_threshold <= 1.0:
            raise ValueError("score_threshold must be within [0, 1]")
        self._vault = vault
        self._score_threshold = score_threshold
        self._analyzer = analyzer if analyzer is not None else build_analyzer()
        self._anonymizer = (
            anonymizer if anonymizer is not None else AnonymizerEngine()  # type: ignore[no-untyped-call]  # unannotated __init__
        )

    def anonymize(self, text: str) -> RedactionResult:
        """Replace each detected entity with a ``[REDACTED_<ENTITY>_<N>]`` vault token.

        Entity spans in the result refer to the original ``text``.
        """
        if not text:
            return RedactionResult(redacted_text=text)
        results = _resolve_overlaps(
            self._analyzer.analyze(
                text=text,
                language=LANGUAGE,
                entities=sorted(self._entities),
                score_threshold=self._score_threshold,
            )
        )
        if not results:
            return RedactionResult(redacted_text=text)

        # Tokenize up front so the operator is a pure lookup: older Presidio releases
        # call custom lambdas with a dummy value during validation.
        tokens: dict[str, dict[str, str]] = {}
        for r in results:
            value = text[r.start : r.end]
            tokens.setdefault(r.entity_type, {})[value] = self._vault.tokenize(r.entity_type, value)
        operators = {
            entity: OperatorConfig("custom", {"lambda": lambda v, m=mapping: m.get(v, "")})
            for entity, mapping in tokens.items()
        }
        anonymized = self._anonymizer.anonymize(
            text=text,
            analyzer_results=[
                RecognizerResult(r.entity_type, r.start, r.end, r.score) for r in results
            ],
            operators=operators,
        )
        ordered_tokens = [tokens[r.entity_type][text[r.start : r.end]] for r in results]
        return RedactionResult(
            redacted_text=anonymized.text,
            entities=tuple(
                PiiEntity(
                    entity_type=r.entity_type,
                    span=TextSpan(start=r.start, end=r.end),
                    score=round(float(r.score), 4),
                )
                for r in results
            ),
            tokens=tuple(dict.fromkeys(ordered_tokens)),
        )

    def deanonymize(self, text: str) -> str:
        """Restore original values for every live token; unknown tokens are left as-is."""
        return self._vault.detokenize(text)


if TYPE_CHECKING:

    def _conforms(adapter: PresidioAnonymizer) -> Redactor:
        return adapter
