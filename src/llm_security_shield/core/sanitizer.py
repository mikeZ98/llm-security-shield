"""Heuristic, rule-based prompt-injection sanitizer (OWASP LLM01, LLM07).

The sanitizer never rewrites the prompt: it reports findings for the engine to score.
Patterns avoid nested unbounded quantifiers so matching stays linear (no ReDoS), and
decoding is bounded in depth and candidate count.
"""

import asyncio
import base64
import binascii
import codecs
import re
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum

from llm_security_shield.schemas import DetectionFinding, OwaspCategory, Severity, TextSpan


class ThreatCategory(StrEnum):
    """Fine-grained threat families; each finding's ``rule_id`` is prefixed with one."""

    JAILBREAK = "jailbreak"
    INSTRUCTION_OVERRIDE = "instruction_override"
    PROMPT_EXTRACTION = "prompt_extraction"
    DELIMITER_INJECTION = "delimiter_injection"
    OBFUSCATION = "obfuscation"
    CHARACTER_SMUGGLING = "character_smuggling"

    @property
    def owasp(self) -> OwaspCategory:
        """OWASP LLM Top 10 risk this threat family belongs to."""
        if self is ThreatCategory.PROMPT_EXTRACTION:
            return OwaspCategory.SYSTEM_PROMPT_LEAKAGE
        return OwaspCategory.PROMPT_INJECTION


def threat_of(finding: DetectionFinding) -> ThreatCategory | None:
    """Recover the :class:`ThreatCategory` encoded in a finding's ``rule_id`` prefix."""
    prefix = finding.rule_id.partition(".")[0]
    try:
        return ThreatCategory(prefix)
    except ValueError:
        return None


_Finder = Callable[[str], re.Match[str] | None]


@dataclass(frozen=True, slots=True)
class _Rule:
    name: str
    threat: ThreatCategory
    severity: Severity
    confidence: float
    description: str
    find: _Finder

    @property
    def rule_id(self) -> str:
        return f"{self.threat}.{self.name}"

    def finding(self, match: re.Match[str]) -> DetectionFinding:
        return DetectionFinding(
            rule_id=self.rule_id,
            category=self.threat.owasp,
            severity=self.severity,
            confidence=self.confidence,
            description=self.description,
            span=TextSpan(start=match.start(), end=match.end()),
        )


def _pattern_rule(
    name: str,
    threat: ThreatCategory,
    severity: Severity,
    confidence: float,
    description: str,
    *,
    pattern: re.Pattern[str],
) -> _Rule:
    return _Rule(name, threat, severity, confidence, description, pattern.search)


_I = re.IGNORECASE
_IM = re.IGNORECASE | re.MULTILINE

_PATTERN_RULES: tuple[_Rule, ...] = (
    # --- Jailbreak personas and "unlocked" modes -------------------------------------
    _pattern_rule(
        "dan_signature",
        ThreatCategory.JAILBREAK,
        Severity.HIGH,
        0.9,
        "DAN-style 'do anything now' jailbreak signature",
        pattern=re.compile(r"\bdo\s+anything\s+now\b", _I),
    ),
    _pattern_rule(
        "persona_adoption",
        ThreatCategory.JAILBREAK,
        Severity.HIGH,
        0.85,
        "request to adopt a known jailbreak persona",
        pattern=re.compile(
            r"\b(?:you\s+are|act\s+as|pretend\s+(?:to\s+be|you\s+are)|become)\s+"
            r"(?:now\s+)?(?:an?\s+)?(?-i:DAN|STAN|DUDE|AIM)\b",
            _I,
        ),
    ),
    _pattern_rule(
        "unrestricted_mode",
        ThreatCategory.JAILBREAK,
        Severity.HIGH,
        0.85,
        "request to enable an unrestricted or developer mode",
        pattern=re.compile(
            r"\b(?:enable|activate|enter|switch\s+to|turn\s+on)\s+(?:the\s+)?"
            r"(?:developer|god|jailbreak|unrestricted|unfiltered|evil)\s+mode\b",
            _I,
        ),
    ),
    _pattern_rule(
        "jailbroken_claim",
        ThreatCategory.JAILBREAK,
        Severity.HIGH,
        0.8,
        "assertion that the model has been jailbroken or freed",
        pattern=re.compile(
            r"\byou\s+(?:are|have\s+been)\s+(?:now\s+)?(?:jailbroken|freed|liberated|unchained)\b",
            _I,
        ),
    ),
    _pattern_rule(
        "no_restrictions",
        ThreatCategory.JAILBREAK,
        Severity.MEDIUM,
        0.5,
        "request to operate without safety restrictions",
        pattern=re.compile(
            r"\b(?:without|free\s+(?:of|from)|no\s+longer\s+(?:bound|restricted)\s+by)\s+"
            r"(?:any\s+|your\s+)?(?:restrictions|limitations|filters|guidelines|censorship|"
            r"ethical\s+constraints|content\s+polic(?:y|ies))\b",
            _I,
        ),
    ),
    # --- System-prompt override ----------------------------------------------------
    _pattern_rule(
        "ignore_previous",
        ThreatCategory.INSTRUCTION_OVERRIDE,
        Severity.HIGH,
        0.9,
        "instruction to ignore or override prior instructions",
        pattern=re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass|skip)\s+"
            r"(?:(?:all|any|every|the|your|my|these|those|of)\s+){0,3}"
            r"(?:previous|prior|above|earlier|preceding|original|initial|system|developer)\s+"
            r"(?:instructions?|prompts?|rules|directives|guidelines|context|messages?)\b",
            _I,
        ),
    ),
    _pattern_rule(
        "new_instructions",
        ThreatCategory.INSTRUCTION_OVERRIDE,
        Severity.MEDIUM,
        0.7,
        "injected replacement instruction block",
        pattern=re.compile(
            r"^[ \t]*(?:new|updated|revised|real|actual)\s+(?:system\s+)?instructions?[ \t]*:", _IM
        ),
    ),
    _pattern_rule(
        "role_reassignment",
        ThreatCategory.INSTRUCTION_OVERRIDE,
        Severity.MEDIUM,
        0.55,
        "attempt to reassign the assistant's role or identity",
        pattern=re.compile(
            r"\b(?:from\s+now\s+on|henceforth),?\s+you\s+(?:are|will|must|shall)\b|"
            r"\byou\s+are\s+no\s+longer\s+(?:an?\s+)?(?:ai|assistant|chatbot|language\s+model)\b",
            _I,
        ),
    ),
    # --- System-prompt extraction (LLM07) ------------------------------------------
    _pattern_rule(
        "reveal_system_prompt",
        ThreatCategory.PROMPT_EXTRACTION,
        Severity.HIGH,
        0.8,
        "request to disclose the system prompt or hidden instructions",
        pattern=re.compile(
            r"\b(?:reveal|print|show|display|repeat|output|leak|dump|tell\s+me|what\s+(?:is|are))\s+"
            r"(?:me\s+)?(?:(?:your|the|all|of|full|entire|exact)\s+){0,3}"
            r"(?:system\s+(?:prompt|message|instructions?)|"
            r"(?:initial|original|hidden|secret)\s+(?:prompt|instructions?)|pre-?prompt)\b",
            _I,
        ),
    ),
    _pattern_rule(
        "repeat_preamble",
        ThreatCategory.PROMPT_EXTRACTION,
        Severity.MEDIUM,
        0.65,
        "request to repeat the text preceding the conversation",
        pattern=re.compile(
            r"\brepeat\s+(?:everything|all|the\s+(?:text|words))\s+(?:above|before)\b", _I
        ),
    ),
    # --- Instruction-boundary escape delimiters ------------------------------------
    _pattern_rule(
        "chat_template_token",
        ThreatCategory.DELIMITER_INJECTION,
        Severity.CRITICAL,
        0.95,
        "raw chat-template control token",
        pattern=re.compile(
            r"<\|(?:im_start|im_end|im_sep|system|user|assistant|endoftext|begin_of_text|"
            r"end_of_text|start_header_id|end_header_id|eot_id)\|>",
            _I,
        ),
    ),
    _pattern_rule(
        "instruction_markers",
        ThreatCategory.DELIMITER_INJECTION,
        Severity.HIGH,
        0.9,
        "Llama-style [INST] or <<SYS>> markers",
        pattern=re.compile(r"\[/?INST\]|<</?SYS>>", _I),
    ),
    _pattern_rule(
        "markdown_role_header",
        ThreatCategory.DELIMITER_INJECTION,
        Severity.HIGH,
        0.8,
        "markdown header impersonating a system or instruction section",
        pattern=re.compile(
            r"^[ \t]*#{2,6}[ \t]*(?:system|developer|assistant|instructions?)"
            r"(?:[ \t]+(?:prompt|message|instructions?))?[ \t]*:?[ \t]*$",
            _IM,
        ),
    ),
    _pattern_rule(
        "role_tag",
        ThreatCategory.DELIMITER_INJECTION,
        Severity.MEDIUM,
        0.7,
        "XML-style tag impersonating a privileged role",
        pattern=re.compile(r"</?(?:system|system_prompt|instructions?|developer)>", _I),
    ),
    _pattern_rule(
        "role_prefix",
        ThreatCategory.DELIMITER_INJECTION,
        Severity.MEDIUM,
        0.5,
        "line prefixed with a privileged role label",
        pattern=re.compile(r"^[ \t]*(?:system|assistant|developer)[ \t]*:", _IM),
    ),
    _pattern_rule(
        "boundary_marker",
        ThreatCategory.DELIMITER_INJECTION,
        Severity.MEDIUM,
        0.6,
        "fake end-of-prompt boundary marker",
        pattern=re.compile(
            r"\b(?:end\s+of\s+(?:the\s+)?(?:system\s+)?(?:prompt|instructions)|"
            r"(?:begin|end)\s+system\s+prompt)\b",
            _I,
        ),
    ),
    # --- Obfuscation intent --------------------------------------------------------
    _pattern_rule(
        "decode_and_execute",
        ThreatCategory.OBFUSCATION,
        Severity.MEDIUM,
        0.65,
        "instruction to decode a payload and act on it",
        pattern=re.compile(
            r"\b(?:decode|decipher|decrypt|unscramble)\b[^\n]{0,80}?"
            r"\b(?:and|then)\s+(?:follow|execute|obey|run|do)\b",
            _I,
        ),
    ),
)

# --- Character-level token smuggling -----------------------------------------------
_TAG_RUN = re.compile("[\U000e0000-\U000e007f]+")
_ZERO_WIDTH = re.compile("[\u200b\u2060-\u2064\ufeff\u180e]")
_BIDI_CONTROL = re.compile("[\u202a-\u202e\u2066-\u2069]")
_VARIATION_RUN = re.compile("[\U000e0100-\U000e01ef]{2,}")
# Stripped before re-scanning: also covers joiners and soft hyphens, which are benign alone.
_INVISIBLE = re.compile(
    "[\u00ad\u034f\u180e\u200b-\u200f\u202a-\u202e"
    "\u2060-\u2069\ufe00-\ufe0f\ufeff\U000e0100-\U000e01ef]"
)
_SPACED_LETTERS = re.compile(r"\b[A-Za-z](?:[ .\-_*|][A-Za-z]){2,}\b")
_NON_LETTER = re.compile(r"[^A-Za-z]")

_BLACK_FLAG = "\U0001f3f4"
_TAG_CANCEL = "\U000e007f"
_MAX_FLAG_TAGS = 7
_TAG_OFFSET = 0xE0000
_TAG_PRINTABLE = range(0xE0020, 0xE007F)

# Common Cyrillic/Greek homoglyphs of Latin letters that NFKC does not fold.
_CONFUSABLES = str.maketrans(
    {
        "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
        "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
        "\u0501": "d", "\u0261": "g", "\u0410": "A", "\u0412": "B", "\u0415": "E",
        "\u041a": "K", "\u041c": "M", "\u041d": "H", "\u041e": "O", "\u0420": "P",
        "\u0421": "C", "\u0422": "T", "\u0425": "X", "\u03b1": "a", "\u03bf": "o",
        "\u0399": "I", "\u039f": "O",
    }
)  # fmt: skip

# --- Obfuscation decoders ------------------------------------------------------------
_BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/_-]{16,8192}={0,2}")
_MAX_BASE64_CANDIDATES = 8
_MIN_DECODED_CHARS = 8
_MIN_PRINTABLE_RATIO = 0.9
_HIDDEN_PAYLOAD_BOOST = 0.05


def _is_flag_sequence(text: str, match: re.Match[str]) -> bool:
    """Subdivision flags (e.g. England) legitimately use tag characters."""
    run = match.group()
    return (
        match.start() > 0
        and text[match.start() - 1] == _BLACK_FLAG
        and run.endswith(_TAG_CANCEL)
        and len(run) <= _MAX_FLAG_TAGS
    )


def _first_tag_run(text: str) -> re.Match[str] | None:
    return next((m for m in _TAG_RUN.finditer(text) if not _is_flag_sequence(text, m)), None)


def _first_zero_width(text: str) -> re.Match[str] | None:
    """A leading byte-order mark is benign; any later zero-width character is not."""
    return next((m for m in _ZERO_WIDTH.finditer(text) if m.start() > 0), None)


_SMUGGLING = ThreatCategory.CHARACTER_SMUGGLING
_SMUGGLING_RULES: tuple[_Rule, ...] = (
    _Rule(
        "unicode_tags",
        _SMUGGLING,
        Severity.HIGH,
        0.85,
        "invisible Unicode tag characters",
        _first_tag_run,
    ),
    _Rule(
        "zero_width", _SMUGGLING, Severity.MEDIUM, 0.5, "zero-width characters", _first_zero_width
    ),
    _Rule(
        "bidi_control",
        _SMUGGLING,
        Severity.MEDIUM,
        0.6,
        "bidirectional override characters",
        _BIDI_CONTROL.search,
    ),
    _Rule(
        "variation_selectors",
        _SMUGGLING,
        Severity.HIGH,
        0.8,
        "variation-selector byte payload",
        _VARIATION_RUN.search,
    ),
)


def _decode_tags(match: re.Match[str]) -> str:
    """Decode a tag run to ASCII, padded so it cannot fuse with adjacent visible words."""
    hidden = "".join(chr(ord(c) - _TAG_OFFSET) for c in match.group() if ord(c) in _TAG_PRINTABLE)
    return f" {hidden} "


def normalize(text: str) -> str:
    """Reveal text hidden by character-level smuggling, for re-scanning only.

    Decodes Unicode tag characters to ASCII, strips invisible and bidi controls, applies
    NFKC, folds common homoglyphs and collapses spaced-out letters (``i g n o r e``).
    """
    revealed = _TAG_RUN.sub(_decode_tags, text)
    revealed = _INVISIBLE.sub("", revealed)
    revealed = unicodedata.normalize("NFKC", revealed).translate(_CONFUSABLES)
    return _SPACED_LETTERS.sub(lambda m: _NON_LETTER.sub("", m.group()), revealed)


def _decode_base64(chunk: str) -> str | None:
    body = chunk.rstrip("=").replace("-", "+").replace("_", "/")
    if len(body) % 4 == 1:
        return None
    try:
        decoded = base64.b64decode(body + "=" * (-len(body) % 4), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    printable = sum(c.isprintable() or c.isspace() for c in decoded)
    if len(decoded) < _MIN_DECODED_CHARS or printable < _MIN_PRINTABLE_RATIO * len(decoded):
        return None
    return decoded


def _wrap_hidden(
    rule_id: str, threat: ThreatCategory, inner: list[DetectionFinding], span: TextSpan | None
) -> DetectionFinding:
    """Summarize findings uncovered inside an obfuscated or smuggled payload."""
    hidden_ids = ", ".join(sorted({f.rule_id for f in inner}))
    return DetectionFinding(
        rule_id=rule_id,
        category=threat.owasp,
        severity=max((f.severity for f in inner), key=lambda s: s.rank),
        confidence=round(min(1.0, max(f.confidence for f in inner) + _HIDDEN_PAYLOAD_BOOST), 4),
        description=f"hidden payload triggers: {hidden_ids}"[:256],
        span=span,
    )


def _span(match: re.Match[str]) -> TextSpan:
    return TextSpan(start=match.start(), end=match.end())


class HeuristicSanitizer:
    """Regex and rule-based prompt-injection detector (a ``Detector`` adapter).

    Results are deterministic: the same text and enabled threats always yield the
    same findings, in the same order, with the same confidences.
    """

    name = "heuristic-sanitizer"

    def __init__(
        self, enabled: Iterable[ThreatCategory] | None = None, *, max_decode_depth: int = 2
    ) -> None:
        self._enabled = frozenset(ThreatCategory if enabled is None else enabled)
        self._rules = tuple(
            r for r in (*_PATTERN_RULES, *_SMUGGLING_RULES) if r.threat in self._enabled
        )
        self._max_decode_depth = max_decode_depth

    @property
    def enabled(self) -> frozenset[ThreatCategory]:
        """Threat families this sanitizer reports."""
        return self._enabled

    async def detect(self, text: str) -> tuple[DetectionFinding, ...]:
        """Scan ``text`` off the event loop (regex work is CPU-bound)."""
        return await asyncio.to_thread(self.scan, text)

    def scan(self, text: str) -> tuple[DetectionFinding, ...]:
        """Return de-duplicated findings ordered by position, then rule id."""
        unique = {(f.rule_id, f.span): f for f in self._scan(text, depth=0)}
        return tuple(
            sorted(
                unique.values(),
                key=lambda f: (f.span is None, f.span.start if f.span else 0, f.rule_id),
            )
        )

    def _scan(self, text: str, depth: int) -> list[DetectionFinding]:
        found = self._match_rules(text)
        if ThreatCategory.CHARACTER_SMUGGLING in self._enabled:
            self._add_hidden(
                found,
                normalize(text),
                "character_smuggling.hidden_payload",
                ThreatCategory.CHARACTER_SMUGGLING,
            )
        if ThreatCategory.OBFUSCATION in self._enabled and depth < self._max_decode_depth:
            found += self._base64_payloads(text, depth)
            self._add_hidden(
                found, codecs.decode(text, "rot13"), "obfuscation.rot13", ThreatCategory.OBFUSCATION
            )
        return found

    def _match_rules(self, text: str) -> list[DetectionFinding]:
        return [rule.finding(match) for rule in self._rules if (match := rule.find(text))]

    def _add_hidden(
        self, found: list[DetectionFinding], variant: str, rule_id: str, threat: ThreatCategory
    ) -> None:
        """Re-scan a transformed ``variant``; report only rules the raw text did not trip."""
        seen = {f.rule_id for f in found}
        hidden = [f for f in self._match_rules(variant) if f.rule_id not in seen]
        if hidden:
            found.append(_wrap_hidden(rule_id, threat, hidden, span=None))

    def _base64_payloads(self, text: str, depth: int) -> list[DetectionFinding]:
        found: list[DetectionFinding] = []
        for index, match in enumerate(_BASE64_CANDIDATE.finditer(text)):
            if index >= _MAX_BASE64_CANDIDATES:
                break
            decoded = _decode_base64(match.group())
            if decoded is None:
                continue
            if inner := self._scan(decoded, depth + 1):
                found.append(
                    _wrap_hidden(
                        "obfuscation.base64", ThreatCategory.OBFUSCATION, inner, _span(match)
                    )
                )
        return found
