"""Multi-vector jailbreak defense (OWASP LLM01).

Three layers on top of the core heuristic sanitizer:

1. **Payload unfolding**: breadth-first decoding of nested wrappers (base64, hex, URL and
   HTML encoding, escape sequences, rot13, reversal), bounded in depth, variant count
   and total size so hostile inputs cannot amplify work.
2. **De-obfuscation**: homoglyph/invisible-character normalization plus leetspeak folding
   before the rules run.
3. **Role-play and cognitive-overload guards**: fictional or hypothetical framings that
   remove the rules, "opposite day", refusal suppression, dual-response formats and
   DAN-style token games, plus a density check for many weak cues at once.
"""

import asyncio
import base64
import binascii
import codecs
import html
import re
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from typing import Final
from urllib.parse import unquote_plus

from llm_security_shield.core.sanitizer import HeuristicSanitizer, ThreatCategory, normalize
from llm_security_shield.guardrails._rules import (
    PatternRule,
    enabled_rules,
    ordered,
    scan_rules,
    wrap_hidden,
)
from llm_security_shield.schemas import DetectionFinding, Severity

_I = re.IGNORECASE
_J = ThreatCategory.JAILBREAK

ROLE_PLAY_RULES: Final[tuple[PatternRule, ...]] = (
    PatternRule(
        "fictional_no_rules",
        _J,
        Severity.HIGH,
        0.75,
        "role-play framing in which the assistant has no rules",
        re.compile(
            r"\b(?:let'?s|we(?:'ll|\s+will)?|you\s+(?:will|must))\s+"
            r"(?:play|pretend|imagine|role-?play)\b[^.\n]{0,120}?"
            r"\byou\s+(?:have|are|will\s+have|now\s+have)\s+(?:no|without|free\s+(?:of|from))\s+"
            r"(?:any\s+)?"
            r"(?:rules|restrictions|limits|limitations|filters|ethics|morals|guidelines)\b|"
            r"\byou\s+are\s+(?:now\s+)?an?\s+(?:ai|assistant|chatbot|model)\s+"
            r"(?:with\s+no|without(?:\s+any)?)\s+(?:rules|restrictions|filters|limits|guidelines)\b",
            _I,
        ),
    ),
    PatternRule(
        "fictional_world",
        _J,
        Severity.MEDIUM,
        0.55,
        "hypothetical world in which safety rules do not apply",
        re.compile(
            r"\bin\s+an?\s+(?:fictional|hypothetical|imaginary|alternate|parallel)\s+"
            r"(?:world|story|scenario|universe|reality)\b[^.\n]{0,80}?"
            r"\b(?:no|without|don'?t\s+exist|aren'?t|are\s+not)\b[^.\n]{0,40}?"
            r"\b(?:rules|laws|restrictions|ethics|guidelines|limits|filters)\b",
            _I,
        ),
    ),
    PatternRule(
        "hypothetical_override",
        _J,
        Severity.HIGH,
        0.7,
        "hypothetical premise that the assistant ignores its rules",
        re.compile(
            r"\b(?:hypothetically|theoretically|imagine|suppose|what\s+if|pretend)\b[^.\n]{0,60}?"
            r"\byou\s+(?:had\s+no|didn'?t\s+have|were\s+without|ignored?|could\s+ignore|"
            r"bypass(?:ed)?|disabled?|turned\s+off)\s+"
            r"(?:any\s+|your\s+|its\s+|the\s+)?"
            r"(?:rules|restrictions|guidelines|filters|safety|system\s+prompt|programming|"
            r"content\s+polic(?:y|ies)|alignment)\b",
            _I,
        ),
    ),
    PatternRule(
        "opposite_day",
        _J,
        Severity.MEDIUM,
        0.6,
        "'opposite day' inversion of the assistant's behaviour",
        re.compile(
            r"\bopposite\s+(?:day|mode|world)\b|"
            r"\b(?:say|do|answer\s+with)\s+the\s+opposite\s+of\s+what\s+you\b",
            _I,
        ),
    ),
    PatternRule(
        "refusal_suppression",
        _J,
        Severity.MEDIUM,
        0.6,
        "instruction never to refuse, warn or add disclaimers",
        re.compile(
            r"\b(?:never|don'?t|do\s+not|must\s+not|cannot|can'?t)\s+"
            r"(?:refuse|decline|say\s+no|apologi[sz]e|add\s+(?:any\s+)?(?:warnings?|disclaimers?))\b|"
            r"\bwithout\s+(?:any\s+)?(?:warnings?|disclaimers?|moralizing|lectures?|censorship)\b",
            _I,
        ),
    ),
    PatternRule(
        "dual_response",
        _J,
        Severity.HIGH,
        0.8,
        "demand for a parallel 'unfiltered' response alongside the normal one",
        re.compile(
            r"\b(?:two|2|dual|both|separate)\s+(?:responses|answers|replies|outputs|ways)\b"
            r"[^.\n]{0,100}?\b(?:jailbr\w*|unfiltered|uncensored|unrestricted|(?-i:DAN))\b",
            _I,
        ),
    ),
    PatternRule(
        "token_game",
        _J,
        Severity.HIGH,
        0.75,
        "DAN-style token penalty game",
        re.compile(
            r"\byou\s+(?:will\s+)?lose\s+\d+\s+tokens\b|"
            r"\byou\s+(?:have|start\s+with)\s+\d+\s+tokens\b[^\n]{0,160}?"
            r"\b(?:lose|deduct|refus\w*|die|cease\s+to\s+exist)\b|"
            r"\btoken\s+system\b[^.\n]{0,80}\b(?:lose|deduct|penal)",
            _I,
        ),
    ),
    PatternRule(
        "grandma_exploit",
        _J,
        Severity.MEDIUM,
        0.6,
        "deceased-relative role-play used to extract restricted content",
        re.compile(
            r"\b(?:dead|late|deceased|passed\s+away)\s+grand(?:ma|mother|pa|father)\b"
            r"[^.\n]{0,120}?\b(?:used\s+to|would)\s+(?:tell|read|recite|say|whisper)\b",
            _I,
        ),
    ),
    PatternRule(
        "privilege_mode",
        _J,
        Severity.MEDIUM,
        0.6,
        "claimed administrator, sudo or god-mode privileges",
        re.compile(
            r"\b(?:enable|grant|activate|enter|you\s+(?:are|have|now\s+have))\s+(?:in\s+)?"
            r"(?:sudo|admin(?:istrator)?|root|god|superuser|maintenance|debug)\s+"
            r"(?:mode|access|override|privileges?|rights)\b",
            _I,
        ),
    ),
)

#: Individually weak jailbreak cues; many at once indicate cognitive-overload prompts.
_CUES: Final = tuple(
    re.compile(p, _I)
    for p in (
        r"\bpretend\b",
        r"\brole-?play\b",
        r"\b(?:stay|remain|break)\s+(?:in\s+)?character\b",
        r"\bhypothetical(?:ly)?\b",
        r"\bfiction(?:al)?\b",
        r"\bno\s+(?:rules|limits|restrictions|filters)\b",
        r"\b(?:uncensored|unfiltered|unrestricted)\b",
        r"\bignore\b",
        r"\bjailbr\w*",
        r"\bpersona\b",
        r"\bopposite\b",
        r"\bnever\s+refuse\b",
        r"\byou\s+must\b",
        r"\bas\s+an?\s+ai\b",
    )
)
_CUE_THRESHOLD = 4
_CUE_BASE_CONFIDENCE = 0.5
_CUE_STEP = 0.1
_CUE_MAX_CONFIDENCE = 0.8

# --- Payload unfolding -------------------------------------------------------------
_BASE64_CHUNK = re.compile(r"[A-Za-z0-9+/_-]{16,8192}={0,2}")
_HEX_CHUNK = re.compile(
    r"(?:0x)?(?:[0-9a-fA-F]{2}){8,4096}|(?:[0-9a-fA-F]{2}[\s:,-]){7,4096}[0-9a-fA-F]{2}"
)
_BACKSLASH = re.escape(chr(92))
_HEX_ESCAPES = re.compile(f"(?:{_BACKSLASH}x[0-9a-fA-F]{{2}}){{4,}}")
_TEXT_ESCAPE = re.compile(f"{_BACKSLASH}(?:x([0-9a-fA-F]{{2}})|u([0-9a-fA-F]{{4}}))")
_PERCENT = re.compile(r"%[0-9a-fA-F]{2}")
_HTML_ENTITY = re.compile(r"&(?:#\d{1,7}|#x[0-9a-fA-F]{1,6}|[a-zA-Z]{2,8});")
_HEX_SEPARATORS = re.compile(r"[\s:,-]|0x")
_MIN_DECODED = 4
_MIN_PRINTABLE_RATIO = 0.85
_MIN_PERCENT_ESCAPES = 3
_MAX_CHUNKS_PER_DECODER = 6

Decoder = Callable[[str], Iterator[str]]


def _printable(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(c.isprintable() or c.isspace() for c in text)
    if len(text) < _MIN_DECODED or printable < _MIN_PRINTABLE_RATIO * len(text):
        return None
    return text


def _limited(matches: Iterable[re.Match[str]]) -> Iterator[re.Match[str]]:
    for index, match in enumerate(matches):
        if index >= _MAX_CHUNKS_PER_DECODER:
            return
        yield match


def _decode_base64(text: str) -> Iterator[str]:
    for match in _limited(_BASE64_CHUNK.finditer(text)):
        body = match.group().rstrip("=").replace("-", "+").replace("_", "/")
        if len(body) % 4 == 1:
            continue
        try:
            raw = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
        except binascii.Error:
            continue
        if (decoded := _printable(raw)) is not None:
            yield decoded


def _decode_hex(text: str) -> Iterator[str]:
    chunks = [m.group() for m in _limited(_HEX_CHUNK.finditer(text))]
    chunks += [m.group().replace(chr(92) + "x", "") for m in _limited(_HEX_ESCAPES.finditer(text))]
    for chunk in chunks:
        digits = _HEX_SEPARATORS.sub("", chunk)
        if len(digits) % 2:
            continue
        try:
            raw = bytes.fromhex(digits)
        except ValueError:
            continue
        if (decoded := _printable(raw)) is not None:
            yield decoded


def _decode_percent(text: str) -> Iterator[str]:
    if len(_PERCENT.findall(text)) >= _MIN_PERCENT_ESCAPES:
        yield unquote_plus(text)


def _decode_html(text: str) -> Iterator[str]:
    if _HTML_ENTITY.search(text):
        yield html.unescape(text)


def _decode_text_escapes(text: str) -> Iterator[str]:
    if _TEXT_ESCAPE.search(text):
        yield _TEXT_ESCAPE.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), text)


def _rot13(text: str) -> Iterator[str]:
    yield codecs.decode(text, "rot13")


def _reverse(text: str) -> Iterator[str]:
    yield text[::-1]


DECODERS: Final[tuple[tuple[str, Decoder], ...]] = (
    ("base64", _decode_base64),
    ("hex", _decode_hex),
    ("url", _decode_percent),
    ("html", _decode_html),
    ("escape", _decode_text_escapes),
    ("rot13", _rot13),
    ("reversed", _reverse),
)


def unfold(
    text: str, *, max_depth: int = 3, max_variants: int = 24, max_total_chars: int = 131_072
) -> list[tuple[str, tuple[str, ...]]]:
    """Breadth-first decodings of ``text`` as ``(variant, decoder chain)`` pairs.

    The original is not included. Every variant is unique, and the search stops at
    ``max_depth`` nested layers, ``max_variants`` results or ``max_total_chars``.
    """
    seen = {text}
    found: list[tuple[str, tuple[str, ...]]] = []
    budget = max_total_chars
    queue: deque[tuple[str, tuple[str, ...]]] = deque([(text, ())])
    while queue:
        current, chain = queue.popleft()
        if len(chain) >= max_depth:
            continue
        for name, decoder in DECODERS:
            for decoded in decoder(current):
                if decoded in seen or not decoded.strip() or len(decoded) > budget:
                    continue
                seen.add(decoded)
                budget -= len(decoded)
                layer = (decoded, (*chain, name))
                found.append(layer)
                queue.append(layer)
                if len(found) >= max_variants:
                    return found
    return found


# --- De-obfuscation ------------------------------------------------------------------
_LEET_COMMON: Final = {
    "0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "!": "i", "|": "l", "+": "t",
}  # fmt: skip
_LEET_AS_I = str.maketrans({**_LEET_COMMON, "1": "i"})
_LEET_AS_L = str.maketrans({**_LEET_COMMON, "1": "l"})
_LEET_MIXED = re.compile(r"[a-z][0-9@$!|+]|[0-9@$!|+][a-z]", _I)


def deobfuscate(text: str) -> tuple[str, ...]:
    """Normalized variants of ``text``: homoglyph-folded, then leetspeak-folded.

    ``1`` is ambiguous (``i`` or ``l``), so both readings are returned.
    """
    base = normalize(text)
    variants = [base]
    if _LEET_MIXED.search(base):
        variants += [base.translate(_LEET_AS_I), base.translate(_LEET_AS_L)]
    return tuple(dict.fromkeys(v for v in variants if v != text))


class JailbreakDefense:
    """Unfolds, de-obfuscates and scores prompts for jailbreak attempts (a ``Detector``)."""

    name = "jailbreak-defense"

    def __init__(
        self,
        enabled: Iterable[ThreatCategory] | None = None,
        *,
        max_depth: int = 3,
        max_variants: int = 24,
    ) -> None:
        threats = frozenset(ThreatCategory if enabled is None else enabled)
        self._threats = threats
        self._rules = enabled_rules(ROLE_PLAY_RULES, threats)
        # Decoding is done here, so the inner sanitizer only evaluates rules.
        self._inner = HeuristicSanitizer(threats, max_decode_depth=0)
        self._max_depth = max_depth
        self._max_variants = max_variants

    async def detect(self, text: str) -> tuple[DetectionFinding, ...]:
        """Scan ``text`` off the event loop."""
        return await asyncio.to_thread(self.scan, text)

    def scan(self, text: str) -> tuple[DetectionFinding, ...]:
        """Deterministic findings, ordered by position then rule id."""
        found = scan_rules(self._rules, text)
        if cues := self._cue_density(text):
            found.append(cues)
        raw_ids = {f.rule_id for f in found} | {f.rule_id for f in self._inner.scan(text)}

        if ThreatCategory.CHARACTER_SMUGGLING in self._threats:
            hidden = [
                f
                for variant in deobfuscate(text)
                for f in self._evaluate(variant)
                if f.rule_id not in raw_ids
            ]
            if hidden:
                found.append(
                    wrap_hidden(
                        "character_smuggling.leetspeak",
                        ThreatCategory.CHARACTER_SMUGGLING,
                        hidden,
                        label="de-obfuscated text",
                    )
                )

        if ThreatCategory.OBFUSCATION in self._threats:
            chains: list[str] = []
            unfolded: list[DetectionFinding] = []
            for variant, chain in unfold(
                text, max_depth=self._max_depth, max_variants=self._max_variants
            ):
                if inner := self._evaluate_deep(variant):
                    unfolded += inner
                    chains.append(">".join(chain))
            if unfolded:
                found.append(
                    wrap_hidden(
                        "obfuscation.unfolded_payload",
                        ThreatCategory.OBFUSCATION,
                        unfolded,
                        label=f"payload decoded via {', '.join(sorted(set(chains)))}",
                        floor=Severity.HIGH,
                    )
                )
        return ordered(found)

    def _evaluate(self, text: str) -> list[DetectionFinding]:
        return [*self._inner.scan(text), *scan_rules(self._rules, text)]

    def _evaluate_deep(self, text: str) -> list[DetectionFinding]:
        found = self._evaluate(text)
        if not found:
            found = [f for variant in deobfuscate(text) for f in self._evaluate(variant)]
        return found

    def _cue_density(self, text: str) -> DetectionFinding | None:
        hits = sum(1 for cue in _CUES if cue.search(text))
        if hits < _CUE_THRESHOLD or _J not in self._threats:
            return None
        confidence = min(
            _CUE_MAX_CONFIDENCE, _CUE_BASE_CONFIDENCE + _CUE_STEP * (hits - _CUE_THRESHOLD)
        )
        return DetectionFinding(
            rule_id="jailbreak.cue_density",
            category=_J.owasp,
            severity=Severity.MEDIUM,
            confidence=round(confidence, 4),
            description=f"{hits} distinct jailbreak cues (cognitive-overload pattern)",
        )
