"""System-prompt leakage and instruction-override barrier (OWASP LLM07).

- **Canary tokens**: random markers the application embeds in its system prompt. A canary
  in a prompt means it was already exfiltrated; a canary in a model response means the
  system prompt is leaking right now (:meth:`SystemOverrideFilter.leaked_canaries`).
- **Distillation queries**: requests to summarize, translate, encode or replay the hidden
  instructions instead of asking for them outright.
- **Structural tampering**: the application's own reserved delimiters appearing in user
  input (delimiter collision), forged conversation transcripts, role JSON, tool-result
  blocks and fake end-of-input markers.
"""

import asyncio
import re
import secrets
from collections.abc import Iterable
from typing import Final

from llm_security_shield.core.sanitizer import ThreatCategory, normalize
from llm_security_shield.guardrails._rules import (
    PatternRule,
    enabled_rules,
    ordered,
    scan_rules,
)
from llm_security_shield.schemas import DetectionFinding, Severity, TextSpan

_I = re.IGNORECASE
_IM = re.IGNORECASE | re.MULTILINE
_X = ThreatCategory.PROMPT_EXTRACTION
_D = ThreatCategory.DELIMITER_INJECTION

#: Wrappers commonly used to fence user input inside prompt templates.
DEFAULT_RESERVED_DELIMITERS: Final = (
    "<user_input>",
    "</user_input>",
    "<untrusted_input>",
    "</untrusted_input>",
    "<<<USER_INPUT>>>",
    "<<</USER_INPUT>>>",
    "[END OF USER INPUT]",
    "[END USER INPUT]",
    "<|user|>",
    "<|end|>",
)
CANARY_PREFIX: Final = "CANARY-"
_MIN_CANARY_CHARS = 8
_MIN_TRANSCRIPT_ROLES = 2

OVERRIDE_RULES: Final[tuple[PatternRule, ...]] = (
    PatternRule(
        "canary_probe",
        _X,
        Severity.MEDIUM,
        0.6,
        "probe for a canary, secret word or hidden key in the instructions",
        re.compile(
            r"\b(?:what|reveal|tell|print|show|repeat|give)\b[^.\n?]{0,40}?"
            r"\b(?:canary|secret|hidden|magic|special)\s+"
            r"(?:token|word|string|phrase|password|key|code)\b",
            _I,
        ),
    ),
    PatternRule(
        "distillation_query",
        _X,
        Severity.HIGH,
        0.75,
        "request to summarize, translate or re-encode the hidden instructions",
        re.compile(
            r"\b(?:summari[sz]e|paraphrase|translate|rephrase|rewrite|encode|convert|"
            r"spell\s+out|list|enumerate)\b[^.\n]{0,40}?"
            r"\b(?:your\s+(?:system\s+|initial\s+|original\s+|hidden\s+|secret\s+)?|"
            r"the\s+(?:system|initial|original|hidden|secret)\s+)"
            r"(?:instructions|prompt|rules|guidelines|directives|configuration)\b",
            _I,
        ),
    ),
    PatternRule(
        "replay_preamble",
        _X,
        Severity.HIGH,
        0.8,
        "request to replay the preamble starting from its opening words",
        re.compile(
            r"\b(?:repeat|print|output|write|copy)\b[^.\n]{0,60}?"
            r"\b(?:starting|beginning)\s+(?:with|from)\s+[\"'`]?(?:you\s+are|your\s+role|system)\b",
            _I,
        ),
    ),
    PatternRule(
        "instruction_origin",
        _X,
        Severity.MEDIUM,
        0.6,
        "question about how the assistant was instructed or configured",
        re.compile(
            r"\b(?:what|how)\s+(?:were|are|have)\s+you\s+(?:been\s+)?"
            r"(?:told|instructed|programmed|configured|prompted)\b",
            _I,
        ),
    ),
    PatternRule(
        "verbatim_dump",
        _X,
        Severity.HIGH,
        0.8,
        "request for the initialization text verbatim or in a code block",
        re.compile(
            r"\b(?:initiali[sz]ation|initial\s+(?:instructions|prompt)|pre-?prompt|meta-?prompt|"
            r"system\s+(?:message|prompt))\b[^.\n]{0,40}?"
            r"\b(?:code\s*block|verbatim|word\s+for\s+word|exactly|raw|unedited)\b",
            _I,
        ),
    ),
    PatternRule(
        "forged_role_json",
        _D,
        Severity.MEDIUM,
        0.55,
        "JSON message object forging a privileged role",
        re.compile(r"[\"']role[\"']\s*:\s*[\"'](?:system|developer|tool|function)[\"']", _I),
    ),
    PatternRule(
        "forged_tool_result",
        _D,
        Severity.HIGH,
        0.8,
        "forged tool or function result block",
        re.compile(
            r"</?(?:function_results?|tool_results?|tool_response|search_results|"
            r"function_calls?|tool_calls?)>",
            _I,
        ),
    ),
    PatternRule(
        "fake_end_of_input",
        _D,
        Severity.MEDIUM,
        0.65,
        "forged end-of-input or end-of-context marker",
        re.compile(
            r"\[\s*(?:end|/)\s*(?:of\s+)?(?:the\s+)?(?:user\s+)?"
            r"(?:input|message|query|context|document)\s*\]|"
            r"</(?:user|user_message|context|document|query)>",
            _I,
        ),
    ),
    PatternRule(
        "separator_injection",
        _D,
        Severity.MEDIUM,
        0.6,
        "separator line followed by a privileged instruction header",
        re.compile(
            r"^[ \t]*[-=_*#~]{5,}[ \t]*\n(?:[ \t]*\n)?[ \t]*"
            r"(?:system|admin(?:istrator)?|developer|important|new|override|priority)\b",
            _IM,
        ),
    ),
)

_TRANSCRIPT_ROLE = re.compile(
    r"^[ \t]*(human|assistant|user|ai|bot|model|system)[ \t]*:", re.IGNORECASE | re.MULTILINE
)
_ASSISTANT_ROLES: Final = frozenset({"assistant", "ai", "bot", "model"})
_COMPLIANCE = re.compile(
    r"\b(?:ignor\w*|bypass\w*|jailbr\w*|unrestricted|unfiltered|uncensored|"
    r"no\s+(?:rules|restrictions|limits|filters)|anything\s+you\s+(?:want|ask)|"
    r"(?:my|the)\s+(?:system\s+prompt|instructions)\s+(?:is|are|says?))\b",
    re.IGNORECASE,
)


def _line_end(text: str, start: int) -> int:
    end = text.find("\n", start)
    return len(text) if end < 0 else end


def generate_canary(nbytes: int = 12) -> str:
    """A fresh random canary token to embed in a system prompt."""
    return CANARY_PREFIX + secrets.token_hex(nbytes).upper()


class SystemOverrideFilter:
    """Detects system-prompt extraction and prompt-structure tampering (a ``Detector``)."""

    name = "system-override-filter"

    def __init__(
        self,
        enabled: Iterable[ThreatCategory] | None = None,
        *,
        canaries: Iterable[str] = (),
        reserved_delimiters: Iterable[str] = DEFAULT_RESERVED_DELIMITERS,
    ) -> None:
        self._threats = frozenset(ThreatCategory if enabled is None else enabled)
        self._rules = enabled_rules(OVERRIDE_RULES, self._threats)
        self._canaries = tuple(dict.fromkeys(canaries))
        if short := [c for c in self._canaries if len(c) < _MIN_CANARY_CHARS]:
            raise ValueError(f"{len(short)} canary token(s) shorter than {_MIN_CANARY_CHARS}")
        self._delimiters = tuple(d.casefold() for d in dict.fromkeys(reserved_delimiters) if d)

    async def detect(self, text: str) -> tuple[DetectionFinding, ...]:
        """Scan ``text`` off the event loop."""
        return await asyncio.to_thread(self.scan, text)

    def scan(self, text: str) -> tuple[DetectionFinding, ...]:
        """Deterministic findings, ordered by position then rule id."""
        found = scan_rules(self._rules, text)
        seen = {f.rule_id for f in found}
        # Homoglyph/invisible-character variants: report rules the raw text did not trip.
        if (normalized := normalize(text)) != text:
            found += [
                f.model_copy(update={"span": None})
                for f in scan_rules(self._rules, normalized)
                if f.rule_id not in seen
            ]
        if _X in self._threats and (canary := self._first_canary(text)):
            found.append(canary)
        if _D in self._threats:
            if collision := self._delimiter_collision(text):
                found.append(collision)
            if transcript := self._forged_transcript(text):
                found.append(transcript)
        return ordered(found)

    def leaked_canaries(self, output: str) -> tuple[str, ...]:
        """Canaries present in a model ``output``: proof the system prompt leaked."""
        return tuple(c for c in self._canaries if c in output)

    def _first_canary(self, text: str) -> DetectionFinding | None:
        for canary in self._canaries:
            if (start := text.find(canary)) >= 0:
                return DetectionFinding(
                    rule_id="prompt_extraction.canary_echo",
                    category=_X.owasp,
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    description="system-prompt canary token present in input",
                    span=TextSpan(start=start, end=start + len(canary)),
                )
        return None

    def _delimiter_collision(self, text: str) -> DetectionFinding | None:
        folded = text.casefold()
        hits = [(folded.find(d), d) for d in self._delimiters if d in folded]
        if not hits:
            return None
        start, delimiter = min(hits)
        return DetectionFinding(
            rule_id="delimiter_injection.reserved_delimiter",
            category=_D.owasp,
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="input contains a delimiter reserved by the prompt template",
            # casefold() can change length for a few scripts; only report exact offsets.
            span=TextSpan(start=start, end=start + len(delimiter))
            if len(folded) == len(text)
            else None,
        )

    def _forged_transcript(self, text: str) -> DetectionFinding | None:
        """Pasted transcripts are common and only weakly suspicious on their own.

        They become strong evidence when they contain a ``system`` turn or a fabricated
        assistant turn that agrees to break its rules.
        """
        matches = list(_TRANSCRIPT_ROLE.finditer(text))
        roles = {m.group(1).lower() for m in matches}
        if len(roles) < _MIN_TRANSCRIPT_ROLES:
            return None
        forged_compliance = any(
            m.group(1).lower() in _ASSISTANT_ROLES
            and _COMPLIANCE.search(text, m.end(), _line_end(text, m.end()))
            for m in matches
        )
        strong = "system" in roles or forged_compliance
        return DetectionFinding(
            rule_id="delimiter_injection.forged_transcript",
            category=_D.owasp,
            severity=Severity.HIGH if strong else Severity.LOW,
            confidence=0.75 if strong else 0.35,
            description=(
                "input forges a privileged or compliant conversation turn"
                if strong
                else "input contains a multi-speaker conversation transcript"
            ),
            span=TextSpan(start=matches[0].start(), end=matches[0].end()),
        )
