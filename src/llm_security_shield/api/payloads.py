"""Payload codecs: prompt extraction from requests, PII redaction of response bodies.

Redaction helpers are synchronous (Presidio is CPU-bound); the middleware runs each
unit of work in a worker thread so the event loop stays responsive.
"""

import json
import re
from collections.abc import Callable
from typing import Any, Final
from urllib.parse import parse_qsl

TextRedactor = Callable[[str], str]

_JSON_SUBTYPE = re.compile(r"^application/(?:[\w.+-]+\+)?json$")
_SSE_DATA = "data:"
_SSE_DONE = "[DONE]"
_ASCII_SPACE: Final = frozenset(b" \t\n\r")
_UTF8_CONTINUATION_MASK: Final = 0xC0
_UTF8_CONTINUATION: Final = 0x80


class UnsupportedMediaError(ValueError):
    """The request body cannot be inspected, so it must not pass."""


class MalformedPayloadError(ValueError):
    """The request body does not parse as its declared media type."""


def parse_content_type(value: str) -> tuple[str, str]:
    """Return ``(media type, charset)`` from a Content-Type header value."""
    media, *params = (part.strip() for part in value.split(";"))
    charset = "utf-8"
    for param in params:
        name, _, raw = param.partition("=")
        if name.strip().lower() == "charset" and raw:
            charset = raw.strip().strip('"').lower()
    return media.lower(), charset


def is_json(media: str) -> bool:
    """``application/json`` or any ``application/*+json`` structured syntax suffix."""
    return bool(_JSON_SUBTYPE.match(media))


# --- Inbound: prompt extraction -------------------------------------------------------


def _json_strings(document: Any, fields: frozenset[str] | None) -> list[str]:
    """Strings under ``fields`` (any depth, lists inherit their key); all if ``None``."""
    found: list[str] = []
    stack: list[tuple[str | None, Any]] = [(None, document)]
    while stack:
        key, value = stack.pop()
        if isinstance(value, str):
            if fields is None or (key is not None and key in fields):
                found.append(value)
        elif isinstance(value, list):
            stack.extend((key, item) for item in reversed(value))
        elif isinstance(value, dict):
            stack.extend((str(k).lower(), v) for k, v in reversed(value.items()))
    return found


def _pairs(pairs: list[tuple[str, str]], fields: frozenset[str] | None) -> list[str]:
    return [v for k, v in pairs if fields is None or k.lower() in fields]


def extract_prompt_text(
    content_type: str, body: bytes, query_string: bytes, fields: frozenset[str] | None
) -> str:
    """Join every prompt-bearing string in the query and body for inspection.

    Raises :class:`UnsupportedMediaError` for non-empty bodies of uninspectable types and
    :class:`MalformedPayloadError` for bodies that do not decode or parse.
    """
    parts = _pairs(parse_qsl(query_string.decode("latin-1"), keep_blank_values=True), fields)
    if body:
        media, charset = parse_content_type(content_type)
        try:
            if is_json(media):
                parts += _json_strings(json.loads(body), fields)
            elif media == "application/x-www-form-urlencoded":
                pairs = parse_qsl(body.decode(charset), keep_blank_values=True)
                parts += _pairs(pairs, fields)
            elif media.startswith("text/"):
                parts.append(body.decode(charset))
            else:
                raise UnsupportedMediaError(media or "missing content-type")
        except (UnicodeDecodeError, LookupError, json.JSONDecodeError, RecursionError) as exc:
            raise MalformedPayloadError(type(exc).__name__) from exc
    return "\n\n".join(p for p in parts if p)


# --- Outbound: redaction --------------------------------------------------------------


def redact_json_value(
    value: Any, redact: TextRedactor, fields: frozenset[str] | None, key: str | None = None
) -> Any:
    """Redact string values (never keys) under ``fields``, or all strings if ``None``."""
    if isinstance(value, str):
        selected = fields is None or (key is not None and key in fields)
        return redact(value) if selected and value.strip() else value
    if isinstance(value, list):
        return [redact_json_value(item, redact, fields, key) for item in value]
    if isinstance(value, dict):
        return {k: redact_json_value(v, redact, fields, str(k).lower()) for k, v in value.items()}
    return value


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def redact_json_text(text: str, redact: TextRedactor, fields: frozenset[str] | None) -> str:
    """Parse, redact and re-serialize a JSON document."""
    return _dump(redact_json_value(json.loads(text), redact, fields))


def redact_sse_event(event: str, redact: TextRedactor, fields: frozenset[str] | None) -> str:
    """Redact the ``data`` payload of one SSE event (delimiter excluded).

    JSON payloads are redacted value by value; other payloads as plain text. Field order,
    comments, ``event``/``id``/``retry`` lines and the ``[DONE]`` sentinel are preserved.
    """
    lines = event.split("\n")
    data = [
        line[len(_SSE_DATA) :].removeprefix(" ") for line in lines if line.startswith(_SSE_DATA)
    ]
    payload = "\n".join(data)
    if not data or not payload.strip() or payload.strip() == _SSE_DONE:
        return event
    try:
        redacted = redact_json_text(payload, redact, fields)
    except json.JSONDecodeError:
        redacted = redact(payload)
    out: list[str] = []
    emitted = False
    for line in lines:
        if not line.startswith(_SSE_DATA):
            out.append(line)
        elif not emitted:
            out.extend(f"{_SSE_DATA} {part}" for part in redacted.split("\n"))
            emitted = True
    return "\n".join(out)


def redact_line(
    line: str, redact: TextRedactor, fields: frozenset[str] | None, *, json_lines: bool
) -> str:
    """Redact one NDJSON record or one line of streamed text."""
    if not line.strip():
        return line
    if json_lines:
        try:
            return redact_json_text(line, redact, fields)
        except json.JSONDecodeError:
            pass
    return redact(line)


def _safe_cut(buffer: bytes, limit: int) -> int:
    """Cut point <= ``limit`` after ASCII whitespace, else on a UTF-8 character boundary."""
    window = buffer[:limit]
    for index in range(len(window) - 1, 0, -1):
        if window[index] in _ASCII_SPACE:
            return index + 1
    cut = limit
    while cut > 0 and buffer[cut] & _UTF8_CONTINUATION_MASK == _UTF8_CONTINUATION:
        cut -= 1
    return cut or limit


class UnitBuffer:
    """Reassembles a byte stream into delimiter-terminated units (SSE events, lines).

    Holds back at most ``max_bytes`` of an unterminated unit; beyond that the oldest
    part is released early, cut at whitespace so entities are rarely split.
    """

    def __init__(self, delimiter: bytes, max_bytes: int, *, normalize_newlines: bool) -> None:
        self._delimiter = delimiter
        self._max_bytes = max_bytes
        self._normalize = normalize_newlines
        self._buffer = b""

    def feed(self, chunk: bytes) -> tuple[list[bytes], bytes]:
        """Add ``chunk``; return complete units (without delimiter) and forced overflow."""
        self._buffer += chunk
        if self._normalize:
            # A CR at the very end may still pair with an LF in the next chunk.
            head, tail = self._buffer[:-1], self._buffer[-1:]
            self._buffer = head.replace(b"\r\n", b"\n") + tail
        *units, self._buffer = self._buffer.split(self._delimiter)
        overflow = b""
        if len(self._buffer) > self._max_bytes:
            cut = _safe_cut(self._buffer, self._max_bytes)
            overflow, self._buffer = self._buffer[:cut], self._buffer[cut:]
        return units, overflow

    def flush(self) -> bytes:
        """Return whatever is left at end of stream."""
        rest, self._buffer = self._buffer, b""
        return rest.replace(b"\r\n", b"\n") if self._normalize else rest
