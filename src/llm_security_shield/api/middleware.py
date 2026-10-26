"""Pure-ASGI security middleware: inspects prompts inbound, redacts PII outbound.

Pure ASGI (not ``BaseHTTPMiddleware``) so streaming responses are handled chunk by chunk.
The middleware fails closed: anything it cannot inspect (oversized, compressed, or an
unparseable payload, or an unavailable model) is refused rather than passed through.
"""

import asyncio
import enum
import logging
import re
import uuid
from typing import Final

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from llm_security_shield.api.payloads import (
    MalformedPayloadError,
    TextRedactor,
    UnitBuffer,
    UnsupportedMediaError,
    extract_prompt_text,
    is_json,
    parse_content_type,
    redact_json_text,
    redact_line,
    redact_sse_event,
)
from llm_security_shield.api.problems import ProblemResponse, make_problem, send_problem
from llm_security_shield.api.services import RedactionUnavailableError, ShieldServices
from llm_security_shield.api.settings import API_PREFIX, normalize_path, path_under
from llm_security_shield.core import DetectorFailureError, TokenVault
from llm_security_shield.schemas import DetectionResult, OwaspCategory

_log = logging.getLogger("llm_security_shield.api")

REQUEST_ID_HEADER: Final = "x-request-id"
SESSION_HEADER: Final = "x-shield-session"
SESSION_PATTERN: Final = r"^[A-Za-z0-9_-]{8,128}$"
_REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
_SESSION_ID = re.compile(SESSION_PATTERN)
_BODYLESS_STATUSES: Final = frozenset({204, 304})


class _ClientDisconnectedError(Exception):
    pass


class _Mode(enum.Enum):
    PASSTHROUGH = enum.auto()
    BUFFER_JSON = enum.auto()
    BUFFER_TEXT = enum.auto()
    STREAM_SSE = enum.auto()
    STREAM_NDJSON = enum.auto()
    STREAM_TEXT = enum.auto()


def _request_id(headers: Headers) -> str:
    supplied = headers.get(REQUEST_ID_HEADER, "")
    return supplied if _REQUEST_ID.fullmatch(supplied) else uuid.uuid4().hex


def session_id(headers: Headers) -> str | None:
    """The validated ``X-Shield-Session`` header value, if any."""
    supplied = headers.get(SESSION_HEADER)
    return supplied if supplied is not None and _SESSION_ID.fullmatch(supplied) else None


async def _read_body(receive: Receive, limit: int) -> bytes | None:
    """Read the full request body; ``None`` once it exceeds ``limit`` bytes."""
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            raise _ClientDisconnectedError
        chunk: bytes = message.get("body", b"")
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks)


def _replay(body: bytes, receive: Receive) -> Receive:
    """A ``receive`` that yields the buffered body once, then defers to the original."""
    pending = True

    async def replay() -> Message:
        nonlocal pending
        if pending:
            pending = False
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replay


def _with_request_id(send: Send, request_id: str) -> Send:
    async def wrapped(message: Message) -> None:
        if message["type"] == "http.response.start":
            headers = [
                (k, v) for k, v in message.get("headers", []) if k.lower() != b"x-request-id"
            ]
            message = {**message, "headers": [*headers, (b"x-request-id", request_id.encode())]}
        await send(message)

    return wrapped


def _blocked_problem(result: DetectionResult, request_id: str) -> ProblemResponse:
    categories = {f.category for f in result.findings}
    if OwaspCategory.UNBOUNDED_CONSUMPTION in categories:
        return make_problem(
            413,
            "input-too-large",
            "Payload Too Large",
            "The prompt exceeds the configured size limit.",
            categories=categories,
            request_id=request_id,
        )
    return make_problem(
        400,
        "prompt-injection",
        "Request Blocked",
        "The request was blocked by the prompt security policy.",
        code="prompt_injection",
        categories=categories,
        request_id=request_id,
    )


class SecurityShieldMiddleware:
    """Inspect prompts with the engine and redact PII from responses on protected paths.

    Every response gets an ``X-Request-ID`` header (the caller's, if well-formed).
    """

    def __init__(self, app: ASGIApp, *, services: ShieldServices) -> None:
        self.app = app
        self.services = services

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        request_id = _request_id(headers)
        scope.setdefault("state", {})["request_id"] = request_id
        send = _with_request_id(send, request_id)

        settings = self.services.api_settings
        path = normalize_path(scope["path"])
        protected = settings.is_protected(scope["path"])
        if not protected and not path_under(path, API_PREFIX):
            await self.app(scope, receive, send)
            return

        try:
            body = await self._buffered_body(headers, receive)
        except _ClientDisconnectedError:
            return
        if body is None:
            await send_problem(
                send,
                make_problem(
                    413,
                    "payload-too-large",
                    "Payload Too Large",
                    "The request body exceeds the configured size limit.",
                    request_id=request_id,
                ),
            )
            return
        receive = _replay(body, receive)

        if protected and settings.scan_requests:
            problem = await self._inspect_request(scope, headers, body, request_id)
            if problem is not None:
                await send_problem(send, problem)
                return
        if protected and settings.redact_responses and scope["method"] != "HEAD":
            send = _ResponseRedactor(send, self.services, headers, request_id)
        await self.app(scope, receive, send)

    async def _buffered_body(self, headers: Headers, receive: Receive) -> bytes | None:
        limit = self.services.api_settings.max_request_bytes
        declared = headers.get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            return None
        return await _read_body(receive, limit)

    async def _inspect_request(
        self, scope: Scope, headers: Headers, body: bytes, request_id: str
    ) -> ProblemResponse | None:
        try:
            text = extract_prompt_text(
                headers.get("content-type", ""),
                body,
                scope.get("query_string", b""),
                self.services.api_settings.prompt_fields,
            )
        except UnsupportedMediaError:
            return make_problem(
                415,
                "unsupported-media-type",
                "Unsupported Media Type",
                "The request body type cannot be inspected.",
                request_id=request_id,
            )
        except MalformedPayloadError:
            return make_problem(
                400,
                "malformed-request",
                "Bad Request",
                "The request body could not be decoded.",
                request_id=request_id,
            )
        if not text:
            return None
        try:
            result = await self.services.engine.inspect(text)
        except DetectorFailureError:
            _log.exception("prompt inspection failed; failing closed")
            return make_problem(
                503,
                "inspection-unavailable",
                "Service Unavailable",
                "The request could not be inspected.",
                request_id=request_id,
            )
        return _blocked_problem(result, request_id) if result.blocked else None


def _select_mode(headers: Headers, status: int) -> _Mode:
    if status in _BODYLESS_STATUSES:
        return _Mode.PASSTHROUGH
    media, _ = parse_content_type(headers.get("content-type", ""))
    if media == "text/event-stream":
        return _Mode.STREAM_SSE
    if media in {"application/x-ndjson", "application/jsonl"}:
        return _Mode.STREAM_NDJSON
    if is_json(media):
        return _Mode.BUFFER_JSON
    if media.startswith("text/"):
        return _Mode.BUFFER_TEXT if "content-length" in headers else _Mode.STREAM_TEXT
    return _Mode.PASSTHROUGH


def _redaction_not_ready(_text: str) -> str:
    raise RuntimeError("redactor used before the response started")


class _ResponseRedactor:
    """ASGI ``send`` wrapper replacing PII in text-like response bodies with tokens.

    JSON and sized text bodies are buffered (up to ``max_response_bytes``) and rewritten
    whole; SSE, NDJSON and unsized text streams are rewritten unit by unit as they
    arrive. An entity split across two SSE events or lines is not detected.
    """

    def __init__(
        self, send: Send, services: ShieldServices, request_headers: Headers, request_id: str
    ) -> None:
        self._send = send
        self._services = services
        self._settings = services.api_settings
        self._session = session_id(request_headers)
        self._request_id = request_id
        self._mode = _Mode.PASSTHROUGH
        self._start: Message = {}
        self._charset = "utf-8"
        self._chunks: list[bytes] = []
        self._size = 0
        self._units: UnitBuffer | None = None
        self._redact: TextRedactor = _redaction_not_ready
        self._failed = False

    async def __call__(self, message: Message) -> None:
        if self._failed:
            return  # a problem response already replaced the app's response
        if message["type"] == "http.response.start":
            await self._on_start(message)
        elif message["type"] == "http.response.body" and self._mode is not _Mode.PASSTHROUGH:
            await self._on_body(message)
        else:
            await self._send(message)

    async def _on_start(self, message: Message) -> None:
        headers = Headers(raw=message.get("headers", []))
        self._mode = _select_mode(headers, message["status"])
        if self._mode is _Mode.PASSTHROUGH:
            await self._send(message)
            return
        if headers.get("content-encoding", "identity").lower() != "identity":
            await self._fail(502, "The response is encoded and cannot be inspected.")
            return
        try:
            redactor = await self._services.redactor(self._vault())
            self._redact = lambda text: redactor.anonymize(text).redacted_text
        except RedactionUnavailableError:
            await self._fail(503, "PII redaction is unavailable.", kind="redaction-unavailable")
            return
        _, self._charset = parse_content_type(headers.get("content-type", ""))
        raw = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"content-length"]
        self._start = {**message, "headers": raw}
        if self._mode in {_Mode.STREAM_SSE, _Mode.STREAM_NDJSON, _Mode.STREAM_TEXT}:
            sse = self._mode is _Mode.STREAM_SSE
            self._units = UnitBuffer(
                b"\n\n" if sse else b"\n",
                self._settings.max_stream_buffer_bytes,
                normalize_newlines=sse,
            )
            await self._send(self._start)

    def _vault(self) -> TokenVault:
        sessions = self._services.sessions
        return sessions.get_or_create(self._session) if self._session else sessions.ephemeral()

    async def _on_body(self, message: Message) -> None:
        chunk: bytes = message.get("body", b"")
        more = bool(message.get("more_body", False))
        if self._units is not None:
            await self._stream(self._units, chunk, more=more)
            return
        self._size += len(chunk)
        if self._size > self._settings.max_response_bytes:
            await self._fail(502, "The response exceeds the inspectable size limit.")
            return
        self._chunks.append(chunk)
        if more:
            return
        try:
            body = await asyncio.to_thread(self._rewrite_buffered, b"".join(self._chunks))
        except (ValueError, LookupError, RecursionError):
            _log.exception("response redaction failed; failing closed")
            await self._fail(502, "The response could not be inspected.")
            return
        headers = [*self._start["headers"], (b"content-length", str(len(body)).encode())]
        await self._send({**self._start, "headers": headers})
        await self._send({"type": "http.response.body", "body": body, "more_body": False})

    def _rewrite_buffered(self, body: bytes) -> bytes:
        text = body.decode(self._charset)
        if self._mode is _Mode.BUFFER_JSON:
            if not text.strip():
                return body
            return redact_json_text(text, self._redact, self._settings.response_fields).encode()
        return self._redact(text).encode(self._charset)

    async def _stream(self, buffer: UnitBuffer, chunk: bytes, *, more: bool) -> None:
        units, overflow = buffer.feed(chunk)
        tail = b"" if more else buffer.flush()
        if units or overflow or tail:
            # Headers are already sent: on failure the exception aborts the connection,
            # which is the only fail-closed option left mid-stream.
            out = await asyncio.to_thread(self._rewrite_units, units, overflow, tail)
            await self._send({"type": "http.response.body", "body": out, "more_body": more})
        elif not more:
            await self._send({"type": "http.response.body", "body": b"", "more_body": False})

    def _rewrite_units(self, units: list[bytes], overflow: bytes, tail: bytes) -> bytes:
        redact, fields = self._redact, self._settings.response_fields
        charset = "utf-8" if self._mode is not _Mode.STREAM_TEXT else self._charset
        if self._mode is _Mode.STREAM_SSE:
            delimiter = "\n\n"
            done = [redact_sse_event(u.decode(charset), redact, fields) for u in units]
        else:
            delimiter = "\n"
            json_lines = self._mode is _Mode.STREAM_NDJSON
            done = [
                redact_line(u.decode(charset), redact, fields, json_lines=json_lines) for u in units
            ]
        out = "".join(unit + delimiter for unit in done)
        if overflow:
            out += redact(overflow.decode(charset))
        if tail:
            out += (
                redact_sse_event(tail.decode(charset), redact, fields)
                if self._mode is _Mode.STREAM_SSE
                else redact_line(
                    tail.decode(charset),
                    redact,
                    fields,
                    json_lines=self._mode is _Mode.STREAM_NDJSON,
                )
            )
        return out.encode(charset)

    async def _fail(
        self, status: int, detail: str, *, kind: str = "response-not-inspectable"
    ) -> None:
        self._failed = True
        title = "Service Unavailable" if status == 503 else "Bad Gateway"  # noqa: PLR2004
        await send_problem(
            self._send, make_problem(status, kind, title, detail, request_id=self._request_id)
        )
