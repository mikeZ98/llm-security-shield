"""Inspection and utility endpoints under ``/v1/shield``.

These routes are excluded from the middleware's inspection (they handle raw prompts and
PII by design) but share its request-size limit and request-ID handling.
"""

import asyncio
import contextlib
import hmac
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, Header, Request, Response
from pydantic import Field

from llm_security_shield import __version__
from llm_security_shield.api.middleware import SESSION_PATTERN
from llm_security_shield.api.problems import ProblemError, make_problem
from llm_security_shield.api.services import RedactionUnavailableError, ShieldServices
from llm_security_shield.api.settings import API_PREFIX
from llm_security_shield.core import DetectorFailureError
from llm_security_shield.schemas import (
    DetectionResult,
    RedactionResult,
    ShieldModel,
    ToolCall,
    ToolCallDecision,
)
from llm_security_shield.tools.presidio import SPACY_MODEL

MAX_TEXT_CHARS = 1_000_000


class TextRequest(ShieldModel):
    """A body carrying one text to process."""

    text: str = Field(max_length=MAX_TEXT_CHARS)


class DeanonymizeResponse(ShieldModel):
    """Text with this session's tokens restored to their original values."""

    text: str


class ComponentHealth(ShieldModel):
    """Availability of one dependency."""

    name: str
    available: bool
    detail: str | None = None


class HealthResponse(ShieldModel):
    """Overall service health; ``degraded`` is served with HTTP 503."""

    status: Literal["ok", "degraded"]
    version: str
    components: tuple[ComponentHealth, ...]


def get_services(request: Request) -> ShieldServices:
    """Dependency: the application's shared :class:`ShieldServices`."""
    return cast("ShieldServices", request.app.state.shield)


def get_request_id(request: Request) -> str | None:
    """Dependency: the request ID assigned by the middleware, if it ran."""
    return cast("str | None", getattr(request.state, "request_id", None))


Services = Annotated[ShieldServices, Depends(get_services)]
RequestId = Annotated[str | None, Depends(get_request_id)]


def _unauthorized(request_id: str | None) -> ProblemError:
    return ProblemError(
        make_problem(
            401,
            "unauthorized",
            "Unauthorized",
            "A valid API key is required.",
            request_id=request_id,
        )
    )


async def require_api_key(
    services: Services,
    request_id: RequestId,
    authorization: Annotated[str | None, Header()] = None,
    x_shield_api_key: Annotated[str | None, Header()] = None,
) -> None:
    """Accept ``Authorization: Bearer <key>`` or ``X-Shield-Api-Key`` when a key is set."""
    expected = services.api_settings.api_key
    if expected is None:
        return
    scheme, _, credential = (authorization or "").partition(" ")
    supplied = credential if scheme.lower() == "bearer" else (x_shield_api_key or "")
    if not hmac.compare_digest(supplied.encode(), expected.get_secret_value().encode()):
        raise _unauthorized(request_id)


async def require_deanonymize_enabled(services: Services, request_id: RequestId) -> None:
    """Deanonymization returns raw PII, so it is off unless an API key is configured."""
    if services.api_settings.api_key is None:
        raise ProblemError(
            make_problem(
                403,
                "deanonymization-disabled",
                "Forbidden",
                "Deanonymization requires SHIELD_API_API_KEY to be configured.",
                request_id=request_id,
            )
        )


def _redaction_unavailable(request_id: str | None) -> ProblemError:
    return ProblemError(
        make_problem(
            503,
            "redaction-unavailable",
            "Service Unavailable",
            "PII redaction is unavailable.",
            request_id=request_id,
        )
    )


router = APIRouter(prefix=API_PREFIX, tags=["shield"])
_protected = APIRouter(dependencies=[Depends(require_api_key)])


@_protected.post("/sanitize")
async def sanitize(body: TextRequest, services: Services, request_id: RequestId) -> DetectionResult:
    """Score a prompt for injection, jailbreak and extraction attempts (never blocks)."""
    try:
        return await services.engine.inspect(body.text)
    except DetectorFailureError as exc:
        raise ProblemError(
            make_problem(
                503,
                "inspection-unavailable",
                "Service Unavailable",
                "The text could not be inspected.",
                request_id=request_id,
            )
        ) from exc


@_protected.post("/anonymize")
async def anonymize(
    body: TextRequest,
    services: Services,
    request_id: RequestId,
    x_shield_session: Annotated[str | None, Header(pattern=SESSION_PATTERN)] = None,
) -> RedactionResult:
    """Replace PII with tokens; with ``X-Shield-Session`` the tokens are restorable."""
    sessions = services.sessions
    vault = sessions.get_or_create(x_shield_session) if x_shield_session else sessions.ephemeral()
    try:
        redactor = await services.redactor(vault)
    except RedactionUnavailableError as exc:
        raise _redaction_unavailable(request_id) from exc
    return await asyncio.to_thread(redactor.anonymize, body.text)


@_protected.post("/deanonymize", dependencies=[Depends(require_deanonymize_enabled)])
async def deanonymize(
    body: TextRequest,
    services: Services,
    response: Response,
    x_shield_session: Annotated[str, Header(pattern=SESSION_PATTERN)],
) -> DeanonymizeResponse:
    """Restore tokens issued to the same authenticated session; others pass unchanged."""
    response.headers["cache-control"] = "no-store"
    vault = services.sessions.get(x_shield_session)
    return DeanonymizeResponse(text=vault.detokenize(body.text) if vault else body.text)


@_protected.post("/tools/validate")
async def validate_tool_call(call: ToolCall, services: Services) -> ToolCallDecision:
    """Evaluate one tool call against the configured policy (OWASP LLM06)."""
    return services.guard.evaluate(call)


@router.get("/health")
async def health(services: Services, response: Response) -> HealthResponse:
    """Report engine, vault and PII model availability; 503 when degraded."""
    with contextlib.suppress(RedactionUnavailableError):
        await services.analyzer()
    model_ok = services.analyzer_loaded
    components = (
        ComponentHealth(name="engine", available=True, detail="heuristic detectors loaded"),
        ComponentHealth(
            name="vault", available=True, detail=f"{len(services.sessions)} active session(s)"
        ),
        ComponentHealth(
            name="pii_model",
            available=model_ok,
            detail=SPACY_MODEL if model_ok else services.analyzer_error,
        ),
    )
    if not model_ok:
        response.status_code = 503
    return HealthResponse(
        status="ok" if model_ok else "degraded", version=__version__, components=components
    )


router.include_router(_protected)
