"""RFC 7807 problem details, shaped as a superset of :class:`ShieldErrorResponse`.

Problems never echo the request: no prompt text, PII or argument values reach the body.
"""

from collections.abc import Iterable
from typing import Final

from pydantic import Field
from starlette.responses import Response
from starlette.types import Send

from llm_security_shield.schemas import ErrorCode, OwaspCategory, ShieldError, ShieldErrorResponse

PROBLEM_MEDIA_TYPE: Final = "application/problem+json"
_TYPE_PREFIX: Final = "urn:llm-security-shield:problem:"
_NO_STORE: Final = {"cache-control": "no-store"}


class ProblemResponse(ShieldErrorResponse):
    """``application/problem+json`` body; ``error`` is an RFC 7807 extension member."""

    type: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=128)
    status: int = Field(ge=400, le=599)
    detail: str = Field(min_length=1, max_length=256)
    instance: str | None = Field(default=None, max_length=160)


class ProblemError(Exception):
    """Raise from routes or dependencies to answer with a problem response."""

    def __init__(self, problem: ProblemResponse) -> None:
        super().__init__(problem.detail)
        self.problem = problem


def make_problem(
    status: int,
    kind: str,
    title: str,
    detail: str,
    *,
    code: ErrorCode | None = None,
    categories: Iterable[OwaspCategory] = (),
    request_id: str | None = None,
) -> ProblemResponse:
    """Build a problem; ``kind`` becomes the ``type`` URN suffix."""
    resolved_code: ErrorCode = code or ("internal_error" if status >= 500 else "policy_violation")  # noqa: PLR2004
    return ProblemResponse(
        type=_TYPE_PREFIX + kind,
        title=title,
        status=status,
        detail=detail,
        instance=f"urn:request:{request_id}" if request_id else None,
        error=ShieldError(
            code=resolved_code,
            message=detail,
            categories=tuple(sorted(set(categories))),
            request_id=request_id,
        ),
    )


def render_problem(problem: ProblemResponse) -> bytes:
    """Serialize ``problem`` to its JSON wire form."""
    return problem.model_dump_json(exclude_none=True).encode()


def problem_response(problem: ProblemResponse) -> Response:
    """Starlette response for ``problem``.

    Carries ``X-Request-ID`` itself: unhandled-error responses are produced outside the
    shield middleware, which would otherwise add the header.
    """
    headers = dict(_NO_STORE)
    if problem.error.request_id:
        headers["x-request-id"] = problem.error.request_id
    return Response(
        render_problem(problem),
        status_code=problem.status,
        media_type=PROBLEM_MEDIA_TYPE,
        headers=headers,
    )


async def send_problem(send: Send, problem: ProblemResponse) -> None:
    """Send ``problem`` as a complete response over raw ASGI."""
    body = render_problem(problem)
    await send(
        {
            "type": "http.response.start",
            "status": problem.status,
            "headers": [
                (b"content-type", PROBLEM_MEDIA_TYPE.encode()),
                (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
