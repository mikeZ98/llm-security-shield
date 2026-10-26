"""Application factory wiring services, middleware, routes and problem handlers."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from http import HTTPStatus

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from presidio_analyzer import AnalyzerEngine
from starlette.exceptions import HTTPException as StarletteHTTPException

from llm_security_shield import __version__
from llm_security_shield.api.middleware import SecurityShieldMiddleware
from llm_security_shield.api.problems import ProblemError, make_problem, problem_response
from llm_security_shield.api.routes import get_request_id, router
from llm_security_shield.api.services import RedactionUnavailableError, ShieldServices
from llm_security_shield.api.settings import ApiSettings
from llm_security_shield.core import ShieldSettings
from llm_security_shield.schemas import ToolPolicy

_log = logging.getLogger("llm_security_shield.api")
_MAX_VALIDATION_ERRORS = 5


def _validation_detail(exc: RequestValidationError) -> str:
    """Locations and error types only: FastAPI's default handler echoes the input."""
    issues = [
        f"{'.'.join(str(part) for part in error['loc'])}: {error['type']}"
        for error in exc.errors()[:_MAX_VALIDATION_ERRORS]
    ]
    return ("Invalid request: " + "; ".join(issues))[:256]


def _install_problem_handlers(app: FastAPI) -> None:
    @app.exception_handler(ProblemError)
    async def _problem(_request: Request, exc: ProblemError) -> Response:
        return problem_response(exc.problem)

    @app.exception_handler(RequestValidationError)
    async def _invalid(request: Request, exc: RequestValidationError) -> Response:
        return problem_response(
            make_problem(
                422,
                "invalid-request",
                "Unprocessable Content",
                _validation_detail(exc),
                request_id=get_request_id(request),
            )
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> Response:
        phrase = HTTPStatus(exc.status_code).phrase
        return problem_response(
            make_problem(
                exc.status_code,
                "http-error",
                phrase,
                phrase,
                request_id=get_request_id(request),
            )
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, _exc: Exception) -> Response:
        return problem_response(
            make_problem(
                500,
                "internal-error",
                "Internal Server Error",
                "An unexpected error occurred.",
                request_id=get_request_id(request),
            )
        )


def create_app(
    settings: ShieldSettings | None = None,
    api_settings: ApiSettings | None = None,
    *,
    tool_policy: ToolPolicy | None = None,
    analyzer: AnalyzerEngine | None = None,
    services: ShieldServices | None = None,
) -> FastAPI:
    """Build the shield application.

    Pass ``services`` to share one container (e.g. across apps or tests); otherwise one
    is built from the other arguments. The PII model is warmed up during startup, and a
    load failure leaves the app running in a degraded state that fails closed.
    """
    shield = services or ShieldServices(
        settings, api_settings, tool_policy=tool_policy, analyzer=analyzer
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            await shield.analyzer()
        except RedactionUnavailableError:
            _log.warning("starting degraded: PII redaction unavailable")
        yield
        shield.sessions.clear()

    app = FastAPI(title="llm-security-shield", version=__version__, lifespan=lifespan)
    app.state.shield = shield
    app.include_router(router)
    _install_problem_handlers(app)
    app.add_middleware(SecurityShieldMiddleware, services=shield)
    return app
