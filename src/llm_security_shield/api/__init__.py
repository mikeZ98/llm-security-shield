"""FastAPI/Starlette integration: security middleware, inspection API and app factory."""

from llm_security_shield.api.app import create_app
from llm_security_shield.api.middleware import (
    REQUEST_ID_HEADER,
    SESSION_HEADER,
    SecurityShieldMiddleware,
)
from llm_security_shield.api.problems import (
    PROBLEM_MEDIA_TYPE,
    ProblemError,
    ProblemResponse,
    make_problem,
)
from llm_security_shield.api.routes import (
    ComponentHealth,
    DeanonymizeResponse,
    HealthResponse,
    TextRequest,
    router,
)
from llm_security_shield.api.services import (
    RedactionUnavailableError,
    SessionVaults,
    ShieldServices,
)
from llm_security_shield.api.settings import API_PREFIX, ApiSettings

__all__ = [
    "API_PREFIX",
    "PROBLEM_MEDIA_TYPE",
    "REQUEST_ID_HEADER",
    "SESSION_HEADER",
    "ApiSettings",
    "ComponentHealth",
    "DeanonymizeResponse",
    "HealthResponse",
    "ProblemError",
    "ProblemResponse",
    "RedactionUnavailableError",
    "SecurityShieldMiddleware",
    "SessionVaults",
    "ShieldServices",
    "TextRequest",
    "create_app",
    "make_problem",
    "router",
]
