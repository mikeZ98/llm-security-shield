"""Error envelope returned to clients when the shield blocks a request."""

from typing import Literal

from pydantic import Field

from llm_security_shield.schemas._base import OwaspCategory, ShieldModel

ErrorCode = Literal["prompt_injection", "tool_call_denied", "policy_violation", "internal_error"]


class ShieldError(ShieldModel):
    """Client-safe error detail; never echoes the offending input."""

    code: ErrorCode
    message: str = Field(min_length=1, max_length=256)
    categories: tuple[OwaspCategory, ...] = ()
    request_id: str | None = Field(default=None, min_length=1, max_length=128)


class ShieldErrorResponse(ShieldModel):
    """JSON body for 4xx/5xx responses produced by the middleware."""

    error: ShieldError
