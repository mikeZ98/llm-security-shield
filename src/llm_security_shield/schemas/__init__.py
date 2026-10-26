"""Immutable, strictly validated data contracts shared across the shield."""

from llm_security_shield.schemas._base import OwaspCategory, Severity, ShieldModel, TextSpan
from llm_security_shield.schemas.detection import DetectionFinding, DetectionResult, RuleId
from llm_security_shield.schemas.errors import ErrorCode, ShieldError, ShieldErrorResponse
from llm_security_shield.schemas.pii import EntityType, PiiEntity, RedactionResult, RedactionToken
from llm_security_shield.schemas.tools import (
    PolicyAction,
    ToolCall,
    ToolCallDecision,
    ToolName,
    ToolPolicy,
    ToolRule,
)

__all__ = [
    "DetectionFinding",
    "DetectionResult",
    "EntityType",
    "ErrorCode",
    "OwaspCategory",
    "PiiEntity",
    "PolicyAction",
    "RedactionResult",
    "RedactionToken",
    "RuleId",
    "Severity",
    "ShieldError",
    "ShieldErrorResponse",
    "ShieldModel",
    "TextSpan",
    "ToolCall",
    "ToolCallDecision",
    "ToolName",
    "ToolPolicy",
    "ToolRule",
]
