"""PII detection and redaction results (OWASP LLM02).

Original values never appear in these models: they live only in the TokenVault.
"""

from typing import Annotated, Self

from pydantic import Field, StringConstraints, model_validator

from llm_security_shield.schemas._base import ShieldModel, TextSpan

#: Presidio-style entity name, e.g. ``EMAIL_ADDRESS``.
EntityType = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Z][A-Z0-9_]*$")
]

#: Placeholder substituted for a PII value, e.g. ``[REDACTED_EMAIL_ADDRESS]``.
RedactionToken = Annotated[
    str, StringConstraints(max_length=96, pattern=r"^\[REDACTED_[A-Z][A-Z0-9_]*\]$")
]


class PiiEntity(ShieldModel):
    """A PII entity located in the original (pre-redaction) text."""

    entity_type: EntityType
    span: TextSpan
    score: float = Field(ge=0.0, le=1.0)


class RedactionResult(ShieldModel):
    """Redacted text plus the entities and tokens that replaced them."""

    redacted_text: str
    entities: tuple[PiiEntity, ...] = ()
    tokens: tuple[RedactionToken, ...] = ()

    @model_validator(mode="after")
    def _check_tokens_present(self) -> Self:
        missing = [t for t in self.tokens if t not in self.redacted_text]
        if missing:
            raise ValueError(f"tokens absent from redacted_text: {missing}")
        return self

    @property
    def redacted(self) -> bool:
        """Whether any value was replaced."""
        return bool(self.tokens)
