"""llm-security-shield: OWASP LLM Top 10 security middleware for FastAPI/Starlette."""

from importlib.metadata import version

__version__: str = version("llm-security-shield")

__all__ = ["__version__"]
