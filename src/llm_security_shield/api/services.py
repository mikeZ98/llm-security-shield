"""Shared service container: engine, tool guard, session vaults and the PII analyzer."""

import asyncio
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Sequence

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

from llm_security_shield.api.settings import ApiSettings
from llm_security_shield.core import Detector, SecurityShieldEngine, ShieldSettings, TokenVault
from llm_security_shield.guardrails import CommandGuard, default_detectors
from llm_security_shield.schemas import ToolPolicy
from llm_security_shield.tools import (
    PresidioAnonymizer,
    ToolCallGuard,
    ToolPolicyGuard,
    build_analyzer,
)

_log = logging.getLogger("llm_security_shield.api")


class RedactionUnavailableError(RuntimeError):
    """Raised when the PII analyzer cannot be loaded; callers must fail closed."""


class SessionVaults:
    """One :class:`TokenVault` per session, so tokens are only restorable by their session.

    Sessions idle longer than the vault TTL are dropped, and the least recently used
    session is evicted at capacity (its tokens then stay unrestorable placeholders).
    """

    def __init__(
        self,
        *,
        ttl_seconds: float,
        max_entries: int,
        max_sessions: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._max_sessions = max_sessions
        self._clock = clock
        self._vaults: OrderedDict[str, tuple[TokenVault, float]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, session_id: str) -> TokenVault | None:
        """Return the live vault for ``session_id`` without creating one."""
        with self._lock:
            now = self._clock()
            self._expire(now)
            if (entry := self._vaults.get(session_id)) is None:
                return None
            self._touch(session_id, entry[0], now)
            return entry[0]

    def get_or_create(self, session_id: str) -> TokenVault:
        """Return the vault for ``session_id``, creating it (and evicting) as needed."""
        with self._lock:
            now = self._clock()
            self._expire(now)
            if (entry := self._vaults.get(session_id)) is not None:
                vault = entry[0]
            else:
                while len(self._vaults) >= self._max_sessions:
                    self._vaults.popitem(last=False)
                vault = self.ephemeral()
            self._touch(session_id, vault, now)
            return vault

    def ephemeral(self) -> TokenVault:
        """A throwaway vault for callers without a session (tokens are not restorable)."""
        return TokenVault(self._ttl, max_entries=self._max_entries, clock=self._clock)

    def clear(self) -> None:
        """Drop every session."""
        with self._lock:
            self._vaults.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._vaults)

    def _touch(self, session_id: str, vault: TokenVault, now: float) -> None:
        self._vaults[session_id] = (vault, now)
        self._vaults.move_to_end(session_id)

    def _expire(self, now: float) -> None:
        while self._vaults:
            session_id, (_, last_used) = next(iter(self._vaults.items()))
            if now - last_used < self._ttl:
                return
            del self._vaults[session_id]


def _load_policy(api_settings: ApiSettings) -> ToolPolicy:
    if api_settings.tool_policy_file is None:
        return ToolPolicy()
    return ToolPolicy.model_validate_json(api_settings.tool_policy_file.read_text("utf-8"))


class ShieldServices:
    """Everything the middleware and routes share; build once per application."""

    def __init__(
        self,
        settings: ShieldSettings | None = None,
        api_settings: ApiSettings | None = None,
        *,
        tool_policy: ToolPolicy | None = None,
        analyzer: AnalyzerEngine | None = None,
        detectors: Sequence[Detector] | None = None,
    ) -> None:
        self.settings = ShieldSettings() if settings is None else settings
        self.api_settings = ApiSettings() if api_settings is None else api_settings
        self.engine = SecurityShieldEngine(
            self.settings, default_detectors(self.settings) if detectors is None else detectors
        )
        self.guard: ToolCallGuard = CommandGuard(
            ToolPolicyGuard(
                _load_policy(self.api_settings) if tool_policy is None else tool_policy,
                sandbox_roots=self.api_settings.sandbox_roots,
            )
        )
        self.sessions = SessionVaults(
            ttl_seconds=self.settings.vault_ttl_seconds,
            max_entries=self.settings.vault_max_entries,
            max_sessions=self.api_settings.max_sessions,
        )
        self._analyzer = analyzer
        self._analyzer_error: str | None = None
        self._analyzer_lock = threading.Lock()
        self._anonymizer = AnonymizerEngine()  # type: ignore[no-untyped-call]  # unannotated

    @property
    def analyzer_loaded(self) -> bool:
        """Whether the PII analyzer is ready."""
        return self._analyzer is not None

    @property
    def analyzer_error(self) -> str | None:
        """Why the analyzer failed to load, if it did."""
        return self._analyzer_error

    async def analyzer(self) -> AnalyzerEngine:
        """Return the shared analyzer, loading it off the event loop on first use."""
        if self._analyzer is not None:
            return self._analyzer
        return await asyncio.to_thread(self._load_analyzer)

    async def redactor(self, vault: TokenVault) -> PresidioAnonymizer:
        """A :class:`PresidioAnonymizer` writing tokens into ``vault``."""
        return PresidioAnonymizer(
            vault, analyzer=await self.analyzer(), anonymizer=self._anonymizer
        )

    def _load_analyzer(self) -> AnalyzerEngine:
        with self._analyzer_lock:
            if self._analyzer is not None:
                return self._analyzer
            if self._analyzer_error is not None:
                raise RedactionUnavailableError(self._analyzer_error)
            try:
                self._analyzer = build_analyzer()
            except Exception as exc:
                self._analyzer_error = f"PII analyzer failed to load: {type(exc).__name__}"
                _log.exception("PII analyzer failed to load")
                raise RedactionUnavailableError(self._analyzer_error) from exc
            return self._analyzer
