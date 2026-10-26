"""Reversible in-memory TokenVault for PII placeholders (OWASP LLM02).

Each original value is sealed with AES-256-GCM under a per-vault random key, with the
token as associated data so a ciphertext cannot be swapped onto another token. A keyed
HMAC-SHA256 digest of ``(entity_type, value)`` indexes values for de-duplication and is
re-checked on every reveal. Plaintext is never stored, logged, repr'd or serialized.

Threat model: the keys live in the same process, so this guards against accidental
exposure (logs, reprs, pickling, debug dumps), not against code running in-process.

Operations hold a ``threading.Lock`` only for short, non-awaiting critical sections, so
the vault is safe to share across threads and to call directly from coroutines.
"""

import hashlib
import hmac
import os
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import NoReturn

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from llm_security_shield.core.config import ShieldSettings

_ENTITY_TYPE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
TOKEN_PATTERN = re.compile(r"\[REDACTED_[A-Z][A-Z0-9_]*\]")

_NONCE_BYTES = 12
_MAC_KEY_BYTES = 32


class VaultError(Exception):
    """Base class for TokenVault errors."""


class VaultFullError(VaultError):
    """Raised when the vault is at capacity after purging expired entries."""


class VaultIntegrityError(VaultError):
    """Raised when a sealed entry fails decryption or digest validation."""


@dataclass(frozen=True, slots=True)
class _Sealed:
    entity_type: str
    nonce: bytes
    ciphertext: bytes
    digest: bytes
    expires_at: float


class TokenVault:
    """Maps ``[REDACTED_<ENTITY>_<n>]`` tokens back to their sealed original values."""

    def __init__(
        self,
        ttl_seconds: float,
        *,
        max_entries: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._clock = clock
        self._aead = AESGCM(AESGCM.generate_key(bit_length=256))
        self._mac_key = os.urandom(_MAC_KEY_BYTES)
        self._entries: dict[str, _Sealed] = {}
        self._index: dict[bytes, str] = {}
        self._counters: dict[str, int] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_settings(cls, settings: ShieldSettings) -> "TokenVault":
        """Build a vault using the configured TTL and capacity."""
        return cls(settings.vault_ttl_seconds, max_entries=settings.vault_max_entries)

    def tokenize(self, entity_type: str, value: str) -> str:
        """Seal ``value`` and return its token. The same live value reuses its token."""
        if not _ENTITY_TYPE.fullmatch(entity_type):
            raise ValueError("entity_type must match [A-Z][A-Z0-9_]{0,63}")
        if not value:
            raise ValueError("value must not be empty")
        digest = self._digest(entity_type, value)
        with self._lock:
            now = self._clock()
            self._purge(now)
            if (token := self._index.get(digest)) is not None:
                self._entries[token] = replace(self._entries[token], expires_at=now + self._ttl)
                return token
            if len(self._entries) >= self._max_entries:
                raise VaultFullError("token vault is at capacity")
            count = self._counters.get(entity_type, 0) + 1
            self._counters[entity_type] = count
            token = f"[REDACTED_{entity_type}_{count}]"
            nonce = os.urandom(_NONCE_BYTES)
            self._entries[token] = _Sealed(
                entity_type=entity_type,
                nonce=nonce,
                ciphertext=self._aead.encrypt(nonce, value.encode(), token.encode()),
                digest=digest,
                expires_at=now + self._ttl,
            )
            self._index[digest] = token
            return token

    def reveal(self, token: str) -> str | None:
        """Return the original value for ``token``, or ``None`` if unknown or expired."""
        with self._lock:
            self._purge(self._clock())
            entry = self._entries.get(token)
        if entry is None:
            return None
        try:
            value = self._aead.decrypt(entry.nonce, entry.ciphertext, token.encode()).decode()
        except (InvalidTag, UnicodeDecodeError) as exc:
            raise VaultIntegrityError("sealed entry failed authentication") from exc
        if not hmac.compare_digest(entry.digest, self._digest(entry.entity_type, value)):
            raise VaultIntegrityError("sealed entry failed digest validation")
        return value

    def detokenize(self, text: str) -> str:
        """Replace every live token in ``text`` with its original; leave others as-is."""
        return TOKEN_PATTERN.sub(lambda m: self.reveal(m.group()) or m.group(), text)

    def purge_expired(self) -> int:
        """Drop expired entries and return how many were removed."""
        with self._lock:
            return self._purge(self._clock())

    def clear(self) -> None:
        """Drop every entry."""
        with self._lock:
            self._entries.clear()
            self._index.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def __repr__(self) -> str:
        return f"TokenVault(entries={len(self)}, ttl_seconds={self._ttl})"

    def __reduce__(self) -> NoReturn:
        raise TypeError("TokenVault cannot be pickled or copied")

    def _digest(self, entity_type: str, value: str) -> bytes:
        message = entity_type.encode() + b"\x00" + value.encode()
        return hmac.new(self._mac_key, message, hashlib.sha256).digest()

    def _purge(self, now: float) -> int:
        expired = [t for t, e in self._entries.items() if e.expires_at <= now]
        for token in expired:
            del self._index[self._entries.pop(token).digest]
        return len(expired)
