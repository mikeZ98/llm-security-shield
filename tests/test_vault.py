"""TokenVault: AES-256-GCM sealing, isolation, TTL, capacity, concurrency and no leakage."""

import copy
import dataclasses
import pickle
import threading

import pytest

from llm_security_shield.core import (
    ShieldSettings,
    TokenVault,
    VaultFullError,
    VaultIntegrityError,
)
from tests.support import FakeClock

EMAIL = "alice@example.com"


def test_roundtrip(vault: TokenVault) -> None:
    token = vault.tokenize("EMAIL_ADDRESS", EMAIL)
    assert token == "[REDACTED_EMAIL_ADDRESS_1]"
    assert vault.reveal(token) == EMAIL


def test_same_value_reuses_token(vault: TokenVault) -> None:
    first = vault.tokenize("PERSON", "Alice")
    assert vault.tokenize("PERSON", "Alice") == first
    assert vault.tokenize("PERSON", "Bob") == "[REDACTED_PERSON_2]"
    assert len(vault) == 2


def test_tokens_are_scoped_by_entity_type(vault: TokenVault) -> None:
    assert vault.tokenize("PERSON", EMAIL) != vault.tokenize("EMAIL_ADDRESS", EMAIL)


def test_unknown_token(vault: TokenVault) -> None:
    assert vault.reveal("[REDACTED_PERSON_9]") is None


def test_detokenize_leaves_unknown_tokens(vault: TokenVault) -> None:
    token = vault.tokenize("EMAIL_ADDRESS", EMAIL)
    text = f"mail {token}, not [REDACTED_NOPE_1]"
    assert vault.detokenize(text) == f"mail {EMAIL}, not [REDACTED_NOPE_1]"


def test_ttl_expiry(vault: TokenVault, clock: FakeClock) -> None:
    token = vault.tokenize("PERSON", "Alice")
    clock.advance(59)
    assert vault.reveal(token) == "Alice"
    clock.advance(1)
    assert vault.reveal(token) is None
    assert len(vault) == 0


def test_reuse_refreshes_ttl(vault: TokenVault, clock: FakeClock) -> None:
    token = vault.tokenize("PERSON", "Alice")
    clock.advance(50)
    vault.tokenize("PERSON", "Alice")
    clock.advance(50)
    assert vault.reveal(token) == "Alice"


def test_purge_expired(vault: TokenVault, clock: FakeClock) -> None:
    vault.tokenize("PERSON", "Alice")
    vault.tokenize("PERSON", "Bob")
    clock.advance(61)
    assert vault.purge_expired() == 2
    assert vault.purge_expired() == 0


def test_capacity(clock: FakeClock) -> None:
    small = TokenVault(10, max_entries=2, clock=clock)
    small.tokenize("X", "1")
    small.tokenize("X", "2")
    with pytest.raises(VaultFullError):
        small.tokenize("X", "3")
    clock.advance(11)
    assert small.tokenize("X", "3") == "[REDACTED_X_3]"


def test_clear(vault: TokenVault) -> None:
    token = vault.tokenize("PERSON", "Alice")
    vault.clear()
    assert len(vault) == 0
    assert vault.reveal(token) is None


@pytest.mark.parametrize(
    ("entity", "value", "message"),
    [
        ("lower", "v", "entity_type"),
        ("X" * 65, "v", "entity_type"),
        ("X", "", "value"),
    ],
)
def test_invalid_input(vault: TokenVault, entity: str, value: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        vault.tokenize(entity, value)


@pytest.mark.parametrize(
    ("ttl", "max_entries", "message"), [(0, 1, "ttl_seconds"), (1, 0, "max_entries")]
)
def test_invalid_construction(ttl: float, max_entries: int, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        TokenVault(ttl, max_entries=max_entries)


def test_from_settings() -> None:
    vault = TokenVault.from_settings(ShieldSettings(vault_ttl_seconds=5, vault_max_entries=1))
    vault.tokenize("X", "a")
    with pytest.raises(VaultFullError):
        vault.tokenize("X", "b")


class TestNoLeakage:
    def test_plaintext_not_stored(self, vault: TokenVault) -> None:
        vault.tokenize("EMAIL_ADDRESS", EMAIL)
        internals = repr((vault._entries, vault._index, vault._counters))
        assert EMAIL not in internals
        assert EMAIL.encode().hex() not in internals
        assert EMAIL not in repr(vault)

    @pytest.mark.parametrize("copier", [pickle.dumps, copy.copy, copy.deepcopy])
    def test_cannot_be_serialized_or_copied(self, vault: TokenVault, copier: object) -> None:
        vault.tokenize("PERSON", "Alice")
        with pytest.raises(TypeError, match="cannot be pickled"):
            copier(vault)  # type: ignore[operator]


class TestIntegrity:
    def test_swapped_ciphertexts_fail(self, vault: TokenVault) -> None:
        first = vault.tokenize("X", "one")
        second = vault.tokenize("X", "two")
        vault._entries[first] = vault._entries[second]
        with pytest.raises(VaultIntegrityError, match="authentication"):
            vault.reveal(first)

    def test_tampered_ciphertext_fails(self, vault: TokenVault) -> None:
        token = vault.tokenize("X", "secret")
        entry = vault._entries[token]
        flipped = bytes([entry.ciphertext[0] ^ 1]) + entry.ciphertext[1:]
        vault._entries[token] = dataclasses.replace(entry, ciphertext=flipped)
        with pytest.raises(VaultIntegrityError, match="authentication"):
            vault.reveal(token)

    def test_digest_mismatch_fails(self, vault: TokenVault) -> None:
        token = vault.tokenize("X", "secret")
        entry = vault._entries[token]
        vault._entries[token] = dataclasses.replace(entry, digest=b"\x00" * 32)
        with pytest.raises(VaultIntegrityError, match="digest"):
            vault.reveal(token)

    def test_vaults_are_cryptographically_isolated(self, clock: FakeClock) -> None:
        first = TokenVault(60, clock=clock)
        second = TokenVault(60, clock=clock)
        token = first.tokenize("PERSON", "Alice")
        assert second.reveal(token) is None
        second._entries[token] = first._entries[token]
        with pytest.raises(VaultIntegrityError):
            second.reveal(token)


def test_thread_safety() -> None:
    vault = TokenVault(60)
    tokens: list[str] = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        token = vault.tokenize("ID", str(i % 50))
        with lock:
            tokens.append(token)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(400)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(set(tokens)) == 50
    assert len(vault) == 50
    assert all(vault.reveal(vault.tokenize("ID", str(i))) == str(i) for i in range(50))
