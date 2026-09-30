# tests/rhosocial/mcpserver_test/test_jwks.py
"""The JWKS cache's failure paths, which are the whole of what it is for."""

from __future__ import annotations

import asyncio
import json

import pytest
from conftest import JWKS_URI, FakeJwks, SigningKey

from rhosocial.mcpserver import JwksCache, JwkUnavailable
from rhosocial.mcpserver.mcp.jwks import Jwk, JwkSet


async def test_first_lookup_fetches_once(clock, signing_key: SigningKey) -> None:
    fake = FakeJwks(keys=[signing_key])
    cache = JwksCache(JWKS_URI, fetch=fake.fetch, clock=clock)

    for _ in range(5):
        key = await cache.key_for("key-1", "ES256")

    assert key.kid == "key-1"
    assert fake.calls == 1, "a warm cache must not re-fetch"


async def test_rotated_key_triggers_exactly_one_refresh(
    clock, signing_key: SigningKey, rotated_key: SigningKey
) -> None:
    fake = FakeJwks(keys=[signing_key])
    cache = JwksCache(JWKS_URI, fetch=fake.fetch, clock=clock)

    assert (await cache.key_for("key-1", "ES256")).kid == "key-1"
    assert fake.calls == 1

    fake.rotate(rotated_key)

    assert (await cache.key_for("key-2", "ES256")).kid == "key-2"
    assert fake.calls == 2, "a kid miss must refresh once, not zero and not twice"


async def test_unknown_kid_is_not_an_infinite_fetch_loop(clock, signing_key: SigningKey) -> None:
    fake = FakeJwks(keys=[signing_key])
    cache = JwksCache(JWKS_URI, fetch=fake.fetch, clock=clock, negative_ttl_seconds=60.0)

    with pytest.raises(JwkUnavailable):
        await cache.key_for("key-999", "ES256")
    assert fake.calls == 1

    for _ in range(20):
        with pytest.raises(JwkUnavailable):
            await cache.key_for("key-999", "ES256")
    assert fake.calls == 1, "the negative memo must absorb a burst of unknown kids"


async def test_negative_memo_expires(clock, signing_key: SigningKey) -> None:
    fake = FakeJwks(keys=[signing_key])
    cache = JwksCache(JWKS_URI, fetch=fake.fetch, clock=clock, negative_ttl_seconds=5.0)

    with pytest.raises(JwkUnavailable):
        await cache.key_for("key-999", "ES256")
    clock.advance(10.0)
    with pytest.raises(JwkUnavailable):
        await cache.key_for("key-999", "ES256")
    assert fake.calls == 2, "after the memo expires a refresh is correct again"


async def test_concurrent_misses_produce_one_fetch(
    clock, signing_key: SigningKey, rotated_key: SigningKey
) -> None:
    """The bug this guards is a lock that serialises without re-checking.

    Fifty requests queue on the lock; without the freshness re-check inside it,
    each finds the cache stale again the moment the previous one releases, and
    the rotation turns into fifty fetches against the authorization server.
    """
    fake = FakeJwks(keys=[signing_key])
    original = fake.fetch

    async def slow_fetch(uri: str) -> object:
        # Slow enough that the other forty-nine callers are queued on the lock
        # when this one releases it — which is the only way the re-check inside
        # the lock gets exercised.
        await asyncio.sleep(0.01)
        return await original(uri)

    cache = JwksCache(JWKS_URI, fetch=slow_fetch, clock=clock)

    await cache.key_for("key-1", "ES256")
    fake.calls = 0
    fake.rotate(rotated_key)

    results = await asyncio.gather(*(cache.key_for("key-2", "ES256") for _ in range(50)))

    assert all(r.kid == "key-2" for r in results)
    assert fake.calls == 1, f"expected one fetch, got {fake.calls}"


async def test_fetch_failure_serves_a_live_cache(
    clock, signing_key: SigningKey
) -> None:
    """A brief authorization-server blip must be invisible to the service."""
    fake = FakeJwks(keys=[signing_key])
    cache = JwksCache(JWKS_URI, fetch=fake.fetch, clock=clock, ttl_seconds=300.0)

    assert (await cache.key_for("key-1", "ES256")).kid == "key-1"

    clock.advance(1000.0)  # the cache is now expired
    fake.fail_with = OSError("connection reset")

    # The refresh failed, so this is served from the last trusted key set rather
    # than rejecting a token that was valid a moment ago.
    key = await cache.key_for("key-1", "ES256")
    assert key.kid == "key-1"
    assert fake.calls == 2


async def test_fetch_failure_with_no_cache_is_an_error(clock, signing_key: SigningKey) -> None:
    fake = FakeJwks(keys=[signing_key])
    fake.fail_with = OSError("connection reset")
    cache = JwksCache(JWKS_URI, fetch=fake.fetch, clock=clock)

    with pytest.raises(JwkUnavailable, match="could not be fetched"):
        await cache.key_for("key-1", "ES256")


async def test_prefetch_warms_the_cache(clock, signing_key: SigningKey) -> None:
    fake = FakeJwks(keys=[signing_key])
    cache = JwksCache(JWKS_URI, fetch=fake.fetch, clock=clock)

    keys = await cache.prefetch()

    assert len(keys) == 1
    assert fake.calls == 1
    await cache.key_for("key-1", "ES256")
    assert fake.calls == 1


async def test_malformed_body_keeps_a_live_cache(clock, signing_key: SigningKey) -> None:
    fake = FakeJwks(keys=[signing_key])
    cache = JwksCache(JWKS_URI, fetch=fake.fetch, clock=clock, ttl_seconds=300.0)
    await cache.key_for("key-1", "ES256")

    clock.advance(1000.0)
    fake.body = b"<html>a proxy error page</html>"

    assert (await cache.key_for("key-1", "ES256")).kid == "key-1"


async def test_malformed_body_with_no_cache_is_an_error(clock, signing_key: SigningKey) -> None:
    fake = FakeJwks(keys=[signing_key])
    fake.body = b"not json at all"
    cache = JwksCache(JWKS_URI, fetch=fake.fetch, clock=clock)

    with pytest.raises(JwkUnavailable):
        await cache.key_for("key-1", "ES256")


async def test_max_age_is_honoured(clock, signing_key: SigningKey) -> None:
    fake = FakeJwks(keys=[signing_key], max_age="600")
    cache = JwksCache(JWKS_URI, fetch=fake.fetch, clock=clock, ttl_seconds=300.0)

    await cache.key_for("key-1", "ES256")
    clock.advance(299.0)
    await cache.key_for("key-1", "ES256")
    assert fake.calls == 1

    clock.advance(400.0)  # now past 600
    await cache.key_for("key-1", "ES256")
    assert fake.calls == 2


async def test_max_age_is_clamped_too_high(clock, signing_key: SigningKey) -> None:
    """An AS caching its JWKS for a year would otherwise pin every service to
    a key set, and a rotation would not be seen until the process restarted."""
    fake = FakeJwks(keys=[signing_key], max_age="31536000")
    cache = JwksCache(
        JWKS_URI, fetch=fake.fetch, clock=clock, max_ttl_seconds=3600.0, min_ttl_seconds=1.0
    )

    await cache.key_for("key-1", "ES256")
    clock.advance(3601.0)
    await cache.key_for("key-1", "ES256")
    assert fake.calls == 2


async def test_max_age_is_clamped_too_low(clock, signing_key: SigningKey) -> None:
    """An AS asking for a 5-second cache must not become a 5-second dependency."""
    fake = FakeJwks(keys=[signing_key], max_age="5")
    cache = JwksCache(
        JWKS_URI, fetch=fake.fetch, clock=clock, min_ttl_seconds=60.0, max_ttl_seconds=3600.0
    )

    await cache.key_for("key-1", "ES256")
    clock.advance(30.0)
    await cache.key_for("key-1", "ES256")
    assert fake.calls == 1, "a 5s max-age must be raised to the 60s floor"


def test_jwk_set_skips_unusable_entries() -> None:
    document = {
        "keys": [
            {"kty": "oct", "kid": "sym", "k": "AAAA"},
            {"kty": "EC", "crv": "P-256", "kid": "ec", "x": "AA", "y": "AA"},
        ]
    }
    keys = JwkSet.parse(document, 0.0)

    assert keys.kids == ("ec",)
    assert keys.get("ec", "ES256") is not None
    # The symmetric key must never satisfy a request, whatever the algorithm.
    assert keys.get("sym", "ES256") is None


def test_jwk_set_rejects_an_empty_document() -> None:
    with pytest.raises(JwkUnavailable, match="no key this library can verify"):
        JwkSet.parse({"keys": []}, 0.0)


def test_jwk_set_rejects_a_document_without_keys() -> None:
    with pytest.raises(JwkUnavailable, match="no 'keys' array"):
        JwkSet.parse({"whatever": True}, 0.0)


def test_jwk_bound_alg_is_honoured() -> None:
    """A key that says which algorithm it is for must not be used for another."""
    jwk = Jwk({"kty": "EC", "crv": "P-256", "kid": "k", "alg": "ES384", "x": "AA", "y": "AA"})

    assert jwk.usable_for("ES384") is True
    assert jwk.usable_for("ES256") is False


def test_encryption_key_is_not_a_verification_key() -> None:
    jwk = Jwk({"kty": "EC", "crv": "P-256", "kid": "k", "use": "enc", "x": "AA", "y": "AA"})

    assert jwk.usable_for("ES256") is False


def test_single_key_without_kid_is_still_usable() -> None:
    """An AS with one key may omit `kid`; trying that one key is correct."""
    jwk = Jwk({"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"})
    keys = JwkSet([jwk], 0.0)

    assert keys.get(None, "ES256") is jwk


def test_several_keys_without_kid_are_not_guessed() -> None:
    """Guessing which of several keys signed a token is a verification oracle."""
    a = Jwk({"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"})
    b = Jwk({"kty": "EC", "crv": "P-256", "x": "BB", "y": "BB"})
    keys = JwkSet([a, b], 0.0)

    assert keys.get(None, "ES256") is None


def test_duplicate_kid_is_not_silently_overwritten() -> None:
    first = Jwk({"kty": "EC", "crv": "P-256", "kid": "dup", "x": "AA", "y": "AA"})
    second = Jwk({"kty": "EC", "crv": "P-256", "kid": "dup", "x": "BB", "y": "BB"})
    keys = JwkSet([first, second], 0.0)

    assert keys.get("dup", "ES256") is first


def test_decode_rejects_a_non_json_body() -> None:
    from rhosocial.mcpserver.mcp.jwks import _decode

    with pytest.raises(JwkUnavailable, match="not valid JSON"):
        _decode(b"{oops")


def test_decode_accepts_a_mapping_directly() -> None:
    from rhosocial.mcpserver.mcp.jwks import _decode

    assert _decode({"keys": []}) == {"keys": []}
    assert _decode(json.dumps({"keys": []})) == {"keys": []}
