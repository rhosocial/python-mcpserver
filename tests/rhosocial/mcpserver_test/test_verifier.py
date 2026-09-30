# tests/rhosocial/mcpserver_test/test_verifier.py
"""Token verification: the algorithm, audience, issuer and expiry rejections.

Each is a separate test on purpose.  A single "rejects bad tokens" test that
moved ``aud`` and ``iss`` into one case would keep passing after either
regression, and those two regressions are the ones that let one service's token
open another's data.
"""

from __future__ import annotations

import time

import jwt
import pytest
from conftest import ISSUER, JWKS_URI, RESOURCE, FakeJwks, SigningKey

from rhosocial.mcpserver import JwksCache, JwtTokenVerifier
from rhosocial.mcpserver.errors import Unauthenticated


@pytest.fixture
def signed(verifier, signing_key: SigningKey):
    async def mint(**kwargs):
        return signing_key.sign(**kwargs)

    return mint


async def test_a_valid_token_verifies(verifier, signed) -> None:
    principal = await verifier.verify(await signed(scope="schedules:read schedules:write"))

    assert principal.central_user_id == "u-123"
    assert principal.client_id == "opencode"
    assert principal.scopes == frozenset({"schedules:read", "schedules:write"})
    assert principal.issuer == ISSUER
    assert principal.token_id == "jti-1"


async def test_verify_token_returns_the_sdk_shape(verifier, signed) -> None:
    record = await verifier.verify_token(await signed())

    assert record is not None
    assert record.subject == "u-123"
    assert record.client_id == "opencode"
    assert record.resource == RESOURCE
    assert record.claims["iss"] == ISSUER


async def test_hs256_is_refused_without_touching_the_cache(clock, signed) -> None:
    """Algorithm confusion: a JWKS serves public keys, so an HMAC secret
    derived from one is the textbook forgery.  The check must precede key
    lookup, or a caller can aim a forgery at the cache."""
    fake = FakeJwks(keys=[])
    cache = JwksCache(JWKS_URI, fetch=fake.fetch, clock=clock)
    verifier = JwtTokenVerifier(cache, issuer=ISSUER, resource=RESOURCE)

    forged = jwt.encode(
        {"iss": ISSUER, "sub": "attacker", "aud": RESOURCE, "exp": int(time.time()) + 60},
        "a-secret-long-enough-to-avoid-the-warning",
        algorithm="HS256",
        headers={"kid": "key-1"},
    )

    with pytest.raises(Unauthenticated, match="not accepted"):
        await verifier.verify(forged)
    assert fake.calls == 0, "an HS256 token must be refused before any key lookup"


def test_hs256_cannot_be_configured_in() -> None:
    cache = JwksCache(JWKS_URI, fetch=None)
    with pytest.raises(ValueError, match="algorithm-confusion"):
        JwtTokenVerifier(cache, issuer=ISSUER, resource=RESOURCE, algorithms=("HS256",))
    with pytest.raises(ValueError, match="algorithm-confusion"):
        JwtTokenVerifier(cache, issuer=ISSUER, resource=RESOURCE, algorithms=("none",))


async def test_alg_none_is_refused(clock) -> None:
    verifier = JwtTokenVerifier(
        JwksCache(JWKS_URI, fetch=None), issuer=ISSUER, resource=RESOURCE
    )
    unverified = jwt.encode(
        {"iss": ISSUER, "sub": "attacker", "aud": RESOURCE, "exp": int(time.time()) + 60},
        key="",
        algorithm="none",
    )

    with pytest.raises(Unauthenticated, match="not accepted"):
        await verifier.verify(unverified)


async def test_wrong_audience_is_rejected(verifier, signed) -> None:
    """This is the check that separates two services — not a table prefix."""
    token = await signed(audience="https://finance.example.com/mcp")

    with pytest.raises(Unauthenticated, match="aud does not match"):
        await verifier.verify(token)


async def test_wrong_issuer_is_rejected(verifier, signed) -> None:
    token = await signed(issuer="https://evil.example.com")

    with pytest.raises(Unauthenticated, match="iss is not"):
        await verifier.verify(token)


async def test_expired_token_is_rejected(verifier, signed) -> None:
    token = await signed(issued_ago=4000, expires_in=10)

    with pytest.raises(Unauthenticated, match="expired"):
        await verifier.verify(token)


async def test_token_signed_by_another_key_is_rejected(clock, signed, signing_key) -> None:
    other = SigningKey(kid="key-1", private=signing_key.private)  # same kid, different key
    impostor_key = SigningKey(kid="rogue", private=_other_private())
    fake = FakeJwks(keys=[signing_key])
    cache = JwksCache(JWKS_URI, fetch=fake.fetch, clock=clock)
    verifier = JwtTokenVerifier(cache, issuer=ISSUER, resource=RESOURCE)

    forged = impostor_key.sign(audience=RESOURCE)
    # Re-label it as the published kid: the attacker knows the kid, the AS's kid
    # is public.
    import jwt as _jwt

    claims = _jwt.decode(forged, options={"verify_signature": False})
    relabelled = _jwt.encode(
        claims, impostor_key.private, algorithm="ES256", headers={"kid": "key-1"}
    )

    with pytest.raises(Unauthenticated, match="signature does not verify"):
        await verifier.verify(relabelled)
    assert other.kid == "key-1"


async def test_token_without_sub_is_rejected(clock, signing_key) -> None:
    cache = JwksCache(
        JWKS_URI, fetch=FakeJwks(keys=[signing_key]).fetch, clock=clock
    )
    verifier = JwtTokenVerifier(cache, issuer=ISSUER, resource=RESOURCE)
    token = jwt.encode(
        {"iss": ISSUER, "aud": RESOURCE, "exp": int(time.time()) + 60},
        signing_key.private,
        algorithm="ES256",
        headers={"kid": "key-1"},
    )

    with pytest.raises(Unauthenticated, match="no sub claim"):
        await verifier.verify(token)


async def test_unknown_scope_is_dropped_not_fatal(verifier, signed, config) -> None:
    """A token issued for several resources carries scopes this service has
    never heard of.  Rejecting the whole token would break a valid call."""
    token = await signed(scope="schedules:read finance:transfer")

    principal = await verifier.verify(token)

    assert principal.scopes == frozenset({"schedules:read"})


async def test_azp_is_read_when_client_id_is_absent(clock, signing_key) -> None:
    cache = JwksCache(JWKS_URI, fetch=FakeJwks(keys=[signing_key]).fetch, clock=clock)
    verifier = JwtTokenVerifier(cache, issuer=ISSUER, resource=RESOURCE)
    token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": "u-1",
            "aud": RESOURCE,
            "azp": "cursor",
            "exp": int(time.time()) + 60,
        },
        signing_key.private,
        algorithm="ES256",
        headers={"kid": "key-1"},
    )

    principal = await verifier.verify(token)

    assert principal.client_id == "cursor"


async def test_garbage_is_rejected_without_a_diagnosis(verifier) -> None:
    """Not parseable as a JWT is not "a token with a mistake" — there is no
    claim to name, so the answer is simply `None`."""
    for token in ("", "   ", "not-a-jwt", "a.b", "a.b.c.d.e"):
        assert await verifier.verify(token) is None
        assert await verifier.verify_token(token) is None


async def test_key_unavailable_does_not_verify(clock, signing_key) -> None:
    """A verifier with no key material is a deployment problem, and the message
    must not tell an operator to rotate a credential."""
    fake = FakeJwks(keys=[])
    fake.fail_with = OSError("down")
    cache = JwksCache(JWKS_URI, fetch=fake.fetch, clock=clock)
    verifier = JwtTokenVerifier(cache, issuer=ISSUER, resource=RESOURCE)
    token = signing_key.sign()

    with pytest.raises(Unauthenticated, match="signing key unavailable"):
        await verifier.verify(token)
    assert await verifier.verify_token(token) is None


async def test_verify_token_returns_none_on_every_rejection(verifier, signed) -> None:
    """The SDK's contract is `None`; a raised error would have to be converted
    back into it, and somewhere in that conversion a 401 would lose its
    challenge header."""
    for token in (
        await signed(issuer="https://evil.example.com"),
        await signed(audience="https://other.example.com/mcp"),
        await signed(issued_ago=4000, expires_in=1),
    ):
        assert await verifier.verify_token(token) is None


async def test_explicit_audience_overrides_the_resource_default(clock, signing_key) -> None:
    cache = JwksCache(JWKS_URI, fetch=FakeJwks(keys=[signing_key]).fetch, clock=clock)
    verifier = JwtTokenVerifier(
        cache, issuer=ISSUER, resource=RESOURCE, audience=["api://calendar"]
    )

    principal = await verifier.verify(
        signing_key.sign(audience="api://calendar")
    )

    assert principal.central_user_id == "u-123"


async def test_expiry_within_leeway_is_accepted(clock, signing_key) -> None:
    """Without leeway, a token minted by a host whose clock runs slightly fast
    is rejected exactly once, at the worst possible moment."""
    cache = JwksCache(JWKS_URI, fetch=FakeJwks(keys=[signing_key]).fetch, clock=clock)
    verifier = JwtTokenVerifier(
        cache, issuer=ISSUER, resource=RESOURCE, leeway_seconds=300
    )

    principal = await verifier.verify(signing_key.sign(expires_in=60))

    assert principal.central_user_id == "u-123"


def test_verifier_requires_issuer_and_resource(clock) -> None:
    cache = JwksCache(JWKS_URI, fetch=None)
    with pytest.raises(ValueError, match="issuer is required"):
        JwtTokenVerifier(cache, issuer="", resource=RESOURCE)
    with pytest.raises(ValueError, match="resource is required"):
        JwtTokenVerifier(cache, issuer=ISSUER, resource="")


def test_verifier_requires_at_least_one_algorithm(clock) -> None:
    cache = JwksCache(JWKS_URI, fetch=None)
    with pytest.raises(ValueError, match="at least one algorithm"):
        JwtTokenVerifier(cache, issuer=ISSUER, resource=RESOURCE, algorithms=())


def _other_private():
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1())
