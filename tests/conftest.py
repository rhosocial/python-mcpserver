# tests/conftest.py
"""Shared fixtures: keys, tokens, and a JWKS that never touches the network.

Every key here is generated in-process.  A committed key in a test suite is a
key that outlives its purpose, and a test that fetches a live JWKS is a test
that fails when someone else's authorization server is down.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

ISSUER = "https://auth.example.com"
RESOURCE = "https://calendar.example.com/mcp"
JWKS_URI = ISSUER + "/.well-known/jwks.json"


@dataclass
class SigningKey:
    """A private key plus the JWK the authorization server would publish."""

    kid: str
    private: Any
    algorithm: str = "ES256"

    def public_jwk(self) -> dict[str, Any]:
        if self.algorithm.startswith("ES"):
            numbers = self.private.public_key().public_numbers()
            # Padded to the curve's fixed width: PyJWT decodes each coordinate to
            # exactly 32 bytes and rejects anything shorter, so a y-coordinate
            # that happens to be small would fail verification for a reason that
            # looks like a bug in the verifier.
            return {
                "kty": "EC",
                "crv": "P-256",
                "kid": self.kid,
                "alg": "ES256",
                "use": "sig",
                "x": _b64u(numbers.x, 32),
                "y": _b64u(numbers.y, 32),
            }
        numbers = self.private.public_key().public_numbers()
        return {
            "kty": "RSA",
            "kid": self.kid,
            "alg": "RS256",
            "use": "sig",
            "n": _b64u(numbers.n),
            "e": _b64u(numbers.e),
        }

    def sign(
        self,
        *,
        sub: str = "u-123",
        scope: str = "schedules:read",
        audience: str = RESOURCE,
        issuer: str = ISSUER,
        expires_in: int = 900,
        issued_ago: int = 0,
        client_id: str = "opencode",
        jti: str | None = "jti-1",
        extra: dict[str, Any] | None = None,
        algorithm: str | None = None,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": issuer,
            "sub": sub,
            "aud": audience,
            "scope": scope,
            "client_id": client_id,
            "iat": now - issued_ago,
            "nbf": now - issued_ago,
            "exp": now - issued_ago + expires_in,
        }
        if jti is not None:
            claims["jti"] = jti
        if extra:
            claims.update(extra)
        return jwt.encode(
            claims,
            self.private,
            algorithm=algorithm or self.algorithm,
            headers={"kid": self.kid},
        )


def _b64u(value: Any, width: int | None = None) -> str:
    """base64url without padding, of an integer's big-endian bytes.

    ``width`` left-pads, which is what an EC coordinate needs: the JWK form is
    fixed-width, so a coordinate whose leading byte happens to be zero has to
    carry the padding or the verifier decodes a different number.
    """
    import base64

    if isinstance(value, int):
        length = max((value.bit_length() + 7) // 8, 1)
        raw = value.to_bytes(length, "big")
    else:
        raw = bytes(value)
    if width is not None and len(raw) < width:
        raw = raw.rjust(width, b"\x00")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture
def signing_key() -> SigningKey:
    return SigningKey(kid="key-1", private=ec.generate_private_key(ec.SECP256R1()))


@pytest.fixture
def rotated_key() -> SigningKey:
    return SigningKey(kid="key-2", private=ec.generate_private_key(ec.SECP256R1()))


@dataclass
class FakeJwks:
    """A JWKS endpoint whose document and failures the test controls."""

    keys: list[SigningKey]
    calls: int = 0
    max_age: str | None = None
    #: Set to an exception instance to make the next and subsequent fetches fail.
    fail_with: BaseException | None = None
    #: Set to a raw body to serve something that is not a JWKS.
    body: Any | None = None
    _published: list[SigningKey] = field(default_factory=list)

    def publish(self, *keys: SigningKey) -> None:
        """Add keys without making them visible until a fetch happens.

        A rotation is *published* and then fetched; a test that made the new key
        visible immediately would not be testing the refresh at all.
        """
        self._published.extend(keys)

    def rotate(self, *keys: SigningKey) -> None:
        """Replace the whole document with *keys*."""
        self.keys = list(keys)
        self._published = list(keys)

    @property
    def document(self) -> dict[str, Any]:
        return {"keys": [k.public_jwk() for k in self.keys]}

    async def fetch(self, uri: str) -> Any:
        self.calls += 1
        if self.fail_with is not None:
            raise self.fail_with
        if self._published:
            self.keys = list(self._published)
            self._published = []
        if self.body is not None:
            return self.body
        return _Response(self.document, self.max_age)


class _Response:
    """Shaped like an ``httpx.Response``, which is what the default fetcher returns."""

    def __init__(self, document: dict[str, Any], max_age: str | None) -> None:
        import json

        self._payload = json.dumps(document).encode()
        self.headers = {"content-type": "application/json"}
        if max_age is not None:
            self.headers["cache-control"] = max_age

    @property
    def text(self) -> str:
        return self._payload.decode()


@pytest.fixture
def fake_jwks(signing_key: SigningKey) -> FakeJwks:
    return FakeJwks(keys=[signing_key])


@pytest.fixture
def clock() -> Callable[[], float]:
    """A manually advanced monotonic clock, so no test sleeps."""

    state = {"now": 1000.0}

    def read() -> float:
        return state["now"]

    def advance(seconds: float) -> None:
        state["now"] += seconds

    read.advance = advance  # type: ignore[attr-defined]
    return read


@pytest.fixture
def cache(fake_jwks: FakeJwks, clock: Callable[[], float]) -> Any:
    from rhosocial.mcpserver import JwksCache

    return JwksCache(JWKS_URI, fetch=fake_jwks.fetch, clock=clock, ttl_seconds=300.0)


@pytest.fixture
def config() -> Any:
    from rhosocial.mcpserver import NO_SCOPE, ServiceConfig

    return ServiceConfig(
        resource=RESOURCE,
        scopes=["schedules:read", "schedules:write"],
        tool_scopes={
            "whoami": NO_SCOPE,
            "list_schedules": "schedules:read",
            "create_schedule": "schedules:write",
        },
    )


@pytest.fixture
def oauth() -> Any:
    from rhosocial.mcpserver import OAuthConfig

    return OAuthConfig(issuer=ISSUER)


@pytest.fixture
def verifier(cache: Any, config: Any) -> Any:
    from rhosocial.mcpserver import JwtTokenVerifier

    return JwtTokenVerifier(
        cache,
        issuer=ISSUER,
        resource=RESOURCE,
        scope_set=config.policy.vocabulary,
    )
