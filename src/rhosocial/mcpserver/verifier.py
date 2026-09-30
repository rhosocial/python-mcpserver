# src/rhosocial/mcpserver/verifier.py
"""Verifying a bearer token locally: signature, issuer, audience, expiry.

This is the replacement for the per-request database lookup that
``schedule-manager`` and ``contact-manager`` each implemented against their own
``<prefix>_api_tokens`` table.  The functional difference is the reason the
library exists: **zero network round trips and zero queries on the warm path.**

The rejections are where the security lives, so each check is a separate,
named failure rather than a single ``False``:

- ``HS256`` is refused before the cache is consulted, because a JWKS serves
  public keys and an HMAC secret that is the public key is the textbook
  algorithm-confusion forgery;
- ``aud`` is checked, and it is what actually separates two services — a token
  minted for ``calendar`` is rejected here, not by a table prefix;
- ``sub`` must be present, since every scoped query needs it.

The request-scope memo exists because the SDK asks the verifier about a token
twice: once in the scope-enforcement middleware, once in its own
``BearerAuthBackend``.  Signing is not free, and the memo is keyed on the exact
credential so a request presenting a different one can never pick up somebody
else's resolution.  It is consumed on read, so a second resolution in the same
request is a bug the memo will surface rather than hide.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from contextvars import ContextVar
from contextvars import Token as ResetToken
from typing import Any

import jwt
from mcp.server.auth.provider import AccessToken

from .config import ResourceServerConfig
from .credentials import CredentialSource
from .errors import Unauthenticated
from .identity import Principal
from .jwks import DEFAULT_ALGORITHMS, Jwk, JwksCache
from .scopes import ScopeSet

__all__ = [
    "JwtTokenVerifier",
    "resolve_for_sdk",
    "DEFAULT_LEEWAY_SECONDS",
    "publish_verified",
    "take_verified",
    "clear_verified",
]

log = logging.getLogger(__name__)

#: The clock skew tolerated on ``exp``/``nbf``.  Five minutes is the RFC 8725
#: §2.2 recommendation and matches what access tokens are sized for; without
#: it, a token minted by a host whose clock runs slightly fast is rejected
#: exactly once, at the worst moment.
DEFAULT_LEEWAY_SECONDS = 300

#: Issuer comparison is exact string comparison (RFC 8414 §3.3, RFC 9207).
#: Normalising here would make this library accept an issuer the AS does not
#: claim, so a trailing slash is a real mismatch and is meant to be one.
#:
#: One ContextVar rather than two: the memo's safety property is that the
#: record and the credential it was resolved from are always read together, and
#: two ContextVars would let a caller publish one and clear the other.
_verified: ContextVar[tuple[str, AccessToken] | None] = ContextVar(
    "rhosocial_mcpserver_verified_token", default=None
)


class JwtTokenVerifier:
    """An ``mcp.server.auth.provider.TokenVerifier`` backed by a JWKS.

    :param jwks_cache: where signing keys come from
    :param issuer: the authorization server this service trusts.  Compared
        against the token's ``iss`` claim exactly.
    :param audience: accepted ``aud`` values.  Defaults to ``[resource]``; a
        service whose AS binds a logical API id instead of the endpoint URL
        passes it explicitly.
    :param resource: this service's RFC 8707 resource identifier, used as the
        default audience and reported on the resulting :class:`AccessToken`.
    :param scope_set: when given, an unknown scope in the token is dropped from
        the result instead of being carried through.  A token may legitimately
        be issued for several resources and so carry scopes this service has
        never heard of; rejecting the whole token for that would break a
        perfectly good call.
    :param algorithms: asymmetric algorithms to accept.
    :param leeway_seconds: clock skew tolerance.
    :param require_subject: whether a token without ``sub`` is rejected.  On
        by default; a service with no user-scoped data can turn it off.
    """

    def __init__(
        self,
        jwks_cache: JwksCache,
        *,
        issuer: str,
        resource: str,
        audience: Sequence[str] | None = None,
        scope_set: ScopeSet | None = None,
        algorithms: Sequence[str] = DEFAULT_ALGORITHMS,
        leeway_seconds: int = DEFAULT_LEEWAY_SECONDS,
        require_subject: bool = True,
        config: ResourceServerConfig | None = None,
    ) -> None:
        if not issuer:
            raise ValueError("issuer is required")
        if not resource:
            raise ValueError("resource is required")
        if not algorithms:
            raise ValueError("at least one algorithm must be allowed")
        for algorithm in algorithms:
            if algorithm.lower() in ("none", "none-none") or algorithm.upper().startswith("HS"):
                raise ValueError(
                    f"{algorithm!r} is refused: a JWKS publishes public keys, so an "
                    "HMAC secret derived from one is the algorithm-confusion forgery. "
                    "Only asymmetric algorithms are accepted."
                )
        self._jwks = jwks_cache
        self._issuer = issuer
        self._resource = resource
        self._audience = tuple(audience) if audience else (resource,)
        self._scopes = scope_set
        self._algorithms = tuple(algorithms)
        self._leeway = int(leeway_seconds)
        self._require_subject = require_subject
        self._config = config

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def resource(self) -> str:
        return self._resource

    @property
    def algorithms(self) -> tuple[str, ...]:
        return self._algorithms

    # -- the CredentialSource interface ----------------------------------

    def metadata(self) -> dict[str, Any] | None:
        """The RFC 9728 document, naming the issuer this verifier trusts.

        Returned by the verifier rather than built by the caller because the
        thing a client must discover is *the authorization server behind these
        tokens*, and only this object knows which one that is.  A caller
        assembling the document itself would work right up until the service
        trusted a second issuer.

        ``None`` when the verifier was built without a config, which is the CLI
        path: there is no request being served, so there is no client to
        discover anything to.  Returning a half-built document there would be
        worse than declining.
        """
        if self._config is None:
            return None
        from .metadata import protected_resource_metadata

        return protected_resource_metadata(self._config)

    # -- the SDK's interface -------------------------------------------

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify *token*, or return ``None``.

        ``None`` rather than an exception, because the SDK's contract is
        ``None``: every 401 it produces carries the challenge header a client
        needs to start discovery, and a raised error here would have to be
        converted back into that same ``None`` anyway.  The cause is logged and
        is visible in the service's own logs, which is the audience for it.
        """
        return await resolve_for_sdk(self, token)

    # -- the actual verification ----------------------------------------

    async def verify(self, token: str) -> Principal | None:
        """Verify *token* and return the principal, or ``None``.

        The async counterpart of :meth:`verify_token` for callers that want the
        :class:`~rhosocial.mcpserver.identity.Principal` rather than the SDK's
        shape — principally the CLI, which has no SDK request to hand it to.

        Two failure shapes, deliberately different:

        ``None``
            The input is not a JWT at all.  There is no claim to have made a
            mistake, so there is nothing to name.
        :class:`Unauthenticated`
            The token parses and *something specific* is wrong with it — wrong
            audience, wrong issuer, expired, bad signature.  The message is for
            the service's log, where it is the difference between "rotate this
            credential" and "the AS rotated and we are behind".
        """
        if not token or not token.strip():
            return None

        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            # Not parseable as a JWT at all — indistinguishable from "not a
            # token", so there is no cause worth reporting.
            return None

        algorithm = header.get("alg")
        if not isinstance(algorithm, str) or algorithm not in self._algorithms:
            # Checked before the cache is touched: an `HS256` token must never
            # reach key lookup, let alone verification.
            raise Unauthenticated(
                f"algorithm {algorithm!r} is not accepted; allowed: {list(self._algorithms)}"
            )

        kid = header.get("kid")
        jwk = await self._key_for(kid, algorithm)

        try:
            claims = jwt.decode(
                token,
                key=jwt.PyJWK(jwk.data, algorithm=algorithm).key,
                algorithms=list(self._algorithms),
                audience=list(self._audience),
                issuer=self._issuer,
                leeway=self._leeway,
                options={
                    "require": ["exp", "iss", "aud"],
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_exp": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise Unauthenticated("the access token has expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise Unauthenticated(
                f"aud does not match this resource; accepted: {list(self._audience)}"
            ) from exc
        except jwt.InvalidIssuerError as exc:
            raise Unauthenticated(f"iss is not {self._issuer!r}") from exc
        except jwt.InvalidSignatureError as exc:
            raise Unauthenticated("the signature does not verify") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise Unauthenticated(f"the access token is missing {exc}") from exc
        except jwt.InvalidTokenError as exc:
            raise Unauthenticated(f"the access token is not valid: {exc}") from exc

        subject = claims.get("sub")
        if self._require_subject and not isinstance(subject, str):
            # Every scoped query needs a sub; a token without one would either
            # raise deep inside the ORM or, worse, query with a NULL predicate.
            raise Unauthenticated("the access token has no sub claim")
        if not isinstance(subject, str):
            subject = ""

        return Principal(
            central_user_id=subject,
            client_id=_client_id(claims),
            scopes=self._accepted_scopes(claims),
            issuer=self._issuer,
            resource=self._resource,
            expires_at=_as_epoch(claims.get("exp")),
            token_id=_as_str(claims.get("jti")),
        )

    async def _key_for(self, kid: str | None, algorithm: str) -> Jwk:
        """Resolve the key, so that an unavailability error is not a rejection.

        A ``JwkUnavailable`` here means the *service* cannot decide, which is a
        deployment problem; a service that reported it as "this token is bad"
        would tell an operator to rotate a credential when the real fault is
        that the AS is unreachable.
        """
        from .errors import JwkUnavailable

        try:
            return await self._jwks.key_for(kid, algorithm)
        except JwkUnavailable as exc:
            raise Unauthenticated(f"signing key unavailable: {exc}") from exc

    def _accepted_scopes(self, claims: Mapping[str, Any]) -> frozenset[str]:
        raw = claims.get("scope")
        if raw is None:
            return frozenset()
        if isinstance(raw, str):
            values = raw.split()
        elif isinstance(raw, (list, tuple)):
            values = [str(v) for v in raw]
        else:
            return frozenset()
        if self._scopes is None:
            return frozenset(values)
        return frozenset(v for v in values if self._scopes.in_vocabulary(v))


def _client_id(claims: Mapping[str, Any]) -> str:
    """The client the token was issued to.

    ``client_id`` is the registered spelling; ``azp`` is the OIDC spelling for
    the same thing and appears when the AS follows RFC 9068.  Both are read
    because guessing wrong here makes every audit log attribute the call to a
    client named ``None``.
    """
    for name in ("client_id", "azp"):
        value = claims.get(name)
        if isinstance(value, str) and value:
            return value
    return "unknown"


def _as_epoch(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


async def resolve_for_sdk(source: CredentialSource, token: str) -> AccessToken | None:
    """Resolve *token* through *source* into the shape the MCP SDK wants.

    The one place a :class:`~rhosocial.mcpserver.credentials.CredentialSource`
    becomes the SDK's :class:`AccessToken`, so every transport that speaks the
    SDK's dialect gets the same memoisation and the same log line.  Duplicating
    this per source would mean the second implementation is the one that forgets
    to check the cache, and a token then gets verified twice per request.

    ``None`` rather than an exception, because the SDK's contract is ``None``:
    every 401 it produces carries the challenge header a client needs to start
    discovery, and a raised error here would have to be converted back into that
    same ``None`` anyway.  The cause is logged, which is the audience for it.
    """
    cached = take_verified(token)
    if cached is not None:
        return cached

    try:
        principal = await source.verify(token)
    except Exception as exc:
        log.info("rejecting bearer token: %s", exc)
        return None
    if principal is None:
        return None
    return _to_access_token(principal, token)


def _to_access_token(principal: Principal, token: str) -> AccessToken:
    """Project a :class:`Principal` onto the SDK's :class:`AccessToken`.

    The raw token is carried through rather than blanked: the SDK logs it in
    some error paths, and a log that says "token: " teaches an operator
    nothing while a log that echoes a credential teaches them where the
    credential is.
    """
    claims: dict[str, Any] = {"iss": principal.issuer}
    if principal.token_id:
        claims["jti"] = principal.token_id
    return AccessToken(
        token=token,
        client_id=principal.client_id,
        scopes=sorted(principal.scopes),
        expires_at=principal.expires_at,
        resource=principal.resource,
        subject=principal.central_user_id,
        claims=claims,
    )


def publish_verified(token: str, record: AccessToken) -> ResetToken:
    """Hand a just-verified credential to whoever asks next in this request.

    Returns a reset token so the caller can scope it to the downstream call
    rather than leaving the memo set for the rest of the task.

    Only successes are published: a token that failed to verify must still be
    answered by the SDK, and a memo that outlived the request would turn a
    revoked token into a still-valid one for as long as the process lives.
    """
    return _verified.set((token, record))


def take_verified(token: str) -> AccessToken | None:
    """The record published for *token* in this request, or ``None``.

    A miss — a different credential, never published, or already consumed —
    falls back to real verification, so this can only ever save work, never
    change an answer.  Comparing the exact credential is the whole safety
    property here: a memo keyed by anything weaker would let one caller's
    resolution answer another's.
    """
    entry = _verified.get()
    if entry is None:
        return None
    verified_token, record = entry
    if verified_token != token:
        return None
    # Consumed, so a second resolve in one request is a bug this surfaces
    # rather than masks.
    _verified.set(None)
    return record


def clear_verified(token: ResetToken) -> None:
    """Undo a :func:`publish_verified` once the downstream call is done."""
    _verified.reset(token)
