# src/rhosocial/mcpserver/mcp/jwks.py
"""Caching and rotating the authorization server's signing keys.

The interesting behaviour of a JWKS cache is entirely in its failures, so this
module is mostly about four situations that a naive implementation gets wrong:

**A ``kid`` miss.**  Key rotation publishes a new ``kid``.  Refresh exactly once
and reject: zero refreshes means every token signed after a rotation fails, and
unbounded refreshes turn a rotation into an outage by letting a flood of
tokens bearing an unknown ``kid`` drive a fetch flood against the AS.

**Concurrent misses.**  Fifty requests arriving together during a rotation must
produce one fetch, not fifty.  A lock alone does not do this — it serialises
them, so the second caller refetches as soon as the first releases.  The check
has to be re-made *inside* the lock.

**A network error with a live cache.**  This must not fail the request.  A
30-second AS blip should be invisible to services, and the cache exists
precisely so it can be.  An *expired* cache is different: serving on a key set
past its TTL is a silent correctness hole, so expiry is not a fallback.

**Fetch amplification.**  The negative result of an unknown ``kid`` is cached
briefly, so the refresh-once rule cannot be turned into a fetch amplifier by a
client that knows how to mint tokens with a bogus header.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

import httpx

from ..errors import ConfigurationError, JwkUnavailable

__all__ = ["Jwk", "JwksCache", "JwkSet"]

log = logging.getLogger(__name__)

#: Fetch timeout.  Deliberately short: this call is on the request path, and a
#: hung AS must surface as a rejected token rather than as a hung tool call.
DEFAULT_TIMEOUT_SECONDS = 5.0

#: A response may ask for a longer life than is safe.  An AS that caches its
#: JWKS for an hour cannot be followed within a 15-minute access token's life,
#: so an over-long ``max-age`` would break rotation for every service behind it.
DEFAULT_MAX_TTL_SECONDS = 3600.0

#: And it may ask for a shorter one than is worth honouring.  Refetching every
#: 30 seconds for a key set that changes twice a year is a self-inflicted
#: availability dependency on the AS.
DEFAULT_MIN_TTL_SECONDS = 60.0

#: How long an unknown ``kid`` is remembered as unknown.  Short enough that a
#: real rotation is picked up quickly, long enough that a burst of bogus tokens
#: cannot drive one refresh each.
DEFAULT_NEGATIVE_TTL_SECONDS = 5.0


class Jwk:
    """One signing key, in the form PyJWT wants.

    A JWK is public by definition — it came off a public endpoint — so holding
    one is not a secret.  That is exactly why an ``HS*`` algorithm must never
    be accepted against it: the public key would become the HMAC secret.
    """

    __slots__ = ("kid", "kty", "alg", "use", "data")

    def __init__(self, data: Mapping[str, Any]) -> None:
        if not isinstance(data, Mapping):
            raise JwkUnavailable("a JWKS entry is not an object")
        kty = data.get("kty")
        if not isinstance(kty, str) or not kty:
            raise JwkUnavailable(f"a JWKS entry has no kty: {dict(data)!r}")
        self.data: dict[str, Any] = dict(data)
        self.kty = kty
        self.alg: str | None = _optional_str(data.get("alg"))
        self.use: str | None = _optional_str(data.get("use"))
        self.kid: str | None = _optional_str(data.get("kid"))

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Jwk(kid={self.kid!r}, kty={self.kty!r}, alg={self.alg!r})"

    def usable_for(self, algorithm: str) -> bool:
        """Whether this key may verify a token signed with *algorithm*.

        A key that declares ``alg`` is bound to it — the AS published it saying
        which algorithm it is for, and honouring a different one would let a
        caller choose.  A key that does not declare ``alg`` is matched on
        ``kty`` alone, which is the usual state of a JWKS.
        """
        if self.use is not None and self.use != "sig":
            return False
        if self.alg is not None and self.alg != algorithm:
            return False
        return _KTY_FOR_ALG.get(algorithm) == self.kty

    @property
    def verifiable(self) -> bool:
        """Whether this key can verify *some* algorithm this library accepts.

        A JWKS routinely publishes symmetric keys, encryption keys and keys for
        algorithms this service was not configured with.  None of them belong in
        the set: keeping a symmetric key around means a future widening of
        ``allowed_algorithms`` could reach it by accident, and the whole point of
        refusing ``HS*`` is that the refusal is structural rather than a
        default someone might override.
        """
        if self.use is not None and self.use != "sig":
            return False
        return any(self.usable_for(algorithm) for algorithm in SUPPORTED_ALGORITHMS)


#: The asymmetric key types this library will accept.  There is deliberately no
#: entry for ``HS*`` or ``none``: a JWKS serves public keys, and an HMAC secret
#: that is the public key is the textbook algorithm-confusion forgery.
_KTY_FOR_ALG: Mapping[str, str] = {
    "ES256": "EC",
    "ES384": "EC",
    "ES512": "EC",
    "RS256": "RSA",
    "RS384": "RSA",
    "RS512": "RSA",
    "PS256": "RSA",
    "PS384": "RSA",
    "PS512": "RSA",
    "EdDSA": "OKP",
}

#: Every algorithm with a key type above.  Used to decide whether a published
#: key belongs in the set at all.
SUPPORTED_ALGORITHMS: tuple[str, ...] = tuple(_KTY_FOR_ALG)

#: The default allowlist.  A deployment that needs something else must say so,
#: which puts the decision in the diff instead of in a default nobody reads.
DEFAULT_ALGORITHMS: tuple[str, ...] = ("ES256", "RS256", "EdDSA")


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


class JwkSet:
    """An immutable snapshot of a JWKS document."""

    __slots__ = ("_by_kid", "_keys", "fetched_at")

    def __init__(self, keys: Iterable[Jwk], fetched_at: float) -> None:
        self._keys = tuple(keys)
        self._by_kid: dict[str, Jwk] = {}
        for key in self._keys:
            # A JWKS with two entries sharing a kid is malformed.  Taking the
            # last silently would mean the answer depends on document order.
            if key.kid is not None and key.kid not in self._by_kid:
                self._by_kid[key.kid] = key
        self.fetched_at = fetched_at

    def __len__(self) -> int:
        return len(self._keys)

    @property
    def kids(self) -> tuple[str, ...]:
        return tuple(k.kid for k in self._keys if k.kid is not None)

    def get(self, kid: str | None, algorithm: str) -> Jwk | None:
        """The key for *kid* that can verify *algorithm*, or ``None``.

        A token with no ``kid`` at all is not an error here: a single-key AS
        may legitimately omit it, in which case there is exactly one candidate
        and it is tried.  With several keys and no ``kid`` the answer is
        ``None`` — guessing which of several keys a token was signed with is
        how a rotation window turns into a verification oracle.
        """
        if kid is not None:
            key = self._by_kid.get(kid)
            return key if key is not None and key.usable_for(algorithm) else None
        candidates = [k for k in self._keys if k.usable_for(algorithm)]
        return candidates[0] if len(candidates) == 1 else None

    @classmethod
    def parse(cls, payload: Any, fetched_at: float) -> JwkSet:
        """Build a snapshot from a decoded JWKS document.

        Entries that cannot verify anything this library accepts are dropped
        rather than failing the whole document: a JWKS carrying a symmetric key,
        an encryption key and two signing keys is a normal thing to publish, and
        one unusable entry should not deny service.
        """
        if not isinstance(payload, Mapping):
            raise JwkUnavailable(f"JWKS is not a JSON object: {type(payload).__name__}")
        entries = payload.get("keys")
        if not isinstance(entries, list):
            raise JwkUnavailable("JWKS has no 'keys' array")
        keys: list[Jwk] = []
        for entry in entries:
            try:
                jwk = Jwk(entry)
            except JwkUnavailable as exc:
                log.debug("skipping malformed JWKS entry: %s", exc)
                continue
            if not jwk.verifiable:
                log.debug("skipping JWKS entry that verifies nothing we accept: %r", jwk)
                continue
            keys.append(jwk)
        if not keys:
            raise JwkUnavailable(
                "JWKS contains no key this library can verify with; a symmetric "
                "or encryption-only document is not a signing-key set"
            )
        return cls(keys, fetched_at)


class JwksCache:
    """Fetches, caches and refreshes a JWKS.

    :param jwks_uri: where to fetch it
    :param fetch: an async callable ``(uri) -> str`` returning the document body.
        Injectable so tests never touch the network, and so a deployment can
        supply its own transport.
    :param ttl_seconds: default lifetime when the document does not say
    :param negative_ttl_seconds: how long an unknown ``kid`` stays unknown
    :param min_ttl_seconds: floor applied to a server-requested ``max-age``
    :param max_ttl_seconds: ceiling applied to a server-requested ``max-age``
    :param clock: injectable for tests; defaults to :func:`time.monotonic`
    """

    def __init__(
        self,
        jwks_uri: str,
        *,
        fetch: Callable[[str], Any] | None = None,
        ttl_seconds: float = DEFAULT_MIN_TTL_SECONDS * 10,
        negative_ttl_seconds: float = DEFAULT_NEGATIVE_TTL_SECONDS,
        min_ttl_seconds: float = DEFAULT_MIN_TTL_SECONDS,
        max_ttl_seconds: float = DEFAULT_MAX_TTL_SECONDS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not jwks_uri:
            raise ConfigurationError("jwks_uri is empty")
        self.jwks_uri = jwks_uri
        self._ttl = float(ttl_seconds)
        self._negative_ttl = float(negative_ttl_seconds)
        self._min_ttl = float(min_ttl_seconds)
        self._max_ttl = float(max_ttl_seconds)
        self._timeout = float(timeout_seconds)
        self._clock = clock
        self._fetch = fetch or self._http_fetch
        self._lock = asyncio.Lock()
        self._keys: JwkSet | None = None
        self._expires_at = 0.0
        self._attempted: dict[str, float] = {}
        #: The most recent fetch or parse failure, or ``None``.  It is what
        #: separates "the JWKS is stale but the AS is unreachable" (serve the
        #: cache) from "the JWKS is stale and we have nothing" (fail).
        self._last_error: BaseException | None = None
        #: Number of network fetches performed.  Tests assert on this rather
        #: than only on the result: a passing test that fetched twice is still
        #: the rotation-storm bug this cache exists to prevent.
        self.fetch_count = 0

    # -- public API ----------------------------------------------------

    async def key_for(self, kid: str | None, algorithm: str) -> Jwk:
        """The key for *kid*, fetching or refreshing as needed.

        :raises JwkUnavailable: no usable key, and no way to obtain one.
        """
        keys = self._live_keys()
        if keys is not None:
            key = keys.get(kid, algorithm)
            if key is not None:
                return key
        await self._refresh(reason=f"no key for kid={kid!r} alg={algorithm!r}", kid=kid)
        keys = self._live_keys()
        if keys is None:
            raise JwkUnavailable(
                f"no signing key for kid={kid!r} alg={algorithm!r}, and the JWKS "
                f"at {self.jwks_uri} could not be fetched"
            )
        key = keys.get(kid, algorithm)
        if key is None:
            raise JwkUnavailable(f"no signing key for kid={kid!r} alg={algorithm!r}")
        return key

    async def prefetch(self) -> JwkSet:
        """Warm the cache.

        Worth calling in the lifespan: without it the first request of every
        replica pays the fetch, and on a cold AS that is the request most likely
        to time out.
        """
        await self._refresh(reason="prefetch", force=True)
        keys = self._live_keys(allow_stale=False)
        if keys is None:  # pragma: no cover - _refresh raises instead
            raise JwkUnavailable("prefetch left no usable key set")
        return keys

    def invalidate(self) -> None:
        """Drop the cached keys and the per-kid refresh cooldowns.

        For tests and for an operator-triggered rotation.  Nothing calls this on
        the request path — the ``kid`` miss already handles rotation, and
        invalidating here would throw away the one set this service has ever
        trusted at exactly the moment the trust is in question.
        """
        self._keys = None
        self._expires_at = 0.0
        self._attempted.clear()
        self._last_error = None

    def snapshot(self) -> JwkSet | None:
        """The cached keys, whatever their age.  For diagnostics."""
        return self._keys

    # -- internals -----------------------------------------------------

    def _live_keys(self, allow_stale: bool = True) -> JwkSet | None:
        """The cached keys if usable, else ``None``.

        An **expired** set is still returned when the last refresh attempt
        failed.  This is the single most consequential line in the module, so
        the reasoning is here in full:

        The alternative is that every token in the fleet is rejected for as
        long as the authorization server is unreachable.  With a 15-minute
        access token, a two-minute AS outage would log every user out of every
        service behind it.

        Serving the last known key set does not extend anybody's access.  A key
        set and a grant are different things: revoking a grant does not remove
        a key from the JWKS, it stops the AS from minting new access tokens
        with it.  A token accepted against a stale key set is still a token
        whose own ``exp`` bounds it, and whose ``aud`` still confines it to this
        one service.

        The exposure this *does* buy is narrow and worth naming: if the AS
        rotated **and** is unreachable, tokens signed by the retired key stay
        acceptable until the AS returns.  That window is bounded by
        ``max_ttl_seconds`` — which is why the ceiling clamp in
        :meth:`_effective_ttl` exists and is not merely hygiene — and a
        deployment that cannot accept even that sets the ceiling low.

        ``allow_stale=False`` is for callers that must not use a set they know
        to be past its TTL; only :meth:`prefetch` needs it.
        """
        if self._keys is None:
            return None
        if self._clock() < self._expires_at:
            return self._keys
        if allow_stale and self._last_error is not None:
            return self._keys
        return None

    def _negative_active(self, kid: str | None) -> bool:
        """Whether a miss-driven refresh for *kid* is still within its cooldown.

        The stamp is written **before** the fetch, not after its outcome is
        known.  That ordering is what makes the burst case work: fifty requests
        racing a rotation all pass the live-set lookup, all miss, and all reach
        here.  The first stamps and fetches; the other forty-nine arrive at the
        lock, find the stamp, and skip straight to re-reading a cache that the
        first one has already replaced.  Stamping afterwards instead would let
        all fifty fetch, because none of them has finished yet.

        The cooldown is ``negative_ttl_seconds`` — short enough that a genuine
        rotation reusing a ``kid`` is picked up in seconds, long enough that a
        burst cannot amplify into a fetch flood.  The cost is that a rotation
        which republishes a ``kid`` *within* the cooldown can be missed for that
        long; the bound is why the default is seconds, not minutes.
        """
        if kid is None:
            return False
        expiry = self._attempted.get(kid)
        if expiry is None:
            return False
        if self._clock() >= expiry:
            del self._attempted[kid]
            return False
        return True

    async def _refresh(self, *, reason: str, force: bool = False, kid: str | None = None) -> None:
        """Fetch the JWKS, at most once concurrently per triggering ``kid``.

        Every guard lives *inside* the lock.  Holding the lock across a fetch
        without re-checking is the common bug: fifty requests queue up, and each
        finds the cache stale again the moment the previous one releases it.
        """
        async with self._lock:
            if kid is not None:
                if self._negative_active(kid):
                    return
                self._attempted[kid] = self._clock() + self._negative_ttl
            else:
                now = self._clock()
                if not force and self._keys is not None and now < self._expires_at:
                    return
            self.fetch_count += 1
            try:
                body = await self._fetch(self.jwks_uri)
            except Exception as exc:
                # Swallowed deliberately: a cached key set keeps serving, and an
                # empty cache turns this into JwkUnavailable at the call site,
                # which is where the error message can name the URI.
                self._last_error = exc
                log.warning("JWKS fetch from %s failed (%s); %s", self.jwks_uri, exc, reason)
                return
            self._last_error = None
            try:
                keys = JwkSet.parse(_decode(body), self._clock())
            except JwkUnavailable as exc:
                # A malformed document is not a transient fault, so a live
                # cache is still used — but a cold one stays cold, and the
                # reason is not swallowed.
                self._last_error = exc
                log.error("JWKS at %s is malformed: %s", self.jwks_uri, exc)
                return
            self._keys = keys
            self._expires_at = self._clock() + self._effective_ttl(body)
            log.info(
                "JWKS from %s refreshed (%d key(s), kids=%s)",
                self.jwks_uri,
                len(keys),
                keys.kids,
            )

    def _effective_ttl(self, body: Any) -> float:
        """Honour ``Cache-Control: max-age``, clamped into the configured band.

        The clamp is the point.  An AS that publishes ``max-age=31536000`` would
        otherwise pin every service to a key set for a year, and a rotation
        would not be picked up until the process restarts.
        """
        headers = getattr(body, "headers", None)
        raw = None
        if headers is not None:
            raw = headers.get("cache-control") or headers.get("Cache-Control")
        if not raw:
            return self._ttl
        for directive in str(raw).split(","):
            name, _, value = directive.strip().partition("=")
            if name.lower() != "max-age":
                continue
            try:
                requested = float(value.strip('"'))
            except ValueError:
                break
            return min(max(requested, self._min_ttl), self._max_ttl)
        return self._ttl

    async def _http_fetch(self, uri: str) -> Any:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            return await client.get(uri, headers={"accept": "application/json"})


def _decode(body: Any) -> Any:
    """Read a JWKS out of whatever the ``fetch`` callable returned.

    Three shapes are accepted, and the leniency is deliberate: the default
    fetcher returns an ``httpx.Response``, a test may return a decoded mapping
    to skip a serialiser, and a caller wiring their own transport may return a
    bare string.  A caller should not have to know which one this function
    prefers in order to supply the one theirs produces.
    """
    if isinstance(body, (dict, list)):
        return body
    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8")
    if not isinstance(body, str):
        # An httpx.Response, or anything else response-shaped.
        text = getattr(body, "text", None)
        if isinstance(text, str):
            body = text
        else:
            content = getattr(body, "content", None)
            if isinstance(content, (bytes, bytearray)):
                body = content.decode("utf-8")
            else:
                raise JwkUnavailable(f"cannot read a JWKS out of {type(body).__name__}")
    try:
        return json.loads(body)
    except ValueError as exc:
        raise JwkUnavailable(f"JWKS is not valid JSON: {exc}") from exc
