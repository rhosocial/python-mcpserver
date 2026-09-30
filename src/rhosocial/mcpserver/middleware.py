# src/rhosocial/mcpserver/middleware.py
"""The ASGI layer: per-tool scope enforcement, the metadata document, health.

Everything here exists because the MCP SDK's own authentication cannot do this
job, and the reason is worth stating once:

``AuthSettings.required_scopes`` is **all-or-nothing**.  A token holding only
``schedules:read`` is refused from ``get_schedule`` because it lacks
``schedules:write``, which is the same refusal a token with no scopes at all
gets.  A read-only credential is the normal case for an agent, and it becomes
unusable.

So the global requirement stays empty and the check happens per tool.  It has to
happen at the **ASGI** layer, not in a ``ServerMiddleware``, because only there
does an HTTP status exist: a middleware inside dispatch raises, and the client
sees a JSON-RPC error object under a ``200``, which is not something any MCP
client can act on.  The client would report "the tool failed" rather than "you
need to re-authorize with more scope", and the user would see a broken tool
with no way to fix it.

The trade-off is that this wrapper runs outside the SDK's transport-security
middleware, so a request with a forged ``Host`` is answered 401/403 rather than
421.  Nothing is disclosed that the caller did not already hold — they presented
the credential themselves.

The other rule this file obeys: **a credential that does not resolve is passed
through untouched.**  Every 401, with its ``WWW-Authenticate`` challenge that
starts discovery, stays in the SDK's hands.  This layer produces 403 and only
403, so the two failure modes cannot be confused for one another in a log.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from .config import HEALTH_PATH, MCP_PATH, PRM_PATH, ResourceServerConfig
from .metadata import CACHE_CONTROL, protected_resource_metadata, scope_challenge
from .verifier import JwtTokenVerifier, clear_verified, publish_verified

__all__ = [
    "ScopeEnforcement",
    "PrincipalResolution",
    "ResourceEndpoints",
    "parse_bearer",
]

log = logging.getLogger(__name__)

#: JSON-RPC call bodies are a few hundred bytes.  The SDK caps the request body
#: at 4 MiB, but this middleware drains it *before* that middleware runs, so the
#: cap has to be re-imposed here — otherwise an unauthenticated caller can make
#: the process buffer an arbitrary amount, and the cap that would have stopped
#: it has already run out of order.
MAX_BODY_BYTES = 64 * 1024

#: How much of an already-refused body is read before the connection is dropped
#: regardless.  Matches the SDK's own 4 MiB cap, so a client within the limit
#: always fits here and gets a proper answer rather than a reset.
DRAIN_CEILING_BYTES = 4 * 1024 * 1024

#: The two callables every ASGI app receives.  Aliased rather than imported
#: from starlette so the middleware carries no framework dependency of its own:
#: it is a plain ASGI callable, and typing it structurally keeps it testable
#: without a server.
Receive = Callable[[], Awaitable[Mapping[str, Any]]]
Send = Callable[[Mapping[str, Any]], Awaitable[None]]


class _BodyTooLarge(Exception):
    def __init__(self, more: bool) -> None:
        self.more = more
        super().__init__("request body too large")


def parse_bearer(header: str | None) -> str | None:
    """Extract the credential from an ``Authorization: Bearer`` header.

    Returns ``None`` for anything else, including a header that says Bearer and
    then has nothing.  A partial credential is not a credential, and treating it
    as one would turn a client bug into an authentication attempt.
    """
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


class ResourceEndpoints:
    """Serves the two unauthenticated GETs that must exist outside the SDK's paths.

    Neither belongs to the MCP protocol, so the SDK routes neither, and both
    have to be answered before authentication: a client that cannot read the
    metadata document cannot know where to authenticate.
    """

    __slots__ = ("_config", "_health")

    def __init__(
        self,
        config: ResourceServerConfig,
        health: Callable[[], Awaitable[bool]] | None = None,
    ) -> None:
        self._config = config
        self._health = health

    async def __call__(self, scope: Mapping[str, Any], receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            return
        method = scope.get("method")
        path = scope.get("path", "")

        if method == "GET" and path.startswith(PRM_PATH):
            await _send_json(
                send,
                200,
                protected_resource_metadata(self._config),
                extra_headers=[(b"cache-control", CACHE_CONTROL.encode())],
            )
            return

        if method == "GET" and path == HEALTH_PATH:
            await self._send_health(send)
            return

        await _send_json(send, 404, {"error": "not_found"})

    async def _send_health(self, send: Send) -> None:
        """Report whether this process can actually serve.

        Without a probe this answers "the process is up", which is how a
        container stays in the load balancer's rotation while unable to answer a
        single tool call.  Any exception is swallowed into a 503: a probe that
        raised would surface as a 500 from the server, and a load balancer needs
        a status it can read, not a stack trace.
        """
        healthy = True
        if self._health is not None:
            try:
                healthy = bool(await self._health())
            except Exception as exc:
                log.warning("health probe raised: %s", exc)
                healthy = False
        status, body = (200, {"status": "ok"}) if healthy else (503, {"status": "unavailable"})
        await _send_json(send, status, body)


class ScopeEnforcement:
    """Refuse a tool call whose token lacks that tool's scope, with an HTTP 403.

    :param app: the wrapped ASGI application
    :param config: this service's description
    :param verifier: used to resolve the presented token *before* the SDK does,
        so the required scope is known
    :param mcp_path: the MCP endpoint, so only that path is inspected
    """

    __slots__ = ("_app", "_config", "_verifier", "_mcp_path", "_max_body")

    def __init__(
        self,
        app: Any,
        *,
        config: ResourceServerConfig,
        verifier: JwtTokenVerifier,
        mcp_path: str = MCP_PATH,
        max_body_bytes: int = MAX_BODY_BYTES,
    ) -> None:
        self._app = app
        self._config = config
        self._verifier = verifier
        self._mcp_path = mcp_path
        self._max_body = max_body_bytes

    async def __call__(self, scope: Any, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return

        if scope.get("method") != "POST" or scope.get("path", "") != self._mcp_path:
            await self._app(scope, receive, send)
            return

        try:
            body, messages = await _drain(receive, self._max_body)
        except _BodyTooLarge as too_large:
            await self._drain_refusal(receive, too_large)
            await _send_json(send, 413, {"error": "payload_too_large"})
            return

        try:
            payload = json.loads(body) if body else None
        except ValueError:
            # Not this layer's error to name: a malformed body is a 400, and
            # the SDK produces that.  Raising here would turn a bad request
            # into an exception raised inside the authentication path.
            payload = None

        replayed = _replay(messages, receive)
        tool = _required_tool(payload)
        if tool is None:
            # Not a `tools/call`, or a body whose shape this layer will not
            # assume.  Neither is this layer's error to name: a malformed body
            # is a 400 and the SDK produces that, and raising here would turn a
            # bad request into an exception inside the authentication path.
            await self._app(scope, replayed, send)
            return

        if not self._config.policy.knows(tool):
            # The name is in the map's absence — a `tools/call` for a tool this
            # service never declared.  A client can only reach a tool the server
            # registered, so this means the two sides disagree, and a request to
            # disagree is not a request to serve.  Answered as 403 rather than
            # deferred, because deferring would let the SDK dispatch a tool with
            # no declared scope at all.
            await self._send_scope_error(send, f"a scope for unknown tool {tool!r}")
            return

        if not self._config.policy.requires_scope(tool):
            # `whoami`, or anything declared as needing no scope.
            await self._app(scope, replayed, send)
            return

        token = parse_bearer(_header(scope, "authorization"))
        if token is None:
            # No credential at all.  The SDK owns the 401 and its challenge,
            # and answering here would produce a 401 without the
            # `WWW-Authenticate: ... resource_metadata=...` header that tells a
            # client where to authenticate.
            await self._app(scope, replayed, send)
            return

        record = await self._verifier.verify_token(token)
        if record is None:
            # Present but unusable — expired, wrong audience, unknown key.
            # Delegated to the SDK so every invalid-credential response comes
            # from one place; a 403 here would both misreport the cause and
            # skip the challenge a client needs.
            await self._app(scope, replayed, send)
            return

        missing = self._config.policy.missing(tool, record.scopes)
        if missing is not None:
            await self._send_scope_error(send, missing)
            return

        # The SDK is about to ask the verifier about this same token.  Hand over
        # the resolution so the signature is not verified twice.  Only
        # successes are published, and the reset is in the `finally` below — so
        # the memo cannot outlive the request it was made for.
        reset = publish_verified(token, record)
        try:
            await self._app(scope, replayed, send)
        finally:
            clear_verified(reset)

    async def _drain_refusal(self, receive: Receive, too_large: _BodyTooLarge) -> None:
        """Read out a body that was refused for being too large.

        Skipped when the body had already arrived in full: there is nothing left
        to read, and asking anyway would block on a message the client has no
        reason to send.
        """
        if not too_large.more:
            return
        try:
            await _discard(receive, DRAIN_CEILING_BYTES)
        except Exception as exc:
            # The peer went away mid-upload.  Answering is then pointless but
            # harmless, and letting it escape would turn a refused request into
            # a 500 that says nothing about why.
            log.debug("client disconnected while discarding an oversized body: %s", exc)

    async def _send_scope_error(self, send: Send, required: str) -> None:
        await _send_json(
            send,
            403,
            {
                "error": "insufficient_scope",
                "error_description": f"Required scope: {required}",
            },
            extra_headers=[
                (b"www-authenticate", scope_challenge(self._config, required).encode())
            ],
        )


def _required_tool(payload: Any) -> str | None:
    """The tool name from a JSON-RPC envelope, or ``None`` when there is none.

    The whole envelope is caller-controlled, so nothing here is trusted to have
    the expected shape: a malformed body has to fall through to the SDK for a
    clean 400 rather than raising inside the authentication path.

    ``None`` covers three cases that all mean the same thing to this layer —
    not a ``tools/call``, a body that is not an object, and a ``tools/call``
    with no usable ``params.name``.  A *present* name that is not in the tool
    map is a different case, and is handled as a 403: a client can only reach a
    tool the server registered, so an unknown name means the two sides
    disagree, and disagreeing sides should not be exchanging data.
    """
    if not isinstance(payload, dict) or payload.get("method") != "tools/call":
        return None
    params = payload.get("params")
    if not isinstance(params, dict):
        return None
    name = params.get("name")
    return name if isinstance(name, str) else None


class PrincipalResolution:
    """Publishes the caller's identity and resolved ``principal_id`` for the request.

    Runs *after* the SDK's authentication, because it needs the token the SDK
    already verified.  Its whole job is the one query the two synchronous
    enforcement points cannot do themselves: resolving (and on first use,
    creating) the local projection row.

    Without it, every request fails with
    :class:`~rhosocial.mcpserver.errors.PrincipalNotResolved` — which is the
    intended behaviour, because the alternative (letting the hooks resolve)
    would mean a nested event loop inside every save.

    A failure here answers **503**, not 401.  The credential was good; the
    service could not do its work.  A load balancer retries a 503 and gives up
    on a 401, and this request is worth retrying.
    """

    __slots__ = ("_app",)

    def __init__(self, app: Any) -> None:
        self._app = app

    async def __call__(self, scope: Any, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return

        from mcp.server.auth.middleware.auth_context import get_access_token

        record = get_access_token()
        if record is None or not record.subject:
            # Unauthenticated, or a token with no subject.  Not this layer's
            # call to make: the SDK owns the 401 and its challenge.
            await self._app(scope, receive, send)
            return

        from .identity import (
            Principal,
            reset_current_principal,
            set_current_principal,
        )
        from .orm.principal import ensure_principal_id

        principal = Principal(
            central_user_id=str(record.subject),
            client_id=record.client_id,
            scopes=frozenset(record.scopes),
            issuer=str((record.claims or {}).get("iss", "")),
            resource=record.resource or "",
            expires_at=record.expires_at,
        )

        principal_token = set_current_principal(principal)
        try:
            await ensure_principal_id(principal)
        except Exception as exc:
            log.warning("could not resolve the principal projection: %s", exc)
            await _send_json(
                send,
                503,
                {"error": "unavailable", "error_description": "principal unavailable"},
            )
            return
        try:
            await self._app(scope, receive, send)
        finally:
            reset_current_principal(principal_token)


# -- ASGI helpers --------------------------------------------------------


async def _send_json(
    send: Send,
    status: int,
    payload: Any,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    body = json.dumps(payload).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def _header(scope: Mapping[str, Any], name: str) -> str | None:
    """Case-insensitive header lookup.

    ASGI lower-cases header names on the way in, but this middleware also
    runs in tests with hand-built scopes, and a silent ``None`` there is a test
    that passes without testing anything.
    """
    target = name.lower().encode()
    for key, value in scope.get("headers", ()):
        if key.lower() == target:
            return bytes(value).decode("latin-1")
    return None


async def _drain(receive: Receive, limit: int) -> tuple[bytes, list[Mapping[str, Any]]]:
    """Read the request body, keeping the messages for replay.

    The body has to be read here — to find the tool name — but the downstream
    application still needs to receive it.  The messages are therefore
    collected and replayed through a wrapped ``receive``; without that, every
    request reaching a tool would arrive with an empty body.
    """
    chunks: list[bytes] = []
    messages: list[Mapping[str, Any]] = []
    total = 0
    more = True
    while more:
        message = await receive()
        messages.append(message)
        if message["type"] != "http.request":
            continue
        chunk = message.get("body", b"")
        total += len(chunk)
        if total > limit:
            raise _BodyTooLarge(bool(message.get("more_body", False)))
        chunks.append(chunk)
        more = bool(message.get("more_body", False))
    return b"".join(chunks), messages


async def _discard(receive: Receive, limit: int) -> None:
    total = 0
    more = True
    while more and total <= limit:
        message = await receive()
        if message["type"] != "http.request":
            continue
        total += len(message.get("body", b""))
        more = bool(message.get("more_body", False))


def _replay(messages: list[Mapping[str, Any]], receive: Receive) -> Receive:
    """Return a ``receive`` that hands back *messages*, then the real one."""
    pending = list(messages)

    async def replayed() -> Mapping[str, Any]:
        if pending:
            return pending.pop(0)
        return await receive()

    return replayed
