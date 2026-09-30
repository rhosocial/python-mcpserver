# src/rhosocial/mcpserver/identity.py
"""Who is calling, and the one place that question is answered.

``current_principal()`` is the only supported way to read the caller's identity.
Not a convention — a rule with a cost: a function that takes a ``principal_id``
argument is a function whose caller can choose the answer, and every such
function is one forgotten ``await`` away from leaking a row.

The value comes from two places, and they are read in this order:

1. **The SDK's request-scoped ContextVar**, populated by the MCP SDK's
   ``AuthContextMiddleware`` after ``JwtTokenVerifier`` has already validated
   the bearer token.  This is the remote-HTTP path.
2. **A ContextVar the CLI sets once at startup.**  The CLI has no HTTP request
   and therefore no SDK authentication layer, so it binds the credential it was
   given directly.

Both paths re-verify.  The ContextVar carries an already-verified value for the
duration of one call, not a session: nothing here is readable after the request
that set it, so a revocation takes effect on the next request exactly as it
would have without any caching at all.

This module imports no model and no database, so ``orm/`` may depend on it
without a cycle.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass, field

from .errors import Unauthenticated

__all__ = [
    "Principal",
    "current_principal",
    "current_principal_id",
    "current_central_user_id",
    "set_cli_principal",
    "reset_cli_principal",
    "set_current_principal",
    "reset_current_principal",
]

_UNTYPED = ""


@dataclass(frozen=True)
class Principal:
    """An authenticated caller.

    Frozen for the obvious reason — it is handed to code that writes it into
    ``WHERE`` clauses, and a mutable identity is a mutable authorization
    decision.

    :param central_user_id: the ``sub`` from the authorization server, i.e. the
        identity *outside* this service.  This is the value every
        ``<prefix>_principals`` row is keyed on.
    :param client_id: which OAuth client presented the token (an agent, a web
        app, a service).  Not the same thing as the user, and one user has many.
    :param scopes: the scopes the token carries.
    :param issuer: the authorization server that signed it.  Unique per issuer
        per RFC 7662 §2.2, which is why it is part of the identity rather than
        a log field.
    :param resource: the RFC 8707 resource indicator the token was issued for.
    :param expires_at: POSIX timestamp, or ``None`` for a non-expiring token.
    :param token_id: the ``jti``, for correlating this request with the AS's
        own logs.  Never an authorization input.
    """

    central_user_id: str
    client_id: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    issuer: str = _UNTYPED
    resource: str = _UNTYPED
    expires_at: int | None = None
    token_id: str | None = None

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.central_user_id} via {self.client_id}"


#: Set by the SDK's ``AuthContextMiddleware`` indirectly — we mirror the token it
#: resolved so that ``orm/`` does not have to import the SDK's accessor and so
#: the CLI and HTTP paths are indistinguishable from here down.
_principal: ContextVar[Principal | None] = ContextVar(
    "rhosocial_mcpserver_principal", default=None
)

#: The CLI's binding.  Separate from ``_principal`` so that a CLI process can
#: never overwrite — or be overwritten by — a value set on the HTTP path.
_cli_principal: ContextVar[Principal | None] = ContextVar(
    "rhosocial_mcpserver_cli_principal", default=None
)


def current_principal() -> Principal:
    """The verified caller, or raise :class:`Unauthenticated`.

    Fails closed with no fallback.  A caller that catches ``Unauthenticated``
    and proceeds anyway has removed the only barrier this design has.
    """
    principal = _principal.get() or _cli_principal.get()
    if principal is None:
        raise Unauthenticated(
            "no verified identity in this context. On a remote MCP request the "
            "bearer token must have been accepted before any handler runs; in "
            "the CLI, bind one with set_cli_principal()."
        )
    return principal


def current_principal_id() -> int:
    """The caller's local ``principal_id``.

    Fails closed, and note *where* the two failure modes differ: the identity
    check happens here, and raises :class:`~rhosocial.mcpserver.errors.Unauthenticated`;
    the projection lookup happens in the ORM layer and raises
    :class:`~rhosocial.mcpserver.errors.ProvisioningError`.  Two different errors
    for the same call is the price of not collapsing "who are you" and "we could
    not store you" into one message an operator cannot act on.
    """
    from .orm.principal import current_principal_id as _resolve

    return _resolve()


def current_central_user_id() -> str:
    """The caller's ``central_user_id`` — cheap, no database round trip.

    This is the value to put in a ``WHERE`` clause when the service stores
    ``central_user_id`` directly.  Services using a local integer
    ``principal_id`` want :func:`current_principal_id` instead, which does cost
    a lookup; see ``orm/principal.py`` for why that lookup is memoised per
    request.
    """
    return current_principal().central_user_id


def set_current_principal(principal: Principal) -> Token:
    """Bind *principal* for the current request.  Returns a reset token.

    For the HTTP path this is called from a middleware; for tests and for
    embedding, it is the supported way to act as a given identity without
    minting a token.
    """
    return _principal.set(principal)


def reset_current_principal(token: Token) -> None:
    """Undo :func:`set_current_principal`."""
    _principal.reset(token)


def set_cli_principal(principal: Principal) -> Token:
    """Bind the identity a CLI process runs as.

    The CLI is authorised by local access: whoever can run the process already
    holds the credentials.  This binds *which* identity that is, and the value
    still came from a real credential — the CLI verifies it through the same
    :class:`~rhosocial.mcpserver.verifier.JwtTokenVerifier` before calling this.
    """
    return _cli_principal.set(principal)


def reset_cli_principal(token: Token) -> None:
    """Undo :func:`set_cli_principal`."""
    _cli_principal.reset(token)
