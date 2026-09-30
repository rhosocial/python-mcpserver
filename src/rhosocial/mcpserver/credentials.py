# src/rhosocial/mcpserver/credentials.py
"""Where a bearer credential comes from, independent of what transport carried it.

A :class:`CredentialSource` answers one question — *is this string a credential,
and whose is it* — and deliberately nothing else.  A service's own token table,
an OAuth 2.1 access token, an mTLS identity: all three reduce to the same call,
so a service picks its authentication once and gets identity, ownership and row
isolation regardless of which transport carries the request.

**What is deliberately not in this interface.**  Scopes, because
:class:`~rhosocial.mcpserver.scopes.ScopePolicy` already answers "may this
caller do this" and belongs to neither side; putting it here would couple *what
a tool requires* to *how the credential was obtained*, and the two change for
different reasons.  The 401 challenge, because in the MCP path it is built from
the configuration's issuer and resource — the protocol would force
every implementation to fabricate a URL it does not have.  Where the credential
comes from is a question; where a 401 tells the client to go is a question about
the server's own shape, and it was already answered without a verifier.

:func:`~rhosocial.mcpserver.identity.set_current_principal` is the other half:
once a source returns a :class:`Principal`, that is the identity for the rest of
the request, whichever transport delivered it.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from .identity import Principal

__all__ = ["CredentialSource", "DiscoverySource"]


@runtime_checkable
class DiscoverySource(Protocol):
    """Something that can describe where to authenticate.

    The half of :class:`CredentialSource` that the discovery document needs, and
    separately declared because something can have one without the other: the
    ``prm`` CLI command prints the document a client would fetch, so it needs an
    issuer to advertise, and it verifies nothing.
    """

    def metadata(self) -> dict[str, Any] | None:
        """The RFC 9728 document, or ``None`` when there is nothing to discover.

        ``None`` means *there is nowhere else to go*: a service that issues and
        checks its own tokens has no external authorization server for a client
        to discover, and returning an empty document would have a client looking
        for one that does not exist.

        RFC 9728 shape for the OAuth case, including the ``authorization_servers``
        entry that points at the issuer.  It is deliberately *not* this service's
        own URL: a resource server that lists itself as its own authorization
        server sends its clients to fetch tokens from the wrong host.
        """
        ...


@runtime_checkable
class CredentialSource(DiscoverySource, Protocol):
    """Something that can turn a presented string into an identity.

    Structural, not inherited: a service's token table and a JWKS verify have
    nothing else in common, and requiring a base class would be requiring them
    to pretend otherwise.
    """

    async def verify(self, token: str) -> Principal | None:
        """Resolve *token* to its owner, or ``None`` if it is not a credential.

        Two failure shapes, and the distinction is the caller's to make:

        ``None``
            This is not a usable credential — absent, unknown, revoked, or
            simply not the kind of string this source issues.  Nothing was
            proven wrong, so there is nothing to report.
        :class:`~rhosocial.mcpserver.errors.Unauthenticated`
            The credential *was* recognised and something specific is wrong with
            it, such as expiry or insufficient scope.  The message is for the
            service's own log, where it is the difference between "rotate this
            credential" and "the issuer moved and we are behind".  Raising rather
            than returning ``None`` keeps a recognised-but-refused credential
            distinguishable from an unrecognised one in the logs, which is the
            only place the difference is actionable.

        The contract is *not* "raise on failure".  A transport that wants a 401
        rather than a 500 has to be able to tell those apart, which it cannot if
        everything arrives as an exception.
        """
