# src/rhosocial/mcpserver/errors.py
"""Errors raised by this library.

Every error carries the *cause* of a rejection, because a rejection that cannot
be named cannot be debugged: a service operator seeing a bare 401 has to
choose between "the AS is down", "the key rotated" and "the audience is wrong"
by reading the AS logs.  These exceptions are what `JwtTokenVerifier` raises
internally and what the CLI prints; at the HTTP boundary they all collapse to a
401 with a ``WWW-Authenticate`` challenge, because the bearer spec forbids
telling an unauthenticated caller *why* its credential failed.
"""

from __future__ import annotations

__all__ = [
    "McpServerError",
    "ConfigurationError",
    "Unauthenticated",
    "ScopeDenied",
    "ProvisioningError",
    "PrincipalNotResolved",
    "JwkUnavailable",
]


class McpServerError(Exception):
    """Base class for every error this library raises."""


class ConfigurationError(McpServerError):
    """The service is misconfigured.

    Raised at construction, not at request time: a config that cannot produce a
    correct PRM document or an impossible audience list is a deployment bug, and
    finding out on the first request means a client is already retrying.
    """


class Unauthenticated(McpServerError):
    """No verified identity is available in this context.

    Two distinct situations share this error, and they are deliberately not
    separated: outside an HTTP request there is no token, and inside one the
    token was already rejected upstream.  Either way the correct behaviour is
    identical — fail closed — and telling them apart would tempt a caller into
    catching this and falling back to something less safe.
    """


class ScopeDenied(McpServerError):
    """The identity is known but lacks the scope this operation requires."""

    def __init__(self, required: str, granted: frozenset[str] | tuple[str, ...] = ()) -> None:
        self.required = required
        self.granted = frozenset(granted)
        super().__init__(f"scope {required!r} is required; granted: {sorted(self.granted)}")


class ProvisioningError(McpServerError):
    """A local principal projection could not be created or resolved.

    Deliberately separate from :class:`Unauthenticated`: the credential was
    valid, so retrying with a different token will not help, and an operator
    reading logs needs to see which of the two happened.
    """


class PrincipalNotResolved(McpServerError):
    """An identity is verified, but its local ``principal_id`` was never resolved.

    The two enforcement points — ``PrincipalScopedQuery.__init__`` and
    ``PrincipalOwnedMixin.prepare_save_data`` — are synchronous hooks and cannot
    resolve a projection themselves, so something upstream must have done it.  If
    nothing did, this is the error, and it is kept apart from
    :class:`Unauthenticated` for a practical reason: the two look identical to a
    client, and collapsing them into a 401 sends an operator to inspect a token
    that is perfectly fine.
    """


class JwkUnavailable(McpServerError):
    """The signing keys could not be obtained and no usable cache exists.

    Distinct from "the key is unknown": an unknown ``kid`` triggers one refresh
    and then rejects the token, while this says the verifier has no key material
    at all and never had any.  The first is a client problem, the second is a
    deployment problem.
    """
