# src/rhosocial/mcpserver/mcp/metadata.py
"""RFC 9728 protected resource metadata — the document that starts discovery.

An MCP client that receives a 401 learns nothing from it beyond "ask someone".
It fetches this document, learns which authorization server issues tokens for
this resource, and which scopes exist, and only then starts a flow.  Every
remote MCP client — OpenCode, Cursor, Claude Code, Codex — does exactly this,
so a service that gets this document wrong is a service that cannot be logged
into by an agent at all.

The document is generated from :class:`~rhosocial.mcpserver.config.ResourceServerConfig`,
never written by hand.  ``scopes_supported`` in particular is derived from the
same vocabulary the enforcement middleware checks against, which is the only
way to keep "what we advertise" and "what we accept" from drifting apart.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..config import PRM_PATH, ResourceServerConfig

__all__ = [
    "protected_resource_metadata",
    "protected_resource_metadata_url",
    "resource_metadata_challenge",
]

#: RFC 9728 §7.1 recommends this lifetime.  Long enough that a client does not
#: refetch per connection, short enough that changing the issuer or the scope
#: list reaches clients without a restart.
CACHE_CONTROL = "public, max-age=3600"


def protected_resource_metadata(config: ResourceServerConfig) -> dict[str, Any]:
    """The RFC 9728 document for *config*.

    ``authorization_servers`` lists the trusted issuer — this is the field a
    client reads to find out where to authenticate, and the field that makes
    the ``aud`` binding work end to end.  It is deliberately *not* the service's
    own URL: a service that lists itself as the authorization server is a
    service whose clients will try to get a token from the wrong host.
    """
    document: dict[str, Any] = {
        "resource": config.resource,
        "authorization_servers": [config.issuer],
        "scopes_supported": list(config.scopes_supported),
        # The MCP spec defines only the header method; saying so explicitly
        # stops a client from probing the form-encoded and query-parameter
        # variants that RFC 6750 also permits but this transport does not.
        "bearer_methods_supported": ["header"],
    }
    if config.service_name:
        document["resource_name"] = config.service_name
    if config.jwks_uri:
        # Optional in RFC 9728, and publishing it is what lets a client verify
        # a token itself — e.g. a proxy doing coarse checks before this service
        # ever sees the request.
        document["jwks_uri"] = config.jwks_uri
    return document


def protected_resource_metadata_url(config: ResourceServerConfig) -> str:
    """The absolute URL of the metadata document.

    RFC 9728 §3.1 constructs this by inserting the well-known suffix
    **between the host component and the path**, not by appending it to the
    resource identifier.  For ``https://host/mcp`` that means
    ``https://host/.well-known/oauth-protected-resource/mcp`` — appending would
    give ``https://host/mcp/.well-known/oauth-protected-resource``, which is not
    a well-known location, resolves nowhere, and therefore breaks discovery for
    every client that follows it.

    That is not hypothetical here: the 401 challenge is built by the SDK and
    already carried the correct URL, while the 403 challenge came from
    :func:`scope_challenge` and advertised the unresolvable one.  A read-only
    token hitting a write tool was therefore told to fetch a document that 404s
    — on exactly the step-up path a client needs when it is short a scope.

    RFC 9728 §3 also requires an absolute URL: a client that received a relative
    one has no base to resolve against after following a redirect to this
    service.
    """
    parts = urlsplit(config.resource)
    path = parts.path.lstrip("/")
    suffix = f"{PRM_PATH}/{path}" if path else PRM_PATH
    return urlunsplit((parts.scheme, parts.netloc, suffix, parts.query, ""))


def resource_metadata_challenge(
    config: ResourceServerConfig,
    error: str = "invalid_token",
    description: str | None = None,
) -> str:
    """A ``WWW-Authenticate: Bearer …`` header value.

    :param error: ``invalid_token`` or ``insufficient_scope``.  These are the
        two RFC 6750 §3.1 values; anything else is not a challenge a client can
        parse.
    :param scope: set on ``insufficient_scope`` to the scope that was missing.
        RFC 6750 §3.1 makes this optional, but a client that is not told what
        to ask for retries the same scope and fails again.
    :param description: a human-readable explanation.  Safe here and only
        here, because this header accompanies a 403 about a token the caller
        *holds* — unlike the 401 path, where the caller has proven nothing and
        the details belong in the service's logs.
    """
    parts = [f'error="{error}"']
    if description:
        parts.append(f'error_description="{_quote(description)}"')
    parts.append(f'resource_metadata="{protected_resource_metadata_url(config)}"')
    return f"Bearer {', '.join(parts)}"


def scope_challenge(config: ResourceServerConfig, required: str) -> str:
    """The challenge accompanying a 403, naming the scope that was missing."""
    challenge = resource_metadata_challenge(
        config,
        error="insufficient_scope",
        description=f"Required scope: {required}",
    )
    # `scope=` is appended rather than folded into the helper: it is meaningful
    # only on insufficient_scope, and a helper that took an optional scope
    # would eventually be called with one on the 401 path, which RFC 6750
    # forbids.
    return f'{challenge}, scope="{_quote(required)}"'


def _quote(value: str) -> str:
    """Escape a quoted-string per RFC 9110 §5.6.4.

    A tool name or a scope reaching this header with a double quote in it would
    otherwise split the header and let a caller inject challenge parameters.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')
