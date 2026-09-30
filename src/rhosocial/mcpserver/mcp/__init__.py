# src/rhosocial/mcpserver/mcp/__init__.py
"""The MCP transport adapter.

Everything in this subpackage knows what MCP is.  Everything above it does not:
identity, scopes, the credential protocol and the ORM mixins import no
transport, no SDK type and no request object, so a service can serve REST or
anything else from the same ownership and isolation code with no changes there.

What is here, and why each belongs on this side of the line:

``verifier``
    Returns the MCP SDK's :class:`~mcp.server.auth.provider.AccessToken`.  A
    service speaking another dialect gets its own adapter and calls
    :func:`~rhosocial.mcpserver.mcp.verifier.resolve_for_sdk` for nothing --
    it adapts its own :class:`~rhosocial.mcpserver.identity.Principal` to its
    own transport's shape, which is the whole point of the split.
``jwks``
    A JWKS is how an asymmetric signing key is published.  A service checking
    tokens it minted itself has no key to publish.
``metadata``
    RFC 9728 Protected Resource Metadata, an OAuth discovery document.
``middleware``
    The ASGI layer that serves the metadata document, the health endpoint and
    per-tool scope enforcement.
``app``
    Assembling the SDK's application with the above.

The package is still called ``mcpserver`` even though half of it is transport
agnostic.  Renaming it would touch four repositories' import lines to fix a
naming lag, and that trade does not pay for itself.
"""

from __future__ import annotations

from .app import (
    DEFAULT_BIND_HOST,
    DEFAULT_BIND_PORT,
    HEALTH_PATH,
    PRM_PATH,
    auth_settings,
    build_asgi_app,
    build_mcp_app,
    serve,
)
from .jwks import Jwk, JwksCache, JwkSet
from .metadata import (
    protected_resource_metadata,
    protected_resource_metadata_url,
    resource_metadata_challenge,
    scope_challenge,
)
from .middleware import (
    PrincipalResolution,
    ProtocolRevisionGate,
    ResourceEndpoints,
    ScopeEnforcement,
)
from .verifier import (
    JwtTokenVerifier,
    clear_verified,
    publish_verified,
    resolve_for_sdk,
    take_verified,
)

__all__ = [
    "auth_settings",
    "build_asgi_app",
    "build_mcp_app",
    "serve",
    "DEFAULT_BIND_HOST",
    "DEFAULT_BIND_PORT",
    "HEALTH_PATH",
    "PRM_PATH",
    # jwks
    "Jwk",
    "JwkSet",
    "JwksCache",
    # metadata
    "protected_resource_metadata",
    "protected_resource_metadata_url",
    "resource_metadata_challenge",
    "scope_challenge",
    # middleware
    "PrincipalResolution",
    "ProtocolRevisionGate",
    "ResourceEndpoints",
    "ScopeEnforcement",
    # verification
    "JwtTokenVerifier",
    "resolve_for_sdk",
    "publish_verified",
    "take_verified",
    "clear_verified",
]
