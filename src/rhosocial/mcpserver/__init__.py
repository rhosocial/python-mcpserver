# src/rhosocial/mcpserver/__init__.py
"""MCP resource server foundation for rhosocial-activerecord services.

A service that sits behind a central OAuth 2.1 authorization server should
contain its domain code and nothing else.  This package is the rest: verifying
the access token locally, refusing a tool call whose token lacks that tool's
scope, and tying every row to the verified caller.

Three points are worth knowing before using it.

**Identity is read in one place.**  :func:`current_principal` is the only
supported way to ask who is calling.  Nothing takes a ``user_id`` argument,
because a parameter is a value a caller can choose.

**Verification is local.**  The token's signature, issuer, audience and expiry
are checked against a cached JWKS.  No request goes to the authorization server,
which is what keeps the AS from being a network dependency of every tool call
in every service.  A revoked token therefore lives for at most its remaining
TTL; a service that needs immediate revocation for a high-risk operation adds
an introspection check itself.

**The scope vocabulary is declared once.**
:class:`ResourceServerConfig` holds it, the per-tool check reads it, and the
RFC 9728 document is generated from it — so what the service advertises and
what it accepts cannot drift apart.

Typical wiring::

    config = ResourceServerConfig(
        resource="https://calendar.example.com/mcp",
        issuer="https://auth.example.com",
        scopes=["schedules:read", "schedules:write"],
        tool_scopes={
            "whoami": NO_SCOPE,
            "list_schedules": "schedules:read",
            "create_schedule": "schedules:write",
        },
        table_prefix="sm",
    )
    cache = JwksCache(config.jwks_uri)
    verifier = JwtTokenVerifier(
        cache,
        issuer=config.issuer,
        resource=config.resource,
        scope_set=config.policy.vocabulary,
    )
    app = build_asgi_app(server, config=config, verifier=verifier)
"""

from __future__ import annotations

from .app import (
    DEFAULT_BIND_HOST,
    DEFAULT_BIND_PORT,
    BindSettings,
    auth_settings,
    build_asgi_app,
    build_mcp_app,
    serve,
)
from .config import HEALTH_PATH, MCP_PATH, PRM_PATH, ResourceServerConfig
from .errors import (
    ConfigurationError,
    JwkUnavailable,
    McpServerError,
    PrincipalNotResolved,
    ProvisioningError,
    ScopeDenied,
    Unauthenticated,
)
from .identity import (
    Principal,
    current_central_user_id,
    current_principal,
    set_cli_principal,
    set_current_principal,
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
    ResourceEndpoints,
    ScopeEnforcement,
    parse_bearer,
)
from .orm import (
    CENTRAL_USER_ID,
    STATUS_ACTIVE,
    STATUS_DELETED,
    STATUS_SUSPENDED,
    PrincipalMixin,
    PrincipalOwnedMixin,
    PrincipalScopedQuery,
    assert_protected,
    clear_principal_id,
    create_projection_schema,
    create_projection_table,
    current_principal_id,
    drop_projection_schema,
    drop_projection_table,
    ensure_principal_id,
    projection_indexes,
    publish_principal_id,
    register_projection,
    registered_projection,
)
from .scopes import NO_SCOPE, ScopePolicy, ScopeSet
from .tables import TableNamespace
from .verifier import JwtTokenVerifier

__version__ = "0.1.0.dev1"

__all__ = [
    # configuration
    "ResourceServerConfig",
    "MCP_PATH",
    "PRM_PATH",
    "HEALTH_PATH",
    # assembly
    "build_asgi_app",
    "build_mcp_app",
    "auth_settings",
    "serve",
    "BindSettings",
    "DEFAULT_BIND_HOST",
    "DEFAULT_BIND_PORT",
    "create_projection_schema",
    "drop_projection_schema",
    # credentials
    "JwksCache",
    "Jwk",
    "JwkSet",
    "JwtTokenVerifier",
    # identity
    "Principal",
    "current_principal",
    "current_principal_id",
    "ensure_principal_id",
    "register_projection",
    "registered_projection",
    "current_central_user_id",
    "set_current_principal",
    "set_cli_principal",
    "publish_principal_id",
    "clear_principal_id",
    # authorization
    "ScopeSet",
    "ScopePolicy",
    "NO_SCOPE",
    "ScopeEnforcement",
    "PrincipalResolution",
    "ResourceEndpoints",
    "parse_bearer",
    "protected_resource_metadata",
    "protected_resource_metadata_url",
    "resource_metadata_challenge",
    "scope_challenge",
    # ORM
    "PrincipalMixin",
    "PrincipalScopedQuery",
    "PrincipalOwnedMixin",
    "assert_protected",
    "create_projection_table",
    "projection_indexes",
    "drop_projection_table",
    "TableNamespace",
    "CENTRAL_USER_ID",
    "STATUS_ACTIVE",
    "STATUS_SUSPENDED",
    "STATUS_DELETED",
    # errors
    "McpServerError",
    "ConfigurationError",
    "Unauthenticated",
    "ScopeDenied",
    "ProvisioningError",
    "PrincipalNotResolved",
    "JwkUnavailable",
    "__version__",
]
