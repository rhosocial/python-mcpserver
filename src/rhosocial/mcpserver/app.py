# src/rhosocial/mcpserver/app.py
"""Assembling the pieces into an ASGI application.

The order of the four layers is not a style preference — each one exists
because the layer inside it cannot do that job, and moving any of them breaks
something specific:

.. code-block:: text

    ResourceEndpoints      PRM document, /healthz
      └── ScopeEnforcement per-tool 403, from the request body
           └── PrincipalResolution   resolve the projection, once per request
                └── <the SDK's app>   401 + the auth ContextVar

**``ResourceEndpoints`` is outermost** because the metadata document and the
health probe are unauthenticated by necessity: a client that cannot read the
document cannot learn where to authenticate, and a load balancer needs the
probe to answer without a credential.

**``ScopeEnforcement`` is above ``PrincipalResolution``** because it already has
the verified token in hand, and ``PrincipalResolution`` is cheaper when it can
take the resolution from the request-scope memo instead of verifying again.
Ordering it the other way would still be correct and one verification slower.

**``PrincipalResolution`` is innermost** because it is the last thing that can
fail before a tool runs, and a failure there — a valid credential against a
database that will not accept writes — is a 503, not a 401.  A load balancer
retries a 503 and gives up on a 401, and this request is worth retrying.

The SDK's app is left to produce **every** 401.  It is the only layer holding a
``WWW-Authenticate`` challenge that starts discovery, and duplicating it here
would mean two places to keep in step with RFC 6750.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Awaitable, Callable
from typing import Any

from .config import HEALTH_PATH, MCP_PATH, PRM_PATH, ResourceServerConfig
from .errors import ConfigurationError
from .middleware import (
    MAX_BODY_BYTES,
    PrincipalResolution,
    ResourceEndpoints,
    ScopeEnforcement,
)
from .verifier import JwtTokenVerifier

__all__ = [
    "build_asgi_app",
    "build_mcp_app",
    "auth_settings",
    "serve",
    "BindSettings",
    "DEFAULT_BIND_HOST",
    "DEFAULT_BIND_PORT",
    "HEALTH_PATH",
    "PRM_PATH",
]

log = logging.getLogger(__name__)

#: Loopback, not ``0.0.0.0``.  A bearer token crosses this hop in a cleartext
#: header, so a service that binds to every interface without a TLS terminator
#: in front is publishing its users' credentials to the local network.  A
#: container that genuinely needs a wider bind sets it explicitly, in a
#: compose file, where the choice is visible.
DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 8000


def build_asgi_app(
    app: Any,
    *,
    config: ResourceServerConfig,
    verifier: JwtTokenVerifier,
    health: Callable[[], Awaitable[bool]] | None = None,
    mcp_path: str = MCP_PATH,
    max_body_bytes: int = MAX_BODY_BYTES,
    resolve_projection: bool = True,
) -> Any:
    """Wrap *app* — the MCP SDK's ASGI application — in the four layers.

    :param app: any ASGI application; normally
        ``MCPServer.streamable_http_app()``
    :param health: called on ``GET /healthz``.  Should touch the database — a
        probe that only reports "the process is up" keeps a container in the
        load balancer's rotation while it cannot answer a single tool call.
    :param max_body_bytes: the cap re-imposed on the request body.  The SDK's
        own cap runs *after* this layer, so without one here an
        unauthenticated caller could make the process buffer anything.
    :param resolve_projection: turn off only for a service that uses neither
        ``PrincipalScopedQuery`` nor ``PrincipalOwnedMixin``.  See
        :class:`~rhosocial.mcpserver.middleware.PrincipalResolution`.
    """
    return ResourceEndpoints(
        config,
        health=health,
        app=ScopeEnforcement(
            PrincipalResolution(app, verifier, resolve_projection=resolve_projection),
            config=config,
            verifier=verifier,
            mcp_path=mcp_path,
            max_body_bytes=max_body_bytes,
        ),
    )


def auth_settings(config: ResourceServerConfig) -> Any:
    """The ``AuthSettings`` an ``MCPServer`` must be constructed with.

    Two settings here look like omissions, and neither is:

    ``required_scopes=[]``
        The SDK's requirement is all-or-nothing, so a read-only token would be
        refused from the read tools as well.  :class:`ScopeEnforcement` checks
        per tool instead.

    ``validate_token_resource=False``
        The SDK compares ``AccessToken.resource`` with *hierarchical* matching —
        a token for a parent path satisfies a child.  This library's verifier
        already checked ``aud`` exactly, which is stricter, so a second
        comparison would only widen what has already been narrowed.

    The issuer and the resource server URL are still set, because the SDK needs
    the latter to build the ``resource_metadata`` URL in its 401 challenge —
    which is how a client discovers the authorization server at all.

    ::

        server = MCPServer(
            name="notes",
            auth=auth_settings(CONFIG),
            token_verifier=verifier,
        )
    """
    from mcp.server.auth.settings import AuthSettings
    from pydantic import AnyHttpUrl

    return AuthSettings(
        # The config holds validated strings and has already refused a non-https
        # issuer, so pydantic's own validation here is redundant — but
        # AuthSettings is typed to take URLs, and converting is the honest way to
        # satisfy that rather than casting.
        issuer_url=AnyHttpUrl(config.issuer),
        resource_server_url=AnyHttpUrl(config.resource),
        required_scopes=[],
        validate_token_resource=False,
    )


def build_mcp_app(
    server: Any,
    *,
    config: ResourceServerConfig,
    verifier: JwtTokenVerifier,
    mcp_path: str = MCP_PATH,
    json_response: bool = False,
    stateless_http: bool = False,
    resolve_projection: bool = True,
    **kwargs: Any,
) -> Any:
    """:func:`build_asgi_app` around a configured ``MCPServer``.

    *server* must already have been built with
    ``auth=auth_settings(config), token_verifier=verifier``.  The SDK reads both
    off the constructor, not off :meth:`streamable_http_app`, so they cannot be
    supplied here — and this function checks rather than assumes, because an
    ``MCPServer`` built without them serves its tools to **everyone** and says
    nothing.  That is not a failure mode worth discovering in production.
    """
    settings = getattr(server, "settings", None)
    if getattr(settings, "auth", None) is None:
        raise ConfigurationError(
            "this MCPServer has no auth settings, so it would serve every tool "
            "to every caller. Construct it with "
            "auth=auth_settings(config), token_verifier=verifier."
        )

    inner = server.streamable_http_app(
        streamable_http_path=mcp_path,
        json_response=json_response,
        stateless_http=stateless_http,
        **kwargs,
    )
    return build_asgi_app(
        inner,
        config=config,
        verifier=verifier,
        mcp_path=mcp_path,
        resolve_projection=resolve_projection,
    )


class BindSettings:
    """Where to listen, and how many workers.

    Loopback by default; see :data:`DEFAULT_BIND_HOST` for why that is not
    ``0.0.0.0``.

    :param workers: uvicorn processes.  One worker is one event loop on one
        core, so this is the throughput ceiling — see a service's
        ``.env.example`` for the measurement.  It is also multiplied by each
        worker's own connection pool when sizing the database.
    """

    __slots__ = ("host", "port", "workers", "log_level")

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        workers: int | None = None,
        log_level: str | None = None,
    ) -> None:
        self.host = host or os.environ.get("MCP_BIND_HOST") or DEFAULT_BIND_HOST
        raw_port = port or os.environ.get("MCP_BIND_PORT") or DEFAULT_BIND_PORT
        self.port = int(raw_port)
        self.workers = int(workers or os.environ.get("MCP_WORKERS") or 1)
        self.log_level = log_level or os.environ.get("MCP_LOG_LEVEL") or "INFO"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"BindSettings({self.host!r}, {self.port}, workers={self.workers})"


def serve(app: Any, settings: BindSettings | None = None, **kwargs: Any) -> None:
    """Run *app* under uvicorn.

    A thin wrapper so a service's entry point is one import, and so the
    loopback default is a property of this library rather than something each
    service has to remember.
    """
    import uvicorn

    bind = settings or BindSettings()
    uvicorn.run(
        app,
        host=bind.host,
        port=bind.port,
        log_level=bind.log_level.lower(),
        **kwargs,
    )
