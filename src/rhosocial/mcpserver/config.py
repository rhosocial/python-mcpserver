# src/rhosocial/mcpserver/config.py
"""How a service describes itself to the authorization server and to clients.

One object holds everything that is *this service's identity*: its RFC 8707
resource indicator, the issuer it trusts, the scope vocabulary, and which tool
needs which scope.  It is built once at startup and read from everywhere.

The scope vocabulary and the tool map live together here for a reason: the
protected-resource document is generated from both, and two independently
maintained lists drift into a document that advertises a scope the server
rejects.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from .errors import ConfigurationError
from .scopes import NO_SCOPE, ScopePolicy, ScopeSet
from .tables import TableNamespace

__all__ = ["ResourceServerConfig", "PRM_PATH", "MCP_PATH", "HEALTH_PATH"]

#: RFC 9728 §3.  Also the URL an MCP client fetches after a 401's
#: ``resource_metadata`` challenge, so the path is part of the contract and not
#: a routing preference.
PRM_PATH = "/.well-known/oauth-protected-resource"

#: Where the MCP endpoint is mounted.  The default matches every service built
#: on this library so far, and the resource indicator defaults to it.
MCP_PATH = "/mcp"

HEALTH_PATH = "/healthz"


class ResourceServerConfig:
    """Immutable description of one MCP resource server.

    :param resource: the RFC 8707 resource identifier — the absolute URL a
        client dials, including the MCP path.  This is what ``aud`` defaults
        to, and what the PRM document reports.  It is *not* the container's
        internal address: a proxy that rewrites ``Host`` will otherwise produce
        a resource identifier no client ever asked for.
    :param issuer: the authorization server whose signatures are trusted.
    :param jwks_uri: where its keys are published.  Derived from *issuer* when
        not given, which is the overwhelmingly common layout.
    :param scopes: the closed scope vocabulary.
    :param tool_scopes: tool name → required scope, or
        :data:`~rhosocial.mcpserver.scopes.NO_SCOPE` for a tool needing none.
    :param audience: accepted ``aud`` values, when the AS does not bind tokens
        to the resource URL.  Defaults to ``[resource]``.
    :param table_prefix: this service's SQL name prefix.
    :param service_name: the human-readable name published in the PRM document.
    :param algorithms: accepted asymmetric signing algorithms.
    :param leeway_seconds: clock-skew tolerance on ``exp``/``nbf``.
    """

    __slots__ = (
        "_resource",
        "_issuer",
        "_jwks_uri",
        "_policy",
        "_audience",
        "_tables",
        "_service_name",
        "_algorithms",
        "_leeway",
    )

    def __init__(
        self,
        *,
        resource: str,
        issuer: str,
        scopes: Any,
        tool_scopes: Mapping[str, str],
        jwks_uri: str | None = None,
        audience: Any = (),
        table_prefix: str = "mcpserver",
        service_name: str | None = None,
        algorithms: Any = ("ES256", "RS256", "EdDSA"),
        leeway_seconds: int = 300,
    ) -> None:
        resource = _normalize_url(resource, "resource")
        issuer = _normalize_url(issuer, "issuer")
        if not issuer.startswith("https://") and not _is_loopback(issuer):
            # RFC 8414 §3 requires HTTPS for the issuer.  A resource server that
            # trusts an http issuer will accept tokens anyone on the path minted.
            raise ConfigurationError(
                f"issuer {issuer!r} is not https; use http only for localhost/127.0.0.1"
            )
        if not resource.startswith("https://") and not _is_loopback(resource):
            raise ConfigurationError(
                f"resource {resource!r} is not https; the resource identifier is "
                "what a token's audience is bound to, and an http one can be "
                "swapped in transit"
            )
        self._resource = resource
        self._issuer = issuer
        self._jwks_uri = jwks_uri or issuer.rstrip("/") + "/.well-known/jwks.json"
        self._policy = ScopePolicy(
            vocabulary=scopes if isinstance(scopes, ScopeSet) else ScopeSet(scopes),
            tool_scopes=tool_scopes,
        )
        self._audience = tuple(audience) or (resource,)
        self._tables = TableNamespace(table_prefix)
        self._service_name = service_name or _default_service_name(resource)
        self._algorithms = tuple(algorithms)
        self._leeway = int(leeway_seconds)
        if not self._algorithms:
            raise ConfigurationError("at least one signing algorithm must be allowed")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ResourceServerConfig(resource={self._resource!r}, issuer={self._issuer!r})"

    # -- identity ------------------------------------------------------

    @property
    def resource(self) -> str:
        return self._resource

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def jwks_uri(self) -> str:
        return self._jwks_uri

    @property
    def audience(self) -> tuple[str, ...]:
        return self._audience

    @property
    def service_name(self) -> str:
        return self._service_name

    @property
    def algorithms(self) -> tuple[str, ...]:
        return self._algorithms

    @property
    def leeway_seconds(self) -> int:
        return self._leeway

    @property
    def policy(self) -> ScopePolicy:
        return self._policy

    @property
    def tables(self) -> TableNamespace:
        return self._tables

    @property
    def scopes_supported(self) -> tuple[str, ...]:
        return self._policy.scopes_supported

    @property
    def vocabulary(self) -> ScopeSet:
        """The closed scope vocabulary, including scopes no tool uses yet."""
        return self._policy.vocabulary

    def require_scope_for(self, tool: str) -> str | None:
        """The scope *tool* needs, or ``None``.

        ``None`` covers both "needs nothing" and "is not a public tool", and
        the enforcement middleware tells them apart by asking
        :meth:`~rhosocial.mcpserver.scopes.ScopePolicy.requires_scope` first.
        """
        return self._policy.scope_for(tool)

    def register(self, tool: str, scope: str = NO_SCOPE) -> None:
        """Declare a tool after construction.

        For services that assemble their tool list as they register handlers,
        which is the common shape.  Mutating the policy after the PRM document
        has been served would advertise a stale vocabulary, so
        :meth:`validate` is called once at startup after registration.
        """
        self._policy.add(tool, scope)

    def validate(self) -> None:
        """Re-check the configuration once all tools are registered.

        Catches a tool map that names a scope outside the vocabulary, which is
        otherwise a ``ConfigurationError`` raised on the first request that
        calls the offending tool — i.e. in production, from a client.
        """
        ScopePolicy(vocabulary=self._policy.vocabulary, tool_scopes=self._policy.as_mapping())

    # -- environment ---------------------------------------------------

    @classmethod
    def from_env(
        cls,
        prefix: str,
        *,
        scopes: Any,
        tool_scopes: Mapping[str, str],
        resource: str | None = None,
        issuer: str | None = None,
        jwks_uri: str | None = None,
        table_prefix: str | None = None,
        service_name: str | None = None,
    ) -> ResourceServerConfig:
        """Build from environment variables named ``<PREFIX>_*``.

        A token exported into the environment is readable through
        ``/proc/<pid>/environ``; a *URL* is not a secret, so environment
        variables are appropriate here and nowhere else in this library.
        """
        table = _EnvTable(prefix)
        return cls(
            resource=resource or table.require("RESOURCE"),
            issuer=issuer or table.require("ISSUER"),
            jwks_uri=jwks_uri or table.get("JWKS_URI"),
            scopes=scopes,
            tool_scopes=tool_scopes,
            table_prefix=table_prefix or table.get("TABLE_PREFIX") or "mcpserver",
            service_name=service_name or table.get("SERVICE_NAME"),
        )


def _normalize_url(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{what} is required and must be a string")
    url = value.strip()
    if "#" in url:
        # RFC 8707 §2: a resource URI MUST NOT carry a fragment, and a client
        # that sends one is sending a different resource than the one bound to
        # the token.  Rejecting it here names the mistake.
        raise ConfigurationError(f"{what} {url!r} must not contain a fragment")
    return url


def _is_loopback(url: str) -> bool:
    from urllib.parse import urlsplit

    host = (urlsplit(url).hostname or "").lower()
    return host in ("localhost", "127.0.0.1", "::1", "[::1]")


def _default_service_name(resource: str) -> str:
    """A human-readable label derived from the resource URL.

    Used in the PRM document's ``resource_name`` so a consent screen has
    something to show.  It is a label, not an identifier — nothing routes on it
    — so a human-readable form is right and a canonical URL would be worse.
    """
    from urllib.parse import urlsplit

    parsed = urlsplit(resource)
    host = parsed.hostname or "mcp"
    if parsed.port:
        host = f"{host}:{parsed.port}"
    path = parsed.path.rstrip("/")
    return f"{host}{path}" if path else host


class _EnvTable:
    """A namespaced view over ``os.environ``."""

    __slots__ = ("_prefix",)

    def __init__(self, prefix: str) -> None:
        self._prefix = prefix.rstrip("_").upper()

    def get(self, key: str) -> str | None:
        value = os.environ.get(f"{self._prefix}_{key}")
        return value.strip() if value and value.strip() else None

    def require(self, key: str) -> str:
        value = self.get(key)
        if value is None:
            raise ConfigurationError(
                f"{self._prefix}_{key} is not set. A resource server cannot verify a "
                "token without knowing which resource it is and who signed it."
            )
        return value
