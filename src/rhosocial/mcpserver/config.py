# src/rhosocial/mcpserver/config.py
"""Two configurations, because they answer two different questions.

:class:`ServiceConfig` is what *this service protects*: its tool-to-scope
mapping, its closed scope vocabulary, its name.  None of that is OAuth, and all
of it stays true whatever transport a request arrived on.

:class:`OAuthConfig` is what a *JWT credential source* needs in order to check
one: who signs it, what it is bound to, which algorithms are acceptable.  A
service that issues and checks its own tokens has no issuer and no ``aud``, and
making it supply both would mean writing a field that is a lie in order to get
past a constructor.

They were one class until a service with its own ``api_tokens`` table needed
them apart.  The single class was not wrong so much as dishonest: ``resource``
was simultaneously the RFC 8707 identifier, the ``aud`` default and the source of
the default service name, and the first two of those do not exist for a
credential the service minted itself.

``enforce_protocol_revision`` is not here either.  It gates the MCP 2026-07-28
handshake, so it belongs to the MCP assembly rather than to either of these, and
it is a parameter of :func:`~rhosocial.mcpserver.mcp.app.build_mcp_app`.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .errors import ConfigurationError
from .scopes import NO_SCOPE, ScopePolicy, ScopeSet

__all__ = [
    "ServiceConfig",
    "OAuthConfig",
    "PRM_PATH",
    "MCP_PATH",
    "HEALTH_PATH",
    "from_env",
]

#: RFC 9728 §3.  Also the URL an MCP client fetches after a 401's
#: ``resource_metadata`` challenge, so the path is part of the contract and not
#: a routing preference.
PRM_PATH = "/.well-known/oauth-protected-resource"

#: Where the MCP endpoint is mounted.  The default matches every service built
#: on this library so far, and the resource indicator defaults to it.
MCP_PATH = "/mcp"

HEALTH_PATH = "/healthz"


class ServiceConfig:
    """What this service exposes and who may call it.  Transport-agnostic.

    :param scopes: the closed scope vocabulary.
    :param tool_scopes: tool name → required scope, or
        :data:`~rhosocial.mcpserver.scopes.NO_SCOPE` for a tool needing none.
    :param resource: the absolute URL a client dials, including the MCP path.
        It is *not* the container's internal address: a proxy that rewrites
        ``Host`` would otherwise produce a URL no client ever asked for.  Used
        as the base for the discovery document's own URL, and as the default
        ``aud`` for a JWT source.
    :param service_name: the human-readable name published in the discovery
        document.
    """

    __slots__ = ("_policy", "_service_name", "_resource")

    def __init__(
        self,
        *,
        scopes: Any,
        tool_scopes: Mapping[str, str],
        resource: str = MCP_PATH,
        service_name: str | None = None,
    ) -> None:
        self._policy = ScopePolicy(
            vocabulary=scopes if isinstance(scopes, ScopeSet) else ScopeSet(scopes),
            tool_scopes=tool_scopes,
        )
        self._resource = resource
        self._service_name = service_name

    @property
    def resource(self) -> str:
        """The service's public URL, relative or absolute.

        Relative is allowed and normal for a service that sits behind a proxy
        which owns the hostname: the discovery URL is then derived from the
        request's own ``Host``, which is the only host a client actually dialled.
        """
        return self._resource

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ServiceConfig(service_name={self._service_name!r})"

    @property
    def service_name(self) -> str | None:
        """The published name, or ``None`` to let it be derived elsewhere.

        ``None`` is a real answer rather than a missing one: a service behind a
        path-suffixed proxy may have no single name worth publishing, and a
        derived one would be wrong in a way nobody notices.
        """
        return self._service_name

    @property
    def policy(self) -> ScopePolicy:
        return self._policy

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
        which is the common shape.  Mutating the policy after the discovery
        document has been served would advertise a stale vocabulary, so
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


class OAuthConfig:
    """What verifying a JWT requires.  Meaningless without an issuer.

    :param issuer: the authorization server whose signatures are trusted.
    :param jwks_uri: where its keys are published.  Derived from *issuer* when
        not given, which is the overwhelmingly common layout.
    :param audience: accepted ``aud`` values, when the AS does not bind tokens
        to the service's resource URL.  Left empty here and supplied by the
        verifier, which is the only object that knows the resource URL.
    :param algorithms: accepted asymmetric signing algorithms.
    :param leeway_seconds: clock-skew tolerance for ``exp``/``nbf``.
    """

    __slots__ = (
        "_issuer",
        "_jwks_uri",
        "_audience",
        "_algorithms",
        "_leeway",
    )

    #: The one algorithm list that is safe against a JWKS.  ``HS*`` is refused
    #: elsewhere too, and a list a service can extend with a symmetric algorithm
    #: would make that refusal decorative.
    DEFAULT_ALGORITHMS = ("ES256", "RS256", "EdDSA")

    def __init__(
        self,
        *,
        issuer: str,
        jwks_uri: str | None = None,
        audience: Any = (),
        algorithms: Any = DEFAULT_ALGORITHMS,
        leeway_seconds: int = 300,
    ) -> None:
        issuer = _normalize_url(issuer, "issuer")
        if not issuer.startswith("https://") and not _is_loopback(issuer):
            # RFC 8414 §3 requires HTTPS for the issuer.  A resource server that
            # trusts an http issuer will accept tokens anyone on the path minted.
            raise ConfigurationError(
                f"issuer {issuer!r} is not https; use http only for localhost/127.0.0.1"
            )
        self._issuer = issuer
        self._jwks_uri = jwks_uri or issuer.rstrip("/") + "/.well-known/jwks.json"
        self._audience = tuple(audience)
        self._algorithms = tuple(algorithms)
        self._leeway = int(leeway_seconds)
        if not self._algorithms:
            raise ConfigurationError("at least one signing algorithm must be allowed")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"OAuthConfig(issuer={self._issuer!r})"

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
    def algorithms(self) -> tuple[str, ...]:
        return self._algorithms

    @property
    def leeway_seconds(self) -> int:
        return self._leeway


def _normalize_url(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{what} is required and must be a URL string")
    return value.strip().rstrip("/")


def _is_loopback(url: str) -> bool:
    return any(host in url for host in ("localhost", "127.0.0.1", "[::1]"))


def from_env(
    prefix: str,
    *,
    scopes: Any,
    tool_scopes: Mapping[str, str],
    resource: str | None = None,
    issuer: str | None = None,
    jwks_uri: str | None = None,
    service_name: str | None = None,
) -> tuple[ServiceConfig, OAuthConfig]:
    """Build both configurations from environment variables named ``<PREFIX>_*``.

    A token exported into the environment is readable through
    ``/proc/<pid>/environ``; a *URL* is not a secret, so environment variables
    are appropriate here and nowhere else in this library.

    Returned as a pair because the two are independent: a service with its own
    token table takes the :class:`ServiceConfig` and ignores the rest, which is
    the reason the pair exists.
    """
    table = _EnvTable(prefix)
    return (
        ServiceConfig(
            scopes=scopes,
            tool_scopes=tool_scopes,
            resource=resource or table.require("RESOURCE"),
            service_name=service_name or table.get("SERVICE_NAME"),
        ),
        OAuthConfig(
            issuer=issuer or table.require("ISSUER"),
            jwks_uri=jwks_uri or table.get("JWKS_URI"),
        ),
    )


class _EnvTable:
    def __init__(self, prefix: str) -> None:
        self._prefix = prefix.rstrip("_").upper()

    def get(self, key: str) -> str | None:
        import os

        return os.environ.get(f"{self._prefix}_{key}") or None

    def require(self, key: str) -> str:
        value = self.get(key)
        if not value:
            raise ConfigurationError(
                f"{self._prefix}_{key} is required; set it in the environment or "
                "pass it explicitly"
            )
        return value
