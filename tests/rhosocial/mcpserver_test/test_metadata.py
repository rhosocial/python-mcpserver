# tests/rhosocial/mcpserver_test/test_metadata.py
"""The RFC 9728 document and the challenges that point at it.

Every remote MCP client — OpenCode, Cursor, Claude Code, Codex — starts an
authentication flow by reading this document.  A field that is wrong here does
not produce an error a user can see; it produces an agent that cannot be logged
in at all.
"""

from __future__ import annotations

import pytest
from conftest import ISSUER, JWKS_URI, RESOURCE

from rhosocial.mcpserver import (
    MCP_PATH,
    PRM_PATH,
    OAuthConfig,
    from_env,
    protected_resource_metadata,
    protected_resource_metadata_url,
    resource_metadata_challenge,
    scope_challenge,
)
from rhosocial.mcpserver.errors import ConfigurationError


class _Issuer:
    """The OAuth half of the document, without a verifier.

    ``protected_resource_metadata`` now takes the credential source and asks it
    where to authenticate.  A full ``JwtTokenVerifier`` would work, but these
    tests are about document *shape*, and building a cache and a key to assert
    on a dict would obscure that.
    """

    def __init__(self) -> None:
        self._oauth = OAuthConfig(issuer=ISSUER, jwks_uri=JWKS_URI)

    def metadata(self) -> dict[str, object]:
        return {
            "authorization_servers": [self._oauth.issuer],
            "jwks_uri": self._oauth.jwks_uri,
        }


@pytest.fixture
def source() -> _Issuer:
    return _Issuer()


def test_document_names_the_authorization_server_not_itself(config, source) -> None:
    """A service listing itself as the authorization server sends its clients
    to the wrong host to get a token."""
    document = protected_resource_metadata(config, source)

    assert document["authorization_servers"] == [ISSUER]
    assert document["authorization_servers"] != [RESOURCE]


def test_document_carries_the_resource_identifier(config, source) -> None:
    assert protected_resource_metadata(config, source)["resource"] == RESOURCE


def test_advertised_scopes_come_from_the_enforced_vocabulary(config, source) -> None:
    """The two lists must be the same object, or the document advertises a scope
    the server rejects and a client that trusted it gets an inexplicable 403."""
    document = protected_resource_metadata(config, source)

    assert document["scopes_supported"] == list(config.scopes_supported)
    assert set(document["scopes_supported"]) <= set(config.vocabulary)


def test_header_method_is_declared_explicitly(config, source) -> None:
    """Saying so stops a client probing the form-encoded variants RFC 6750 also
    permits but this transport does not."""
    document = protected_resource_metadata(config, source)

    assert document["bearer_methods_supported"] == ["header"]


def test_jwks_uri_is_published(config, source) -> None:
    assert protected_resource_metadata(config, source)["jwks_uri"] == JWKS_URI


def test_service_name_is_derived_from_the_resource() -> None:
    from rhosocial.mcpserver import ServiceConfig

    config = ServiceConfig(
        resource="https://calendar.example.com/mcp",
        service_name="calendar.example.com/mcp",
        scopes=["a:read"],
        tool_scopes={"r": "a:read"},
    )

    assert config.service_name == "calendar.example.com/mcp"


def test_metadata_url_is_absolute(config) -> None:
    """A client that followed a redirect has no base to resolve a relative URL
    against, so RFC 9728 §5.1 requires an absolute one.

    The URL is *not* the resource identifier with ``PRM_PATH`` appended: RFC
    9728 §3.1 inserts the suffix between the host and the path. The exact
    construction is pinned in ``test_end_to_end``; this asserts the shape.
    """
    url = protected_resource_metadata_url(config)

    assert url.startswith("https://")
    assert PRM_PATH in url
    # The resource's own path must follow the suffix, not precede it.
    assert url.index(PRM_PATH) < url.rindex("/mcp")


def test_challenge_carries_the_metadata_url(config) -> None:
    challenge = resource_metadata_challenge(config)

    assert challenge.startswith("Bearer ")
    assert 'error="invalid_token"' in challenge
    assert f'resource_metadata="{protected_resource_metadata_url(config)}"' in challenge


def test_scope_challenge_names_the_missing_scope(config) -> None:
    """A client not told which scope to ask for retries the same scope and
    fails again."""
    challenge = scope_challenge(config, "schedules:write")

    assert 'error="insufficient_scope"' in challenge
    assert 'scope="schedules:write"' in challenge
    assert f'resource_metadata="{protected_resource_metadata_url(config)}"' in challenge


def test_challenge_escapes_a_quote_in_the_scope(config) -> None:
    """An unescaped quote would split the header and let a caller inject
    challenge parameters."""
    challenge = scope_challenge(config, 'we"ird')

    assert 'scope="we\\"ird"' in challenge


def test_description_is_escaped(config) -> None:
    challenge = resource_metadata_challenge(config, description='say "hi"')

    assert 'error_description="say \\"hi\\""' in challenge


def test_an_issuer_that_is_not_https_is_refused() -> None:
    """A resource server that trusts an http issuer accepts tokens anyone on the
    path minted."""
    from rhosocial.mcpserver import OAuthConfig

    with pytest.raises(ConfigurationError, match="not https"):
        OAuthConfig(issuer="http://auth.example.com")


def test_loopback_http_is_allowed_for_development() -> None:
    from rhosocial.mcpserver import OAuthConfig

    config = OAuthConfig(issuer="http://127.0.0.1:8000")
    assert config.issuer == "http://127.0.0.1:8000"


def test_an_absolute_resource_that_is_not_https_is_refused_by_the_verifier() -> None:
    """The audience binding is the reason, and the verifier is where it applies.

    ``ServiceConfig.resource`` is only the service's public URL and may be
    relative, because a proxy owns the hostname and fills it in per request.  It
    becomes an ``aud`` value in exactly one place -- where a JWT is checked --
    and that is where a swappable-in-transit identifier has to be refused.  A
    service with its own token table has no ``aud`` to swap and is not asked for
    one.
    """
    from rhosocial.mcpserver import JwtTokenVerifier

    with pytest.raises(ConfigurationError, match="not https"):
        JwtTokenVerifier(
            jwks_cache=None,
            issuer=ISSUER,
            resource="http://calendar.example.com/mcp",
        )


def test_a_relative_resource_is_allowed() -> None:
    """Because behind a proxy it is the request's own Host, not this string."""
    from rhosocial.mcpserver import JwtTokenVerifier, ServiceConfig

    service = ServiceConfig(scopes=["a:read"], tool_scopes={"r": "a:read"})
    assert service.resource == MCP_PATH
    verifier = JwtTokenVerifier(jwks_cache=None, issuer=ISSUER, resource=service.resource)
    assert verifier is not None


def test_config_can_be_built_from_the_environment(monkeypatch, config, source) -> None:
    monkeypatch.setenv("SM_RESOURCE", RESOURCE)
    monkeypatch.setenv("SM_ISSUER", ISSUER)
    monkeypatch.setenv("SM_TABLE_PREFIX", "sm")


    service, oauth = from_env(
        "SM", scopes=["a:read"], tool_scopes={"r": "a:read"}
    )

    assert service.resource == RESOURCE
    assert oauth.issuer == ISSUER


def test_missing_environment_variable_names_itself(monkeypatch) -> None:

    monkeypatch.delenv("SM_RESOURCE", raising=False)
    monkeypatch.setenv("SM_ISSUER", ISSUER)

    with pytest.raises(ConfigurationError, match="SM_RESOURCE"):
        from_env("SM", scopes=["a:read"], tool_scopes={"r": "a:read"})


def test_validate_accepts_a_consistent_config(config) -> None:
    config.validate()


def test_validate_catches_a_tool_added_with_an_unknown_scope(config) -> None:
    config.policy._tool_scopes["sneaky"] = "not:in:vocabulary"

    with pytest.raises(ConfigurationError, match="outside the vocabulary"):
        config.validate()
