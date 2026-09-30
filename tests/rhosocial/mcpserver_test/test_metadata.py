# tests/rhosocial/mcpserver_test/test_metadata.py
"""The RFC 9728 document and the challenges that point at it.

Every remote MCP client — OpenCode, Cursor, Claude Code, Codex — starts an
authentication flow by reading this document.  A field that is wrong here does
not produce an error a user can see; it produces an agent that cannot be logged
in at all.
"""

from __future__ import annotations

import pytest
from conftest import ISSUER, RESOURCE

from rhosocial.mcpserver import (
    PRM_PATH,
    protected_resource_metadata,
    protected_resource_metadata_url,
    resource_metadata_challenge,
    scope_challenge,
)
from rhosocial.mcpserver.errors import ConfigurationError


def test_document_names_the_authorization_server_not_itself(config) -> None:
    """A service listing itself as the authorization server sends its clients
    to the wrong host to get a token."""
    document = protected_resource_metadata(config)

    assert document["authorization_servers"] == [ISSUER]
    assert document["authorization_servers"] != [RESOURCE]


def test_document_carries_the_resource_identifier(config) -> None:
    assert protected_resource_metadata(config)["resource"] == RESOURCE


def test_advertised_scopes_come_from_the_enforced_vocabulary(config) -> None:
    """The two lists must be the same object, or the document advertises a scope
    the server rejects and a client that trusted it gets an inexplicable 403."""
    document = protected_resource_metadata(config)

    assert document["scopes_supported"] == list(config.scopes_supported)
    assert set(document["scopes_supported"]) <= set(config.vocabulary)


def test_header_method_is_declared_explicitly(config) -> None:
    """Saying so stops a client probing the form-encoded variants RFC 6750 also
    permits but this transport does not."""
    document = protected_resource_metadata(config)

    assert document["bearer_methods_supported"] == ["header"]


def test_jwks_uri_is_published(config) -> None:
    assert protected_resource_metadata(config)["jwks_uri"] == config.jwks_uri


def test_service_name_is_derived_from_the_resource() -> None:
    from rhosocial.mcpserver import ResourceServerConfig

    config = ResourceServerConfig(
        resource="https://calendar.example.com/mcp",
        issuer=ISSUER,
        scopes=["a:read"],
        tool_scopes={"r": "a:read"},
        table_prefix="sm",
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


def test_plain_http_is_refused() -> None:
    """The resource identifier is what a token's audience is bound to; an http
    one can be swapped in transit."""
    from rhosocial.mcpserver import ResourceServerConfig

    with pytest.raises(ConfigurationError, match="not https"):
        ResourceServerConfig(
            resource="http://calendar.example.com/mcp",
            issuer=ISSUER,
            scopes=["a:read"],
            tool_scopes={"r": "a:read"},
        )


def test_plain_http_issuer_is_refused() -> None:
    from rhosocial.mcpserver import ResourceServerConfig

    with pytest.raises(ConfigurationError, match="not https"):
        ResourceServerConfig(
            resource=RESOURCE,
            issuer="http://auth.example.com",
            scopes=["a:read"],
            tool_scopes={"r": "a:read"},
        )


def test_loopback_http_is_allowed_for_development() -> None:
    from rhosocial.mcpserver import ResourceServerConfig

    config = ResourceServerConfig(
        resource="http://127.0.0.1:8000/mcp",
        issuer="http://localhost:9000",
        scopes=["a:read"],
        tool_scopes={"r": "a:read"},
    )

    assert config.jwks_uri == "http://localhost:9000/.well-known/jwks.json"


def test_resource_with_a_fragment_is_refused() -> None:
    """RFC 8707 §2: a resource URI must not carry a fragment, so a client that
    sends one is asking for a different resource than the token is bound to."""
    from rhosocial.mcpserver import ResourceServerConfig

    with pytest.raises(ConfigurationError, match="fragment"):
        ResourceServerConfig(
            resource="https://calendar.example.com/mcp#frag",
            issuer=ISSUER,
            scopes=["a:read"],
            tool_scopes={"r": "a:read"},
        )


def test_config_can_be_built_from_the_environment(monkeypatch, config) -> None:
    monkeypatch.setenv("SM_RESOURCE", RESOURCE)
    monkeypatch.setenv("SM_ISSUER", ISSUER)
    monkeypatch.setenv("SM_TABLE_PREFIX", "sm")

    from rhosocial.mcpserver import ResourceServerConfig

    built = ResourceServerConfig.from_env(
        "SM", scopes=["a:read"], tool_scopes={"r": "a:read"}
    )

    assert built.resource == RESOURCE
    assert built.tables.prefix == "sm"


def test_missing_environment_variable_names_itself(monkeypatch) -> None:
    from rhosocial.mcpserver import ResourceServerConfig

    monkeypatch.delenv("SM_RESOURCE", raising=False)
    monkeypatch.setenv("SM_ISSUER", ISSUER)

    with pytest.raises(ConfigurationError, match="SM_RESOURCE is not set"):
        ResourceServerConfig.from_env("SM", scopes=["a:read"], tool_scopes={"r": "a:read"})


def test_validate_accepts_a_consistent_config(config) -> None:
    config.validate()


def test_validate_catches_a_tool_added_with_an_unknown_scope(config) -> None:
    config.policy._tool_scopes["sneaky"] = "not:in:vocabulary"

    with pytest.raises(ConfigurationError, match="outside the vocabulary"):
        config.validate()
