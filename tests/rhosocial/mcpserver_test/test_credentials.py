# tests/rhosocial/mcpserver_test/test_credentials.py
"""What a credential source has to be able to do, and what it must not have to.

The point of the protocol is that a service's own token table and a JWKS
verify are interchangeable. These tests pin the two properties that make that
true: a source needs nothing but ``verify`` and ``metadata``, and the SDK
adaptation is shared rather than reimplemented per source.
"""

from __future__ import annotations

from typing import Any

import pytest

from rhosocial.mcpserver import (
    SELF_ISSUED,
    CredentialSource,
    Principal,
    ServiceConfig,
    resolve_for_sdk,
)
from rhosocial.mcpserver.config import ScopePolicy
from rhosocial.mcpserver.scopes import ScopeSet


class _TableSource:
    """What a service with its own ``api_tokens`` table writes.

    Deliberately defined without inheriting anything, and holding no
    connection: it is handed one callable and knows nothing about the schema
    behind it. If satisfying the protocol required a base class or a config
    object, this would not compile.
    """

    def __init__(self, users: dict[str, str]) -> None:
        self._users = users
        self.seen: list[str] = []

    async def verify(self, token: str) -> Principal | None:
        self.seen.append(token)
        subject = self._users.get(token)
        if subject is None:
            return None
        return Principal(central_user_id=subject, client_id=SELF_ISSUED)

    def metadata(self) -> dict[str, Any] | None:
        return None  # issues and checks its own tokens; nothing to discover


def test_a_plain_object_satisfies_the_protocol() -> None:
    """Structural, not nominal: nothing to subclass, nothing to register."""
    assert isinstance(_TableSource({}), CredentialSource)


def test_a_source_needs_no_configuration_object() -> None:
    """The interface is two methods, not a constructor contract.

    A source that had to be handed a config, a connection or a registry to
    satisfy the protocol would be a source that knows this library's internals,
    and adding a second transport would mean adding a second set of internals
    to hand it.
    """
    source = _TableSource({"good": "alice"})

    assert isinstance(source, CredentialSource)
    assert set(CredentialSource.__protocol_attrs__ if hasattr(
        CredentialSource, "__protocol_attrs__"
    ) else {"verify", "metadata"}) == {"verify", "metadata"}


@pytest.mark.anyio
async def test_a_known_token_resolves_and_an_unknown_one_is_none() -> None:
    """The two failure shapes, kept apart.

    ``None`` for "not a credential" and an exception for "a credential that is
    wrong" is what lets a transport answer 401 for a stale token and 500 for a
    genuine fault, instead of collapsing both into a 401 the operator then has
    to read logs to explain.
    """
    source = _TableSource({"tok_alice": "alice"})

    assert await source.verify("tok_alice") == Principal("alice", SELF_ISSUED)
    assert await source.verify("tok_nobody") is None
    assert source.seen == ["tok_alice", "tok_nobody"]


@pytest.mark.anyio
async def test_the_sdk_adapter_works_for_any_source() -> None:
    """The adaptation lives in one place, not one per source.

    A second implementation that forgot the verified-memo would verify every
    token twice per request; one that forgot the ``None`` contract would answer
    500. Both are cheap to write and expensive to find, so the shared helper is
    what the middleware calls.
    """
    source = _TableSource({"tok_alice": "alice"})

    record = await resolve_for_sdk(source, "tok_alice")
    assert record is not None
    assert record.subject == "alice"

    assert await resolve_for_sdk(source, "tok_nobody") is None


def test_a_source_may_declare_no_discovery_document() -> None:
    """``None`` means "nowhere else to authenticate", which is a real answer.

    A service whose tokens it issues itself has no authorization server for a
    client to find, and an empty document would send it looking.
    """
    assert _TableSource({}).metadata() is None


def test_a_jwt_verifier_is_a_credential_source() -> None:
    from rhosocial.mcpserver.mcp.verifier import JwtTokenVerifier

    verifier = JwtTokenVerifier(
        jwks_cache=None, issuer="https://auth.example.com", resource="https://a/mcp"
    )
    assert isinstance(verifier, CredentialSource)


def test_a_jwt_verifier_advertises_only_its_own_half() -> None:
    """The OAuth half comes from the source; the rest is the service's.

    ``resource`` and ``scopes_supported`` are deliberately absent here. They are
    the service's own facts, and a document that took them from the credential
    source would be one that could publish a scope vocabulary nobody enforces.
    """
    from rhosocial.mcpserver.mcp.verifier import JwtTokenVerifier

    verifier = JwtTokenVerifier(
        jwks_cache=None, issuer="https://auth.example.com", resource="https://a/mcp"
    )

    advertised = verifier.metadata()
    assert advertised["authorization_servers"] == ["https://auth.example.com"]
    assert "resource" not in advertised
    assert "scopes_supported" not in advertised


def test_the_composed_document_names_the_issuer() -> None:
    """And this is the one field a client cannot do without.

    ``authorization_servers`` is what makes the ``aud`` binding work end to
    end. It is deliberately not the service's own URL: a resource server that
    lists itself as its own authorization server sends its clients to fetch
    tokens from the wrong host.
    """
    from rhosocial.mcpserver.mcp.metadata import protected_resource_metadata
    from rhosocial.mcpserver.mcp.verifier import JwtTokenVerifier

    service = ServiceConfig(
        resource="https://svc.example.com/mcp",
        scopes=ScopeSet(["a:read"]),
        tool_scopes={"read": "a:read"},
    )
    verifier = JwtTokenVerifier(
        jwks_cache=None, issuer="https://auth.example.com", resource=service.resource
    )

    document = protected_resource_metadata(service, verifier)
    assert document is not None
    assert document["authorization_servers"] == ["https://auth.example.com"]
    assert document["resource"] == "https://svc.example.com/mcp"
    assert document["scopes_supported"] == ["a:read"]


def test_a_service_with_its_own_tokens_publishes_nothing() -> None:
    """The gap this split exists to close.

    Before it, ``protected_resource_metadata`` took one config and always
    returned a document -- so a service checking tokens from its own table
    answered the well-known path with an ``authorization_servers`` entry
    pointing at an issuer that does not exist, sending a client off to
    authenticate against nothing.  ``None`` makes that a 404, which is a fact a
    client can act on.
    """
    from rhosocial.mcpserver.mcp.metadata import protected_resource_metadata

    service = ServiceConfig(
        resource="https://svc.example.com/mcp",
        scopes=ScopeSet(["a:read"]),
        tool_scopes={"read": "a:read"},
    )

    assert protected_resource_metadata(service) is None
    assert protected_resource_metadata(service, _TableSource({})) is None
    assert protected_resource_metadata(service, _TableSource({"t": "alice"})) is None


def test_self_issued_is_not_an_empty_client_id() -> None:
    """An empty string reads as a client that failed to identify itself.

    That is a different event from "there is no client", and the two want to
    look different in a log line read six months later.
    """
    assert SELF_ISSUED
    assert SELF_ISSUED.strip()


def test_scope_policy_stays_out_of_the_protocol() -> None:
    """What a tool requires and how a credential arrived are separate answers.

    If ``scopes`` were part of the source's contract, then changing a tool's
    required scope would mean changing how the service authenticates, and the
    two would start being versioned together for no reason.
    """
    policy = ScopePolicy(vocabulary=ScopeSet(["a:read"]), tool_scopes={"read": "a:read"})
    assert policy.missing("read", frozenset()) == "a:read"
    assert policy.missing("read", frozenset({"a:read"})) is None


@pytest.mark.anyio
async def test_a_service_with_its_own_tokens_serves_no_discovery_document() -> None:
    """The 404, proven through the endpoint rather than the builder.

    ``protected_resource_metadata`` returning ``None`` is only half a claim. What
    matters is that a client gets a 404: a document missing its required
    ``authorization_servers`` would be worse than nothing, because a client
    would treat it as an authorization server being temporarily unavailable and
    retry, instead of concluding there is nothing to discover.
    """
    from rhosocial.mcpserver import PRM_PATH, ServiceConfig
    from rhosocial.mcpserver.mcp.middleware import ResourceEndpoints

    status: list[int] = []

    async def send(message: dict) -> None:
        if message["type"] == "http.response.start":
            status.append(message["status"])

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    app = ResourceEndpoints(
        ServiceConfig(
            resource="https://svc.example.com/mcp",
            scopes=ScopeSet(["a:read"]),
            tool_scopes={"read": "a:read"},
        ),
        source=_TableSource({"tok": "alice"}),
    )
    await app(
        {
            "type": "http",
            "method": "GET",
            "path": PRM_PATH,
            "headers": [(b"host", b"svc.example.com")],
        },
        receive,
        send,
    )

    assert status == [404]
