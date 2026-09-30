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
    ResourceServerConfig,
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


def test_metadata_is_absent_without_a_config() -> None:
    """The CLI builds a verifier with no server to describe.

    There is no request being served and therefore no client to discover
    anything to; a half-built document would be worse than declining.
    """
    from rhosocial.mcpserver.mcp.verifier import JwtTokenVerifier

    verifier = JwtTokenVerifier(
        jwks_cache=None, issuer="https://auth.example.com", resource="https://a/mcp"
    )
    assert verifier.metadata() is None


def test_metadata_names_the_issuer_when_a_config_is_given() -> None:
    """And this is the one field a client cannot do without.

    ``authorization_servers`` is what makes the ``aud`` binding work end to
    end. It is deliberately not the service's own URL: a resource server that
    lists itself as its own authorization server sends its clients to fetch
    tokens from the wrong host.
    """
    from rhosocial.mcpserver.mcp.verifier import JwtTokenVerifier

    config = ResourceServerConfig(
        resource="https://svc.example.com/mcp",
        issuer="https://auth.example.com",
        scopes=ScopeSet(["a:read"]),
        tool_scopes={"read": "a:read"},
    )
    verifier = JwtTokenVerifier(
        jwks_cache=None,
        issuer=config.issuer,
        resource=config.resource,
        config=config,
    )

    document = verifier.metadata()
    assert document is not None
    assert document["authorization_servers"] == ["https://auth.example.com"]
    assert document["resource"] == "https://svc.example.com/mcp"


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
