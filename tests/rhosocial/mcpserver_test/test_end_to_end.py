# tests/rhosocial/mcpserver_test/test_end_to_end.py
"""A real MCP server behind the real stack, driven by real HTTP.

Every other test drives one layer with a stub for the layer inside it.  This
one builds an ``MCPServer``, wraps it with :func:`build_mcp_app`, and talks to
it over HTTP with the MCP SDK's own client — because a mistake in the wiring
*between* layers is exactly the kind that no unit test can see: each piece is
correct in isolation and the assembled thing is unreachable.

What it pins down:

* the 401 carries the ``resource_metadata`` challenge, without which discovery
  cannot start and an agent cannot be logged in at all;
* the PRM document an agent reads names the real scope vocabulary, not the
  SDK's empty one — the SDK derives its own from ``required_scopes``, which is
  deliberately empty here;
* a read-only token reaches the read tool and is refused 403 on the write tool,
  naming the missing scope;
* a token minted for another resource is refused — ``aud``, not a table prefix,
  is what separates two services;
* an unlisted tool is refused, so a client that disagrees with the server cannot
  make it act.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx2
import pytest
from asgi_lifespan import LifespanManager
from conftest import ISSUER, RESOURCE, FakeJwks
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from rhosocial.mcpserver import (
    NO_SCOPE,
    JwksCache,
    JwtTokenVerifier,
    ResourceServerConfig,
    auth_settings,
    build_mcp_app,
    current_principal,
)

ACCEPT = "application/json, text/event-stream"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def make_config() -> ResourceServerConfig:
    return ResourceServerConfig(
        resource=RESOURCE,
        issuer=ISSUER,
        scopes=["notes:read", "notes:write"],
        tool_scopes={
            "whoami": NO_SCOPE,
            "list_notes": "notes:read",
            "add_note": "notes:write",
        },
        table_prefix="t",
    )


@pytest.fixture
def app(fake_jwks: FakeJwks, clock) -> Any:
    """The wired application, with the JWKS served in-process."""
    from contextlib import asynccontextmanager

    config = make_config()
    cache = JwksCache(config.jwks_uri, fetch=fake_jwks.fetch, clock=clock)
    verifier = JwtTokenVerifier(
        cache,
        issuer=config.issuer,
        resource=config.resource,
        scope_set=config.policy.vocabulary,
    )
    notes: list[str] = []

    server = MCPServer(
        name="notes",
        version="0.1.0",
        auth=auth_settings(config),
        token_verifier=verifier,
    )

    @asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncIterator[dict[str, list[str]]]:
        # Warm the key cache on boot.  Not a test convenience: without it the
        # first request of every replica pays the fetch, and on a cold AS that
        # is the request most likely to time out.
        try:
            await cache.prefetch()
        except Exception:  # pragma: no cover - the first lookup retries anyway
            pass
        yield {"notes": notes}

    server.lifespan = lifespan

    @server.tool(description="List note titles.")
    async def list_notes() -> list[str]:
        return notes

    @server.tool(description="Add a note.")
    async def add_note(title: str) -> str:
        notes.append(title)
        return f"added {title}"

    @server.tool(description="Say who is calling.")
    async def whoami() -> str:
        return current_principal().central_user_id

    return build_mcp_app(
        server,
        config=config,
        verifier=verifier,
        # Stateless so each request stands alone; a stateful session would hold
        # the SSE stream open and change nothing these tests are about.
        stateless_http=True,
        json_response=True,
        # These tools use `current_principal` but no owned model, so there is no
        # projection table to resolve.  The default path is exercised in
        # `test_the_default_path_requires_a_registered_projection`.
        resolve_projection=False,
        # What a real deployment on a hostname has to do: the SDK only disables
        # its DNS-rebinding protection automatically for a loopback bind, so a
        # service behind a proxy that rewrites Host must name its own host or
        # every request is refused as a rebinding attempt.
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["calendar.example.com"],
            allowed_origins=["https://calendar.example.com"],
        ),
    )


@pytest.fixture
def no_projection():
    """Clear the process-global projection registration for the duration.

    ``register_projection`` is process state by design — a process serves one
    service, so there is exactly one answer — which means the ORM tests leave
    theirs registered and every later test would inherit it.  Reached for
    directly rather than through a library helper: the inverse of a documented
    invariant is not API, it is a test's problem.
    """
    from rhosocial.mcpserver.orm import principal as module

    saved = module._projection_model
    module._projection_model = None
    try:
        yield
    finally:
        module._projection_model = saved


def client_for(app: Any, token: str | None = None) -> httpx2.AsyncClient:
    headers = {"accept": ACCEPT, "content-type": "application/json"}
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        # The Host must be the resource's own host, or the SDK's DNS-rebinding
        # protection rejects it — which is the correct behaviour and a useful
        # reminder that a proxy rewriting Host needs an explicit allowlist.
        base_url=RESOURCE.rsplit("/mcp", 1)[0],
        headers=headers,
        follow_redirects=True,
    )


def rpc(method: str, params: Any = None) -> dict[str, Any]:
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    return body


def call(name: str, arguments: Any = None) -> dict[str, Any]:
    return rpc("tools/call", {"name": name, "arguments": arguments or {}})


# -- discovery -----------------------------------------------------------


async def test_the_401_carries_the_discovery_challenge(app) -> None:
    """Without ``resource_metadata`` a client has nothing to follow."""
    async with LifespanManager(app), client_for(app) as client:
        response = await client.post("/mcp", json=rpc("tools/list"))

    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert "invalid_token" in challenge
    assert "/.well-known/oauth-protected-resource" in challenge


async def test_the_prm_document_names_the_real_vocabulary(app) -> None:
    """The SDK builds its own document from ``required_scopes``, which is empty
    by design.  Ours is generated from the enforced vocabulary and is the one a
    client reaches, so a drift between them would be invisible from the SDK."""
    async with LifespanManager(app), client_for(app) as client:
        response = await client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    document = response.json()
    assert document["resource"] == RESOURCE
    assert document["authorization_servers"] == [ISSUER]
    assert document["scopes_supported"] == ["notes:read", "notes:write"]


async def test_the_health_probe_is_unauthenticated(app) -> None:
    async with LifespanManager(app), client_for(app) as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# -- the scope decision --------------------------------------------------


async def test_a_read_only_token_reaches_the_read_tool(app, signing_key) -> None:
    """The whole reason ``required_scopes`` is empty: an agent's credential is
    usually read-only, and the SDK's all-or-nothing rule would refuse it from the
    reads too."""
    token = signing_key.sign(scope="notes:read")
    async with LifespanManager(app), client_for(app, token) as client:
        response = await client.post("/mcp", json=call("list_notes"))

    assert response.status_code == 200, response.text
    assert "result" in json.loads(response.text)


async def test_a_read_only_token_is_refused_the_write_tool(app, signing_key) -> None:
    token = signing_key.sign(scope="notes:read")
    async with LifespanManager(app), client_for(app, token) as client:
        response = await client.post("/mcp", json=call("add_note", {"title": "x"}))

    assert response.status_code == 403
    challenge = response.headers["www-authenticate"]
    assert 'error="insufficient_scope"' in challenge
    assert 'scope="notes:write"' in challenge


async def test_whoami_needs_no_scope(app, signing_key) -> None:
    """A token with no grants at all must still be able to find out who it is."""
    token = signing_key.sign(scope="")
    async with LifespanManager(app), client_for(app, token) as client:
        response = await client.post("/mcp", json=call("whoami"))

    assert response.status_code == 200, response.text
    text = response.text
    assert "u-123" in text


async def test_an_unlisted_tool_is_refused(app, signing_key) -> None:
    token = signing_key.sign(scope="notes:read notes:write")
    async with LifespanManager(app), client_for(app, token) as client:
        response = await client.post("/mcp", json=call("drop_everything"))

    assert response.status_code == 403


# -- the credential decisions -------------------------------------------


async def test_a_token_for_another_resource_is_refused(app, signing_key) -> None:
    """``aud`` is what separates two services."""
    token = signing_key.sign(scope="notes:read", audience="https://finance.example.com/mcp")
    async with LifespanManager(app), client_for(app, token) as client:
        response = await client.post("/mcp", json=call("list_notes"))

    assert response.status_code == 401
    assert "invalid_token" in response.headers["www-authenticate"]


async def test_an_expired_token_is_refused(app, signing_key) -> None:
    token = signing_key.sign(scope="notes:read", issued_ago=4000, expires_in=5)
    async with LifespanManager(app), client_for(app, token) as client:
        response = await client.post("/mcp", json=call("list_notes"))

    assert response.status_code == 401


async def test_a_token_from_another_issuer_is_refused(app, signing_key) -> None:
    token = signing_key.sign(scope="notes:read", issuer="https://evil.example.com")
    async with LifespanManager(app), client_for(app, token) as client:
        response = await client.post("/mcp", json=call("list_notes"))

    assert response.status_code == 401


# -- the SDK's own client ------------------------------------------------


async def test_a_real_client_completes_the_flow(app, signing_key) -> None:
    """The MCP SDK's client, not a hand-written request.

    This is the one that catches a mismatch between what the server publishes
    and what a client expects — the class of bug where every individual test
    passes and no agent can connect.
    """
    token = signing_key.sign(scope="notes:read notes:write")
    async with LifespanManager(app):
        async with client_for(app, token) as http:
            async with streamable_http_client(f"{RESOURCE}", http_client=http) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    assert {t.name for t in listed.tools} >= {"list_notes", "add_note"}

                    result = await session.call_tool("add_note", {"title": "hello"})
                    assert "added hello" in str(result.content[0].text)  # type: ignore[union-attr]

                    listed = await session.call_tool("list_notes")
                    assert "hello" in str(listed.content[0].text)  # type: ignore[union-attr]


async def test_a_real_client_sees_a_read_only_token_limited(app, signing_key) -> None:
    """The same client, refused the write — with a 403 rather than a JSON-RPC
    error inside a 200, which is the failure mode per-tool enforcement exists
    to avoid."""
    token = signing_key.sign(scope="notes:read")
    with pytest.raises(Exception) as caught:
        async with LifespanManager(app):
            async with client_for(app, token) as http:
                async with streamable_http_client(f"{RESOURCE}", http_client=http) as (r, w):
                    async with ClientSession(r, w) as session:
                        await session.initialize()
                        await session.call_tool("add_note", {"title": "x"})

    # The client surfaces the refusal as an error rather than as a tool result.
    # It cannot report the missing scope — that is in the 403's
    # `WWW-Authenticate`, which the raw-HTTP test above asserts directly.
    nested = [
        e
        for group in getattr(caught.value, "exceptions", (caught.value,))
        for e in getattr(group, "exceptions", (group,))
    ]
    assert any("error" in str(e).lower() for e in nested), nested

# -- the guards ----------------------------------------------------------


async def test_the_default_path_requires_a_registered_projection(
    fake_jwks, clock, signing_key, no_projection
) -> None:
    """The default resolves the projection, and nothing is registered here.

    So a service that forgot ``register_as_projection()`` gets a 503 — a loud,
    retryable failure — instead of queries with no ownership predicate, which
    would look like it worked.
    """
    config = make_config()
    verifier = JwtTokenVerifier(
        JwksCache(config.jwks_uri, fetch=fake_jwks.fetch, clock=clock),
        issuer=config.issuer,
        resource=config.resource,
    )
    server = MCPServer(
        name="notes", auth=auth_settings(config), token_verifier=verifier
    )

    @server.tool(description="List notes.")
    async def list_notes() -> list[str]:
        return []

    app = build_mcp_app(
        server,
        config=config,
        verifier=verifier,
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            allowed_hosts=["calendar.example.com"],
            allowed_origins=["https://calendar.example.com"],
        ),
    )
    token = signing_key.sign(scope="notes:read")
    async with LifespanManager(app), client_for(app, token) as client:
        response = await client.post("/mcp", json=call("list_notes"))

    assert response.status_code == 503
    assert response.json()["error"] == "unavailable"


def test_build_mcp_app_refuses_an_unauthenticated_server(fake_jwks, clock) -> None:
    """An ``MCPServer`` built without auth serves every tool to every caller and
    says nothing.  That is not worth discovering in production."""
    from rhosocial.mcpserver import ConfigurationError

    config = make_config()
    verifier = JwtTokenVerifier(
        JwksCache(config.jwks_uri, fetch=fake_jwks.fetch, clock=clock),
        issuer=config.issuer,
        resource=config.resource,
    )

    with pytest.raises(ConfigurationError, match="no auth settings"):
        build_mcp_app(MCPServer(name="notes"), config=config, verifier=verifier)


async def test_an_unknown_path_is_passed_through(app) -> None:
    """The outermost layer claims only the two endpoints it owns."""
    async with LifespanManager(app), client_for(app) as client:
        response = await client.get("/not-a-route")

    assert response.status_code == 404


async def test_an_oversized_body_is_refused(app, signing_key) -> None:
    """The SDK's cap runs after this layer, so without one here an
    unauthenticated caller could make the process buffer anything."""
    token = signing_key.sign(scope="notes:read")
    async with LifespanManager(app), client_for(app, token) as client:
        response = await client.post("/mcp", content=b"x" * 200_000)

    assert response.status_code == 413
