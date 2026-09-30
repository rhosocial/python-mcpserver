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
    PROTOCOL_REVISION,
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
#
# `ClientSession.initialize()` is the *legacy* handshake, which revision
# 2026-07-28 deleted.  These two tests are kept because the SDK's high-level
# client is still the most likely thing an agent actually speaks, so a
# regression here is a real outage — but they no longer describe the transport
# this library targets.  The 2026-07-28 shape is pinned further down.


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


# -- protocol revision 2026-07-28 -----------------------------------------
#
# Everything above drives the SDK's client through `session.initialize()`,
# which is the *legacy* handshake.  Revision 2026-07-28 deleted it, along with
# protocol-level sessions, the `Mcp-Session-Id` header and the standalone GET
# stream.  These tests therefore talk raw HTTP and send the request shape a
# 2026-07-28 client actually sends, so the modern path is covered rather than
# incidentally exercised.
#
# If the SDK ever stops accepting these, the library's transport support is
# what broke -- not an accident in a test.

PROTOCOL_VERSION = PROTOCOL_REVISION

#: SEP-2575: version and client capabilities ride in `_meta`, since there is no
#: longer a handshake whose result could carry them.
MODERN_META = {
    "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
    "io.modelcontextprotocol/clientCapabilities": {},
}


def modern(method: str, params: dict[str, Any] | None = None, **headers: str) -> dict[str, str]:
    """The three routing headers 2026-07-28 requires on a POST (SEP-2243)."""
    return {
        "mcp-protocol-version": PROTOCOL_VERSION,
        "mcp-method": method,
        **({"mcp-name": params["name"]} if params and "name" in params else {}),
        **headers,
    }


def modern_call(name: str, arguments: Any = None) -> dict[str, Any]:
    """A ``tools/call`` in modern shape: no session id, version in ``_meta``."""
    body = rpc("tools/call", {"name": name, "arguments": arguments or {}, "_meta": MODERN_META})
    return {"body": body, "headers": modern("tools/call", {"name": name})}


async def test_discovery_advertises_only_the_current_revision(app, signing_key) -> None:
    """``server/discover`` replaces the handshake, and must offer 2026-07-28.

    The old SDK default was ``DEFAULT_NEGOTIATED_VERSION = 2025-03-26``, three
    revisions behind, so a service that never answers this correctly looks
    healthy until a modern client arrives.
    """
    token = signing_key.sign(scope="notes:read notes:write")
    async with LifespanManager(app), client_for(app, token) as client:
        response = await client.post(
            "/mcp",
            json=rpc("server/discover", {"_meta": MODERN_META}),
            headers=modern("server/discover"),
        )

    assert response.status_code == 200, response.text
    assert response.json()["result"]["supportedVersions"] == [PROTOCOL_VERSION]


async def test_a_tool_runs_without_a_handshake_or_a_session(app, signing_key) -> None:
    """The core 2026-07-28 property: no ``initialize``, no ``Mcp-Session-Id``.

    Two independent requests, no session between them -- which is exactly what
    a stateful transport could not do, and therefore what would regress first
    if this service were ever wired back to one.
    """
    token = signing_key.sign(scope="notes:read notes:write")
    write = modern_call("add_note", {"title": "modern"})
    read = modern_call("list_notes")

    async with LifespanManager(app), client_for(app, token) as client:
        first = await client.post("/mcp", json=write["body"], headers=write["headers"])
        second = await client.post("/mcp", json=read["body"], headers=read["headers"])

    assert first.status_code == 200, first.text
    assert "added modern" in first.text
    assert second.status_code == 200, second.text
    assert "modern" in second.text
    # No session was issued, so a client cannot be holding one open.
    assert "mcp-session-id" not in first.headers


async def test_scope_is_still_enforced_per_tool_in_the_modern_shape(app, signing_key) -> None:
    """The 403 must survive the change of envelope.

    Per-tool enforcement is this library's reason for existing, and the modern
    request shape moves the tool name into ``_meta`` and the routing headers --
    so a parser that only understood the legacy body would silently stop
    refusing anything.
    """
    token = signing_key.sign(scope="notes:read")
    write = modern_call("add_note", {"title": "nope"})

    async with LifespanManager(app), client_for(app, token) as client:
        response = await client.post("/mcp", json=write["body"], headers=write["headers"])

    assert response.status_code == 403, response.text
    assert "notes:write" in response.headers["www-authenticate"]


async def test_a_mismatched_routing_header_is_the_sdks_refusal_not_ours(app, signing_key) -> None:
    """``Mcp-Name`` must agree with the body; the SDK answers, and it is a 400.

    Worth pinning because it looks like something this library should have
    produced: it did not.  ``ScopeEnforcement`` never reads the routing
    headers, and a header that disagrees with the body is refused before any
    scope decision is reached.
    """
    token = signing_key.sign(scope="notes:read notes:write")
    write = modern_call("add_note", {"title": "x"})
    headers = write["headers"] | {"mcp-name": "list_notes"}

    async with LifespanManager(app), client_for(app, token) as client:
        response = await client.post("/mcp", json=write["body"], headers=headers)

    assert response.status_code == 400, response.text
    assert response.json()["error"]["code"] == -32020


# -- the revision gate, when a service opts in ---------------------------

def _strict_config() -> ResourceServerConfig:
    return ResourceServerConfig(
        resource=RESOURCE,
        issuer=ISSUER,
        scopes=["notes:read"],
        tool_scopes={"whoami": NO_SCOPE},
        table_prefix="t",
        enforce_protocol_revision=True,
    )


@pytest.fixture
def strict_app(fake_jwks: FakeJwks, clock) -> Any:
    """A service that refuses anything but 2026-07-28."""
    config = _strict_config()
    cache = JwksCache(config.jwks_uri, fetch=fake_jwks.fetch, clock=clock)
    verifier = JwtTokenVerifier(
        cache, issuer=config.issuer, resource=config.resource, scope_set=config.policy.vocabulary
    )
    server = MCPServer(
        name="notes", version="0.1.0", auth=auth_settings(config), token_verifier=verifier
    )

    @server.tool(description="Say who is calling.")
    async def whoami() -> str:
        return "someone"

    return build_mcp_app(
        server,
        config=config,
        verifier=verifier,
        json_response=True,
        resolve_projection=False,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["calendar.example.com"],
            allowed_origins=["https://calendar.example.com"],
        ),
    )


async def test_the_gate_admits_the_current_revision(strict_app, signing_key) -> None:
    token = signing_key.sign(scope="notes:read")
    call = modern_call("whoami")
    async with LifespanManager(strict_app), client_for(strict_app, token) as client:
        response = await client.post("/mcp", json=call["body"], headers=call["headers"])

    assert response.status_code == 200, response.text
    assert "someone" in response.text


@pytest.mark.parametrize(
    "version", ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05", None]
)
async def test_the_gate_refuses_every_other_revision(strict_app, signing_key, version) -> None:
    """Including no header at all, which is what a pre-2025-06-18 client sends.

    Measured against the SDK with the gate off: all of these answer 200, and the
    2025 ones *negotiate down*.  So leaving the gate off is what keeps those
    clients working, which is why :class:`ProtocolRevisionGate` is opt-in.
    """
    token = signing_key.sign(scope="notes:read")
    body = rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
    headers = {"mcp-method": "initialize"}
    if version is not None:
        headers["mcp-protocol-version"] = version

    async with LifespanManager(strict_app), client_for(strict_app, token) as client:
        response = await client.post("/mcp", json=body, headers=headers)

    assert response.status_code == 400, response.text
    error = response.json()["error"]
    assert error["code"] == -32022
    assert error["data"]["supported"] == [PROTOCOL_VERSION]


async def test_the_gate_off_is_what_keeps_legacy_clients_working(app, signing_key) -> None:
    """The default must stay permissive, or this library breaks Claude Code.

    See anthropics/claude-code#96183: Claude Code 2.1.280 sends a legacy
    ``initialize`` even after a modern-only server answers ``server/discover``.
    """
    assert make_config().enforce_protocol_revision is False

    token = signing_key.sign(scope="notes:read")
    body = rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
    async with LifespanManager(app), client_for(app, token) as client:
        response = await client.post(
            "/mcp",
            json=body,
            headers={"mcp-protocol-version": "2025-11-25", "mcp-method": "initialize"},
        )

    assert response.status_code == 200, response.text


# -- RFC 9728 §3.1: where the metadata document lives --------------------

@pytest.mark.parametrize(
    ("resource", "expected"),
    [
        # No path component: the suffix alone.
        ("https://rs.example.com", "https://rs.example.com/.well-known/oauth-protected-resource"),
        # Path component: inserted *between host and path*, per §3.1. Appending
        # it would give .../mcp/.well-known/..., which resolves nowhere.
        (
            "https://rs.example.com/mcp",
            "https://rs.example.com/.well-known/oauth-protected-resource/mcp",
        ),
        ("https://rs.example.com/a/b", "https://rs.example.com/.well-known/oauth-protected-resource/a/b"),
        # A query rides after the suffix, since §3.1 inserts before path *and* query.
        (
            "https://rs.example.com/mcp?tenant=1",
            "https://rs.example.com/.well-known/oauth-protected-resource/mcp?tenant=1",
        ),
    ],
)
def test_the_metadata_url_is_built_per_rfc9728(resource: str, expected: str) -> None:
    from rhosocial.mcpserver import protected_resource_metadata_url

    config = ResourceServerConfig(
        resource=resource, issuer=ISSUER, scopes=["notes:read"], tool_scopes={"t": "notes:read"}
    )
    assert protected_resource_metadata_url(config) == expected


async def test_the_challenge_advertised_url_actually_resolves(app, signing_key) -> None:
    """The whole discovery chain, end to end: 401 -> URL -> document.

    Worth a test of its own because the two halves were produced by different
    code — the SDK builds the 401 challenge, this library builds the 403 one —
    and they disagreed. The 403 half advertised a URL that 404s, so a client
    short a scope was told to fetch a document that does not exist.
    """
    token = signing_key.sign(scope="notes:read")
    async with LifespanManager(app):
        async with client_for(app, token) as client:
            denied = await client.post("/mcp", json=call("add_note"))
            advertised = denied.headers["www-authenticate"].split('resource_metadata="')[1]
            advertised = advertised.split('"')[0]
            fetched = await client.get(advertised)

    assert denied.status_code == 403
    assert advertised.endswith("/.well-known/oauth-protected-resource/mcp")
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["resource"] == RESOURCE
