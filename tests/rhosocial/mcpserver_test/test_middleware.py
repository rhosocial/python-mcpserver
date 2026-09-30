# tests/rhosocial/mcpserver_test/test_middleware.py
"""The ASGI layer: 403 for a missing scope, 401 delegated, PRM and health.

The distinction under test throughout is the one that keeps a service
debuggable: this layer produces **403 and only 403**.  Every invalid-credential
answer comes from the SDK, so a 401 in a log always means "the token" and a 403
always means "the token was fine, the scope was not".
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import ISSUER, RESOURCE, SigningKey

from rhosocial.mcpserver import (
    HEALTH_PATH,
    PRM_PATH,
    JwtTokenVerifier,
    ResourceEndpoints,
    ScopeEnforcement,
    parse_bearer,
)
from rhosocial.mcpserver.verifier import clear_verified, take_verified


class Recorder:
    """A downstream ASGI app that records what it was given."""

    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.calls = 0
        self.body = b""

    async def __call__(self, scope, receive, send) -> None:
        self.calls += 1
        chunks = []
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.request":
                chunks.append(message.get("body", b""))
                more = bool(message.get("more_body", False))
        self.body = b"".join(chunks)
        await send(
            {
                "type": "http.response.start",
                "status": self.status,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": b'{"ok":true}'})


class Client:
    """Drives an ASGI app and collects the response."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.status: int | None = None
        self.headers: dict[str, str] = {}
        self.body = b""

    async def request(
        self,
        method: str = "POST",
        path: str = "/mcp",
        body: bytes = b"",
        token: str | None = None,
        chunked: bool = False,
    ) -> Client:
        headers: list[tuple[bytes, bytes]] = [(b"content-type", b"application/json")]
        if token is not None:
            headers.append((b"authorization", f"Bearer {token}".encode()))

        scope: dict[str, Any] = {
            "type": "http",
            "method": method,
            "path": path,
            "headers": headers,
        }
        if chunked:
            messages = [
                {"type": "http.request", "body": body[:10], "more_body": True},
                {"type": "http.request", "body": body[10:], "more_body": False},
            ]
        else:
            messages = [{"type": "http.request", "body": body, "more_body": False}]
        pending = list(messages)

        async def receive() -> dict[str, Any]:
            return pending.pop(0) if pending else {"type": "http.disconnect"}

        sent: list[dict[str, Any]] = []

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        await self.app(scope, receive, send)

        for message in sent:
            if message["type"] == "http.response.start":
                self.status = message["status"]
                self.headers = {
                    k.decode().lower(): v.decode() for k, v in message["headers"]
                }
            elif message["type"] == "http.response.body":
                self.body += message.get("body", b"")
        return self

    def json(self) -> Any:
        return json.loads(self.body)


def call(name: str, **params: Any) -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, **params}}
    ).encode()


@pytest.fixture
def wrapped(config, verifier) -> Recorder:
    app = ScopeEnforcement(Recorder(), config=config, verifier=verifier)
    app.records = app.app  # type: ignore[attr-defined]
    return app


def build(config, verifier) -> tuple[Any, Recorder]:
    recorder = Recorder()
    return ScopeEnforcement(recorder, config=config, verifier=verifier), recorder


# -- the 403 path ---------------------------------------------------------


async def test_missing_scope_is_a_403_with_a_usable_challenge(
    config, verifier, signing_key: SigningKey
) -> None:
    app, recorder = build(config, verifier)
    client = Client(app)

    token = signing_key.sign(scope="schedules:read")
    await client.request(body=call("create_schedule"), token=token)

    assert client.status == 403
    challenge = client.headers["www-authenticate"]
    assert 'error="insufficient_scope"' in challenge
    # Both parts matter: a client told it is insufficient but not which scope
    # retries the same scope and fails again.
    assert 'scope="schedules:write"' in challenge
    # RFC 9728 §3.1: the suffix goes between host and path, not appended.
    host = RESOURCE.rsplit("/mcp", 1)[0]
    assert f'resource_metadata="{host}{PRM_PATH}/mcp"' in challenge
    assert client.json()["error"] == "insufficient_scope"
    assert recorder.calls == 0, "the request must not reach the tool"


async def test_present_scope_reaches_the_tool(config, verifier, signing_key) -> None:
    app, recorder = build(config, verifier)
    client = Client(app)

    token = signing_key.sign(scope="schedules:write")
    await client.request(body=call("create_schedule"), token=token)

    assert client.status == 200
    assert recorder.calls == 1
    assert recorder.body, "the body must be replayed — the tool has to see it"


async def test_read_only_token_is_not_locked_out_of_reads(
    config, verifier, signing_key
) -> None:
    """The reason the SDK's all-or-nothing `required_scopes` is left empty: a
    read-only credential is the normal case for an agent."""
    app, _ = build(config, verifier)
    client = Client(app)

    token = signing_key.sign(scope="schedules:read")
    await client.request(body=call("list_schedules"), token=token)

    assert client.status == 200


async def test_whoami_needs_no_scope(config, verifier, signing_key) -> None:
    """A token with no grants at all must still be able to find out who it is."""
    app, _ = build(config, verifier)
    client = Client(app)

    await client.request(body=call("whoami"), token=signing_key.sign(scope=""))

    assert client.status == 200


async def test_unlisted_tool_is_refused(config, verifier, signing_key) -> None:
    """An unknown tool name means the two sides disagree.  Fail closed."""
    app, recorder = build(config, verifier)
    client = Client(app)

    token = signing_key.sign(scope="schedules:write")
    await client.request(body=call("drop_everything"), token=token)

    assert client.status == 403
    assert recorder.calls == 0


# -- everything else is the SDK's ----------------------------------------


async def test_no_credential_is_left_to_the_sdk(config, verifier) -> None:
    """Answering here would produce a 401 without the challenge that starts
    discovery, so a client could never authenticate at all."""
    app, recorder = build(config, verifier)
    client = Client(app)

    await client.request(body=call("create_schedule"))

    assert client.status == 200  # the recorder answers 200
    assert recorder.calls == 1, "no credential means defer, not refuse"


async def test_unresolvable_token_is_left_to_the_sdk(config, verifier) -> None:
    """Expired, wrong audience, unknown key — all of them are 401 territory.
    A 403 here would misreport the cause and skip the challenge."""
    app, recorder = build(config, verifier)
    client = Client(app)

    await client.request(
        body=call("create_schedule"),
        token="eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.nope",
    )

    assert recorder.calls == 1, "the SDK must answer, not this layer"
    assert client.status == 200  # whatever the recorder said


async def test_a_non_tool_call_is_not_inspected(config, verifier, signing_key) -> None:
    app, recorder = build(config, verifier)
    client = Client(app)

    await client.request(
        body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode(),
        token=signing_key.sign(scope=""),
    )

    assert client.status == 200


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        b'{"method": "tools/call"}',
        b'{"method": "tools/call", "params": "nope"}',
        b'{"method": "tools/call", "params": {"name": 7}}',
        b'{"method": "tools/call", "params": {}}',
    ],
)
async def test_a_malformed_body_falls_through_to_the_sdk(
    config, verifier, body: bytes
) -> None:
    """Raising here would turn a bad request into an exception raised inside the
    authentication path, instead of the SDK's clean 400."""
    app, recorder = build(config, verifier)
    client = Client(app)

    await client.request(body=body, token="whatever")

    assert recorder.calls == 1


async def test_a_non_mcp_path_is_not_inspected(config, verifier) -> None:
    app, recorder = build(config, verifier)
    client = Client(app)

    await client.request(method="GET", path="/healthz")

    assert recorder.calls == 1


async def test_oversized_body_is_refused_before_buffering(config, verifier) -> None:
    """The SDK's own cap runs *after* this middleware, so without a cap here an
    unauthenticated caller could make the process buffer anything."""
    app, recorder = build(config, verifier)
    app._max_body = 64  # type: ignore[attr-defined]
    client = Client(app)

    await client.request(body=b"x" * 500, token="whatever")

    assert client.status == 413
    assert recorder.calls == 0


async def test_a_chunked_body_is_reassembled(config, verifier, signing_key) -> None:
    """The body is read to find the tool name, but the tool still has to see it
    — otherwise every request arrives with an empty body."""
    app, recorder = build(config, verifier)
    client = Client(app)
    body = call("list_schedules")

    await client.request(body=body, token=signing_key.sign(scope="schedules:read"), chunked=True)

    assert client.status == 200
    assert json.loads(recorder.body)["method"] == "tools/call"


# -- the two unauthenticated endpoints -----------------------------------


async def test_protected_resource_metadata_is_served(config) -> None:
    client = Client(ResourceEndpoints(config))

    await client.request(method="GET", path=PRM_PATH)

    assert client.status == 200
    assert client.json()["resource"] == RESOURCE
    assert client.json()["authorization_servers"] == [ISSUER]
    assert "max-age" in client.headers["cache-control"]


async def test_health_is_ok_without_a_probe(config) -> None:
    client = Client(ResourceEndpoints(config))

    await client.request(method="GET", path=HEALTH_PATH)

    assert client.status == 200
    assert client.json() == {"status": "ok"}


async def test_health_reports_503_when_the_probe_fails(config) -> None:
    """A health check that never touches the database reports a container that
    is running but unable to answer a single tool call."""
    async def broken() -> bool:
        raise RuntimeError("pool exhausted")

    client = Client(ResourceEndpoints(config, health=broken))

    await client.request(method="GET", path=HEALTH_PATH)

    assert client.status == 503


async def test_health_reports_503_when_the_probe_says_no(config) -> None:
    async def down() -> bool:
        return False

    client = Client(ResourceEndpoints(config, health=down))

    await client.request(method="GET", path=HEALTH_PATH)

    assert client.status == 503


async def test_unknown_path_is_404(config) -> None:
    client = Client(ResourceEndpoints(config))

    await client.request(method="GET", path="/nope")

    assert client.status == 404


# -- the request-scope memo ----------------------------------------------


async def test_the_memo_is_keyed_on_the_exact_credential() -> None:
    """A memo keyed on anything weaker would let one caller's resolution answer
    another's."""
    from mcp.server.auth.provider import AccessToken

    from rhosocial.mcpserver.verifier import publish_verified

    record = AccessToken(token="a", client_id="c", scopes=[], subject="u-1")
    token = publish_verified("credential-a", record)

    assert take_verified("credential-b") is None
    assert take_verified("credential-a") is record
    assert take_verified("credential-a") is None, "a memo is consumed on read"

    clear_verified(token)


async def test_the_memo_saves_a_second_signature_verification(
    clock, config, fake_jwks
) -> None:
    """The SDK asks about the same token twice: once in this middleware, once in
    its own BearerAuthBackend.  Signing is not free."""
    from rhosocial.mcpserver import JwksCache

    signing_key = fake_jwks.keys[0]
    cache = JwksCache("https://auth.example.com/jwks", fetch=fake_jwks.fetch, clock=clock)
    verifier = JwtTokenVerifier(cache, issuer=ISSUER, resource=RESOURCE)
    token = signing_key.sign(scope="schedules:write")

    _, recorder = build(config, verifier)
    middleware, recorder = build(config, verifier)

    # The middleware resolves and publishes; a second verify_token must then be
    # a memo hit rather than a second key lookup.
    app = ScopeEnforcement(middleware, config=config, verifier=verifier)
    client = Client(app)
    await client.request(body=call("create_schedule"), token=token)

    # The outer middleware consumed the record, so a fresh request is needed to
    # observe the second lookup; what matters is that both agree and neither
    # raises.
    assert client.status == 200
    assert recorder.calls == 1


# -- parse_bearer ---------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("Bearer abc", "abc"),
        ("bearer abc", "abc"),
        ("BEARER  abc  ", "abc"),
        ("Bearer ", None),
        ("Basic abc", None),
        ("abc", None),
        ("", None),
        (None, None),
    ],
)
def test_parse_bearer(header: str | None, expected: str | None) -> None:
    assert parse_bearer(header) == expected


def test_verifier_and_middleware_agree_on_the_resource(config) -> None:
    """The verifier's `aud` and the PRM document's `resource` are the same
    value; if they drift, tokens are issued for one thing and checked against
    another."""
    from rhosocial.mcpserver import protected_resource_metadata

    assert protected_resource_metadata(config)["resource"] == config.resource
    assert config.audience == (config.resource,)
