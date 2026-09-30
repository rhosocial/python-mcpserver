# rhosocial-mcpserver

MCP **Resource Server** foundation for
[rhosocial-activerecord](https://github.com/rhosocial/python-activerecord)
services that sit behind a central OAuth 2.1 authorization server.

A service that consumes a short-lived JWT and owns some tables should contain
its domain code and nothing else. This package is the rest: verifying the
access token locally, refusing a tool call whose token lacks that tool's scope,
and tying every row to the verified caller.

It replaces the ~800 lines of security-critical code that
[`vistart/schedule-manager`](https://github.com/vistart/schedule-manager) and
[`vistart/contact-manager`](https://github.com/vistart/contact-manager) each
wrote — twice, by copying each other, including a per-request database lookup
on the hot path.

## What it does

| | |
|---|---|
| **Verify locally** | JWT signature, `iss`, `aud`, `exp` against a cached JWKS. No request reaches the authorization server, so the AS is not a network dependency of every tool call. |
| **Enforce per tool** | An HTTP 403 naming the missing scope, produced at the ASGI layer where a status code exists. |
| **Answer discovery** | RFC 9728 protected-resource metadata, generated from the same scope vocabulary the enforcement checks. |
| **Tie rows to callers** | Two enforcement points — a scoped query class and a save hook — so no query and no write can cross a principal. |
| **Project the identity** | A local row per central user, created on first use, holding only what the service needs. |

## What it deliberately does not do

Not a token store, not an authorization server, not a user table, not
service-to-service authorization, not a web framework. Each of those has a
tempting "while I'm here" version that would make every downstream service
depend on this package for something it should not own. The full list, with the
reason for each, is in
[`.claude/plan/2026-09-30/python-mcpserver-plan.md`](.claude/plan/2026-09-30/python-mcpserver-plan.md) §1.3.

## Install

```bash
pip install rhosocial-mcpserver
```

Python 3.10+ — the MCP SDK v2 floor. SQLite needs no extra package; other
backends come from the corresponding `rhosocial-activerecord-<name>` package.

## Use

```python
from rhosocial.mcpserver import (
    NO_SCOPE,
    ResourceServerConfig,
    JwtTokenVerifier,
    JwksCache,
    PrincipalMixin,
    PrincipalOwnedMixin,
    PrincipalScopedQuery,
    ResourceEndpoints,
    ScopeEnforcement,
    TableNamespace,
)

tables = TableNamespace("sm")          # one prefix; every name derives from it

CONFIG = ResourceServerConfig(
    resource="https://calendar.example.com/mcp",   # RFC 8707 resource id == aud
    issuer="https://auth.example.com",
    scopes=["schedules:read", "schedules:write"],
    tool_scopes={
        "whoami": NO_SCOPE,              # reports the caller, discloses nothing
        "list_schedules": "schedules:read",
        "create_schedule": "schedules:write",
    },
    table_prefix="sm",
)

verifier = JwtTokenVerifier(
    JwksCache(CONFIG.jwks_uri),
    issuer=CONFIG.issuer,
    resource=CONFIG.resource,
    scope_set=CONFIG.policy.vocabulary,
)
```

Models:

```python
class ContactPrincipal(AsyncActiveRecord, PrincipalMixin):
    __table_name__ = tables.table("principals")
    __pk_auto_generated__ = True

    id: Optional[int] = None
    central_user_id: str = ""          # the AS's `sub`; opaque, so TEXT
    status: str = PrincipalMixin.STATUS_ACTIVE
    provided_by: Optional[str] = None
    provisioned_at: Optional[datetime] = None
    # ... service-private columns: timezone, locale, default view


class Contact(PrincipalOwnedMixin, AsyncActiveRecord):
    __table_name__ = tables.table("contacts")
    __pk_auto_generated__ = True
    __query_class__ = PrincipalScopedQuery

    id: Optional[int] = None
    principal_id: int = 0              # placeholder; overwritten on every write
    name: str = ""


ContactPrincipal.register_as_projection()   # once, at import time
```

The application:

```python
async def get_contact(name: str) -> str:
    """No `user_id` argument anywhere — identity is not a choice."""
    contact = await Contact.query().where(Contact.c.name == name).one()
    return contact.name
```

Wiring:

```python
app = ScopeEnforcement(
    PrincipalResolution(mcp_asgi_app),      # resolves principal_id per request
    config=CONFIG,
    verifier=verifier,
)
app = ResourceEndpoints(CONFIG, health=probe)(app)   # PRM + /healthz
```

## Design notes

Four decisions are worth knowing before extending this, because each one
looks like a simplification until you hit the failure it prevents.

**A `kid` miss refreshes the JWKS at most once per cooldown, and the cooldown
is stamped before the fetch.** Fifty requests racing a rotation all miss; the
first to reach the lock stamps the `kid` and fetches, and the other forty-nine
find the stamp and read a cache the first one already replaced. Stamping after
the fetch would let all fifty fetch.

**A failed fetch still serves the cached key set, even past its TTL.** A key
set and a grant are different things: revoking a grant does not remove a key
from the JWKS, it stops the AS minting new tokens with it. Serving stale keys
during a two-minute AS outage costs less than rejecting every token in the
fleet, and the window is bounded by `max_ttl_seconds`.

**`HS*` is refused, and the refusal is structural.** A JWKS publishes public
keys; an HMAC secret that is the public key is the algorithm-confusion forgery.
Symmetric and encryption-only keys are dropped from the key set at parse time,
so widening `allowed_algorithms` cannot reach one by accident.

**Identity is read in exactly one place, and it is never a parameter.** Nothing
takes a `user_id`. `PrincipalScopedQuery.__init__` and
`PrincipalOwnedMixin.prepare_save_data` are the only two enforcement points,
and the second is a *synchronous* hook — which is why the projection is
resolved in middleware rather than inside it. A third enforcement point would
mean a third place to forget.

The reasoning behind each of these, and the failure it prevents, is in
[`.claude/rules/security.md`](.claude/rules/security.md).

## Development

```bash
python -m venv .venv3.14-ubuntu26.04
.venv3.14-ubuntu26.04/bin/pip install -e ../python-activerecord
.venv3.14-ubuntu26.04/bin/pip install -e ".[dev]"

export PYTHONPATH=src:tests
.venv3.14-ubuntu26.04/bin/pytest tests/ -q
.venv3.14-ubuntu26.04/bin/ruff check src/ tests/
.venv3.14-ubuntu26.04/bin/mypy src/
```

Tests run against a real SQLite database rather than mocks: the rules here are
about what reaches a `WHERE` clause, and a mock cannot see that.

## License

Apache-2.0
