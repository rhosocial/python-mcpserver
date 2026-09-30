# python-mcpserver — Developer Instructions

## What this project is

An MCP **Resource Server** foundation for `rhosocial-activerecord` services that
sit behind a central OAuth 2.1 authorization server. It turns "central AS issues
a short-lived JWT, every service verifies it locally" into a library, so a
domain service contains domain code and nothing else.

Source lives in `src/rhosocial/mcpserver/` (PEP 420 namespace at `rhosocial/`,
so there is **no** `src/rhosocial/__init__.py`). Tests live in
`tests/rhosocial/mcpserver_test/`.

- **Python**: >= 3.10 (the MCP SDK v2 floor)
- **Version**: defined only in `pyproject.toml`
- **Downstream**: `vistart/schedule-manager`, `vistart/contact-manager`
- **Sibling**: `authserver` (not yet created) issues the tokens this verifies

## Iron rules (do not skip)

1. **Run tests with `PYTHONPATH=src:tests`.**
2. **No line exceeds 100 chars** (ruff config in `pyproject.toml`).
3. **Identity is never an argument.** No `user_id` / `principal_id` parameter on
   any public function or MCP tool. It comes from
   `rhosocial.mcpserver.identity.current_principal()`, the single exit.
4. **The only two enforcement points are `PrincipalScopedQuery.__init__` and
   `PrincipalOwnedMixin.prepare_save_data`.** Do not add a third, and do not
   move either one to a terminal query method — the execution paths are not
   unified (`count` and numeric aggregates funnel through `aggregate()`, `all()`
   goes through `to_sql()`), so a per-terminal override silently misses one.
5. **Asymmetric algorithms only by default.** A JWKS serves public keys;
   accepting `HS*` there is algorithm-confusion. Reject rather than downgrade.
6. **A `kid` miss refreshes the JWKS exactly once.** A second miss is a 401.
7. **No SQL in this library.** All DB access goes through `Model.query()`. This
   is what makes rule 4 checkable: there is no CTE path to route around.
8. **Table names have exactly one source** (`tables.TableNamespace`), including
   index names — PostgreSQL puts every index in one namespace.

## Repository map

```
src/rhosocial/mcpserver/
├── __init__.py     # the only facade; re-exports the stable API
├── config.py       # ResourceServerConfig: env-driven, closed scope vocabulary
├── errors.py       # McpServerError and friends
├── identity.py     # Principal + current_principal() — the single exit
├── jwks.py         # JwksCache: TTL, kid rotation, single-flight, degradation
├── verifier.py     # JwtTokenVerifier + request-scope memo
├── scopes.py       # ScopeSet + tool→scope mapping
├── metadata.py     # RFC 9728 protected resource metadata
├── middleware.py   # ScopeEnforcement / HealthProbe / BodyGuard
├── tables.py       # TableNamespace
├── orm/            # principal.py / scoped.py / owned.py
├── app.py          # build_asgi_app()
└── cli.py          # mcpserver CLI
```

## Rules Index

| File | When to use |
|------|-------------|
| [.claude/plan/2026-09-30/python-mcpserver-plan.md](plan/2026-09-30/python-mcpserver-plan.md) | Why the project exists, its boundary, phases |
| [rules/code-style.md](rules/code-style.md) | Naming, typing, docs, line width |
| [rules/security.md](rules/security.md) | JWT/JWKS/scope/identity rules with the reasoning |
| [rules/testing.md](rules/testing.md) | Test layout, fixtures, how to run |

## Commands

```bash
source .venv3.14-ubuntu26.04/bin/activate
export PYTHONPATH=src:tests
pytest tests/ -q -m 'not benchmark'
ruff check src/ tests/
mypy src/
```

## Commits

Conventional Commits with a scope. Suggested scopes: `jwks`, `verifier`,
`identity`, `scopes`, `metadata`, `middleware`, `orm`, `cli`, `app`, `ci`, `docs`.
