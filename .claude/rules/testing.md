# Testing

## Layout

```
tests/
├── conftest.py                                  # shared fixtures
└── rhosocial/mcpserver_test/
    ├── test_jwks.py
    ├── test_verifier.py
    ├── test_identity.py
    ├── test_scopes.py
    ├── test_metadata.py
    ├── test_middleware.py
    ├── test_tables.py
    └── orm/
        ├── test_principal.py
        ├── test_scoped.py
        └── test_owned.py
```

## Running

```bash
source .venv3.14-ubuntu26.04/bin/activate
export PYTHONPATH=src:tests
pytest tests/ -q
pytest tests/ -q -k jwks            # single module
pytest tests/ -m benchmark           # benchmarks, excluded by default
```

`PYTHONPATH=src:tests` is required — tests are not installed.

## What to test

The JWKS cache and the verifier are the security-critical surface, and their
interesting behaviour is entirely in the **failure** paths. Cover at minimum:

- key rotation: a token signed by a newly published `kid` is accepted after
  exactly one refresh;
- an unknown `kid` that stays unknown is rejected without a fetch loop;
- concurrent misses produce one fetch (assert the fetch counter, not just the
  result — a passing test with two fetches is still a bug);
- a fetch error with a live cache still verifies; with an expired cache it does
  not;
- `HS256` is rejected without consulting the network;
- a wrong `aud`, a wrong `iss`, and an expired token are each rejected
  separately, so a failure names the cause.

The middleware's interesting behaviour is also in failures: 403 carries
`WWW-Authenticate` with `insufficient_scope` **and** the required `scope`, and
an unresolvable token produces the SDK's 401 rather than this layer's 403.

## Fixtures

- **JWKS**: build keys in-process with `cryptography`, serve them from a
  `respx`-mocked or in-process ASGI transport. Never commit a real key, and
  never fetch a live JWKS in a test.
- **Tokens**: mint with the test's own private key so a signature mismatch is
  impossible by accident.
- **Database**: SQLite in a temp file via the core library's SQLite backend.
  A real database, not a mock — the ownership rules are about what reaches the
  SQL string, and a mock cannot see that.
- **Time**: freeze `exp`/`iat` explicitly by constructing tokens with
  timestamps in the past or future. Do not `sleep`.

## Style

- One behaviour per test, named for the behaviour
  (`test_unknown_kid_refreshes_once_then_rejects`), not the function
  (`test_verify_2`).
- Assert on the security-relevant value, not just truthiness: assert the
  `WWW-Authenticate` header contains the required scope, not that the status is
  403.
- No `xfail` without a comment naming the bug it is waiting on.

## Output

Show the full pytest output. Do not pipe test results through `grep`, `head`
or `tail` — a filtered failure count is how a red suite gets committed.
