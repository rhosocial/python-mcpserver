# Code Style

## Line width

**100 characters maximum.** Enforced by `[tool.ruff] line-length = 100`.

This project is a library consumed by services; a long line in the library
becomes a long line in every downstream file that reads it.

## Typing

- Python 3.10+ syntax. The MCP SDK v2 floor is 3.10, so `X | None` and
  `list[str]` are available without `from __future__ import annotations` for
  most cases — but keep the future import where a PEP 604 union appears in a
  *runtime-evaluated* position (pydantic models, `TypeVar` bounds).
- `from __future__ import annotations` at the top of every module, matching the
  rhosocial family.
- Every public function has a signature. No untyped public API.

## Module docstrings

Every module opens with a docstring stating what it is responsible for **and
what it deliberately is not**, when the second part is not obvious. A reader who
does not know where a responsibility lives should be able to tell from the
docstrings of the two candidates.

Docstrings explain *why*, not *what*. `"""Return the JWKS cache."""` is noise;
`"""Why the cache degrades instead of raising."""` is not.

## Naming

| Kind | Convention | Example |
|---|---|---|
| Module | snake_case | `jwks.py` |
| Class | CapWords | `JwksCache`, `ResourceServerConfig` |
| Function | snake_case, verb-first | `current_principal`, `build_asgi_app` |
| Constant | SCREAMING_SNAKE | `MAX_BODY_BYTES` |
| Env var | `MCP_<SERVICE>_<KEY>` | `MCP_SCHEDULE_ISSUER` |

**No abbreviations that hide a security-relevant concept.** `scopes`, not
`scp`; `principal`, not `pr`.

## Public API surface

`__init__.py` is the **only** facade. Re-export explicitly by name; never
`from .x import *`. A downstream service writes

```python
from rhosocial.mcpserver import JwtTokenVerifier, ScopeEnforcement
```

and if that import breaks, this is a breaking change for every consumer.

Anything not exported from `__init__.py` is internal and may change without a
deprecation period. Say so in the module docstring when a module is internal.

## Comments

Comments carry reasoning that the code cannot state. Delete any comment that
merely restates the next line. In this project most load-bearing comments are
attributed — "…because `count` funnels through `aggregate()` while `all()` uses
`to_sql()`" — because the reasoning survives refactoring but the attribution
tells the next reader whether to trust it.
