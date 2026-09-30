# tests/rhosocial/mcpserver_test/test_layering.py
"""The transport-agnostic half must stay free of the transport.

This is the whole reason the package is split, so it is checked rather than
described: a later import that reaches for an SDK type "just for a type hint"
is the exact change that makes a second transport impossible to add, and it
would not fail any behavioural test.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

SRC = pathlib.Path(__file__).resolve().parents[3] / "src" / "rhosocial" / "mcpserver"

#: What a module above the line is allowed to know about.  The identity,
#: scope, credential and ORM layers must work for a REST service as much as for
#: an MCP one, and the only way to know that is still true is to forbid the
#: import.
FORBIDDEN = ("mcp.", "jwt", "jose", "starlette", "fastapi")

#: Modules that own transport concerns, and so legitimately import the SDK.
#:
#: ``cli.py`` is here because it is an OAuth *client* -- it decodes a JWT to
#: print one -- which is a legitimate thing for a CLI in this package to be and
#: not evidence that the layers it imports are transport-bound.
TRANSPORT = {
    "mcp/verifier.py",
    "mcp/app.py",
    "mcp/middleware.py",
    "mcp/metadata.py",
    "cli.py",
}


def _modules_above_the_line() -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC).as_posix()
        if rel in TRANSPORT or rel.startswith("mcp/"):
            continue
        out.append(path)
    return out


@pytest.mark.parametrize(
    "path", _modules_above_the_line(), ids=lambda p: p.relative_to(SRC).as_posix()
)
def test_no_transport_import_above_the_line(path: pathlib.Path) -> None:
    tree = ast.parse(path.read_text())
    offenders: list[str] = []
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module]
        for name in names:
            if any(name == bad or name.startswith(bad) for bad in FORBIDDEN):
                offenders.append(name)
    assert not offenders, (
        f"{path.relative_to(SRC)} imports {offenders}; a service serving "
        "REST or anything else cannot use a module that needs the MCP SDK"
    )


_NOT_ANNOTATIONS = {"__init__.py"}


@pytest.mark.parametrize(
    "path",
    [p for p in _modules_above_the_line() if p.name not in _NOT_ANNOTATIONS],
    ids=lambda p: p.relative_to(SRC).as_posix(),
)
def test_no_transport_import_hidden_in_an_annotation(path: pathlib.Path) -> None:
    # Excluded from this check: __init__.py, which is the facade and exists to
    # name both layers in one namespace.  See the companion test below.
    """Annotations are imports in every way that matters here.

    A quoted ``"mcp.server.auth.provider.AccessToken"`` under
    ``from __future__ import annotations`` never executes, so a grep for the
    import misses it -- and it is still a coupling: the module cannot be
    imported by anything that has not imported the SDK first.
    """
    text = path.read_text()
    quoted = [
        bad
        for bad in ("AccessToken", "MCPServer", "JwtTokenVerifier")
        if f'"{bad}' in text or f"'{bad}" in text
    ]
    assert not quoted, f"{path.relative_to(SRC)} names {quoted} in an annotation"


def test_the_facade_is_the_one_deliberate_exception() -> None:
    """``__init__.py`` re-exports both layers, and that is its whole job.

    It is excluded from the annotation check above because naming a transport
    type in ``__all__`` is what a facade does; the point of the split is that
    *nothing else* has to.
    """
    import rhosocial.mcpserver as top

    assert "JwtTokenVerifier" in top.__all__
    assert "CredentialSource" in top.__all__


def test_the_subpackage_exists_and_is_importable() -> None:
    """A split nobody can import is a split that did not happen."""
    import rhosocial.mcpserver.mcp as adapter

    for name in ("build_asgi_app", "build_mcp_app", "JwtTokenVerifier", "ScopeEnforcement"):
        assert hasattr(adapter, name), f"rhosocial.mcpserver.mcp lost {name}"


def test_the_public_facade_still_reexports_both_layers() -> None:
    """Moving modules must not break anyone importing the top-level package.

    Every export remains reachable from ``rhosocial.mcpserver`` even though its
    module moved to ``.mcp``, so a service upgrading this library changes no
    import lines.
    """
    import rhosocial.mcpserver as top

    for name in ("build_asgi_app", "JwtTokenVerifier", "CredentialSource", "Principal"):
        assert name in top.__all__, f"{name} vanished from the public facade"
