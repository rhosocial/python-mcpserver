# tests/rhosocial/mcpserver_test/test_identity.py
"""The single exit for "who is calling", and its two bindings."""

from __future__ import annotations

import pytest

from rhosocial.mcpserver import Principal, Unauthenticated
from rhosocial.mcpserver.identity import (
    current_central_user_id,
    current_principal,
    reset_cli_principal,
    reset_current_principal,
    set_cli_principal,
    set_current_principal,
)


def make(central_user_id: str = "u-123", **kwargs) -> Principal:
    return Principal(central_user_id=central_user_id, client_id="opencode", **kwargs)


def test_no_identity_fails_closed() -> None:
    """There is no fallback.  A caller that catches this and carries on has
    removed the only barrier this design has."""
    with pytest.raises(Unauthenticated, match="no verified identity"):
        current_principal()


def test_request_binding_is_visible() -> None:
    token = set_current_principal(make("u-7"))

    assert current_principal().central_user_id == "u-7"

    reset_current_principal(token)
    with pytest.raises(Unauthenticated):
        current_principal()


def test_cli_binding_is_visible() -> None:
    token = set_cli_principal(make("u-cli"))

    assert current_principal().central_user_id == "u-cli"

    reset_cli_principal(token)
    with pytest.raises(Unauthenticated):
        current_principal()


def test_the_two_bindings_do_not_collide() -> None:
    """A CLI process must never overwrite — or be overwritten by — a value set
    on the HTTP path.  They are separate ContextVars for exactly that reason."""
    http = set_current_principal(make("u-http"))
    cli = set_cli_principal(make("u-cli"))

    assert current_principal().central_user_id == "u-http"

    reset_cli_principal(cli)
    assert current_principal().central_user_id == "u-http"

    reset_current_principal(http)
    with pytest.raises(Unauthenticated):
        current_principal()


def test_binding_is_nested_scoped_not_leaked() -> None:
    """Resetting restores the previous value rather than clearing it, so a
    request-scoped binding cannot erase an outer one."""
    outer = set_current_principal(make("outer"))
    inner = set_current_principal(make("inner"))
    assert current_principal().central_user_id == "inner"

    reset_current_principal(inner)
    assert current_principal().central_user_id == "outer"

    reset_current_principal(outer)


def test_central_user_id_needs_no_database() -> None:
    token = set_current_principal(make("u-42"))

    assert current_central_user_id() == "u-42"

    reset_current_principal(token)


def test_principal_is_frozen() -> None:
    """It is handed to code that writes it into WHERE clauses; a mutable
    identity is a mutable authorization decision."""
    principal = make()

    # Frozen dataclass: the error type is a detail, the immutability is the point.
    with pytest.raises((AttributeError, TypeError)):
        principal.central_user_id = "someone-else"


def test_has_scope() -> None:
    principal = make(scopes=frozenset({"a:read"}))

    assert principal.has_scope("a:read") is True
    assert principal.has_scope("a:write") is False


def test_string_form_is_for_logs_only() -> None:
    assert str(make("u-1")) == "u-1 via opencode"


def test_principal_defaults() -> None:
    principal = Principal(central_user_id="u-1", client_id="c")

    assert principal.scopes == frozenset()
    assert principal.issuer == ""
    assert principal.resource == ""
    assert principal.expires_at is None
    assert principal.token_id is None
