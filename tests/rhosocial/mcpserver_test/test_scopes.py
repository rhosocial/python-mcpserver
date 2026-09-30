# tests/rhosocial/mcpserver_test/test_scopes.py
"""The scope vocabulary, and the drift between "advertised" and "accepted"."""

from __future__ import annotations

import pytest

from rhosocial.mcpserver import NO_SCOPE, ScopePolicy, ScopeSet
from rhosocial.mcpserver.errors import ConfigurationError


def test_vocabulary_is_sorted_and_deduplicated() -> None:
    scopes = ScopeSet(["b:read", "a:read", "b:read"])

    assert scopes.values == ("a:read", "b:read")
    assert len(scopes) == 2


def test_empty_vocabulary_is_a_configuration_error() -> None:
    """A service with no scopes has either declared nothing or lost its
    declaration; either way every tool would be unprotected."""
    with pytest.raises(ConfigurationError, match="at least one"):
        ScopeSet([])


def test_scope_with_a_space_is_rejected() -> None:
    """A space splits the header's space-delimited list into two scopes, so the
    value silently grants less than it appears to."""
    with pytest.raises(ConfigurationError, match="RFC 6749"):
        ScopeSet(["schedules read"])


def test_scope_with_a_double_quote_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="RFC 6749"):
        ScopeSet(['schedules:"read"'])


def test_scope_with_a_backslash_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="RFC 6749"):
        ScopeSet(["schedules\\read"])


def test_scope_with_a_control_character_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="RFC 6749"):
        ScopeSet(["schedules\nread"])


def test_unlisted_tool_is_not_public() -> None:
    """A client can only reach a tool the server registered, so an unknown name
    means the two sides disagree — and disagreeing sides should not exchange
    data.  This is the fail-closed half of `scope_for` returning None."""
    policy = ScopePolicy(ScopeSet(["a:read"]), {"list_things": "a:read"})

    assert policy.scope_for("delete_everything") is None
    assert policy.requires_scope("delete_everything") is False


def test_tool_needing_no_scope_is_still_public() -> None:
    """`whoami` reveals nothing about other users, so a token with no grants
    must still be able to find out who it is."""
    policy = ScopePolicy(ScopeSet(["a:read"]), {"whoami": NO_SCOPE})

    assert policy.scope_for("whoami") == ""
    assert policy.requires_scope("whoami") is False
    assert policy.missing("whoami", ()) is None


def test_missing_scope_is_named() -> None:
    policy = ScopePolicy(ScopeSet(["a:read", "a:write"]), {"write_thing": "a:write"})

    assert policy.missing("write_thing", ("a:read",)) == "a:write"
    assert policy.missing("write_thing", ("a:read", "a:write")) is None


def test_tool_naming_an_unknown_scope_is_a_startup_error() -> None:
    """The typo that would otherwise deny every caller, at the first request
    that reaches the tool — i.e. in production."""
    with pytest.raises(ConfigurationError, match="outside the vocabulary"):
        ScopePolicy(ScopeSet(["a:read"]), {"w": "a:write"})


def test_advertised_scopes_exclude_declared_but_unused() -> None:
    """Publishing a scope the server has no tool behind is a promise it cannot
    keep, and a client that trusted the document would try it."""
    vocabulary = ScopeSet(["a:read", "a:write", "a:delete"])
    policy = ScopePolicy(vocabulary, {"read_thing": "a:read"})

    assert policy.scopes_supported == ("a:read",)
    assert "a:delete" in vocabulary, "the declaration stays; only the document drops it"


def test_registering_a_tool_updates_the_advertised_set() -> None:
    policy = ScopePolicy(ScopeSet(["a:read", "a:write"]), {})

    policy.add("write_thing", "a:write")

    assert policy.scopes_supported == ("a:write",)
    assert policy.scope_for("write_thing") == "a:write"


def test_registering_an_unknown_scope_is_refused() -> None:
    policy = ScopePolicy(ScopeSet(["a:read"]), {})

    with pytest.raises(ConfigurationError, match="not in the vocabulary"):
        policy.add("w", "a:write")


def test_as_mapping_round_trips() -> None:
    """`ResourceServerConfig.validate` rebuilds the policy from this, so it has
    to be faithful or validation checks a different object than the one used."""
    original = ScopePolicy(ScopeSet(["a:read"]), {"r": "a:read", "who": NO_SCOPE})

    rebuilt = ScopePolicy(original.vocabulary, original.as_mapping())

    assert rebuilt.as_mapping() == original.as_mapping()
    assert rebuilt.scopes_supported == original.scopes_supported


def test_membership_and_iteration() -> None:
    scopes = ScopeSet(["a:read", "a:write"])

    assert "a:read" in scopes
    assert "a:delete" not in scopes
    assert list(scopes) == ["a:read", "a:write"]
    assert scopes.in_vocabulary("a:write") is True
    assert scopes.in_vocabulary("nope") is False
