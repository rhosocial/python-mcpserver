# tests/rhosocial/mcpserver_test/test_tables.py
"""Table and index naming, and the collision it exists to prevent."""

from __future__ import annotations

import pytest

from rhosocial.mcpserver import ConfigurationError, TableNamespace


def test_names_are_prefixed() -> None:
    ns = TableNamespace("sm")

    assert ns.table("users") == "sm_users"
    assert ns.index("users", "email") == "idx_sm_users_email"
    assert ns.unique_constraint("users", ("central_user_id",)) == (
        "uq_sm_users_central_user_id"
    )


def test_two_services_cannot_collide_on_an_index() -> None:
    """The failure this prevents: PostgreSQL puts every index in one namespace,
    so two services both creating ``idx_users_email`` do not merely clash on
    lookup — the second ``CREATE TABLE`` fails and takes the deploy with it."""
    schedule = TableNamespace("sm")
    contact = TableNamespace("cm")

    assert schedule.index("users", "email") != contact.index("users", "email")
    assert schedule.table("users") != contact.table("users")


def test_a_trailing_underscore_in_the_prefix_is_normalised() -> None:
    """``"sm_"`` and ``"sm"`` must not produce ``sm__users`` on one side and
    ``sm_users`` on the other — that is a silent divergence between two
    services that believe they share a prefix."""
    assert TableNamespace("sm_").table("users") == TableNamespace("sm").table("users")


def test_index_takes_an_unprefixed_table_name() -> None:
    """Documenting the double-prefix, because the signature cannot prevent it.

    ``index`` takes the bare table name so ``idx_sm_sm_users_email`` is visibly
    wrong at the call site rather than silently created.  It cannot be *rejected*
    — the doubled name is a valid identifier — which is why a model that reads
    its table name back from ``TableNamespace`` (which is what
    ``__table_name__`` should be) is the real protection.
    """
    ns = TableNamespace("sm")

    assert ns.index("users", "email") == "idx_sm_users_email"
    assert ns.index("sm_users", "email") == "idx_sm_sm_users_email"


def test_empty_prefix_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="empty"):
        TableNamespace("  ")


def test_prefix_with_anything_but_an_identifier_is_refused() -> None:
    for prefix in ("sm-users", "1sm", "sm.users", "sm users", 'sm"'):
        with pytest.raises(ConfigurationError, match="bare SQL identifier"):
            TableNamespace(prefix)


def test_over_long_name_is_refused_at_construction_time() -> None:
    """PostgreSQL truncates at 63 bytes.  Truncation turns distinct names into
    one, so it has to fail here rather than silently collide in the database."""
    ns = TableNamespace("a_very_long_service_prefix_for_testing_only")

    with pytest.raises(ConfigurationError, match="identifier limit"):
        ns.table("a_table_name_that_pushes_the_total_past_the_limit_for_sure")


def test_name_at_exactly_the_limit_is_accepted() -> None:
    ns = TableNamespace("a_very_long_service_prefix_for_testing_only")
    prefix = len("a_very_long_service_prefix_for_testing_only")
    budget = 63 - prefix - 1  # "a_" + name must fit in 63

    name = ns.table("x" * budget)

    assert len(name.encode()) == 63


def test_prefix_is_exposed() -> None:
    assert TableNamespace("SM").prefix == "sm"
