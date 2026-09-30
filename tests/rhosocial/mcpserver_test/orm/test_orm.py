# tests/rhosocial/mcpserver_test/orm/test_orm.py
"""The read and write enforcement points, against a real database.

Every test writes as one principal and reads as another.  A mock would not see
the WHERE clause, and the WHERE clause is the entire subject.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from rhosocial.mcpserver import (
    ProvisioningError,
    Unauthenticated,
    assert_protected,
    current_principal_id,
)
from rhosocial.mcpserver.orm.principal import (
    clear_principal_id,
    publish_principal_id,
)

from .conftest import Note, NotePrincipal


@pytest.fixture(autouse=True)
def _no_leaked_memo():
    """The principal-id memo is request-scoped; a leaked one would make a test
    pass for the wrong reason.

    Cleared with ``set`` rather than a saved token, because ``reset`` refuses a
    token created in a different context — and a sync fixture's teardown runs in
    a different context from the async test body that bound it.
    """
    from rhosocial.mcpserver.orm.principal import _principal_id

    _principal_id.set(None)
    yield
    _principal_id.set(None)


# -- provisioning --------------------------------------------------------


async def test_first_use_creates_the_projection(tables, identity) -> None:
    identity("u-1")

    principal_id = await NotePrincipal.resolve()

    assert principal_id is not None
    row = await NotePrincipal.query().one()
    assert row.central_user_id == "u-1"
    assert row.status == "active"
    assert row.provided_by == "test-client"


async def test_second_use_does_not_create_a_second_row(tables, identity) -> None:
    identity("u-1")
    first = await NotePrincipal.resolve()
    second = await NotePrincipal.resolve()

    assert first == second
    assert len(await NotePrincipal.query().all()) == 1


async def test_two_principals_get_different_rows(tables, identity) -> None:
    identity("u-1")
    one = await NotePrincipal.resolve()
    identity("u-2")
    two = await NotePrincipal.resolve()

    assert one != two
    assert len(await NotePrincipal.query().all()) == 2


async def test_resolve_without_an_identity_fails_closed(tables) -> None:
    with pytest.raises(Unauthenticated):
        await NotePrincipal.resolve()


async def test_provisioning_failure_is_not_an_authentication_failure(
    tables, identity, monkeypatch
) -> None:
    """A valid credential against a database that will not accept writes needs
    a different answer from a bad credential, or an operator is told to rotate
    something that is fine."""

    async def explode(self):
        raise RuntimeError("disk is on fire")

    identity("u-1")
    # Patched at the save, not at `_create`: `_create` is where the error is
    # *classified*, so replacing it would remove the thing under test.
    monkeypatch.setattr(NotePrincipal, "save", explode)

    with pytest.raises(ProvisioningError, match="could not provision"):
        await NotePrincipal.resolve()


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (RuntimeError("UNIQUE constraint failed: t_principals.central_user_id"), True),
        (RuntimeError("duplicate key value violates unique constraint"), True),
        (RuntimeError("IntegrityError: 1062 Duplicate entry"), True),
        (RuntimeError("disk is on fire"), False),
    ],
)
def test_unique_violations_are_recognised_across_drivers(error, expected) -> None:
    """A wrong positive costs one re-read; a wrong negative costs a 500 on a
    user's very first request to the service."""
    from rhosocial.mcpserver.orm.principal import _is_unique_violation

    assert _is_unique_violation(error) is expected


def test_sqlstate_is_preferred_over_the_message() -> None:
    """A driver that reports the state is trusted over the wording, which is
    localised and driver-specific."""
    from rhosocial.mcpserver.orm.principal import _is_unique_violation

    class WithState(Exception):
        sqlstate = "23505"

    assert _is_unique_violation(WithState("something unrelated")) is True
    assert _is_unique_violation(RuntimeError("something unrelated")) is False


async def test_a_unique_violation_resolves_to_the_winner(tables, identity, monkeypatch) -> None:
    """Two concurrent first requests must both end up with the same row.  The
    loser re-reads rather than retrying the insert, which under PostgreSQL would
    raise the same violation again."""
    real_save = NotePrincipal.save
    competitor_inserted = False

    async def lose_the_race(self):
        nonlocal competitor_inserted
        if not competitor_inserted:
            # The other request's insert lands between our SELECT and ours.
            competitor_inserted = True
            await real_save(NotePrincipal(central_user_id=self.central_user_id))
        raise RuntimeError("UNIQUE constraint failed: t_principals.central_user_id")

    identity("u-1")
    monkeypatch.setattr(NotePrincipal, "save", lose_the_race)

    resolved = await NotePrincipal.resolve()

    assert resolved == 1
    assert len(await NotePrincipal.query().all()) == 1


async def test_resolve_rejects_recursion(tables, identity) -> None:
    """A projection resolve that needs another projection would recurse; the
    guard turns that into a named error instead of a stack overflow."""
    from rhosocial.mcpserver.orm.principal import _provisioning

    identity("u-1")
    _provisioning.set(("NotePrincipal",))
    try:
        with pytest.raises(ProvisioningError, match="re-entered itself"):
            await NotePrincipal.resolve(_Recursing())
    finally:
        _provisioning.set(())


class _Recursing:
    """A stand-in principal: ``resolve`` only reads ``central_user_id``."""

    central_user_id = "u-1"


# -- the read side -------------------------------------------------------


async def test_a_query_only_sees_its_own_rows(tables, as_principal) -> None:
    await as_principal("u-1")
    await Note(title="mine").save()
    await as_principal("u-2")
    await Note(title="theirs").save()

    assert [n.title for n in await Note.query().all()] == ["theirs"]


async def test_find_by_id_cannot_reach_another_principal(tables, as_principal) -> None:
    """A caller cannot reach another principal's row by passing its id — the
    predicate is already in the query, not in the tool."""
    await as_principal("u-1")
    victim = Note(title="mine")
    await victim.save()
    await as_principal("u-2")

    found = await Note.query().where(Note.c.id == victim.id).one()

    assert found is None


async def test_count_does_not_see_another_principal(tables, as_principal) -> None:
    """`count` funnels through `aggregate()` while `all()` goes through
    `to_sql()`.  A per-terminal override that missed one of them raises nothing
    and returns the wrong count, so both are checked."""
    await as_principal("u-1")
    await Note(title="a").save()
    await Note(title="b").save()
    await as_principal("u-2")
    await Note(title="c").save()

    assert await Note.query().count() == 1
    assert len(await Note.query().all()) == 1


async def test_exists_does_not_see_another_principal(tables, as_principal) -> None:
    await as_principal("u-1")
    victim = Note(title="mine")
    await victim.save()
    await as_principal("u-2")

    assert await Note.query().where(Note.c.id == victim.id).exists() is False


async def test_update_all_cannot_reach_another_principal(tables, as_principal) -> None:
    await as_principal("u-1")
    victim = Note(title="mine")
    await victim.save()
    await as_principal("u-2")

    await Note.query().where(Note.c.id == victim.id).update_all({"title": "stolen"})

    await as_principal("u-1")
    assert (await Note.query().one()).title == "mine"


async def test_delete_all_cannot_reach_another_principal(tables, as_principal) -> None:
    await as_principal("u-1")
    victim = Note(title="mine")
    await victim.save()
    await as_principal("u-2")

    await Note.query().where(Note.c.id == victim.id).delete_all()

    await as_principal("u-1")
    assert len(await Note.query().all()) == 1


# -- the write side ------------------------------------------------------


async def test_ownership_is_never_taken_from_the_caller(tables, as_principal) -> None:
    await as_principal("u-2")

    note = Note(title="mine", principal_id=9999)
    await note.save()

    assert note.principal_id == (await NotePrincipal.resolve())
    assert note.principal_id != 9999


async def test_the_instance_and_the_stored_row_agree(tables, as_principal) -> None:
    """The framework hands `prepare_save_data` a payload, not the model, so
    without the in-memory write the two would disagree for the rest of the
    request."""
    await as_principal("u-1")

    note = Note(title="mine")
    await note.save()

    stored = await Note.query().one()
    assert stored.principal_id == note.principal_id


async def test_a_row_cannot_be_transferred_out(tables, as_principal) -> None:
    """Ownership follows the *writer*, not the row.

    The realistic shape of an attempted transfer is a long-lived object handed
    between requests, or a stale instance saved by code that was mid-switch.  The
    save hook reassigns the row to whoever is saving, so a row cannot leave its
    principal's set by being written by somebody else.
    """
    await as_principal("u-1")
    note = Note(title="mine")
    await note.save()
    original_owner = note.principal_id

    await as_principal("u-2")
    note.title = "edited by the other principal"
    note.principal_id = original_owner  # explicitly asking to keep u-1 as owner
    await note.save()

    await as_principal("u-1")
    assert await Note.query().count() == 0, "the row left u-1"
    await as_principal("u-2")
    assert (await Note.query().one()).title == "edited by the other principal"


async def test_unscoped_reaches_every_row(tables, as_principal) -> None:
    """Management plane only.  The loud name is what makes `grep` find the
    uses."""
    await as_principal("u-1")
    await Note(title="mine").save()
    await as_principal("u-2")
    await Note(title="theirs").save()

    assert len(await Note.unscoped().all()) == 2


# -- the memo ------------------------------------------------------------


async def test_the_memo_survives_within_one_request(tables, as_principal) -> None:
    await as_principal("u-1")

    first = current_principal_id()
    second = current_principal_id()

    assert first == second
    assert len(await NotePrincipal.query().all()) == 1


async def test_a_published_memo_is_used(tables, as_principal) -> None:
    """Middleware resolves once per request and publishes; the hot path is then
    a ContextVar read rather than a query per model."""
    await as_principal("u-1")
    resolved = await NotePrincipal.resolve()

    reset = publish_principal_id(resolved)
    try:
        assert current_principal_id() == resolved
    finally:
        clear_principal_id(reset)


async def test_a_management_resolve_is_not_memoised(tables, as_principal) -> None:
    """Caching an explicit principal under the request's own memo would make
    the next `current_principal_id()` return the wrong user."""
    await as_principal("u-1")
    other = NotePrincipal(central_user_id="u-9", status="active")
    await other.save()
    other_id = int(other.id)

    from rhosocial.mcpserver import Principal

    await NotePrincipal.resolve(Principal(central_user_id="u-9", client_id="admin"))

    assert current_principal_id() != other_id


# -- the startup guard ---------------------------------------------------


def test_a_fully_protected_model_passes() -> None:
    assert_protected(Note)


def test_a_model_without_the_query_class_is_refused() -> None:
    class UnprotectedRead(Note):
        __query_class__ = None  # type: ignore[assignment]

    with pytest.raises(TypeError, match="not read-protected"):
        assert_protected(UnprotectedRead)


def test_a_model_without_the_owned_mixin_is_refused() -> None:
    from rhosocial.activerecord.base.field_proxy import FieldProxy
    from rhosocial.activerecord.model import AsyncActiveRecord

    from rhosocial.mcpserver import PrincipalScopedQuery

    class UnprotectedWrite(AsyncActiveRecord):
        __table_name__ = "t_notes"
        __query_class__ = PrincipalScopedQuery
        c: ClassVar[FieldProxy] = FieldProxy()

        id: int | None = None
        principal_id: int = 0
        title: str = ""

    with pytest.raises(TypeError, match="not write-protected"):
        assert_protected(UnprotectedWrite)


def test_the_projection_itself_is_not_principal_scoped() -> None:
    """It is deliberately unscoped, because management commands need
    cross-principal reads — which is also why it must never be an MCP tool."""
    from rhosocial.mcpserver import PrincipalScopedQuery

    assert NotePrincipal.__query_class__ is not PrincipalScopedQuery
