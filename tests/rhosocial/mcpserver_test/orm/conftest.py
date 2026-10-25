# tests/rhosocial/mcpserver_test/orm/conftest.py
"""Real SQLite models, so the ownership rules are checked against real SQL.

A mock cannot see what reaches the WHERE clause, and what reaches the WHERE
clause is the entire subject.  Every test here writes rows as one principal and
reads them as another.
"""

from __future__ import annotations

from datetime import datetime
from typing import ClassVar

import pytest
from rhosocial.activerecord.backend.impl.sqlite.backend.async_backend import AsyncSQLiteBackend
from rhosocial.activerecord.backend.impl.sqlite.config import SQLiteConnectionConfig
from rhosocial.activerecord.base.field_proxy import FieldProxy
from rhosocial.activerecord.model import AsyncActiveRecord

from rhosocial.mcpserver import (
    Principal,
    PrincipalMixin,
    PrincipalOwnedMixin,
    PrincipalScopedQuery,
    create_projection_table,
    ensure_principal_id,
    projection_indexes,
)
from rhosocial.mcpserver.identity import set_current_principal

#: Imported, not redefined.  A test that spelled the projection table out for
#: itself could drift from the DDL builder, and then every test in this file
#: fails with "no such table" -- which is loud, but it fails for a reason that
#: has nothing to do with what the tests are checking.
from rhosocial.mcpserver.orm.ddl import PRINCIPALS  # noqa: E402

#: The test's own table, prefixed so it cannot be mistaken for a service table.
NOTES = "t_notes"

__table_name__ = NOTES
__query_class__ = PrincipalScopedQuery


class NotePrincipal(AsyncActiveRecord, PrincipalMixin):
    """The projection table: central id plus service-private state.

    No password, no email, no profile — a projection, not a copy.  See
    ``orm/principal.py``.
    """

    __table_name__ = PRINCIPALS
    __pk_auto_generated__ = True

    c: ClassVar[FieldProxy] = FieldProxy()

    id: int | None = None
    central_user_id: str = ""
    status: str = PrincipalMixin.STATUS_ACTIVE
    provided_by: str | None = None
    #: Declared even though nothing writes it here, because the DDL builder
    #: emits the column and `SELECT *` would otherwise hand the row hydrator one
    #: it has no field for.  A service's projection model must declare every
    #: column the shared DDL creates.
    provisioned_at: datetime | None = None


class Note(PrincipalOwnedMixin, AsyncActiveRecord):
    """A row owned by exactly one principal."""

    __table_name__ = NOTES
    __pk_auto_generated__ = True
    __query_class__ = PrincipalScopedQuery

    c: ClassVar[FieldProxy] = FieldProxy()

    id: int | None = None
    #: Placeholder only.  `PrincipalOwnedMixin.prepare_save_data` overwrites it
    #: on every write, so whatever a caller supplies is never what is stored.
    principal_id: int = 0
    title: str = ""


def principal_for(central_user_id: str) -> Principal:
    return Principal(central_user_id=central_user_id, client_id="test-client")


@pytest.fixture
def config(tmp_path):
    return SQLiteConnectionConfig(database=str(tmp_path / "mcpserver_test.db"))


@pytest.fixture
async def backend(config):
    backend = AsyncSQLiteBackend(config)
    try:
        yield backend
    finally:
        await backend.disconnect()


@pytest.fixture
async def tables(backend, config):
    """Create the projection table and the note table."""
    dialect = backend.dialect
    for expression in (
        create_projection_table(dialect),
        *projection_indexes(dialect),
    ):
        await backend.execute(*expression.to_sql())
    await backend.execute(
        *_create_notes_table(dialect, NOTES).to_sql()
    )
    await backend.execute(
        *_create_notes_index(dialect).to_sql()
    )
    # `Model.configure` is per-class: each call builds its *own* backend and
    # opens its *own* connection.  That is the trap schedule-manager's `db.py`
    # exists to avoid, and a test that uses `configure` inherits it — so the
    # teardown below closes them.
    #
    # Without this the pytest process finishes the tests and then never exits:
    # aiosqlite runs each connection on a non-daemon thread, so a leaked
    # connection keeps the interpreter alive indefinitely.  pytest reports
    # "187 passed" and the job hangs until it is cancelled, which is how this
    # cost 25 minutes of CI before it was found.
    await Note.configure(config, type(backend))
    await NotePrincipal.configure(config, type(backend))
    # The ownership hooks resolve through this; a process serves one service, so
    # there is exactly one projection table.
    NotePrincipal.register_as_projection()
    yield NOTES
    for model in (Note, NotePrincipal):
        await model.backend().disconnect()


def _create_notes_table(dialect, table: str):
    from rhosocial.activerecord.backend.expression.objects import Table as TableNode
    from rhosocial.activerecord.backend.expression.statements.ddl_table import (
        CreateTableStatement,
    )

    from rhosocial.mcpserver.orm.ddl import column, serial_type_for

    return CreateTableStatement(
        dialect=dialect,
        table=TableNode(dialect, table),
        columns=[
            column(dialect, "id", serial_type_for(dialect), primary_key=True),
            column(dialect, "principal_id", "INTEGER", not_null=True),
            column(dialect, "title", "TEXT", not_null=True),
        ],
        if_not_exists=True,
    )


def _create_notes_index(dialect):
    from rhosocial.activerecord.backend.expression.objects import Index as IndexNode
    from rhosocial.activerecord.backend.expression.objects import Table as TableNode
    from rhosocial.activerecord.backend.expression.statements.ddl_index import (
        CreateIndexStatement,
    )

    return CreateIndexStatement(
        dialect,
        index=IndexNode(dialect, f"idx_{NOTES}_principal_id"),
        table=TableNode(dialect, NOTES),
        columns=["principal_id"],
        if_not_exists=True,
    )


@pytest.fixture
async def as_principal():
    """Bind an identity *and* resolve its projection, exactly as middleware does.

    Both halves are needed: the identity is what ``current_principal`` reads and
    the resolved id is what the two enforcement points read.  Setting only the
    first is the wiring mistake ``PrincipalNotResolved`` names, so the fixture
    would be testing less than production if it did not also resolve.

    Async because resolving may create a row, and a sync fixture cannot drive
    the loop the async test is already running on — the same reason the
    production code resolves in middleware rather than in the hooks.
    """
    from rhosocial.mcpserver.identity import _principal as _http_principal
    from rhosocial.mcpserver.orm.principal import _principal_id

    async def bind(central_user_id: str) -> Principal:
        # `set_current_principal` returns a reset token, not the principal, so
        # the principal is built here and passed to both.
        principal = principal_for(central_user_id)
        set_current_principal(principal)
        _principal_id.set(None)
        await ensure_principal_id(principal)
        return principal

    yield bind

    _http_principal.set(None)
    _principal_id.set(None)


@pytest.fixture
async def identity():
    """Bind an identity *without* resolving its projection.

    The complement of ``as_principal``: tests about provisioning itself need the
    row not to exist yet, and a fixture that resolves on bind would defeat them.
    """
    from rhosocial.mcpserver.identity import _principal as _http_principal
    from rhosocial.mcpserver.orm.principal import _principal_id

    def bind(central_user_id: str) -> Principal:
        _principal_id.set(None)
        return set_current_principal(principal_for(central_user_id))

    yield bind

    _http_principal.set(None)
    _principal_id.set(None)
