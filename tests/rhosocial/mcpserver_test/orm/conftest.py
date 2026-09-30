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
    TableNamespace,
    create_projection_table,
    ensure_principal_id,
    projection_indexes,
)
from rhosocial.mcpserver.identity import set_current_principal

TABLES = TableNamespace("t_")

__table_name__ = TABLES.table("notes")
__query_class__ = PrincipalScopedQuery


class NotePrincipal(AsyncActiveRecord, PrincipalMixin):
    """The projection table: central id plus service-private state.

    No password, no email, no profile — a projection, not a copy.  See
    ``orm/principal.py``.
    """

    __table_name__ = TABLES.table("principals")
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

    __table_name__ = TABLES.table("notes")
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
        create_projection_table(dialect, TABLES),
        *projection_indexes(dialect, TABLES),
    ):
        await backend.execute(*expression.to_sql())
    await backend.execute(
        *_create_notes_table(dialect, TABLES.table("notes")).to_sql()
    )
    await backend.execute(
        *_create_notes_index(dialect, TABLES).to_sql()
    )
    # `Model.configure` is per-class, so each model is pointed at the same
    # backend instance here.  A production service uses a shared pool
    # published on a ContextVar instead — see schedule-manager's `db.py`; for a
    # single-process test, one backend for both models is enough.
    await Note.configure(config, type(backend))
    await NotePrincipal.configure(config, type(backend))
    # The ownership hooks resolve through this; a process serves one service, so
    # there is exactly one projection table.
    NotePrincipal.register_as_projection()
    return TABLES


def _create_notes_table(dialect, table: str):
    from rhosocial.activerecord.backend.expression import CreateTableExpression

    from rhosocial.mcpserver.orm.ddl import column, serial_type_for

    return CreateTableExpression(
        dialect=dialect,
        table=table,
        columns=[
            column(dialect, "id", serial_type_for(dialect), primary_key=True),
            column(dialect, "principal_id", "INTEGER", not_null=True),
            column(dialect, "title", "TEXT", not_null=True),
        ],
        if_not_exists=True,
    )


def _create_notes_index(dialect, tables: TableNamespace):
    from rhosocial.activerecord.backend.expression import CreateIndexExpression

    return CreateIndexExpression(
        dialect,
        tables.index(tables.table("notes"), "principal_id"),
        tables.table("notes"),
        ["principal_id"],
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
