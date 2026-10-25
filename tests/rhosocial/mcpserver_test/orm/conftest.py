# tests/rhosocial/mcpserver_test/orm/conftest.py
"""Real SQLite models, so the ownership rules are checked against real SQL.

A mock cannot see what reaches the WHERE clause, and what reaches the WHERE
clause is the entire subject.  Every test here writes rows as one principal and
reads them as another.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import pathlib
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar

import pytest
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


def pytest_asyncio_loop_factories(config, item):
    """Use a selector loop on Windows, as the service's CLI does.

    psycopg refuses the ProactorEventLoop, and the server scenarios are the
    reason this hook exists; SQLite is happy either way.
    """
    del config, item
    if sys.platform == "win32":
        return {"selector": asyncio.SelectorEventLoop}
    return {"default": asyncio.new_event_loop}

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


@dataclass(frozen=True)
class _Backend:
    """The backend under test: its name, class and connection config."""

    name: str
    backend_cls: type
    config: Any


#: ``${NAME}`` / ``${NAME:-default}`` in the scenario file.  Kept tiny on
#: purpose: the file is read by tests, not by a template engine.
_EXPAND = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand(value: Any) -> Any:
    if not isinstance(value, str):
        return value

    def substitute(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        if name in os.environ:
            return os.environ[name]
        if default is not None:
            return default
        raise RuntimeError(f"scenario variable {name} is not set and has no default")

    return _EXPAND.sub(substitute, value)


def _import_fqn(qualified_name: str) -> Any:
    """Import ``module.Class`` and return the attribute."""
    module_name, _, attribute = qualified_name.rpartition(".")
    if not module_name or not attribute:
        raise RuntimeError(f"{qualified_name!r} is not a fully qualified name")
    return getattr(importlib.import_module(module_name), attribute)


def _load_scenario(name: str) -> dict[str, Any]:
    import yaml

    path = pathlib.Path(__file__).resolve().parents[3] / "config" / "scenarios.yaml"
    with path.open(encoding="utf-8") as handle:
        document = yaml.safe_load(handle)
    try:
        scenario = document["scenarios"][name]
    except KeyError:
        available = ", ".join(sorted(document.get("scenarios", {})))
        raise RuntimeError(f"unknown scenario {name!r}; available: {available}") from None
    return {key: _expand(value) for key, value in scenario.items()}


def _select_backend(tmp_path) -> _Backend:
    """Build the backend named by ``MCP_TEST_SCENARIO`` (default: sqlite).

    Every scenario names two classes: ``backend`` and ``connection_config``,
    both fully qualified.  The remaining keys are passed to the config
    constructor unchanged, so adding a backend needs no code here.
    """
    name = os.getenv("MCP_TEST_SCENARIO", "sqlite")
    scenario = _load_scenario(name)
    backend_cls = _import_fqn(str(scenario.pop("backend")))
    config_cls = _import_fqn(str(scenario.pop("connection_config")))

    if backend_cls.__name__ == "AsyncSQLiteBackend" and not scenario.get("database"):
        scenario["database"] = str(tmp_path / "mcpserver_test.db")
    if "port" in scenario:
        scenario["port"] = int(scenario["port"])

    return _Backend(name, backend_cls, config_cls(**scenario))


@pytest.fixture
def backend_spec(tmp_path) -> _Backend:
    return _select_backend(tmp_path)


@pytest.fixture
async def backend(backend_spec):
    backend = backend_spec.backend_cls(connection_config=backend_spec.config)
    try:
        await backend.connect()
        await backend.introspect_and_adapt()
        yield backend
    finally:
        await backend.disconnect()


@pytest.fixture
async def tables(backend, backend_spec):
    """Create the projection table and the note table.

    Server backends share one database across tests, so the tables are dropped
    first: a second test would otherwise collide on an index that the backend
    cannot create with ``IF NOT EXISTS``.  The first drop on Oracle raises
    ``ORA-00942`` because that dialect has no ``IF EXISTS``; it is ignored.
    """
    dialect = backend.dialect
    from rhosocial.activerecord.backend.expression.objects import Table as TableNode
    from rhosocial.activerecord.backend.expression.statements.ddl_table import (
        DropTableStatement,
    )

    for table_name in (NOTES, PRINCIPALS):
        try:
            await backend.execute(
                *DropTableStatement(
                    dialect,
                    table=TableNode(dialect, table_name),
                    if_exists=True,
                ).to_sql()
            )
        except Exception:  # noqa: BLE001 - the first drop on Oracle has no IF EXISTS
            pass

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
    await Note.configure(backend_spec.config, type(backend))
    await NotePrincipal.configure(backend_spec.config, type(backend))
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

    from rhosocial.mcpserver.orm.ddl import column

    return CreateTableStatement(
        dialect=dialect,
        table=TableNode(dialect, table),
        columns=[
            column(dialect, "id", "INTEGER", primary_key=True),
            column(dialect, "principal_id", "INTEGER", not_null=True),
            column(dialect, "title", "VARCHAR(255)", not_null=True),
        ],
        if_not_exists=True,
    )


def _create_notes_index(dialect):
    from rhosocial.activerecord.backend.expression.objects import Index as IndexNode
    from rhosocial.activerecord.backend.expression.objects import Table as TableNode
    from rhosocial.activerecord.backend.expression.statements.ddl_index import (
        CreateIndexStatement,
    )

    # The notes table is dropped and rebuilt for every test, so the index
    # cannot already exist; MySQL and SQL Server reject IF NOT EXISTS anyway.
    return CreateIndexStatement(
        dialect,
        index=IndexNode(dialect, f"idx_{NOTES}_principal_id"),
        table=TableNode(dialect, NOTES),
        columns=["principal_id"],
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
