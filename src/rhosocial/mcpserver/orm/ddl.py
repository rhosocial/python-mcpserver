# src/rhosocial/mcpserver/orm/ddl.py
"""DDL for the principal projection table.

Kept out of ``models/`` on purpose, and for the same reason
``schedule-manager`` and ``contact-manager`` keep it out: the core library
presents DDL *declarations* but leaves rendering and execution to the consumer.
Models own the Python side; this module owns the SQL side.

There is no migration path.  Every statement is ``IF NOT EXISTS``, which means
DDL is the schema — a database carrying an older shape is not something this
library upgrades in place.  A library that shipped migration machinery would
have to own the migration history of every service using it, which is a
different and much larger product.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from rhosocial.activerecord.backend.dialect.exceptions import UnsupportedFeatureError
from rhosocial.activerecord.backend.dialect.protocols.ddl.auto_increment import (
    AutoIncrementColumnSupport,
)
from rhosocial.activerecord.backend.dialect.protocols.ddl.identity_column import (
    IdentityColumnSupport,
)
from rhosocial.activerecord.backend.dialect.protocols.ddl.index.create_index import (
    CreateIndexSupport,
)
from rhosocial.activerecord.backend.dialect.protocols.query.data_type import (
    DataTypeSupport,
)
from rhosocial.activerecord.backend.expression.objects import Index as IndexNode
from rhosocial.activerecord.backend.expression.objects import Table as TableNode
from rhosocial.activerecord.backend.expression.statements.ddl_index import (
    CreateIndexStatement,
)
from rhosocial.activerecord.backend.expression.statements.ddl_table import (
    ColumnConstraint,
    ColumnDefaultConstraint,
    ColumnDefinition,
    ColumnForeignKeyConstraint,
    ColumnNotNullConstraint,
    ColumnPrimaryKeyConstraint,
    ColumnUniqueConstraint,
    CreateTableStatement,
    DropTableStatement,
)

from .principal import (
    CENTRAL_USER_ID,
    ID,
    PROVIDED_BY,
    PROVISIONED_AT,
    STATUS,
)

if TYPE_CHECKING:  # pragma: no cover
    from rhosocial.activerecord.backend.dialect.base import SQLDialectBase

__all__ = [
    "create_projection_table",
    "projection_indexes",
    "drop_projection_table",
    "create_projection_schema",
    "drop_projection_schema",
    "PRINCIPALS",
    "TIMESTAMP",
]

#: The projection table. A literal, not a name plus a configurable prefix: this
#: package declares one table, and a deployment that needs another name
#: overrides ``Model.table_name()`` and passes the same string here.
PRINCIPALS = "mcp_principals"


def _type_support(dialect: SQLDialectBase) -> DataTypeSupport:
    """Return *dialect* as a :class:`DataTypeSupport`, or fail clearly.

    ``SQLDialectBase`` does not declare ``parse_type``; concrete dialects add it
    through their type mixins.  Checking the capability here keeps the rest of
    the module honest: a dialect that lacks it fails with a named error instead
    of an ``AttributeError`` from inside a half-built DDL statement.
    """
    if not isinstance(dialect, DataTypeSupport):
        raise UnsupportedFeatureError(
            type(dialect).__name__,
            "data type parsing",
            "DDL rendering needs the DataTypeSupport capability",
        )
    return dialect


def _timestamp_type(dialect: SQLDialectBase) -> str:
    """The dialect's spelling for a timestamp with a time zone.

    SQL Server calls it ``DATETIMEOFFSET`` and parses the SQL-standard form as
    an opaque ``CustomType``; every other supported backend accepts
    ``TIMESTAMP WITH TIME ZONE``.  The spelling is chosen by asking the type
    parser, not by naming a backend.
    """
    support = _type_support(dialect)
    for spelling in ("TIMESTAMP WITH TIME ZONE", "DATETIMEOFFSET"):
        if type(support.parse_type(spelling)).__name__ != "CustomType":
            return spelling
    raise UnsupportedFeatureError(
        type(dialect).__name__,
        "timestamp with time zone",
        "no supported spelling parses as a timestamp type",
    )


def _index_if_not_exists(dialect: SQLDialectBase) -> bool:
    """Whether the dialect accepts ``CREATE INDEX IF NOT EXISTS``.

    MySQL, SQL Server and Oracle reject the modifier.  The projection schema
    creates its indexes only after its tables, so a fresh table makes the
    modifier unnecessary there; callers re-running against an existing table
    must drop it first.
    """
    return isinstance(dialect, CreateIndexSupport) and dialect.supports_index_if_not_exists()


def _generates_primary_key(dialect: SQLDialectBase) -> bool:
    """Whether the dialect needs an explicit generated-key clause.

    SQLite needs none: ``INTEGER PRIMARY KEY`` *is* the rowid alias.  Every
    other supported backend expresses generation through a column clause, and
    the capability probes are how the dialect says which mechanism it has:
    ``AUTO_INCREMENT`` (MySQL, MariaDB) or SQL-standard ``GENERATED ... AS
    IDENTITY`` (PostgreSQL, SQL Server, Oracle).
    """
    if isinstance(dialect, AutoIncrementColumnSupport) and dialect.supports_auto_increment_column():
        return True
    if isinstance(dialect, IdentityColumnSupport) and dialect.supports_identity_column():
        return True
    return False

#: ``TIMESTAMP WITH TIME ZONE``.  Chosen over a naive timestamp because a
#: projection's ``provisioned_at`` is compared against an AS clock and against
#: this service's clock, and a naive column cannot answer either correctly
#: across a DST boundary.
TIMESTAMP = "TIMESTAMP WITH TIME ZONE"


def create_projection_table(
    dialect: SQLDialectBase,
    *,
    extra_columns: Sequence[Any] = (),
) -> CreateTableStatement:
    """``CREATE TABLE IF NOT EXISTS <prefix>_principals``.

    :param extra_columns: service-private ``ColumnDefinition`` objects, built
        by the caller so this module does not have to know their types.
    """
    return CreateTableStatement(
        dialect=dialect,
        table=TableNode(dialect, PRINCIPALS),
        columns=[
            column(dialect, ID, "INTEGER", primary_key=True),
            # VARCHAR, not TEXT: MySQL and MariaDB refuse to index a TEXT
            # column without a prefix length, and this column carries the
            # unique index that makes concurrent provisioning collapse onto
            # one row.  255 is the portable upper bound for that index.
            column(dialect, CENTRAL_USER_ID, "VARCHAR(255)", not_null=True),
            column(dialect, STATUS, "VARCHAR(32)", not_null=True, default="active"),
            column(dialect, PROVIDED_BY, "VARCHAR(255)"),
            column(dialect, PROVISIONED_AT, _timestamp_type(dialect)),
            *extra_columns,
        ],
        if_not_exists=True,
    )


def projection_indexes(
    dialect: SQLDialectBase,
) -> tuple[CreateIndexStatement, ...]:
    """Indexes for the projection table.

    The unique index on ``central_user_id`` is the one that matters: it is what
    makes concurrent first requests collapse onto one row instead of two, and
    it is what the provisioning race-detection relies on to notice it lost.

    Note this is a *unique index* rather than a ``UNIQUE`` constraint.  Both
    enforce the same thing, but index names are schema-global in PostgreSQL
    while constraint names are table-scoped — and a name that collides on
    ``CREATE TABLE`` takes the whole statement down.
    """
    # `index` takes the *bare* table name; passing the already-prefixed one
    # would produce `idx_t_t_principals_...`, which is a valid identifier and so
    # would be created without complaint.
    table = TableNode(dialect, PRINCIPALS)
    if_not_exists = _index_if_not_exists(dialect)
    return (
        CreateIndexStatement(
            dialect,
            index=IndexNode(dialect, f"idx_{PRINCIPALS}_CENTRAL_USER_ID"),
            table=table,
            columns=[CENTRAL_USER_ID],
            unique=True,
            if_not_exists=if_not_exists,
        ),
        CreateIndexStatement(
            dialect,
            index=IndexNode(dialect, f"idx_{PRINCIPALS}_STATUS"),
            table=table,
            columns=[STATUS],
            if_not_exists=if_not_exists,
        ),
    )


def drop_projection_table(
    dialect: SQLDialectBase,
) -> DropTableStatement:
    """``DROP TABLE IF EXISTS`` for the projection table.

    Only ever touches a prefixed name.  A service's database may be shared, and
    dropping another service's tables would destroy its data.
    """
    return DropTableStatement(
        dialect=dialect,
        table=TableNode(dialect, PRINCIPALS),
        if_exists=True,
    )


def _sql_type(dialect: SQLDialectBase, raw: str) -> str:
    """A spelling of *raw* the dialect can parse.

    Only ``TEXT`` is remapped: Oracle has no such type, and the closest
    bounded string (``VARCHAR(4000)``) is also what an index needs.  Any other
    spelling the parser does not recognise is passed through unchanged -- it
    may be a dialect-specific type the caller deliberately asked for, and
    guessing a replacement would be worse than letting the server decide.
    """
    support = _type_support(dialect)
    if type(support.parse_type(raw)).__name__ != "CustomType":
        return raw
    if raw.upper() == "TEXT":
        for alternative in ("VARCHAR(4000)", "VARCHAR2(4000)"):
            if type(support.parse_type(alternative)).__name__ != "CustomType":
                return alternative
    return raw


def column(
    dialect: SQLDialectBase,
    name: str,
    sql_type: str,
    *,
    primary_key: bool = False,
    not_null: bool = False,
    unique: bool = False,
    default: Any = None,
    references: tuple[str, str] | None = None,
) -> ColumnDefinition:
    """Build one ``ColumnDefinition``.

    Constraint names are left to the server.  MariaDB refuses a ``CONSTRAINT
    <name>`` prefix on a column constraint (it accepts one only before
    ``REFERENCES``), and a per-column name buys nothing here, so the portable
    form omits it everywhere.

    A primary key is generated unless the dialect says otherwise:
    :func:`_generates_primary_key` is the probe, and SQLite's rowid alias is
    the one case that answers no.
    """
    constraints: list[ColumnConstraint] = []
    if primary_key:
        constraints.append(
            ColumnConstraint(
                dialect,
                branch=ColumnPrimaryKeyConstraint(
                    dialect,
                    is_auto_increment=_generates_primary_key(dialect),
                ),
            )
        )
    # DEFAULT before NOT NULL: Oracle's grammar puts the default before inline
    # constraints, and the other backends accept this order too.
    if default is not None:
        constraints.append(
            ColumnConstraint(dialect, branch=ColumnDefaultConstraint(dialect, default))
        )
    if not_null:
        constraints.append(
            ColumnConstraint(dialect, branch=ColumnNotNullConstraint(dialect))
        )
    if unique:
        constraints.append(
            ColumnConstraint(dialect, branch=ColumnUniqueConstraint(dialect))
        )
    if references is not None:
        table, target = references
        constraints.append(
            ColumnConstraint(
                dialect,
                branch=ColumnForeignKeyConstraint(
                    dialect,
                    (TableNode(dialect, table), [target]),
                ),
            )
        )
    return ColumnDefinition(
        dialect,
        name,
        _type_support(dialect).parse_type(_sql_type(dialect, sql_type)),
        constraints=constraints or None,
    )


async def create_projection_schema(
    backend: Any,
    *,
    extra_columns: Sequence[Any] = (),
) -> list[str]:
    """Create the projection table and its indexes if absent.  Returns the SQL run.

    Every statement is ``IF NOT EXISTS``, so this is safe to call on every
    boot — but a service with more than one replica should still run it as a
    deploy step rather than at startup.  Replicas booting together all issue
    the same ``CREATE TABLE`` and contend on the same locks, and the loser
    sometimes wins the lock and blocks the others' connections for the length of
    the DDL, which reads in a health check as an outage.
    """
    dialect = backend.dialect
    statements: list[str] = []
    for expression in (
        create_projection_table(dialect, extra_columns=extra_columns),
        *projection_indexes(dialect),
    ):
        await backend.execute(*expression.to_sql())
        statements.append(str(expression.to_sql()[0]))
    return statements


async def drop_projection_schema(backend: Any) -> str:
    """Drop the projection table if present.  Returns the SQL run.

    Touches only ``mcp_principals``.  A service's database may be shared with
    another service, and dropping another service's tables destroys its data --
    which is the reason the table name is a literal in one place rather than a
    prefix a caller could point somewhere else.
    """
    expression = drop_projection_table(backend.dialect)
    await backend.execute(*expression.to_sql())
    return str(expression.to_sql()[0])
