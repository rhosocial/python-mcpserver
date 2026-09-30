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

from rhosocial.activerecord.backend.expression import (
    CreateIndexExpression,
    CreateTableExpression,
    DropTableExpression,
)
from rhosocial.activerecord.backend.expression.statements import (
    ColumnConstraint,
    ColumnConstraintType,
    ColumnDefinition,
)

from .principal import (
    CENTRAL_USER_ID,
    ID,
    PROVIDED_BY,
    PROVISIONED_AT,
    STATUS,
)

if TYPE_CHECKING:  # pragma: no cover
    from rhosocial.activerecord.backend.expression.bases import SQLDialectBase

__all__ = [
    "create_projection_table",
    "projection_indexes",
    "drop_projection_table",
    "create_projection_schema",
    "drop_projection_schema",
    "serial_type_for",
    "PRINCIPALS",
    "TIMESTAMP",
]

#: The projection table. A literal, not a name plus a configurable prefix: this
#: package declares one table, and a deployment that needs another name
#: overrides ``Model.table_name()`` and passes the same string here.
PRINCIPALS = "mcp_principals"


def serial_type_for(dialect: SQLDialectBase) -> str:
    """The dialect's auto-increment primary-key column type.

    Not a constant, and the reason is a quiet one.  ``SERIAL`` is PostgreSQL's
    spelling.  SQLite accepts *any* type name in a column definition, so a
    ``SERIAL`` primary key there is created as an ordinary column named
    ``SERIAL`` — **not** an alias for the rowid.  ``INSERT`` then stores a
    literal ``NULL`` for it, and every row comes back with a null id, which
    surfaces much later as an opaque ``int() argument must be … not 'NoneType'``
    in provisioning rather than as anything to do with types.

    So the type is resolved from the dialect's own affinity rules: if it does
    not know ``SERIAL``, it gets the plain integer that its rowid alias needs.
    """
    parsed = dialect.parse_type("SERIAL")
    if type(parsed).__name__ == "CustomType":
        return "INTEGER"
    return "SERIAL"

#: ``TIMESTAMP WITH TIME ZONE``.  Chosen over a naive timestamp because a
#: projection's ``provisioned_at`` is compared against an AS clock and against
#: this service's clock, and a naive column cannot answer either correctly
#: across a DST boundary.
TIMESTAMP = "TIMESTAMP WITH TIME ZONE"


def create_projection_table(
    dialect: SQLDialectBase,
    *,
    extra_columns: Sequence[Any] = (),
) -> CreateTableExpression:
    """``CREATE TABLE IF NOT EXISTS <prefix>_principals``.

    :param extra_columns: service-private ``ColumnDefinition`` objects, built
        by the caller so this module does not have to know their types.
    """
    table = PRINCIPALS
    return CreateTableExpression(
        dialect=dialect,
        table=table,
        columns=[
            column(dialect, ID, serial_type_for(dialect), primary_key=True),
            # TEXT, not VARCHAR(n): a central id is an opaque string whose
            # length is the authorization server's business.  A column too
            # short to hold it truncates, and a truncated id that still matches
            # an existing one merges two users' data.
            column(dialect, CENTRAL_USER_ID, "TEXT", not_null=True),
            column(dialect, STATUS, "TEXT", not_null=True, default="active"),
            column(dialect, PROVIDED_BY, "TEXT"),
            column(dialect, PROVISIONED_AT, TIMESTAMP),
            *extra_columns,
        ],
        if_not_exists=True,
    )


def projection_indexes(
    dialect: SQLDialectBase,
) -> tuple[CreateIndexExpression, ...]:
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
    table = PRINCIPALS
    return (
        CreateIndexExpression(
            dialect,
            f"idx_{PRINCIPALS}_CENTRAL_USER_ID",
            table,
            [CENTRAL_USER_ID],
            unique=True,
            if_not_exists=True,
        ),
        CreateIndexExpression(
            dialect,
            f"idx_{PRINCIPALS}_STATUS",
            table,
            [STATUS],
            if_not_exists=True,
        ),
    )


def drop_projection_table(
    dialect: SQLDialectBase,
) -> DropTableExpression:
    """``DROP TABLE IF EXISTS`` for the projection table.

    Only ever touches a prefixed name.  A service's database may be shared, and
    dropping another service's tables would destroy its data.
    """
    return DropTableExpression(
        dialect=dialect, table=PRINCIPALS, if_exists=True
    )


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

    Constraint names are left to the server for everything except the primary
    key, where ``pk_<table>`` is conventional and harmless.  Naming a foreign
    key ``fk_<column>`` on every service would collide the moment two services
    shared a schema — the asymmetry between index and constraint names is the
    whole reason the prefix rules differ.
    """
    constraints: list[ColumnConstraint] = []
    if primary_key:
        constraints.append(
            ColumnConstraint(dialect, ColumnConstraintType.PRIMARY_KEY, name=f"pk_{name}")
        )
    if not_null:
        constraints.append(ColumnConstraint(dialect, ColumnConstraintType.NOT_NULL))
    if unique:
        constraints.append(ColumnConstraint(dialect, ColumnConstraintType.UNIQUE))
    if default is not None:
        constraints.append(
            ColumnConstraint(dialect, ColumnConstraintType.DEFAULT, default_value=default)
        )
    if references is not None:
        table, target = references
        constraints.append(
            ColumnConstraint(
                dialect,
                ColumnConstraintType.FOREIGN_KEY,
                foreign_key_reference=(table, [target]),
            )
        )
    return ColumnDefinition(
        dialect,
        name,
        dialect.parse_type(sql_type),
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
