# src/rhosocial/mcpserver/tables.py
"""Table and index naming, in one place.

Every service that shares a PostgreSQL database needs its own name prefix, and
needs the *index* names prefixed too — PostgreSQL puts every index in a single
per-schema namespace, so two services that both create ``idx_users_email``
will not merely collide, they will take down each other's ``CREATE TABLE`` in
the middle of a deploy.  That failure surfaces as a startup crash in whichever
service happened to run second, which is a confusing way to learn about it.

The failure mode this guards against is a name written out in two places.  A
model declares ``__table_name__`` and a DDL module repeats the string; they
agree today and diverge on the rename nobody remembered.  :class:`TableNamespace`
makes the divergence impossible to express: the model reads its name back from
here, and so does the DDL builder.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from .errors import ConfigurationError

__all__ = ["TableNamespace"]

# PostgreSQL truncates identifiers at 63 bytes.  Silently truncated names
# collide with each other, so the limit is enforced before the database does it
# and with an error rather than a surprise.
MAX_IDENTIFIER_BYTES = 63

_SQL_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]*$")


class TableNamespace:
    """Resolves table and index names under a service prefix.

    ::

        ns = TableNamespace("sm")
        ns.table("users")        # 'sm_users'
        ns.index("users", "email")  # 'idx_sm_users_email'
    """

    __slots__ = ("_prefix",)

    def __init__(self, prefix: str) -> None:
        normalized = prefix.strip().lower().rstrip("_")
        if not normalized:
            raise ConfigurationError("table prefix is empty")
        if not _SQL_IDENTIFIER.match(normalized):
            raise ConfigurationError(
                f"table prefix {prefix!r} is not a bare SQL identifier: use "
                "lowercase letters, digits and underscores, starting with a "
                "letter or underscore"
            )
        self._prefix = normalized

    @property
    def prefix(self) -> str:
        return self._prefix

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"TableNamespace({self._prefix!r})"

    def table(self, name: str) -> str:
        """The prefixed table name."""
        return self._checked(f"{self._prefix}_{name}", f"table {name!r}")

    def index(self, table: str, suffix: str) -> str:
        """The prefixed index name for ``suffix`` on ``table``.

        Takes the *unprefixed* table name so the two cannot be passed in
        inconsistent forms; prefixing an already-prefixed name is the mistake
        this signature makes unrepresentable.
        """
        return self._checked(f"idx_{self._prefix}_{table}_{suffix}", f"index on {table!r}")

    def unique_constraint(self, table: str, columns: Iterable[str]) -> str:  # type: ignore[name-defined]
        """A UNIQUE *constraint* name.

        Separate from :meth:`index` because PostgreSQL scopes constraints per
        table while indexes are schema-global — the exact asymmetry that makes
        one shared name dangerous and the other merely untidy.
        """
        return self._checked(
            f"uq_{self._prefix}_{table}_{'_'.join(columns)}",
            f"unique constraint on {table!r}",
        )

    def _checked(self, name: str, what: str) -> str:
        if not _SQL_IDENTIFIER.match(name):
            raise ConfigurationError(
                f"{what} resolves to {name!r}, which is not a bare SQL identifier"
            )
        if len(name.encode("utf-8")) > MAX_IDENTIFIER_BYTES:
            raise ConfigurationError(
                f"{what} resolves to {name!r}, {len(name.encode('utf-8'))} bytes — "
                f"over PostgreSQL's {MAX_IDENTIFIER_BYTES}-byte identifier limit, "
                "where it would be silently truncated into a collision"
            )
        return name
