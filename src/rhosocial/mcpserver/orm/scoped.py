# src/rhosocial/mcpserver/orm/scoped.py
"""The read-side enforcement point: every query carries the caller's principal.

One override covers every read, and the seam is deliberately
:meth:`__init__` rather than the terminal methods.  The reasoning, which is
inherited from the two services this library replaces and is worth keeping
verbatim because it is easy to get wrong later:

``Model.query()`` is ``return cls.__query_class__(cls)``
(``base/query_mixin.py:135``) and the query's ``__init__`` is synchronous, so a
predicate attached there is in ``where_clause`` before any execution path reads
it.  That makes one override cover ``all`` / ``one`` / ``count`` / ``exists`` /
``aggregate`` / ``sum_`` / ``avg`` / ``min_`` / ``max_`` / ``update_all`` /
``delete_all``, and whatever is added later.

Overriding the terminal methods instead would take five or six patches,
because the execution paths are not unified: ``count`` and the numeric
aggregates funnel into ``self.aggregate()`` while ``all()`` goes through
``self.to_sql()``.  **Missing one raises nothing.**  It silently returns
another user's rows, which is the one failure mode a test suite that only
exercises the happy path cannot see.
"""

from __future__ import annotations

from typing import Any

from rhosocial.activerecord.query import AsyncActiveQuery

from .principal import current_principal_id

__all__ = ["PrincipalScopedQuery"]


class PrincipalScopedQuery(AsyncActiveQuery):
    """A query that is already filtered to the caller's own rows.

    Compose onto a model that *owns* rows::

        class Schedule(AsyncActiveRecord):
            __table_name__ = tables.table("schedules")
            __query_class__ = PrincipalScopedQuery
    """

    def __init__(self, model_class: type[Any], *, principal_scope: bool = True) -> None:
        super().__init__(model_class)
        if principal_scope:
            # Resolved here, at construction, and not in the terminal methods:
            # see the module docstring.  The resolution is memoised per request
            # by `orm.principal`, so a request touching five models still
            # provisions once.
            self.where(model_class.c.principal_id == current_principal_id())
