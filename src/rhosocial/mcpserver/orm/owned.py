# src/rhosocial/mcpserver/orm/owned.py
"""The write-side enforcement point: ownership is never taken from a caller.

``PrincipalOwnedMixin`` overwrites ``principal_id`` on every write, so a row's
owner is always the verified caller and can never be supplied, inherited, or
transferred by any code path — including an ``UPDATE`` that sets it
explicitly.

The column needs a default so that ``Schedule(title=...)`` constructs at all;
the default exists only to satisfy the constructor and is replaced here before
the statement is built, so the placeholder never reaches the database.
"""

from __future__ import annotations

from typing import Any, cast

from rhosocial.activerecord.interface.update import IDataPreparationBehavior

from .principal import current_principal_id

__all__ = ["PrincipalOwnedMixin"]


class PrincipalOwnedMixin(IDataPreparationBehavior):
    """Forces ``principal_id`` to the current caller on INSERT and UPDATE."""

    @classmethod
    def unscoped(cls) -> Any:
        """A query that ignores the caller's identity.

        Management plane only — migrations, audits, an admin tool.  Never
        reachable from an MCP tool or a business command.

        Note this also bypasses any soft-delete filter the model carries, since
        it constructs the query class directly rather than going through
        ``Model.query()``.  That is the intent: management wants to see deleted
        rows too.  The name is loud on purpose, so ``grep`` finds every use.
        """
        # ``__query_class__`` is supplied by the model's ``QueryMixin``, not by
        # this mixin, so the type checker cannot see it on ``cls``.
        query_class = cast(Any, cls).__query_class__
        return query_class(cls, principal_scope=False)

    def prepare_save_data(self, data: dict, is_new: bool) -> dict:
        # Synchronous by necessity: the framework calls this from inside its
        # own coroutine, so the projection cannot be resolved here even in an
        # async service.  `current_principal_id` reads the per-request memo
        # that `PrincipalResolution` filled; it raises rather than inventing an
        # id, because a row nobody owns is worse than a failed write.
        principal_id = current_principal_id()
        data["principal_id"] = principal_id
        # Also reflected on the instance: the framework hands this hook a
        # payload rather than the model, so without this the in-memory object
        # would keep the constructor default while the stored row has the real
        # owner — and the two would disagree for the rest of the request.
        self.principal_id = principal_id
        return data
