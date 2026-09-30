# src/rhosocial/mcpserver/orm/__init__.py
"""The ORM side: how a table's rows are tied to a verified caller.

Three pieces, and the division between them is the point:

- :class:`PrincipalMixin` — resolves *who* the caller is locally, creating the
  projection row on first use.
- :class:`PrincipalScopedQuery` — forces every **read** to that caller.
- :class:`PrincipalOwnedMixin` — forces every **write** to that caller.

A model is protected when it uses the last two, and protected *completely*
when it uses all three.  A model that mixes in only one of them is a model with
one of its two paths open, which is why :meth:`PrincipalMixin.assert_protected`
exists: it turns that mistake into a startup failure rather than a data leak.
"""

from __future__ import annotations

from typing import Any

from .ddl import (
    create_projection_table,
    drop_projection_table,
    projection_indexes,
)
from .owned import PrincipalOwnedMixin
from .principal import (
    CENTRAL_USER_ID,
    ID,
    PROVIDED_BY,
    PROVISIONED_AT,
    STATUS,
    STATUS_ACTIVE,
    STATUS_DELETED,
    STATUS_SUSPENDED,
    PrincipalMixin,
    clear_principal_id,
    current_principal_id,
    ensure_principal_id,
    publish_principal_id,
    register_projection,
    registered_projection,
)
from .scoped import PrincipalScopedQuery

__all__ = [
    "PrincipalMixin",
    "PrincipalScopedQuery",
    "PrincipalOwnedMixin",
    "assert_protected",
    "create_projection_table",
    "projection_indexes",
    "drop_projection_table",
    "current_principal_id",
    "ensure_principal_id",
    "publish_principal_id",
    "register_projection",
    "registered_projection",
    "clear_principal_id",
    "CENTRAL_USER_ID",
    "ID",
    "STATUS",
    "STATUS_ACTIVE",
    "STATUS_SUSPENDED",
    "STATUS_DELETED",
    "PROVIDED_BY",
    "PROVISIONED_AT",
]


def assert_protected(model: Any) -> None:
    """Fail fast unless *model* is protected on both the read and write paths.

    :raises TypeError: with the specific missing half named.

    Worth the ceremony because the failure it prevents is silent.  A model with
    only the scoped query still lets ``create()`` write a row with the
    constructor's default owner; a model with only the owned mixin still lets
    ``query()`` read every row in the table.  Neither raises, and a test that
    creates rows as one user and reads them as another is the only thing that
    catches it — which is exactly the test a new service does not write yet.

    ::

        @classmethod
        def configure(cls, backend):
            cls.configure_backend(backend)
            assert_protected(cls)
    """
    query_class = getattr(model, "__query_class__", None)
    if not (query_class is not None and issubclass(query_class, PrincipalScopedQuery)):
        raise TypeError(
            f"{model.__name__} is not read-protected: its __query_class__ must be "
            "PrincipalScopedQuery, so the caller's principal_id is in the WHERE "
            "clause before any execution path reads it"
        )
    if not issubclass(model, PrincipalOwnedMixin):
        raise TypeError(
            f"{model.__name__} is not write-protected: it must inherit "
            "PrincipalOwnedMixin, so principal_id is overwritten on INSERT and "
            "UPDATE rather than taken from the caller"
        )
