# src/rhosocial/mcpserver/orm/principal.py
"""The local principal projection, and the single place it is resolved.

A *projection* is a local row that says "central user U123 has used this
service".  It exists for two reasons, and the second is the important one:

1. It gives the service somewhere to put its own per-user state — a timezone, a
   default view, a locale.
2. It gives business tables a local integer key, so the ownership predicate is
   an integer equality that uses an index, and so a change to the central
   identity scheme does not rewrite every foreign key.

What it deliberately is **not** is a second copy of the user.  There is no
password, no email, no profile.  A service that needs a display name asks the
identity service; copying it here converts the projection into a second source
of truth that drifts, and a drifted permission display is worse than none.

Provisioning is lazy: the row is created on the first request that resolves a
``sub``.  Eager provisioning would mean the AS knows the full catalogue of
services, and adding one would become a deploy of the AS — the coupling this
design exists to remove.
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from contextvars import Token as ResetToken
from datetime import datetime, timezone
from typing import Any, ClassVar

from ..errors import ConfigurationError, PrincipalNotResolved, ProvisioningError
from ..identity import Principal, current_principal

__all__ = [
    "PrincipalMixin",
    "current_principal_id",
    "ensure_principal_id",
    "registered_projection",
    "register_projection",
    "publish_principal_id",
    "clear_principal_id",
    "PROVIDED_BY",
    "PROVISIONED_AT",
    "CENTRAL_USER_ID",
    "ID",
    "STATUS",
    "STATUS_ACTIVE",
    "STATUS_SUSPENDED",
    "STATUS_DELETED",
]

log = logging.getLogger(__name__)

#: Column names, named once so a DDL builder and a model cannot disagree.
ID = "id"
CENTRAL_USER_ID = "central_user_id"
STATUS = "status"
PROVIDED_BY = "provided_by"
PROVISIONED_AT = "provisioned_at"

#: Projection states.  Deliberately **not** the same vocabulary as the
#: authorization state: a suspended projection has lost access while its data is
#: still here, and collapsing the two is how "revoke" turns into "delete".
#:
#: ``ACTIVE``      — the service may read and write this user's data.
#: ``SUSPENDED``   — access refused, rows retained.  Re-activating restores.
#: ``DELETED``     — the user asked for erasure.  Only an explicit delete gets
#:                    here, and a service reaching it should anonymise, not
#:                    simply flip a flag and keep the rows.
STATUS_ACTIVE = "active"
STATUS_SUSPENDED = "suspended"
STATUS_DELETED = "deleted"

_PROJECTION_STATES = (STATUS_ACTIVE, STATUS_SUSPENDED, STATUS_DELETED)

#: The resolved ``principal_id`` for the current request, or ``None``.
#:
#: This is a per-request memo, not a cache: it is never read across requests, so
#: revocation and suspension semantics are unchanged.  It exists because both
#: enforcement points — the scoped query and the owned mixin — need the integer,
#: and without it a request touching five tables would resolve it five times.
_principal_id: ContextVar[int | None] = ContextVar(
    "rhosocial_mcpserver_principal_id", default=None
)

#: Set while a projection is being created, to break the recursion when
#: resolving the principal needs a query that itself needs a principal id.  An
#: int rather than a bool: nesting is a bug, and the model name in the message
#: is what makes it findable.
_provisioning: ContextVar[tuple[str, ...]] = ContextVar(
    "rhosocial_mcpserver_provisioning", default=()
)

#: The one model that *is* this process's projection table.  A process serves
#: exactly one service, so there is exactly one; a module-level slot is what
#: makes the ownership predicate work without threading a config object through
#: every model, the query class and the save hook.
_projection_model: type | None = None


def register_projection(model: Any) -> Any:
    """Declare *model* as this process's projection table.  Returns it.

    Idempotent for the same class and an error for a different one: a second
    projection table in one process is either a test artefact or a bug, and
    silently letting the last registration win would mean two models' rows were
    keyed by whichever was imported last.
    """
    global _projection_model
    if _projection_model is not None and _projection_model is not model:
        raise ConfigurationError(
            f"{_projection_model.__name__} is already registered as this "
            f"process's projection table; refusing to replace it with "
            f"{model.__name__}"
        )
    _projection_model = model
    return model


def registered_projection() -> Any:
    """The registered projection model, or a named error.

    Named because the fix is one line at the service's import site and an
    anonymous ``NoneType is not callable`` at the first request sends the reader
    to the wrong file entirely.
    """
    if _projection_model is None:
        raise ConfigurationError(
            "no projection model is registered. Call "
            "YourPrincipalModel.register_as_projection() once, at import time — "
            "without it the ownership predicate has no table to resolve against."
        )
    return _projection_model


def current_principal_id() -> int:
    """The caller's local ``principal_id``, from the request's memo.

    Synchronous, and necessarily so: this is what both enforcement points call
    from ``__init__`` and ``prepare_save_data``, neither of which can await.
    Resolving the projection *is* async — it may have to create a row — so that
    happens once per request in
    :class:`rhosocial.mcpserver.middleware.PrincipalResolution`, and this
    function only reads the result.

    :raises Unauthenticated: no verified identity in this context.
    :raises PrincipalNotResolved: an identity exists but the projection has not
        been resolved yet.  Distinct from the above because collapsing them
        produces a 401 that sends an operator to inspect the token when the
        problem is a missing middleware.
    """
    memo = _principal_id.get()
    if memo is not None:
        return memo
    # Calling this raises `Unauthenticated` when nobody is calling at all, and
    # falls through to the specific error when somebody is but nothing has
    # resolved them yet.
    current_principal()
    raise PrincipalNotResolved(
        "a verified identity is present but its principal_id has not been "
        "resolved. PrincipalResolution middleware must run before any handler "
        "constructs a query or saves a row — or call ensure_principal_id() "
        "yourself."
    )


async def ensure_principal_id(principal: Principal | None = None) -> int:
    """Resolve the projection for *principal* (default: the caller) and memoise it.

    The one query per request that both enforcement points depend on.  Called
    by :class:`rhosocial.mcpserver.middleware.PrincipalResolution`; a service
    that establishes identity some other way calls it directly.

    The memo is only written when the resolved principal **is** the current
    one.  That distinction is the whole reason ``resolve`` and this function are
    separate: a management command asking "what is the id for user X" must not
    overwrite the memo, or the next ``current_principal_id()`` in the same
    request would answer with the wrong user.

    :raises Unauthenticated: no verified identity and no explicit *principal*.
    :raises ConfigurationError: no projection model is registered — a service
        must call ``YourPrincipalModel.register_as_projection()`` once.
    :raises ProvisioningError: the row could not be created or read.
    """
    if principal is None:
        memo = _principal_id.get()
        if memo is not None:
            return memo
    resolved = int(await registered_projection().resolve(principal))
    if principal is None or principal == _current_principal_or_none():
        _principal_id.set(resolved)
    return resolved


def _current_principal_or_none() -> Principal | None:
    from ..errors import Unauthenticated

    try:
        return current_principal()
    except Unauthenticated:
        return None


def publish_principal_id(principal_id: int) -> ResetToken:
    """Bind the resolved id for the rest of the request.

    Middleware calls this after provisioning so the hot path is a ContextVar
    read rather than a query per model.
    """
    return _principal_id.set(principal_id)


def clear_principal_id(token: ResetToken) -> None:
    """Undo :func:`publish_principal_id`."""
    _principal_id.reset(token)


class PrincipalMixin:
    """Gives a model the ``mcp_principals`` table's shape and behaviour.

    Compose onto a model that *is* the projection::

        class ContactPrincipal(AsyncActiveRecord, PrincipalMixin):
            __table_name__ = "mcp_principals"

    The mixin provides :meth:`resolve` — find-or-create by ``central_user_id``
    — and the column-name constants.  It does not add columns: the model
    declares them, because a library that silently adds columns to a service's
    table is a library that has opinions about somebody's schema.
    """

    #: The state constants, re-exported on the model so callers write
    #: ``ContactPrincipal.STATUS_ACTIVE`` rather than importing from here.
    STATUS_ACTIVE: ClassVar[str] = STATUS_ACTIVE
    STATUS_SUSPENDED: ClassVar[str] = STATUS_SUSPENDED
    STATUS_DELETED: ClassVar[str] = STATUS_DELETED

    #: Central user ids are opaque strings, not integers.  An AS that uses a
    #: UUID today may use a ULID tomorrow, and every service holding a stored
    #: copy would need a migration on that day.  Not typed here: this is a
    #: namespace, not a model, and the model owns its annotation.
    CENTRAL_USER_ID: ClassVar[str] = CENTRAL_USER_ID

    @classmethod
    def register_as_projection(cls) -> Any:
        """Declare this model as the process's projection table.

        Called once, at the service's import site::

            ContactPrincipal.register_as_projection()

        Registration is what lets ``PrincipalScopedQuery`` and
        ``PrincipalOwnedMixin`` resolve a ``principal_id`` without being handed
        a config object: both are mixed into models that know nothing about
        which table holds the projection, and a process serves exactly one
        service, so there is exactly one answer.
        """
        return register_projection(cls)

    @classmethod
    async def resolve(cls, principal: Principal | None = None) -> int:
        """The local id for *principal* (default: the current caller), creating it.

        Find-then-create, not an upsert, because the two need different
        behaviour on a race: two concurrent first requests must both end up with
        the same row, and only a constraint violation tells us which one lost.
        The loser re-reads instead of retrying the insert, which under
        PostgreSQL would raise the same violation again.

        Pure with respect to the request memo — :func:`ensure_principal_id`
        owns that.  A management caller wants an answer, not a cache write.
        """
        caller = principal if principal is not None else current_principal()

        guard = _provisioning.get()
        if cls.__name__ in guard:
            raise ProvisioningError(
                f"resolving {cls.__name__} re-entered itself "
                f"({' -> '.join((*guard, cls.__name__))}); a projection resolve "
                "must not depend on another projection"
            )

        reset = _provisioning.set((*guard, cls.__name__))
        try:
            row = await cls._find_or_create(caller)
        finally:
            _provisioning.reset(reset)  # type: ignore[union-attr]

        return int(row.id)

    @classmethod
    async def _find_or_create(cls: Any, principal: Principal) -> Any:
        existing = await cls._find(principal.central_user_id)
        if existing is not None:
            return existing
        return await cls._create(principal)

    @classmethod
    async def _find(cls: Any, central_user_id: str) -> Any | None:
        # `cls` is a model here, not a mixin: PrincipalMixin composes onto
        # AsyncActiveRecord and this class only exists to describe it.
        return await cls.query().where(cls.c.central_user_id == central_user_id).one()

    @classmethod
    async def _create(cls: Any, principal: Principal) -> Any:
        row = cls(central_user_id=principal.central_user_id)
        # Field presence is read from `model_fields`, not `hasattr`.  A pydantic
        # v2 model class does not expose its fields as class attributes, so
        # `hasattr(cls, "provided_by")` is False for a model that has the
        # field — and a `hasattr` guard would skip populating it in silence.
        fields = cls.model_fields
        if STATUS in fields:
            row.status = STATUS_ACTIVE
        if PROVIDED_BY in fields:
            # The only moment this answer is available: by the time an operator
            # asks which client caused a projection to appear, the request that
            # created the row is long gone.
            row.provided_by = principal.client_id
        if PROVISIONED_AT in fields:
            row.provisioned_at = datetime.now(tz=timezone.utc)
        try:
            await row.save()
        except Exception as exc:
            if not _is_unique_violation(exc):
                raise ProvisioningError(
                    f"could not provision {cls.__name__} for "
                    f"{principal.central_user_id!r}: {exc}"
                ) from exc
            # Lost a race.  The other request's row is the correct answer, and
            # re-inserting would raise the same violation.
            existing = await cls._find(principal.central_user_id)
            if existing is None:  # pragma: no cover - only if the row vanished
                raise ProvisioningError(
                    f"{cls.__name__} for {principal.central_user_id!r} vanished "
                    "between the insert and the re-read"
                ) from exc
            return existing
        return row


#: SQLSTATE values for a unique violation are declared next to the errno table
#: below; see :func:`_is_unique_violation` for why both exist.


def _is_unique_violation(exc: BaseException) -> bool:
    """Whether *exc* is a unique-constraint violation.

    Falls back to inspecting the message, because not every driver surfaces the
    SQLSTATE the same way: MySQL's connector puts the code on ``errno``, SQLite
    raises with a fixed English phrase, and SQL Server uses two different
    numbers depending on whether a unique index or a constraint was hit.  A
    wrong positive here costs one re-read; a wrong negative costs a 500 on a
    user's very first request to a service, which is much worse.
    """
    for attribute in ("sqlstate", "pgcode", "sql_state"):
        value = getattr(exc, attribute, None)
        if isinstance(value, str) and value in _UNIQUE_VIOLATION_STATES:
            return True
    errno = getattr(exc, "errno", None)
    if isinstance(errno, int) and errno in _UNIQUE_VIOLATION_ERRNOS:
        return True
    text = str(exc).lower()
    return "unique" in text or "duplicate" in text


#: SQLSTATE for a unique violation, per backend.
_UNIQUE_VIOLATION_STATES = frozenset(
    {
        "23505",  # PostgreSQL, SQL Server (23000 is the generic class)
        "23000",  # MySQL / MariaDB integrity constraint violation
        "23001",  # Firebird: violation of a PRIMARY or UNIQUE key
    }
)

#: Native error numbers, for drivers that do not populate ``sqlstate``.
_UNIQUE_VIOLATION_ERRNOS = frozenset(
    {
        1062,  # MySQL / MariaDB ER_DUP_ENTRY
        1169,  # MySQL / MariaDB ER_DUP_UNIQUE
        19,  # SQLite SQLITE_CONSTRAINT
        1555,  # SQL Server duplicate key on unique index
        2067,  # SQL Server duplicate key on unique index (alternate)
        2627,  # SQL Server violation of unique constraint
    }
)
