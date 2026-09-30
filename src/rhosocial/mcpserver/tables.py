# src/rhosocial/mcpserver/tables.py
"""Table and index naming, in one place.

The logic lives in ``rhosocial.activerecord.backend.naming`` so there is exactly
one implementation: at least three packages in this family need it — the
authorization server, this one, and every business service on top of them — and
a copy per package is precisely the drift this arrangement exists to prevent.

What stays here is the error type. This package raises
:class:`~rhosocial.mcpserver.errors.ConfigurationError`, which is a
``McpServerError``, and callers catch that. Letting a bad prefix escape as the
core's plain ``ValueError`` would mean ``except McpServerError`` silently stopped
covering it — a misconfiguration reported as something unhandled, which is the
opposite of "raised at construction, not at request time".
"""

from __future__ import annotations

from rhosocial.activerecord.backend.naming import MAX_IDENTIFIER_BYTES
from rhosocial.activerecord.backend.naming import TableNamespace as _CoreTableNamespace

from .errors import ConfigurationError

__all__ = ["TableNamespace", "ConfigurationError", "MAX_IDENTIFIER_BYTES"]


class TableNamespace(_CoreTableNamespace):
    """See :class:`rhosocial.activerecord.backend.naming.TableNamespace`."""

    __slots__ = ()

    _error_class = ConfigurationError