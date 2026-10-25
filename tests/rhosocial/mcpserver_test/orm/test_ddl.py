# tests/rhosocial/mcpserver_test/orm/test_ddl.py
"""The DDL helpers require the dialect's DataTypeSupport capability."""

from __future__ import annotations

import pytest
from rhosocial.activerecord.backend.dialect.exceptions import UnsupportedFeatureError

from rhosocial.mcpserver.orm.ddl import column


def test_column_rejects_a_dialect_without_type_support() -> None:
    """A base dialect has no ``parse_type``; fail by name, not AttributeError."""
    with pytest.raises(UnsupportedFeatureError):
        column(object(), "id", "INTEGER")  # type: ignore[arg-type]
