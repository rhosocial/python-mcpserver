# src/rhosocial/mcpserver/scopes.py
"""The scope vocabulary and the tool-to-scope mapping.

Two things in this file are the same object on purpose.  The *closed
vocabulary* — the set of scopes a service understands — and the *tool map* —
which tool needs which scope — are declared once, and the PRM document is
generated from both.

Keeping them apart is how the classic drift happens: the metadata document
advertises ``contacts:read`` while the server enforces ``contacts:list``, so a
client that trusted the document gets an inexplicable 403 the first time it
calls.  Nothing fails until a real client hits it, which is the worst time.

So: :class:`ScopeSet` owns the vocabulary, :class:`ScopePolicy` owns the tool
map and the PRM fields, and every place that needs either reads it from here.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType

from .errors import ConfigurationError

__all__ = ["ScopeSet", "ScopePolicy"]

#: Sentinel meaning "this tool needs no scope at all".  Distinct from ``""``,
#: which would be a scope named by the empty string and a bug rather than a
#: declaration.
NO_SCOPE = ""


class ScopeSet:
    """An immutable, closed set of scope strings.

    Closed means a token carrying a scope outside the set is not an error — it
    simply never satisfies a check, because the set of tools is fixed and each
    one names its own scope.  What is rejected is *configuration* naming an
    unknown scope, because that is a typo that would silently deny every caller.
    """

    __slots__ = ("_values", "_by_suffix")

    def __init__(self, values: Iterable[str]) -> None:
        normalized = tuple(dict.fromkeys(v.strip() for v in values if v and v.strip()))
        if not normalized:
            raise ConfigurationError(
                "the scope vocabulary is empty; a service must declare at least one"
            )
        for value in normalized:
            _validate_shape(value)
        self._values = tuple(sorted(normalized))
        # Read/write pairs are the near-universal shape (``schedules:read``).
        # Indexing the suffix lets the README and the PRM document sort a
        # service's scopes by resource rather than alphabetically, which is how
        # a human reads them.
        self._by_suffix = MappingProxyType(
            {value.rsplit(":", 1)[-1]: value for value in self._values if ":" in value}
        )

    @property
    def values(self) -> tuple[str, ...]:
        """The vocabulary, sorted."""
        return self._values

    def __contains__(self, scope: object) -> bool:
        return scope in self._values

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ScopeSet({list(self._values)!r})"

    def in_vocabulary(self, scope: str) -> bool:
        """Whether *scope* is one of ours."""
        return scope in self._values

    def for_resource(self, name: str) -> str:
        """The scope for a resource's default verb, e.g. ``schedules`` → ``schedules:read``.

        Only used for constructing a vocabulary; the tool map is explicit.
        """
        candidate = f"{name}:read"
        if candidate not in self._by_suffix.values():
            raise ConfigurationError(
                f"no read scope for resource {name!r}; the vocabulary has "
                f"{list(self._values)!r}"
            )
        return candidate


def _validate_shape(scope: str) -> None:
    """Reject a scope string that cannot be advertised in a PRM document.

    RFC 6749 §3.3 restricts scope values to ``%x21 / %x23-5B / %x5D-7E`` — VCHAR
    minus the double quote and backslash, because the value travels inside a
    space-delimited list in a header.  A space is the important one: a scope
    containing one splits into two scopes, silently granting less than intended.
    """
    for char in scope:
        code = ord(char)
        if code < 0x21 or code == 0x22 or code == 0x5C or code > 0x7E:
            raise ConfigurationError(
                f"scope {scope!r} contains {char!r}, which RFC 6749 §3.3 does not "
                "permit in a scope value (printable ASCII except space and "
                'double quote, backslash)'
            )


class ScopePolicy:
    """Which scope each tool requires, and the metadata derived from that.

    ``tool_scopes`` maps a tool name to the scope it needs, or to
    :data:`NO_SCOPE` for a tool that needs none.  A tool that is not in the map
    is *not* public: :meth:`scope_for` returns ``None`` and the caller treats
    that as "refuse", because an unlisted tool is more likely a typo in the
    server than a tool the author forgot to protect.
    """

    __slots__ = ("_vocabulary", "_tool_scopes", "_all_scopes", "_used")

    def __init__(self, vocabulary: ScopeSet, tool_scopes: Mapping[str, str]) -> None:
        unknown = sorted({s for s in tool_scopes.values() if s and not vocabulary.in_vocabulary(s)})
        if unknown:
            raise ConfigurationError(
                f"tool map names scope(s) outside the vocabulary: {unknown}; "
                f"declared: {list(vocabulary.values)!r}"
            )
        self._vocabulary = vocabulary
        self._tool_scopes = dict(tool_scopes)
        self._used = {s for s in tool_scopes.values() if s}
        self._all_scopes = tuple(s for s in vocabulary if s in self._used)

    def as_mapping(self) -> Mapping[str, str]:
        """The tool map, for reconstructing a policy during validation."""
        return dict(self._tool_scopes)

    def add(self, tool: str, scope: str) -> None:
        """Declare another tool.

        Mutating rather than immutable, because services register their tools
        as they build the server and a frozen map would mean declaring every
        tool before any of them exist.  The cost is that the advertised
        ``scopes_supported`` can go stale; :meth:`ServiceConfig.validate`
        exists to recompute it once registration is finished, and the
        enforcement middleware is the thing that has to be called.
        """
        if scope and not self._vocabulary.in_vocabulary(scope):
            raise ConfigurationError(
                f"tool {tool!r} needs scope {scope!r}, which is not in the "
                f"vocabulary {list(self._vocabulary.values)!r}"
            )
        self._tool_scopes[tool] = scope
        if scope:
            self._used.add(scope)
        self._all_scopes = tuple(s for s in self._vocabulary if s in self._used)

    @property
    def vocabulary(self) -> ScopeSet:
        return self._vocabulary

    @property
    def scopes_supported(self) -> tuple[str, ...]:
        """What to advertise in ``scopes_supported``.

        The whole *used* vocabulary, not just the scopes one tool happens to
        need.  A scope declared but backing no tool is dead configuration and
        is filtered out here rather than published as a promise the server
        cannot keep.
        """
        return self._all_scopes

    @property
    def tools(self) -> tuple[str, ...]:
        return tuple(self._tool_scopes)

    def knows(self, tool: str) -> bool:
        """Whether *tool* appears in the map at all.

        Distinct from :meth:`requires_scope`, and the distinction is the whole
        point of refusing an unlisted name: a declared tool that needs no scope
        is a deliberate configuration, while an absent one is a disagreement
        between the client and the server.
        """
        return tool in self._tool_scopes

    def scope_for(self, tool: str) -> str | None:
        """The scope *tool* requires, or ``None`` when it is not public.

        ``None`` is also returned for an unknown tool, which the enforcement
        middleware treats as a 403 — see :meth:`knows`.
        """
        return self._tool_scopes.get(tool)

    def requires_scope(self, tool: str) -> bool:
        """Whether *tool* needs any scope at all."""
        scope = self._tool_scopes.get(tool)
        return scope is not None and scope != NO_SCOPE

    def missing(self, tool: str, granted: Iterable[str]) -> str | None:
        """The scope *tool* needs that *granted* does not include, else ``None``.

        Returned rather than raised so the caller decides the transport: the
        ASGI middleware turns it into a 403, the CLI prints it.
        """
        required = self.scope_for(tool)
        if required is None or required == NO_SCOPE:
            return None
        held = frozenset(granted)
        return None if required in held else required
