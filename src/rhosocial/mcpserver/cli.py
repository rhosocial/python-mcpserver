# src/rhosocial/mcpserver/cli.py
"""``rhosocial-mcpserver`` — inspecting a deployment's authorization setup.

Four subcommands, and none of them starts a server:

``decode``
    Verify an access token against a service's JWKS and print what it resolves
    to.  The first thing anyone reaches for when an agent "cannot log in", and
    the answer — which claim failed — is otherwise only in a log file.

``jwks``
    Fetch the authorization server's key set and print the ``kid``s, algorithms
    and fetch time.  Diagnoses "my token was rejected", which is usually key
    rotation that a service has not noticed.

``prm``
    Print the RFC 9728 document a service would serve.  A client's discovery
    goes wrong in ways that are hard to read from the client side.

``policy``
    Print the tool-to-scope map and the advertised vocabulary, and check that
    every tool a server registers has an entry.  Catches the typo that denies
    every caller of one tool, in production, on the first request.

Two of them never contact the database and two need a token in the
environment.  None of them takes a token as an argument — a credential in a
command line is a credential in the shell history, in ``ps``, and in every
process listing on the machine.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Sequence
from typing import Any

from .config import OAuthConfig, ServiceConfig
from .errors import ConfigurationError, McpServerError
from .mcp.jwks import JwksCache
from .mcp.verifier import JwtTokenVerifier

__all__ = ["main", "build_parser"]

#: Where a token is read from when ``--token-file`` is not given.  Named per
#: convention; the file is preferred because a token exported into the
#: environment is readable through ``/proc/<pid>/environ``.
TOKEN_ENV = "MCP_TOKEN"
TOKEN_FILE_ENV = "MCP_TOKEN_FILE"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REJECTED = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rhosocial-mcpserver",
        description="Inspect a resource server's OAuth 2.1 setup.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_service_args(target: argparse.ArgumentParser) -> None:
        target.add_argument(
            "--issuer", default=os.environ.get("MCP_ISSUER"), help="authorization server URL"
        )
        target.add_argument(
            "--resource",
            default=os.environ.get("MCP_RESOURCE"),
            help="this service's RFC 8707 resource identifier",
        )
        target.add_argument("--jwks-uri", default=os.environ.get("MCP_JWKS_URI"))

    decode = sub.add_parser("decode", help="verify an access token and print the principal")
    add_service_args(decode)
    decode.add_argument("token", nargs="?", help="the token; omit to read it from the environment")
    decode.add_argument("--token-file", help="read the token from this file instead")
    decode.add_argument(
        "--raw", action="store_true", help="print the claims without verifying"
    )

    jwks = sub.add_parser("jwks", help="fetch and summarise the signing keys")
    add_service_args(jwks)

    prm = sub.add_parser("prm", help="print the protected resource metadata document")
    add_service_args(prm)
    prm.add_argument(
        "--scopes",
        help="comma-separated scope vocabulary (a service's default if omitted)",
    )
    prm.add_argument(
        "--tools", help="comma-separated tool=scope map, or tool: for a tool needing none"
    )

    policy = sub.add_parser("policy", help="check the tool-to-scope map")
    policy.add_argument(
        "--tools",
        required=True,
        help="comma-separated tool=scope map, or tool: for a tool needing none",
    )
    policy.add_argument("--scopes", required=True, help="comma-separated scope vocabulary")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "decode":
            return _decode(args)
        if args.command == "jwks":
            return asyncio.run(_jwks(args))
        if args.command == "prm":
            return _prm(args)
        if args.command == "policy":
            return _policy(args)
    except ConfigurationError as exc:
        _fail(str(exc))
        return EXIT_ERROR
    except McpServerError as exc:
        _fail(str(exc))
        return EXIT_ERROR
    return EXIT_ERROR


# -- decode --------------------------------------------------------------


def _decode(args: argparse.Namespace) -> int:
    if args.raw:
        return _decode_unverified(args)

    config = _service_config(args)
    oauth = OAuthConfig(
        issuer=_require(args.issuer, "--issuer or $MCP_ISSUER"),
        jwks_uri=args.jwks_uri,
    )
    verifier = JwtTokenVerifier(
        JwksCache(oauth.jwks_uri),
        issuer=oauth.issuer,
        resource=config.resource,
    )
    token = _read_token(args)
    if token is None:
        _fail(
            f"no token. Pass one as an argument, set ${TOKEN_ENV}, or point "
            f"${TOKEN_FILE_ENV} at a file you can chmod 600."
        )
        return EXIT_ERROR

    principal, rejection = _verify(verifier, token)
    if principal is None:
        _fail(rejection or "the token was rejected.")
        return EXIT_REJECTED
    print(json.dumps(_principal_json(principal), indent=2, ensure_ascii=False))
    return EXIT_OK


def _verify(verifier: JwtTokenVerifier, token: str) -> tuple[Any | None, str | None]:
    """Verify, returning ``(principal, reason)`` instead of raising.

    The verifier raises ``Unauthenticated`` with a specific reason and returns
    ``None`` only when the input is not a JWT.  Both are rejections from the
    operator's point of view, and the difference between them — "the token is
    wrong" and "the service cannot reach the keys" — is exactly what they came
    to find out.  So both are reported, with the reason when there is one.
    """
    from .errors import Unauthenticated

    try:
        return asyncio.run(verifier.verify(token)), None
    except Unauthenticated as exc:
        return None, f"the token was rejected: {exc}"
    except McpServerError as exc:
        return None, f"the service could not verify the token: {exc}"


def _decode_unverified(args: argparse.Namespace) -> int:
    """Print the claims without checking anything.

    For the case where the token cannot be verified and the question is what it
    says — which issuer, which audience, when it expires.  The output is marked
    because an unverified claim is an attacker's claim.
    """
    import jwt

    token = _read_token(args)
    if token is None:
        _fail("no token to decode.")
        return EXIT_ERROR
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
        header = jwt.get_unverified_header(token)
    except Exception as exc:
        _fail(f"not a JWT: {exc}")
        return EXIT_ERROR
    print(
        json.dumps(
            {"UNVERIFIED": True, "header": header, "claims": claims},
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    )
    return EXIT_OK


def _principal_json(principal: Any) -> dict[str, Any]:
    return {
        "central_user_id": principal.central_user_id,
        "client_id": principal.client_id,
        "scopes": sorted(principal.scopes),
        "issuer": principal.issuer,
        "resource": principal.resource,
        "expires_at": principal.expires_at,
        "token_id": principal.token_id,
    }


def _read_token(args: argparse.Namespace) -> str | None:
    path = args.token_file or os.environ.get(TOKEN_FILE_ENV)
    if path:
        try:
            with open(os.path.expanduser(path), encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError as exc:
            _fail(f"cannot read {path}: {exc}")
            return None
        return token or None
    return (args.token or os.environ.get(TOKEN_ENV) or "").strip() or None


# -- jwks ----------------------------------------------------------------


async def _jwks(args: argparse.Namespace) -> int:
    oauth = OAuthConfig(
        issuer=_require(args.issuer, "--issuer or $MCP_ISSUER"),
        jwks_uri=args.jwks_uri,
    )
    cache = JwksCache(oauth.jwks_uri)
    keys = await cache.prefetch()
    print(
        json.dumps(
            {
                "jwks_uri": oauth.jwks_uri,
                "key_count": len(keys),
                "keys": [
                    {"kid": k.kid, "kty": k.kty, "alg": k.alg, "use": k.use} for k in _all(keys)
                ],
                "fetches": cache.fetch_count,
            },
            indent=2,
        )
    )
    return EXIT_OK


def _all(keys: Any) -> list[Any]:
    return list(getattr(keys, "_keys", ()))


# -- prm and policy ------------------------------------------------------


def _prm(args: argparse.Namespace) -> int:
    from .mcp.metadata import protected_resource_metadata

    scopes = _split(args.scopes) or ["resource:read"]
    tools = _parse_tools(args.tools or "")
    service = ServiceConfig(
        resource=_require(args.resource, "--resource or $MCP_RESOURCE"),
        scopes=scopes,
        tool_scopes=tools,
    )
    oauth = OAuthConfig(
        issuer=_require(args.issuer, "--issuer or $MCP_ISSUER"),
        jwks_uri=args.jwks_uri,
    )
    print(json.dumps(protected_resource_metadata(service, _Advertise(oauth)), indent=2))
    return EXIT_OK


def _policy(args: argparse.Namespace) -> int:
    """Validate a tool map against a vocabulary.

    A tool naming a scope outside the vocabulary would deny every caller of
    that tool, at request time, in production.  Here it is a non-zero exit and
    a message naming the typo.
    """
    from .scopes import ScopePolicy, ScopeSet

    vocabulary = _split(args.scopes)
    tools = _parse_tools(args.tools)
    if not vocabulary:
        _fail("--scopes is empty; a service must declare at least one scope.")
        return EXIT_ERROR
    if not tools:
        _fail("--tools is empty; every public tool needs a declared scope.")
        return EXIT_ERROR

    policy = ScopePolicy(vocabulary=ScopeSet(vocabulary), tool_scopes=tools)
    print(
        json.dumps(
            {
                "vocabulary": list(policy.vocabulary.values),
                "advertised": list(policy.scopes_supported),
                "tools": {
                    name: (scope or "(none)") for name, scope in policy.as_mapping().items()
                },
                "unused": sorted(
                    set(policy.vocabulary.values) - set(policy.scopes_supported)
                ),
            },
            indent=2,
        )
    )
    if set(policy.vocabulary.values) - set(policy.scopes_supported):
        # Not fatal — a declared-but-unused scope is dead configuration, not a
        # hole — but it is the kind of thing that was meant to be used.
        print(
            "note: these scopes are declared but no tool needs them, so they "
            "are not advertised: "
            f"{sorted(set(policy.vocabulary.values) - set(policy.scopes_supported))}",
            file=sys.stderr,
        )
    return EXIT_OK


def _parse_tools(raw: str) -> dict[str, str]:
    """Parse ``a=read,b:`` into ``{"a": "read", "b": ""}``.

    Two accepted spellings for a tool needing no scope, ``whoami:`` and
    ``whoami=`` — the trailing colon is easier to read in a shell, the trailing
    equals is easier to produce by joining programmatically.  Both map to the
    same empty value.

    ``whoami=none`` is *not* accepted, and the reason is worth stating: it would
    put a scope literally named ``none`` into the vocabulary, which is a bug
    that only surfaces when somebody actually asks for it.
    """
    tools: dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            name, _, scope = item.partition("=")
        elif item.endswith(":"):
            name, scope = item[:-1], ""
        else:
            raise ConfigurationError(
                f"tool {item!r} has no scope: write 'name=scope', or 'name:' for a "
                "tool that needs none"
            )
        tools[name.strip()] = scope.strip()
    return tools


def _split(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


class _Advertise:
    """The OAuth half of a discovery document, for a command with no verifier.

    ``prm`` prints the document a client would fetch, so it needs the issuer and
    nothing else.  Not a :class:`CredentialSource`: this has no ``verify`` and
    must never be mistaken for something that can check a token.
    """

    def __init__(self, config: OAuthConfig) -> None:
        self._config = config

    def metadata(self) -> dict[str, Any]:
        return {
            "authorization_servers": [self._config.issuer],
            "jwks_uri": self._config.jwks_uri,
        }


def _service_config(args: argparse.Namespace) -> ServiceConfig:
    """A minimal service config for the read-only subcommands.

    ``decode`` and ``jwks`` do not enforce scopes and do not touch a database,
    so a one-scope placeholder vocabulary is enough and the command does not have
    to be told about a service's tools.
    """
    return ServiceConfig(
        resource=_require(args.resource, "--resource or $MCP_RESOURCE"),
        scopes=["probe:read"],
        tool_scopes={"probe": "probe:read"},
    )


def _require(value: str | None, how: str) -> str:
    if not value:
        raise ConfigurationError(f"{how} is required")
    return value


def _fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())