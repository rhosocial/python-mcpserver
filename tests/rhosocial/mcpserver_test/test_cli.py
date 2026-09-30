# tests/rhosocial/mcpserver_test/test_cli.py
"""The CLI: the answers an operator reaches for when an agent cannot log in."""

from __future__ import annotations

import json

import pytest
from conftest import ISSUER, JWKS_URI, RESOURCE

from rhosocial.mcpserver.cli import (
    EXIT_ERROR,
    EXIT_OK,
    EXIT_REJECTED,
    build_parser,
    main,
)

TOKEN = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIn0.eyJzdWIiOiJ1LTEifQ.c2ln"


def test_no_subcommand_is_a_usage_error() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_prm_prints_a_document_generated_from_the_flags(capsys) -> None:
    code = main(
        [
            "prm",
            "--issuer",
            ISSUER,
            "--resource",
            RESOURCE,
            "--scopes",
            "schedules:read,schedules:write",
            "--tools",
            "whoami:,list_schedules=schedules:read",
        ]
    )

    assert code == EXIT_OK
    document = json.loads(capsys.readouterr().out)
    assert document["resource"] == RESOURCE
    assert document["authorization_servers"] == [ISSUER]
    # `whoami:` declared no scope, so only the read scope is advertised — and
    # the advertised set is exactly the enforced set.
    assert document["scopes_supported"] == ["schedules:read"]
    assert document["jwks_uri"] == JWKS_URI


def test_prm_needs_a_issuer(capsys) -> None:
    code = main(["prm", "--resource", RESOURCE, "--scopes", "a:read", "--tools", "r=a:read"])

    assert code == EXIT_ERROR
    assert "--issuer" in capsys.readouterr().err


def test_policy_accepts_a_consistent_map(capsys) -> None:
    code = main(
        [
            "policy",
            "--scopes",
            "a:read,a:write",
            "--tools",
            "whoami:,r=a:read,w=a:write",
        ]
    )

    assert code == EXIT_OK
    report = json.loads(capsys.readouterr().out)
    assert report["advertised"] == ["a:read", "a:write"]
    assert report["tools"]["whoami"] == "(none)"


def test_policy_rejects_a_tool_with_no_scope_specified(capsys) -> None:
    code = main(["policy", "--scopes", "a:read", "--tools", "whoami"])

    assert code == EXIT_ERROR
    assert "has no scope" in capsys.readouterr().err


def test_policy_rejects_a_scope_outside_the_vocabulary(capsys) -> None:
    code = main(["policy", "--scopes", "a:read", "--tools", "w=a:write"])

    assert code == EXIT_ERROR
    err = capsys.readouterr().err
    assert "outside the vocabulary" in err
    # The message names the offending value, because "some scope is wrong" is
    # not actionable.
    assert "a:write" in err


def test_policy_notes_a_declared_but_unused_scope(capsys) -> None:
    code = main(["policy", "--scopes", "a:read,a:write", "--tools", "r=a:read"])

    assert code == EXIT_OK
    captured = capsys.readouterr()
    assert json.loads(captured.out)["unused"] == ["a:write"]
    assert "no tool needs them" in captured.err


def test_policy_needs_a_nonempty_tool_map(capsys) -> None:
    code = main(["policy", "--scopes", "a:read", "--tools", ""])

    assert code == EXIT_ERROR
    assert "every public tool needs a declared scope" in capsys.readouterr().err


def test_decode_without_a_token_says_where_to_put_one(capsys, monkeypatch) -> None:
    monkeypatch.delenv("MCP_TOKEN", raising=False)
    monkeypatch.delenv("MCP_TOKEN_FILE", raising=False)

    code = main(["decode", "--issuer", ISSUER, "--resource", RESOURCE])

    assert code == EXIT_ERROR
    err = capsys.readouterr().err
    assert "MCP_TOKEN" in err
    assert "chmod 600" in err


def test_decode_raw_prints_claims_unverified(capsys) -> None:
    """The case where the token cannot be verified and the question is what it
    says.  The output says so, because an unverified claim is an attacker's
    claim."""
    code = main(["decode", "--raw", TOKEN])

    assert code == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["UNVERIFIED"] is True
    assert payload["claims"]["sub"] == "u-1"


def test_decode_raw_rejects_a_non_jwt(capsys) -> None:
    assert main(["decode", "--raw", "nonsense"]) == EXIT_ERROR
    assert "not a JWT" in capsys.readouterr().err


def test_decode_reads_a_token_file(capsys, tmp_path, monkeypatch) -> None:
    path = tmp_path / "token"
    path.write_text(f"  {TOKEN}\n", encoding="utf-8")
    monkeypatch.setenv("MCP_TOKEN", "wrong-token")

    code = main(["decode", "--raw", "--token-file", str(path)])

    assert code == EXIT_OK
    assert json.loads(capsys.readouterr().out)["claims"]["sub"] == "u-1"


def test_decode_reports_a_missing_token_file(capsys, tmp_path) -> None:
    code = main(["decode", "--issuer", ISSUER, "--resource", RESOURCE, "--token-file",
                 str(tmp_path / "absent")])

    assert code == EXIT_ERROR
    assert "cannot read" in capsys.readouterr().err


def test_a_rejected_token_exits_with_its_own_code(capsys, monkeypatch) -> None:
    """Distinct from a configuration error, so a script can retry one and not
    the other."""
    monkeypatch.setenv("MCP_TOKEN", TOKEN)
    code = main(["decode", "--issuer", ISSUER, "--resource", RESOURCE, "--jwks-uri",
                 "http://127.0.0.1:1/unreachable"])

    assert code == EXIT_REJECTED
    err = capsys.readouterr().err
    # The reason is printed, because "rejected" and "could not reach the keys"
    # send an operator to completely different places.
    assert "signing key unavailable" in err