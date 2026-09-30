#!/usr/bin/env python3
# scripts/check_core_version.py
"""Fail legibly when the pinned core ORM version is not obtainable.

`pip` reports an unsatisfiable pin as a wall of `ResolutionImpossible`, which
does not say the one useful thing: *the version you need exists only on a local
working tree*.  That is not a hypothetical here — `rhosocial-activerecord`
`1.0.0.dev30` was on an unpushed feature branch while this package required it,
and the resulting CI failure sent the reader looking for a dependency conflict
rather than for the missing release.

Run before the install step, so the error names the cause:

    python scripts/check_core_version.py --required '>=1.0.0.dev30'
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

from packaging.requirements import Requirement
from packaging.version import InvalidVersion, Version

PACKAGE = "rhosocial-activerecord"


def available(index_url: str | None) -> list[str]:
    """Every version the index can offer.

    ``--index-url`` because a CI job may point at a private mirror, in which
    case the answer is that mirror's catalogue and not PyPI's.

    Parsed from the ``Available versions:`` line rather than the first line:
    pip prints ``<pkg> (1.2.3)`` first, and ``INSTALLED:`` / ``LATEST:`` after —
    the last of which is the newest on the index, so taking the first line or
    the last line both give the wrong answer.
    """
    command = [sys.executable, "-m", "pip", "index", "versions", PACKAGE, "--pre"]
    if index_url:
        command += ["--index-url", index_url]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise SystemExit(
            f"cannot query {PACKAGE} from the index. Check connectivity, or pass "
            f"--index-url if this job uses a mirror.\n{output.strip()}"
        )
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Available versions:"):
            return [
                item.strip()
                for item in stripped.split(":", 1)[1].split(",")
                if item.strip()
            ]
    raise SystemExit(f"unexpected `pip index versions` output:\n{output.strip()}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--required", default=">=1.0.0.dev30", help="the specifier this package pins"
    )
    parser.add_argument("--index-url", help="a private index to query instead of the default")
    args = parser.parse_args(argv)

    requirement = Requirement(f"{PACKAGE}{args.required}")
    versions = available(args.index_url)
    if not versions:
        print(f"error: no version of {PACKAGE} is published at all.", file=sys.stderr)
        return 1

    try:
        newest = max((Version(v) for v in versions), key=lambda v: (v.is_prerelease, v))
        usable = [
            v
            for v in versions
            if requirement.specifier.contains(Version(v), prereleases=True)
        ]
    except InvalidVersion as exc:  # pragma: no cover - an index with junk in it
        print(f"error: the index offered an unparseable version: {exc}", file=sys.stderr)
        return 1

    if usable:
        print(
            json.dumps(
                {"required": str(requirement.specifier), "resolved": max(usable, key=Version)},
                indent=2,
            )
        )
        return 0

    print(
        "\n".join(
            [
                f"error: this package requires {PACKAGE}{args.required},",
                f"       and the newest the index offers is {newest}.",
                "",
                "The pinned API is not in any published release. Two ways forward:",
                "",
                "  1. Release the core library.  Merge and tag the branch carrying it,",
                "     bump its version, publish, then re-run.  This is the fix to take",
                "     before anything downstream depends on it.",
                "",
                "  2. Point CI at an unpublished source for now, by setting CORE_SOURCE",
                "     in .github/workflows/test.yml to a git ref that has it.  Fine for",
                "     an internal branch; not fine for a published release, because a",
                "     consumer resolving this package from PyPI cannot get it.",
                "",
                f"available: {', '.join(versions)}",
            ]
        ),
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())