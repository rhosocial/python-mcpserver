#!/usr/bin/env python3
# scripts/check_core_version.py
"""Check that the pinned core ORM version is obtainable, from wherever it comes from.

`pip` reports an unsatisfiable pin as a wall of `ResolutionImpossible`, which
does not say the one useful thing: *the version you need exists only on a branch
nobody has pushed*.  That is not hypothetical — this package needs the core's
`IDataPreparationBehavior` and the dialect-carrying `ColumnConstraint`, both of
which arrived after `1.0.0.dev29`, so the pin was satisfiable from no index at
all.

So this runs before the install step and says which of the two cases it is:

* an **index** source — checks PyPI (or a mirror) actually offers a version
  satisfying the pin;
* a **git** source — resolves the ref and reads the version out of the fetched
  `pyproject.toml`, because a git install is not on any index and asking one
  about it answers a question nobody asked.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

PACKAGE = "rhosocial-activerecord"

#: Enough to read a version out of a pyproject without a TOML parser: the file
#: is not ours, and a regex keeps this script dependency-free on a runner that
#: has only pip.
_VERSION_LINE = re.compile(r"^\s*version\s*=\s*[\"']([^\"']+)[\"']", re.MULTILINE)


def version_from_pyproject(text: str) -> str | None:
    match = _VERSION_LINE.search(text)
    return match.group(1) if match else None


# ── index ──────────────────────────────────────────────────────────────


def index_versions(index_url: str | None) -> list[str]:
    """Every version the index can offer.

    ``--index-url`` because a CI job may point at a private mirror, in which
    case the answer is that mirror's catalogue and not PyPI's.

    Parsed from the ``Available versions:`` line rather than the first or the
    last: pip prints ``<pkg> (1.2.3)`` first and ``INSTALLED:`` / ``LATEST:``
    after, so both of the obvious choices give the wrong answer.
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
            return [v.strip() for v in stripped.split(":", 1)[1].split(",") if v.strip()]
    raise SystemExit(f"unexpected `pip index versions` output:\n{output.strip()}")


def check_index(required: str, index_url: str | None) -> int:
    from packaging.requirements import Requirement
    from packaging.version import InvalidVersion, Version

    specifier = Requirement(f"{PACKAGE}{required}").specifier
    versions = index_versions(index_url)
    if not versions:
        print(f"error: no version of {PACKAGE} is published at all.", file=sys.stderr)
        return 1
    try:
        newest = max((Version(v) for v in versions), key=Version)
        usable = [v for v in versions if specifier.contains(Version(v), prereleases=True)]
    except InvalidVersion as exc:  # pragma: no cover - an index with junk in it
        print(f"error: the index offered an unparseable version: {exc}", file=sys.stderr)
        return 1

    if usable:
        print(
            json.dumps(
                {"source": "index", "required": required, "resolved": max(usable, key=Version)},
                indent=2,
            )
        )
        return 0
    print(_index_failure(required, str(newest), versions), file=sys.stderr)
    return 1


def _index_failure(required: str, newest: str, versions: list[str]) -> str:
    return "\n".join(
        [
            f"error: this package requires {PACKAGE}{required},",
            f"       and the newest the index offers is {newest}.",
            "",
            "The pinned API is in no published release. Two ways forward:",
            "",
            "  1. Release the core library.  Merge and tag the branch carrying it,",
            "     bump its version, publish, then re-run.  This is the fix to take",
            "     before anything downstream depends on it.",
            "",
            "  2. Point CORE_SOURCE at a git ref that has it, in",
            "     .github/workflows/test.yml.  Fine for an internal branch; not",
            "     fine for a published release, because a consumer resolving this",
            "     package from an index cannot get it.",
            "",
            f"available: {', '.join(versions)}",
        ]
    )


# ── git ────────────────────────────────────────────────────────────────


def check_git(source: str, required: str) -> int:
    """Resolve a ``git+https://…@ref`` source and read its declared version.

    Not by installing: an install is slow, and it would mask the one thing worth
    checking, which is whether the *ref* is reachable and carries the pin.
    """
    from packaging.requirements import Requirement
    from packaging.version import InvalidVersion, Version

    url, _, ref = source.partition("@")
    url = url.removeprefix("git+")
    if not ref:
        print(
            f"error: CORE_SOURCE={source!r} has no ref, so the source moves under "
            "the build. Pin it to a branch or a tag.",
            file=sys.stderr,
        )
        return 1

    with tempfile.TemporaryDirectory() as work:
        result = subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                ref,
                "--quiet",
                url,
                str(Path(work) / "src"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            print(
                "\n".join(
                    [
                        f"error: cannot clone {url} at ref {ref!r}.",
                        result.stderr.strip(),
                        "",
                        "Usually the ref is on nobody's remote yet. Push the branch",
                        "carrying the API this package needs, or point CORE_SOURCE at",
                        "a ref that is already published.",
                    ]
                ),
                file=sys.stderr,
            )
            return 1
        pyproject = Path(work) / "src" / "pyproject.toml"
        version = None
        if pyproject.exists():
            version = version_from_pyproject(pyproject.read_text(encoding="utf-8"))

    if version is None:
        print(f"error: {url}@{ref} has no readable version in pyproject.toml.", file=sys.stderr)
        return 1

    specifier = Requirement(f"{PACKAGE}{required}").specifier
    try:
        satisfies = specifier.contains(Version(version), prereleases=True)
    except InvalidVersion as exc:  # pragma: no cover
        print(f"error: {url}@{ref} declares an unparseable version: {exc}", file=sys.stderr)
        return 1

    if not satisfies:
        print(
            f"error: {url}@{ref} declares {version}, which does not satisfy "
            f"{PACKAGE}{required}. Either the ref is wrong or this package's pin "
            "is behind what it uses.",
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            {"source": url, "ref": ref, "required": required, "declared": version}, indent=2
        )
    )
    return 0


# ── entry point ────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the pinned core ORM is obtainable.")
    parser.add_argument(
        "--required",
        default=">=1.0.0.dev30",
        help="the specifier this package pins",
    )
    parser.add_argument(
        "--source",
        default=None,
        help="a git+https source to check instead of an index",
    )
    parser.add_argument("--index-url", help="a private index to query instead of the default")
    args = parser.parse_args(argv)

    if args.source and args.source.startswith("git+"):
        return check_git(args.source, args.required)
    return check_index(args.required, args.index_url)


if __name__ == "__main__":
    raise SystemExit(main())