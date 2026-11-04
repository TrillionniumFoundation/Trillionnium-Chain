#!/usr/bin/env python3
"""Exercise the independent-source guard against real, isolated Git attacks.

Supply a local checkout of the exact upstream pin with --source. Each case uses
a temporary shared clone with only mldsa/ materialized; no upstream files,
production keys, network service, or original Git refs are modified. This tests
source attribution only, not ML-DSA correctness or deployment qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import mldsa_native_differential as guard


class NativeSourcePinTests(unittest.TestCase):
    upstream: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.expected = guard.checked_source(cls.upstream)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="trnm-mldsa-source-pin-")
        self.addCleanup(temporary.cleanup)
        self.checkout = Path(temporary.name) / "source"
        self.environment = {
            **os.environ,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
        subprocess.run(
            ["git", "clone", "--quiet", "--shared", "--no-checkout",
             str(self.upstream), str(self.checkout)],
            env=self.environment, check=True, capture_output=True, timeout=30,
        )
        self.git("sparse-checkout", "set", "--no-cone", "/mldsa/")
        self.git("checkout", "--quiet", "--detach", guard.UPSTREAM_COMMIT)

    def git(self, *arguments: str, input: bytes | None = None) -> bytes:
        # Ordinary Git deliberately honors replacement refs. The attack case
        # must show their effect before the guarded reader refuses the checkout.
        return subprocess.run(
            ["git", "-C", str(self.checkout), *arguments],
            input=input, env=self.environment, check=True, capture_output=True,
            timeout=30,
        ).stdout

    def test_pristine_pinned_source_is_accepted(self) -> None:
        self.assertEqual(guard.checked_source(self.checkout), self.expected)

    def test_modified_tracked_source_is_rejected(self) -> None:
        path = self.checkout / "mldsa/mldsa_native.c"
        path.write_bytes(path.read_bytes() + b"\n/* changed source */\n")
        with self.assertRaises(ValueError):
            guard.checked_source(self.checkout)

    def test_missing_tracked_source_is_rejected(self) -> None:
        (self.checkout / "mldsa/mldsa_native.c").unlink()
        with self.assertRaises(ValueError):
            guard.checked_source(self.checkout)

    def test_untracked_include_is_rejected(self) -> None:
        (self.checkout / "mldsa/trnm-untracked-include.h").write_bytes(
            b"/* Untracked compile input must not belong to the pinned source. */\n"
        )
        with self.assertRaises(ValueError):
            guard.checked_source(self.checkout)

    def test_symlinked_source_is_rejected_even_when_bytes_match(self) -> None:
        path = self.checkout / "mldsa/mldsa_native.c"
        path.unlink()
        path.symlink_to(self.upstream / "mldsa/mldsa_native.c")
        with self.assertRaises(ValueError):
            guard.checked_source(self.checkout)

    def test_different_commit_with_identical_source_is_rejected(self) -> None:
        tree = self.git("rev-parse", "HEAD^{tree}").decode().strip()
        # A real commit object with identical source but another identity.
        # Fixture-only identities never leave this temporary clone.
        self.environment.update({
            "GIT_AUTHOR_NAME": "Source pin test",
            "GIT_AUTHOR_EMAIL": "source-pin-test@invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
            "GIT_COMMITTER_NAME": "Source pin test",
            "GIT_COMMITTER_EMAIL": "source-pin-test@invalid",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
        })
        alternate = self.git(
            "commit-tree", tree, "-p", guard.UPSTREAM_COMMIT,
            input=b"source pin regression fixture\n",
        ).decode().strip()
        self.git("update-ref", "HEAD", alternate, guard.UPSTREAM_COMMIT)
        self.assertEqual(self.git("rev-parse", "HEAD^{tree}").decode().strip(), tree)
        with self.assertRaises(ValueError):
            guard.checked_source(self.checkout)

    def test_replaced_tree_cannot_inherit_the_original_commit_identity(self) -> None:
        original_tree = self.git("rev-parse", "HEAD^{tree}").decode().strip()
        original_blob = self.git(
            "rev-parse", "HEAD:mldsa/mldsa_native.c"
        ).decode().strip()
        path = self.checkout / "mldsa/mldsa_native.c"
        path.write_bytes(path.read_bytes() + b"\n/* replacement-tree attack */\n")
        self.git("add", "--", "mldsa/mldsa_native.c")
        alternate_tree = self.git("write-tree").decode().strip()
        self.git("replace", original_tree, alternate_tree)

        # The exact failure mode: HEAD remains the trusted pin, but a normal
        # tree walk now names the attacker's changed source blob.
        self.assertEqual(
            self.git("rev-parse", "HEAD").decode().strip(), guard.UPSTREAM_COMMIT
        )
        replaced_entry = self.git("ls-tree", "HEAD", "--", "mldsa/mldsa_native.c")
        self.assertNotEqual(replaced_entry.split()[2].decode(), original_blob)
        with self.assertRaises(ValueError):
            guard.checked_source(self.checkout)

    def test_grafted_history_is_rejected(self) -> None:
        path = Path(self.git("rev-parse", "--git-path", "info/grafts").decode().strip())
        if not path.is_absolute():
            path = self.checkout / path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(guard.UPSTREAM_COMMIT + "\n", encoding="ascii")
        with self.assertRaises(ValueError):
            guard.checked_source(self.checkout)

    def test_nested_source_root_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            guard.checked_source(self.checkout / "mldsa")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    args = parser.parse_args()
    NativeSourcePinTests.upstream = args.source.resolve(strict=True)
    guard_path = Path(guard.__file__).resolve(strict=True)
    print(json.dumps({
        "scope": "real Git source-pin regression only",
        "upstream_commit": guard.UPSTREAM_COMMIT,
        "upstream_checkout": str(NativeSourcePinTests.upstream),
        "guard": str(guard_path),
        "guard_sha256": hashlib.sha256(guard_path.read_bytes()).hexdigest(),
    }, sort_keys=True), flush=True)
    result = unittest.main(argv=[sys.argv[0], "-v"], exit=False).result
    return 0 if result.wasSuccessful() and result.testsRun > 0 and not result.skipped else 1


if __name__ == "__main__":
    raise SystemExit(main())
