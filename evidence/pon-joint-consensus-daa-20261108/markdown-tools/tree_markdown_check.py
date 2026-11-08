#!/usr/bin/env python3
"""Check tracked Markdown links against one immutable Git tree.

This is an independent, tree-based link check. It does not execute, replace,
or report a PASS for scripts/ci/check_repository.py. It never materializes
placeholders or writes a source/index/ref. Optional fetches fill only the
normal Git object cache, with no destination ref and no FETCH_HEAD update.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
from urllib.parse import unquote, urlsplit


FENCE = r"^```[^\n]*\n.*?^```[^\n]*$"
INLINE = r"\[[^\]]*\]\(([^\s)]+)\)"
EXCLUDED = {".git", "target", "__pycache__", ".pytest_cache", "node_modules"}
CHECKER = "scripts/ci/check_repository.py"
# This exact checker source was independently inspected at both parents of
# the integration merge. A different source requires a fresh review and an
# explicit verifier update; merely retaining old regex text is insufficient.
APPROVED_CHECKER_SHA256 = frozenset({
    "0d7040ac82a54a97a2db0a3d94db30822a047af5a8f4946ff4d4fc29ae9a190f",
})


class Invalid(ValueError):
    pass


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_json(path: pathlib.Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


class Tree:
    def __init__(self, repo: pathlib.Path, commit: str, output: pathlib.Path,
                 prefetch: bool = False):
        self.repo, self.output, self.prefetch = repo, output, prefetch
        self.blobs: dict[str, bytes] = {}
        self.fetches: list[dict] = []
        self.commit = self.git("rev-parse", "--verify", commit + "^{commit}").decode().strip()
        if self.commit != commit:
            raise Invalid("input commit did not resolve to its exact supplied object ID")
        self.tree = self.git("rev-parse", commit + "^{tree}").decode().strip()
        self.raw_tree = self.git("ls-tree", "-r", "-t", "-z", "--full-tree", commit)
        (output / "tree-index.z").write_bytes(self.raw_tree)
        self.entries: dict[str, dict[str, str]] = {
            "": {"mode": "040000", "type": "tree", "oid": self.tree}
        }
        for raw in self.raw_tree.split(b"\0"):
            if not raw:
                continue
            header, path_raw = raw.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split()
            path = path_raw.decode("utf-8", "strict")
            if (path.startswith("/") or any(p in {"", ".", ".."} for p in path.split("/"))
                    or path in self.entries):
                raise Invalid("noncanonical or duplicate tree path: " + repr(path))
            self.entries[path] = {"mode": mode, "type": kind, "oid": oid}
        # Resolve symlinks using their committed bytes, never the filesystem.
        self.load_blobs({r["oid"] for r in self.entries.values() if r["mode"] == "120000"})

    def git(self, *args: str, data: bytes | None = None,
            no_lazy: bool = False) -> bytes:
        env = dict(os.environ)
        env["GIT_OPTIONAL_LOCKS"] = "0"
        if no_lazy:
            env["GIT_NO_LAZY_FETCH"] = "1"
        proc = subprocess.run(["git", "-C", str(self.repo), *args], input=data,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        if proc.returncode:
            raise Invalid("git " + args[0] + " failed: " + proc.stderr.decode("utf-8", "replace"))
        return proc.stdout

    def load_blobs(self, oids: set[str]) -> None:
        needed = sorted(oids - self.blobs.keys())
        if not needed:
            return
        request = ("\n".join(needed) + "\n").encode("ascii")
        # A direct cat-file query for a missing promisor object can fail rather
        # than return "missing" when lazy fetch is disabled. Enumerating only
        # physically cached objects avoids both accidental per-blob fetching
        # and that version-dependent missing-object behavior.
        metadata = self.git("cat-file", "--batch-all-objects",
                            "--batch-check=%(objectname) %(objecttype)",
                            no_lazy=True).decode("ascii").splitlines()
        available = dict(line.split() for line in metadata)
        missing = [wanted for wanted in needed if wanted not in available]
        for wanted in set(needed) - set(missing):
            if available[wanted] != "blob":
                raise Invalid("requested Markdown/symlink object is not a blob: " + wanted)
        if missing:
            if not self.prefetch:
                raise Invalid(f"{len(missing)} required real blobs are missing; rerun with --prefetch")
            # Explicit SHA refspecs without a destination never update a ref.
            command = ["git", "-C", str(self.repo), "-c", "fetch.negotiationAlgorithm=noop",
                       "fetch", "--no-tags", "--no-write-fetch-head", "--recurse-submodules=no",
                       "--no-auto-maintenance", "--filter=blob:none", "--stdin", "origin"]
            proc = subprocess.run(command, input=("\n".join(missing) + "\n").encode("ascii"),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            index = len(self.fetches) + 1
            (self.output / f"prefetch-{index:02d}.stdout").write_bytes(proc.stdout)
            (self.output / f"prefetch-{index:02d}.stderr").write_bytes(proc.stderr)
            self.fetches.append({"object_ids": missing, "exit_code": proc.returncode,
                                 "stdout_sha256": sha256(proc.stdout),
                                 "stderr_sha256": sha256(proc.stderr)})
            write_json(self.output / "prefetch.json", self.fetches)
            if proc.returncode:
                raise Invalid("normal promisor prefetch failed; raw logs retained")
        raw = self.git("cat-file", "--batch", data=request, no_lazy=True)
        pos = 0
        for wanted in needed:
            end = raw.find(b"\n", pos)
            if end < 0:
                raise Invalid("truncated batch header")
            fields = raw[pos:end].decode("ascii").split()
            if len(fields) != 3 or fields[0] != wanted or fields[1] != "blob":
                raise Invalid("required blob remains unavailable: " + " ".join(fields))
            size = int(fields[2])
            begin, pos = end + 1, end + 1 + size
            content = raw[begin:pos]
            if len(content) != size or raw[pos:pos + 1] != b"\n":
                raise Invalid("truncated batch blob")
            pos += 1
            actual = hashlib.sha1(b"blob " + str(size).encode() + b"\0" + content).hexdigest()
            if actual != wanted:
                raise Invalid("blob content does not match its Git object ID")
            self.blobs[wanted] = content
        if pos != len(raw):
            raise Invalid("unexpected trailing batch response")

    def resolve(self, base: str, target: str) -> str:
        """POSIX, case-sensitive resolution with committed symlinks.

        Escaping the tree is rejected even if a later component might return.
        This is deliberately conservative for absolute committed symlinks;
        it never assumes the checkout's external filesystem layout.
        """
        if "\0" in target or target.startswith("/"):
            raise Invalid("absolute or NUL-containing local target")
        stack = base.split("/") if base else []
        pending = target.split("/")
        symlink_hops = 0
        while pending:
            item = pending.pop(0)
            if item in {"", "."}:
                continue
            if item == "..":
                if not stack:
                    raise Invalid("local target escapes repository root")
                stack.pop()
                continue
            current = "/".join(stack + [item])
            row = self.entries.get(current)
            if row is None:
                raise Invalid("missing case-exact tree path: " + current)
            if row["mode"] == "120000":
                symlink_hops += 1
                if symlink_hops > 40:
                    raise Invalid("symlink loop or excessive symlink depth")
                link = self.blobs[row["oid"]].decode("utf-8", "strict")
                if not link or link.startswith("/") or "\0" in link:
                    raise Invalid("unsupported absolute, empty or NUL symlink: " + current)
                pending = link.split("/") + pending
                continue
            stack.append(item)
            if any(p not in {"", "."} for p in pending) and row["type"] != "tree":
                raise Invalid("non-directory path component: " + current)
        resolved = "/".join(stack)
        if resolved not in self.entries:
            raise Invalid("resolved path is absent from tree")
        return resolved


def check(repo: pathlib.Path, commit: str, output: pathlib.Path,
          prefetch: bool = False) -> dict:
    if not re.fullmatch("[0-9a-f]{40}", commit):
        raise Invalid("supply an exact 40-digit commit object ID")
    tree = Tree(repo, commit, output, prefetch)
    checker = tree.entries.get(CHECKER)
    if checker is None or checker["type"] != "blob" or checker["mode"] == "120000":
        raise Invalid("canonical checker source is missing or not a regular tracked file")
    candidates = sorted(p for p, row in tree.entries.items()
                        if p.endswith(".md") and row["type"] == "blob"
                        and not EXCLUDED.intersection(p.split("/")))
    resolved_mds = {path: tree.resolve("", path) for path in candidates}
    md_oids = {tree.entries[p]["oid"] for p in resolved_mds.values()}
    tree.load_blobs(md_oids | {checker["oid"]})
    canonical = tree.blobs[checker["oid"]]
    # Fail on parser drift rather than silently calling this the same grammar.
    if sha256(canonical) not in APPROVED_CHECKER_SHA256:
        raise Invalid("canonical checker source is not the independently reviewed version")
    canonical_text = canonical.decode("utf-8", "strict")
    if FENCE not in canonical_text or INLINE not in canonical_text:
        raise Invalid("canonical Markdown parser has changed; independent checker needs review")
    (output / "canonical-check_repository.py").write_bytes(canonical)
    inputs, links, errors = [], [], []
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in candidates:
            resolved = resolved_mds[path]
            row = tree.entries[resolved]
            if row["type"] != "blob" or row["mode"] == "120000":
                raise Invalid("Markdown path does not resolve to a regular blob: " + path)
            raw = tree.blobs[row["oid"]]
            content = raw.decode("utf-8", "strict")
            inputs.append({"path": path, "resolved_source_path": resolved,
                           "git_blob": row["oid"], "sha256": sha256(raw), "bytes": len(raw)})
            info = tarfile.TarInfo(path)
            info.size, info.mode, info.mtime = len(raw), 0o644, 0
            archive.addfile(info, io.BytesIO(raw))
            content = re.sub(FENCE, "", content, flags=re.M | re.S)
            for target in re.findall(INLINE, content):
                record = {"source": path, "target": target}
                try:
                    parsed = urlsplit(target.strip("<>"))
                    if parsed.scheme or parsed.netloc or not parsed.path:
                        continue
                    # Path.parent in the original checker is the link's source
                    # location, even when the .md file itself is a symlink.
                    parent = path.rpartition("/")[0]
                    resolved_target = tree.resolve(parent, unquote(parsed.path))
                    record["resolved_target"] = resolved_target
                    record["target_kind"] = tree.entries[resolved_target]["type"]
                    links.append(record)
                except (Invalid, ValueError, UnicodeError) as exc:
                    record["error"] = str(exc)
                    errors.append(record)
    archive_bytes = gzip.compress(tar_buffer.getvalue(), mtime=0)
    (output / "markdown-inputs.tar.gz").write_bytes(archive_bytes)
    write_json(output / "markdown-inputs.json", inputs)
    write_json(output / "local-links.json", links)
    write_json(output / "link-errors.json", errors)
    report = {
        "schema": "independent-git-tree-markdown-links-v1",
        "result": "PASS" if not errors else "FAIL",
        "commit": commit, "tree": tree.tree,
        "tree_index_sha256": sha256(tree.raw_tree),
        "tree_entry_count": len(tree.entries) - 1,
        "markdown_files": len(candidates), "local_links": len(links),
        "link_errors": len(errors), "all_tracked_markdown_read": True,
        "markdown_input_bytes": sum(row["bytes"] for row in inputs),
        "markdown_archive_sha256": sha256(archive_bytes),
        "canonical_checker_git_blob": checker["oid"],
        "canonical_checker_sha256": sha256(canonical),
        "canonical_checker_source_approved": True,
        "canonical_check_repository_executed": False,
        "full_repository_gate_pass_claimed": False,
        "checks_fragment_anchors": False,
        "checks_reference_style_links": False,
        "parser": "same fenced-block removal and inline-link regex as committed check_repository.py",
        "scope": "tracked commit tree only; no working-tree, JSON/TOML, Cargo or other repository gates",
        "symlink_resolution": "committed relative symlink targets; absolute/escaping symlinks fail closed",
        "prefetch_batches": len(tree.fetches),
    }
    write_json(output / "result.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=pathlib.Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--prefetch", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        report = check(args.repo.resolve(strict=True), args.commit, args.output, args.prefetch)
        code = 0 if report["result"] == "PASS" else 2
    except (Invalid, OSError, ValueError, UnicodeError) as exc:
        report = {"schema": "independent-git-tree-markdown-links-v1", "result": "FAIL",
                  "commit": args.commit, "error": str(exc),
                  "canonical_check_repository_executed": False,
                  "full_repository_gate_pass_claimed": False}
        code = 2
    report["started_utc"] = started
    report["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    report["verifier_sha256"] = sha256(pathlib.Path(__file__).read_bytes())
    write_json(args.output / "result.json", report)
    print(json.dumps(report, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
