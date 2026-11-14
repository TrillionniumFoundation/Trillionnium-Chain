#!/usr/bin/env python3
"""Observe the retained recovery-order SQL without running or modifying a Node.

Extract the exact BASE_DDL and recovery_target query from one committed source.
Use separate in-memory databases for the original schema and an index-removal
control. The fixture contains synthetic SQL rows, not admitted native blocks.
"""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import sqlite3
import subprocess


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def observe(ddl, query, entries, expected, indexed):
    # Do not reuse an EXPLAIN statement across a schema change. Each arm has a
    # fresh connection and disables the Python driver's prepared-statement cache.
    with sqlite3.connect(":memory:", cached_statements=0) as db:
        db.executescript(ddl)
        if not indexed:
            db.execute("DROP INDEX work_order")
        db.executemany("INSERT INTO blocks VALUES(?,?,?,?,?,?)", entries)
        plan = [list(row) for row in db.execute("EXPLAIN QUERY PLAN " + query)]
        actual = db.execute(query).fetchone()[0]
        index_seen = any("USING COVERING INDEX work_order" in row[3] for row in plan)
        temporary_sort = any("USE TEMP B-TREE FOR ORDER BY" in row[3] for row in plan)
        result = {
            "index_present": indexed,
            "fixture_rows": len(entries),
            "query_plan": plan,
            "work_order_covering_index_seen": index_seen,
            "temporary_order_btree": temporary_sort,
            "result_id": actual.hex(),
            "result_matches_independent_sort": actual == expected,
        }
        if actual != expected or index_seen != indexed or temporary_sort == indexed:
            raise RuntimeError(json.dumps({"unexpected_observation": result}))
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--source", required=True, help="Commit or ref, resolved once to a commit")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    commit = git(args.repo, "rev-parse", "--verify", args.source + "^{commit}").decode().strip()
    path = "trillionnium/crates/trnm-pon-node/src/store.rs"
    raw = git(args.repo, "show", f"{commit}:{path}")
    source = raw.decode("utf-8")
    ddl_match = re.search(r'const BASE_DDL:&str="(.*?)";', source, re.S)
    query_match = re.search(
        r'fn recovery_target\(&self\) -> Result<Hash>.*?"(SELECT id FROM blocks[^"]+)"',
        source,
        re.S,
    )
    if ddl_match is None or query_match is None:
        raise RuntimeError("Source no longer has the reviewed DDL/query shape")
    ddl, query = ddl_match.group(1), query_match.group(1)
    if "\\" in ddl or query != "SELECT id FROM blocks ORDER BY chainwork DESC,height,id LIMIT 1":
        raise RuntimeError("Review changed Rust literal escaping or query semantics before use")

    entries = [
        (
            i.to_bytes(32, "big"),
            None,
            (i * 101) % 4096,
            ((i * 7919) % 65536).to_bytes(64, "big"),
            b"",
            bytes(32),
        )
        for i in range(4096)
    ]
    # The highest work has both a height tie and an ID tie-break. Work is a
    # fixed-width big-endian BLOB, matching the retained native ordering.
    entries.extend(
        (i.to_bytes(32, "big"), None, height, (1 << 510).to_bytes(64, "big"), b"", bytes(32))
        for i, height in [(9000, 4), (9001, 3), (9002, 3)]
    )
    expected = min(entries, key=lambda row: (-int.from_bytes(row[3], "big"), row[2], row[0]))[0]
    result = {
        "schema": "chain-recovery-order-sql-observation-v1",
        "source_commit": commit,
        "source_tree": git(args.repo, "rev-parse", f"{commit}^{{tree}}").decode().strip(),
        "source_path": path,
        "source_git_blob": git(args.repo, "rev-parse", f"{commit}:{path}").decode().strip(),
        "source_sha256": sha256(raw),
        "script_sha256": sha256(Path(__file__).read_bytes()),
        "base_ddl_sha256": sha256(ddl.encode()),
        "query": query,
        "query_sha256": sha256(query.encode()),
        "sqlite_version": sqlite3.sqlite_version,
        "python_version": platform.python_version(),
        "reference_order": "descending integer work, ascending height, ascending full ID bytes",
        "observations": [observe(ddl, query, entries, expected, indexed) for indexed in (True, False)],
        "native_node_executed": False,
        "business_tps_measured": False,
        "scope": (
            "Source-extracted SQL in isolated Python SQLite databases with synthetic records. "
            "No state validity, native recovery, time bound, or throughput claim."
        ),
    }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
