#!/usr/bin/env python3
"""Source-bound finite GHOSTDAG ordering comparison and exact replay.

This runner compares the bitset/counter kernel with the independent set-based
test oracle. It neither generates nor verifies work, and has no node, transport,
transaction, confirmation or throughput result. No protocol qualification can
follow from a passing campaign. Exhaustive graph size is intentionally bounded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

FORMAL = Path(__file__).resolve().parents[1]
ROOT = FORMAL.parents[1]
sys.path.insert(0, str(FORMAL))

from ghostdag_order_reference import ASSUMPTIONS, canonical  # noqa: E402
from test_ghostdag_order_reference import (  # noqa: E402
    SATURATED_BLUE, checked_case, exhaustive_observation, graph_from_parents, oracle_order,
)

SCHEMA = "trnm-ghostdag-order-campaign-v1"
SOURCE_FILES = (
    "formal/pon-nakamoto-v1/ghostdag_order_reference.py",
    "formal/pon-nakamoto-v1/test_ghostdag_order_reference.py",
    "formal/pon-nakamoto-v1/experiments/ghostdag_order_campaign.py",
)


def source_record(head: str | None = None) -> dict:
    if head is None:
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if type(head) is not str or re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise ValueError("SOURCE_HEAD")
    kind = subprocess.run(["git", "cat-file", "-t", head], cwd=ROOT, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if kind.returncode or kind.stdout.strip() != "commit":
        raise ValueError("SOURCE_HEAD")
    digests: dict[str, str] = {}
    uncommitted: list[str] = []
    for name in SOURCE_FILES:
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 262144:
            raise ValueError("SOURCE_FILE_BOUND")
        digests[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        previous = subprocess.run(["git", "show", head + ":" + name], cwd=ROOT,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if previous.returncode or hashlib.sha256(previous.stdout).hexdigest() != digests[name]:
            uncommitted.append(name)
    return {"git_head": head, "source_sha256": digests,
            "all_source_files_committed_at_head": not uncommitted,
            "uncommitted_source_files": uncommitted,
            "scope": "enumerated Python kernel, independent test oracle and campaign bytes only"}


def make_report(max_blocks: int = 5, *, head: str | None = None) -> dict:
    if type(max_blocks) is not int or not 1 <= max_blocks <= 6:
        raise ValueError("ENUMERATION_BOUND")
    source = source_record(head)
    observation = exhaustive_observation(max_blocks)
    blocks = graph_from_parents(SATURATED_BLUE)
    correct, _ = checked_case(blocks, 2)
    incorrect = oracle_order(blocks, 2, candidate_only=True)
    if correct["blue"] == incorrect["blue"] or not any(n > 2 for _, n in incorrect["blue_anticone_sizes"]):
        raise AssertionError("COUNTEREXAMPLE_NOT_REPRODUCED")
    if source_record(source["git_head"]) != source:
        raise ValueError("SOURCE_CHANGED_DURING_CAMPAIGN")
    return {"schema": SCHEMA, "scope": json.loads(canonical(ASSUMPTIONS)), "source": source,
            "parameters": {"max_blocks": max_blocks}, "observation": observation,
            "candidate_only_counterexample": {
                "k": 2, "blocks": [b.__dict__ for b in blocks],
                "correct": correct, "incorrect_candidate_only": incorrect,
                "finding": "candidate-only admission violates an existing blue vertex's k bound",
            },
            "verdict": "FINITE_ORDERING_EQUIVALENCE_ONLY"}


def replay_report(value: dict) -> dict:
    fields = {"schema", "scope", "source", "parameters", "observation",
              "candidate_only_counterexample", "verdict"}
    if type(value) is not dict or set(value) != fields or value["schema"] != SCHEMA:
        raise ValueError("REPORT_SCHEMA")
    if value["scope"] != ASSUMPTIONS or value["verdict"] != "FINITE_ORDERING_EQUIVALENCE_ONLY":
        raise ValueError("REPORT_SCOPE")
    if type(value["parameters"]) is not dict or set(value["parameters"]) != {"max_blocks"}:
        raise ValueError("REPORT_PARAMETERS")
    if type(value["source"]) is not dict or "git_head" not in value["source"]:
        raise ValueError("REPORT_SOURCE")
    head = value["source"]["git_head"]
    if value["source"] != source_record(head):
        raise ValueError("REPORT_SOURCE")
    replayed = make_report(value["parameters"]["max_blocks"], head=head)
    if canonical(replayed) != canonical(value):
        raise ValueError("REPORT_REPLAY_DIFFERENCE")
    return {"schema": "trnm-ghostdag-order-replay-v1", "result": "PASS",
            "source_head": head, "cases": replayed["observation"]["cases"],
            "transcript_sha256": replayed["observation"]["transcript_sha256"],
            "scope": "exact source-bound finite ordering replay",
            "security_theorem": False, "production_activation": False}


def _strict_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def read_report(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_048_576:
        raise ValueError("REPORT_FILE_BOUND")
    with path.open("rb") as stream:
        raw = stream.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError("REPORT_FILE_BOUND")
    value = json.loads(raw, object_pairs_hook=_strict_object)
    if type(value) is not dict:
        raise ValueError("REPORT_SCHEMA")
    return value


def publish_new_report(path: Path, data: bytes) -> None:
    """Publish once by atomic hard link; an existing/concurrent target wins.

    The temporary inode is written and fsynced before it acquires the requested
    name. os.link never replaces that name, including a dangling symlink. The
    same-directory temporary file is always removed. A filesystem that cannot
    supply these operations raises; no non-atomic overwrite fallback is used.
    A failure after linking may leave a complete file whose durability has not
    been acknowledged, so callers must inspect rather than overwrite on retry.
    """
    if type(data) is not bytes or len(data) > 1_048_576:
        raise ValueError("REPORT_FILE_BOUND")
    fd, name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".partial", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise ValueError("OUTPUT_ALREADY_EXISTS") from exc
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-blocks", type=int, help="exhaustive bound 1..6 (default 5)")
    parser.add_argument("--output", type=Path, help="write a new JSON receipt after full success")
    parser.add_argument("--replay", type=Path, help="recompute and compare a source-bound receipt")
    args = parser.parse_args()
    if args.replay:
        if args.max_blocks is not None or args.output is not None:
            parser.error("--replay cannot change the original inputs or overwrite the receipt")
        print(json.dumps(replay_report(read_report(args.replay)), sort_keys=True))
        return
    report = make_report(5 if args.max_blocks is None else args.max_blocks)
    data = canonical(report) + b"\n"
    if args.output:
        publish_new_report(args.output, data)
    else:
        print(data.decode("utf-8"), end="")


if __name__ == "__main__":
    main()
