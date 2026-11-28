"""Prepare an isolated signed-legacy rollback fixture or replay its retained local test."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))
from hia.platform.execution_state.rust_oracle import clean_build_environment, load_json, need

MODULE = "trillionnium/crates/trnm-pon-node/src/operator_task_store_tests.rs"
BEFORE = "9562ab948150efb1342790ec9fcd28ad94c63a59"
AFTER = "e985660e39b6c78bce2c0b6cb7d27b7984fb69bf"
FIXTURE = HERE / "rust_legacy_pool_rollback.rs"
ANCHOR = b"#[test]\nfn reserved_work_is_cheaply_held_but_its_private_consumer_and_durable_duplicate_keep_native_truth()"
NAME = "legacy_owner_enable_pool_insert_cancels_before_commit_and_cold_read_matches"
TEST = "store::operator_task_store_tests::" + NAME
SOURCES = (
    "trillionnium", "config", "formal", "rust-toolchain.toml",
    "evidence/cell-capacity-release-dc0357-20261109/model/index.json",
    "evidence/cell-capacity-release-dc0357-20261109/model/source-inputs.v2.json",
    "scripts/cell_sealed_bootstrap_v1.py", "scripts/llm_cell_sealed_worker_v1.py",
    "tests/fixtures/cell-content-graph-v3/vectors.json",
    "tests/fixtures/cpq1-content-v1/vectors.json",
    "tests/vectors/pon/native-growth-reference-v2.json",
)
EVENT = re.compile(
    r"legacy-pool-enable cancel=(true|false) insert=(\d+) commit_callbacks=(\d+) "
    r"rollback_callbacks=(\d+) claims=(\d+) cold_tables=(\[[0-9, ]+\]) "
    r"active_parent=([0-9a-f]{64}) active_generation=(\d+)"
)


def git(*args):
    return subprocess.check_output(["git", "-C", ROOT, *args], timeout=30)


def git_blob(data):
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def evidence_file(archive, name):
    path = archive / name
    need(path == path.resolve(strict=True) and path.is_file(), "Canonical archive file required")
    return path


def small_evidence(archive, name):
    with evidence_file(archive, name).open("rb") as source:
        raw = source.read(65537)
    need(len(raw) <= 65536, "Unexpected overlarge evidence metadata")
    return raw


def fresh_directory(path):
    path = path.absolute()
    need(path.parent == path.parent.resolve(strict=True) and not path.exists()
         and not path.is_symlink() and not path.is_relative_to(ROOT)
         and not ROOT.is_relative_to(path), "Fresh disjoint output directory required")
    path.mkdir(mode=0o700)
    return path


def fixture_bytes(original):
    need(git_blob(original) == BEFORE and original.count(ANCHOR) == 1, "Original test module differs")
    patched = original.replace(ANCHOR, FIXTURE.read_bytes() + b"\n" + ANCHOR)
    need(git_blob(patched) == AFTER, "Adapter splice differs from the actually tested bytes")
    return patched


def prepare(source, output):
    need(re.fullmatch("[0-9a-f]{40}", source) and git("rev-parse", source + "^{commit}").strip().decode()
         == source, "Exact original commit required")
    original = git("show", source + ":" + MODULE)
    patched = fixture_bytes(original)
    rows = {}
    for entry in git("ls-tree", "-r", "-l", "-z", source, "--", *SOURCES).split(b"\0"):
        if not entry:
            continue
        meta, name = entry.decode().split("\t", 1)
        mode, kind, sha, size = meta.split()
        path = PurePosixPath(name)
        need(not path.is_absolute() and ".." not in path.parts and path.as_posix() == name
             and kind == "blob" and mode in {"100644", "100755"} and name not in rows,
             "Unexpected original tree entry")
        rows[name] = (mode, sha, int(size))
    need(MODULE in rows and rows[MODULE][1] == BEFORE and all(
        any(name == x or name.startswith(x + "/") for name in rows) for x in SOURCES
    ), "Incomplete original-source tree")
    total = sum(size for _, _, size in rows.values())
    need(shutil.disk_usage(output.absolute().parent).free >= total + 128 * 2**20,
         "Insufficient space for isolated source plus reserve")
    output = fresh_directory(output)
    isolated = output / "source"
    isolated.mkdir(mode=0o700)
    seen = set()
    with subprocess.Popen(["git", "-C", ROOT, "archive", "--format=tar", source, "--", *SOURCES],
                          stdout=subprocess.PIPE) as proc:
        try:
            with tarfile.open(fileobj=proc.stdout, mode="r|") as archive:
                for member in archive:
                    if member.isdir():
                        continue
                    name = member.name
                    need(member.isreg() and name not in seen and name in rows,
                         "Unexpected original archive member")
                    mode, sha, size = rows[name]
                    need(member.size == size, "Original archive size differs")
                    raw = archive.extractfile(member).read()
                    need(git_blob(raw) == sha, "Original Git blob differs")
                    path = isolated / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open("xb") as target:
                        target.write(patched if name == MODULE else raw)
                    path.chmod(int(mode, 8) & 0o777)
                    seen.add(name)
        except BaseException:
            proc.kill()
            raise
        need(proc.wait(timeout=30) == 0 and seen == rows.keys(), "Original archive incomplete")
    need(git("show", source + ":" + MODULE) == original, "Committed original test module changed")
    report = {
        "scope": "isolated-test-preparation-not-execution", "source": source,
        "tree": git("rev-parse", source + "^{tree}").decode().strip(),
        "input_files": len(rows), "input_original_bytes": total,
        "original_inventory_sha256": digest(json.dumps(rows, sort_keys=True).encode()),
        "test_only_delta": {MODULE: {"original_git_blob": BEFORE, "prepared_git_blob": AFTER}},
        "rust_test_filter": TEST,
    }
    (output / "preparation.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def observed_rows(raw):
    lines = raw.decode().splitlines()
    need(lines.count("running 1 test") == 1
         and sum(line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;") for line in lines) == 1,
         "Original Rust case did not report exactly one successful test")
    matching = [line for line in lines if "legacy-pool-enable" in line]
    need(len(matching) == 2 and matching[0].startswith(f"test {TEST} ... ")
         and matching[1].startswith("legacy-pool-enable "), "Exact original filtered case required")
    rows = []
    for line in matching:
        row = EVENT.fullmatch(line.removeprefix(f"test {TEST} ... "))
        need(row is not None, "Malformed rollback event")
        rows.append(list(row.groups()))
    need(len(rows) == 2, "Original control and cancelled case required")
    pos, neg = rows
    need(pos[:2] == ["false", "1"] and int(pos[2]) >= 1 and pos[3:6] == ["0", "1", "[1, 0, 0, 0]"]
         and neg[:6] == ["true", "1", "0", "1", "1", "[0, 0, 0, 0]"]
         and pos[6:] == neg[6:], "Rollback/control or cold-row observation differs")
    return rows


def retained(archive, receipt_sha, repeat_sha):
    archive = archive.absolute()
    need(archive == archive.resolve(strict=True) and archive.is_dir(), "Canonical evidence archive required")
    raw = small_evidence(archive, "verified-receipt.json")
    need(digest(raw) == receipt_sha, "Retained receipt digest differs")
    report = load_json(raw)
    need(report["test_only_local_node_opt_level"] == "0"
         and report["bounded_scope"] == {
             "signed_legacy_fixture": True, "live_owner_signal_after_actual_sql_write": True,
             "cold_readback_sqlite_and_new_dev_node": True, "continuous_owner_tested": False,
             "native_owner_switch_tested": False, "protected_deployment_owner_reauthentication_tested": False,
             "production_modified": False, "full_hosted_oracle_tested": False,
         }, "Retained diagnostic scope differs")
    source, parent, tree = report["baseline"]
    need(git("show", "-s", "--format=%H %P %T", source).decode().split() == [source, parent, tree],
         "Retained original commit identity differs")
    fixture_bytes(git("show", source + ":" + MODULE))
    case, = [entry for entry in report["tests"] if entry["test"] == TEST]
    primary = small_evidence(archive, NAME + ".stdout")
    repeat = small_evidence(archive, "independent-repeat.stdout")
    need({"bytes": len(primary), "sha256": digest(primary)} == case["stdout"]
         and digest(repeat) == repeat_sha, "One of the raw original observations differs")
    need(observed_rows(primary) == observed_rows(repeat) == report["original_observations"],
         "Original repeated observations differ")
    return report


def replay(args, report):
    need(shutil.disk_usage(args.output.absolute().parent).free >= report["unit_binary"]["bytes"] + 128 * 2**20,
         "Insufficient space for bounded diagnostic replay")
    output = fresh_directory(args.output)
    env = clean_build_environment()
    with tempfile.TemporaryDirectory(dir=output, prefix=".legacy-pool-test-") as temp:
        binary = Path(temp) / "original-unit-test"
        identity = report["unit_binary"]
        count = 0
        hashed = hashlib.sha256()
        archive_binary = evidence_file(args.archive.absolute(), "local-qualification-unit-test.gz")
        with gzip.open(archive_binary, "rb") as stream, binary.open("xb") as out:
            while data := stream.read(1024 * 1024):
                count += len(data)
                need(count <= identity["bytes"], "Retained executable expanded beyond its pinned length")
                hashed.update(data)
                out.write(data)
        need(count == identity["bytes"] and hashed.hexdigest() == identity["sha256"],
             "Retained executable digest differs")
        binary.chmod(0o500)
        env["TMPDIR"] = temp
        result = subprocess.run([binary, TEST, "--exact", "--test-threads=1", "--nocapture"],
                                cwd=temp, env=env, capture_output=True, timeout=45)
        (output / "replay.stdout").write_bytes(result.stdout)
        (output / "replay.stderr").write_bytes(result.stderr)
        need(result.returncode == 0 and not result.stderr
             and observed_rows(result.stdout) == report["original_observations"],
             "Actual archived test executable did not reproduce the retained rows")
    return {"scope": "actual-retained-legacy-test-replay-opt0-not-a-rebuild",
            "test_executable": identity, "rows": observed_rows(result.stdout)}


def main():
    need(__debug__, "Optimized Python is not admitted")
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--source", required=True)
    prep.add_argument("--output", type=Path, required=True)
    for name in ("readback", "replay"):
        check = sub.add_parser(name)
        check.add_argument("--archive", type=Path, required=True)
        check.add_argument("--receipt-sha256", required=True)
        check.add_argument("--repeat-sha256", required=True)
        if name == "replay":
            check.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        result = prepare(args.source, args.output)
    else:
        report = retained(args.archive, args.receipt_sha256, args.repeat_sha256)
        result = (replay(args, report) if args.command == "replay" else
                  {"scope": "retained-legacy-opt0-observation-readback-no-execution",
                   "rows": report["original_observations"]})
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
