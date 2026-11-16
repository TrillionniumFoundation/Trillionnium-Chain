"""Three dependent physical full-State stages, each suitable for a 20-minute job."""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import resource
import re
import shutil
import subprocess
import time

from hia.platform.build import new_output, sha256, write_json
from hia.platform.typed_store.build import Build, file_identity
from hia.platform.typed_store.cases import BLOCK, SLOT, delta
from hia.platform.typed_store.native_io import run
from hia.tests.test_state_root import reference

REPOSITORY = Path(__file__).resolve().parents[3]
COUNT = 65536
RAW_BYTES = 279969808
RAW_SHA256 = "cc4eaec0976403b6399b6233faa453524d6d306dc0425de8707de353b7b966b3"
VALUE = b'"' + b"v" * 4094 + b'"'
ROOT_SECONDS = 900
ROW_SECONDS = 240
SCHEMA = "trnm.hia.typed-staging-capacity-stage.v1"

def require(condition, message):
    if not condition:
        raise ValueError(message)

def process_ok(actual):
    return (not actual["timed_out"] and not actual["gate_errors"] and actual["inputs_unchanged"]
        and not actual.get("controller_stop_requested", False))

def resources():
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    result = {"hosted_self_peak_rss_kib": own.ru_maxrss,
        "children_peak_rss_kib_including_native_build": children.ru_maxrss}
    for name in ("memory.current", "memory.peak"):
        path = Path("/sys/fs/cgroup") / name
        if path.is_file():
            try:
                result["observed_cgroup_" + name.replace(".", "_") + "_bytes"] = int(path.read_text())
            except (OSError, ValueError):
                pass
    return result

def snapshot_archive(path, *, remove=False):
    raw = file_identity(path)
    archived = path.parent / "maximum-state.kv.xz"
    require(not archived.exists(), "Snapshot archive already exists")
    with path.open("rb") as source, lzma.open(archived, "wb", preset=1) as destination:
        shutil.copyfileobj(source, destination, 1 << 20)
    value, size = hashlib.sha256(), 0
    with lzma.open(archived, "rb") as source:
        while block := source.read(1 << 20):
            value.update(block)
            size += len(block)
    require(raw == {"bytes": size, "sha256": value.hexdigest()}, "Lossless snapshot archive differs")
    if remove:
        path.unlink()
    return {"filename": archived.name, "raw": raw, "archive": file_identity(archived)}

def restore_snapshot(prior, prior_directory, output):
    record = prior["snapshot"]
    require(record["filename"] == "maximum-state.kv.xz", "Unexpected snapshot artifact name")
    source = prior_directory / record["filename"]
    require(file_identity(source) == record["archive"], "Captured archive bytes differ")
    require(record["raw"] == {"bytes": RAW_BYTES, "sha256": RAW_SHA256}, "Wrong complete State corpus")
    destination = output / "restored-state.kv"
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=16 << 20)
    remaining = RAW_BYTES
    with source.open("rb") as compressed, destination.open("xb") as raw:
        while not decoder.eof:
            block = compressed.read(65536) if decoder.needs_input else b""
            require(block or not decoder.needs_input, "Truncated snapshot archive")
            decoded = decoder.decompress(block, max_length=min(1 << 20, remaining + 1))
            require(len(decoded) <= remaining, "Snapshot expands beyond the fixed complete State extent")
            raw.write(decoded)
            remaining -= len(decoded)
        require(remaining == 0, "Snapshot is shorter than the fixed complete State extent")
        require(not decoder.unused_data and compressed.read(1) == b"", "Trailing snapshot archive data")
        raw.flush()
        os.fsync(raw.fileno())
    require(file_identity(destination) == record["raw"], "Actual restored full State differs")
    return destination

def current_head():
    head = subprocess.check_output(["git", "-C", str(REPOSITORY), "rev-parse", "HEAD"],
        text=True, timeout=10).strip()
    expected = os.environ.get("TRNM_EXPECTED_SOURCE_SHA")
    if os.environ.get("GITHUB_ACTIONS") == "true" or expected is not None:
        require(isinstance(expected, str) and re.fullmatch(r"[0-9a-fA-F]{40}", expected) is not None,
            "Missing or invalid TRNM_EXPECTED_SOURCE_SHA for the exact source checkout")
        require(head == expected.lower(), "Checkout differs from exact expected source head")
    return head

def sources_match_head(manifest, head):
    for relative, expected in manifest.items():
        result = subprocess.run(["git", "-C", str(REPOSITORY), "cat-file", "blob", head + ":" + relative],
            capture_output=True, timeout=10, check=False)
        if result.returncode or {"bytes": len(result.stdout), "sha256": sha256(result.stdout)} != expected:
            return False
    return True

def execute_stage(stage, output, *, run_id, attempt, prior=None):
    output = new_output(Path(output))
    if not run_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._" for char in run_id):
        raise ValueError("An explicit bounded run identifier is required")
    require(0 < int(attempt) < (1 << 31), "Invalid run attempt")
    require(stage in {"produce", "cold", "bounds"}, "Unknown capacity stage")
    start = time.monotonic_ns()
    controls, events = [], []
    report = {"schema": SCHEMA, "status": "RUNNING", "stage": stage,
        "run_id": run_id, "attempt": int(attempt), "raw_state_bytes": RAW_BYTES,
        "rows": COUNT, "key_bytes": 160, "value_bytes": 4096,
        "root_child_wall_seconds": ROOT_SECONDS, "row_child_wall_seconds": ROW_SECONDS,
        "runtime_host_proxy": False, "namespace_or_commit_authority": False,
        "physical_power_loss_qualified": False, "growth_maximum_extent_qualified": False,
        "resource_scope": "RSS high-water includes hosted verifier/native build; cgroup peak is the observed whole cgroup, not an isolated native RSS claim",
        "resources_before": resources(), "github_event_sha": os.environ.get("GITHUB_SHA"),
        "expected_source_sha": os.environ.get("TRNM_EXPECTED_SOURCE_SHA")}
    def save(label, **details):
        events.append({"label": label, "elapsed_seconds": (time.monotonic_ns() - start) / 1e9, **details})
        report.update(controls=controls, events=events, resources_after=resources())
        write_json(output / "report.json", report)
        print(json.dumps({"stage": stage, "event": label, **details}), flush=True)
    try:
        build = Build(output / "build", REPOSITORY)
        executable, built = build.build()
        head = current_head()
        exact = sources_match_head(built["source_inputs"], head)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            require(exact, "Workflow capacity source inputs differ from the exact committed head")
        lineage = {"git_head": head, "run_id": run_id, "attempt": int(attempt),
            "source_set_sha256": built["source_set_sha256"],
            "original_source_set_sha256": sha256(json.dumps(built["original_sources"],
                sort_keys=True, separators=(",", ":")).encode()),
            "executable_sha256": built["executable"]["sha256"],
            "native_source_inputs_match_git_head": exact}
        report.update(build=built, lineage=lineage)
        prior_bytes = None
        if stage == "produce":
            require(prior is None, "Produce cannot consume a previous stage")
        else:
            require(prior is not None, "A successful exact prior capacity stage is required")
            prior_directory = Path(prior).resolve(strict=True)
            prior_path = prior_directory / "report.json"
            require(not prior_path.is_symlink(), "Symlinked prior receipt")
            prior_bytes = prior_path.read_bytes()
            parent = json.loads(prior_bytes)
            require(parent["schema"] == SCHEMA and parent["status"] == "PASS", "Prior capacity stage did not pass")
            require(parent["stage"] == ("produce" if stage == "cold" else "cold"), "Prior stage order differs")
            require(parent["lineage"] == lineage, "Capacity head/run/attempt/source/executable binding differs")
            require(parent["build"]["source_inputs"] == built["source_inputs"]
                and parent["build"]["original_sources"] == built["original_sources"], "Prior complete source identities differ")
            report["prior_receipt_sha256"] = sha256(prior_bytes)
            report["independent_root_hex"] = parent["independent_root_hex"]
        save("independent-native-build-verified", executable_sha256=built["executable"]["sha256"])
        if stage == "produce":
            seed = output / "maximum-state.input"
            with seed.open("xb") as stream:
                stream.write(b"TKVSTR01" + COUNT.to_bytes(8, "little"))
                for index in range(COUNT):
                    key = f"k{index:06}".encode() + b"x" * 153
                    stream.write((160).to_bytes(8, "little") + (4096).to_bytes(8, "little") + key + VALUE)
            require(file_identity(seed) == {"bytes": RAW_BYTES, "sha256": RAW_SHA256},
                "Complete classical input construction differs")
            save("full-input-created", bytes=RAW_BYTES, sha256=RAW_SHA256)
            actual = run(executable, output / "native-root", seed, delta(()), observe=False,
                retain_bytes=False, timeout=ROOT_SECONDS, stop_file=output / "STOP")
            controls.append({"name": "complete-classical-state-root", "actual": actual})
            save("native-root-returned", exit=actual["exit"], wall_seconds=actual["elapsed_ns"] / 1e9)
            require(process_ok(actual) and actual["exit"] == 0 and not actual["stderr_hex"],
                "Complete classical native root failed")
            expected_receipt = {"kind": 2, "count": COUNT, "output_bytes": RAW_BYTES,
                "delta_count": 0, "progresses": 261, "block_hex": BLOCK.hex(), "slot": SLOT,
                "root_hex": actual["receipt"]["root_hex"], "reserved": 0}
            require(actual["receipt"] == expected_receipt and actual["output_bytes"] == RAW_BYTES
                and actual["output_sha256"] == RAW_SHA256, "Complete native receipt or bytes differ")
            save("independent-full-root-started")
            oracle_start = time.monotonic_ns()
            code, root = reference([(f"k{index:06}".encode() + b"x" * 153, VALUE) for index in range(COUNT)])
            require(code == 0 and root.hex() == actual["receipt"]["root_hex"],
                "Independent maximum classical root differs")
            report["independent_root_hex"] = root.hex()
            report["independent_root_wall_seconds"] = (time.monotonic_ns() - oracle_start) / 1e9
            save("independent-full-root-matched", root_hex=root.hex(),
                wall_seconds=report["independent_root_wall_seconds"])
            report["snapshot"] = snapshot_archive(Path(actual["output_path"]), remove=True)
            archive_path = Path(actual["output_path"]).parent / "maximum-state.kv.xz"
            archive_path.rename(output / "maximum-state.kv.xz")
            seed.unlink()
        else:
            seed = restore_snapshot(parent, prior_directory, output)
            save("complete-prior-output-restored-and-synchronized", bytes=RAW_BYTES, sha256=RAW_SHA256)
            if stage == "cold":
                actual = run(executable, output / "cold-root", seed, delta(()), observe=False,
                    retain_bytes=False, timeout=ROOT_SECONDS, stop_file=output / "STOP")
                controls.append({"name": "fresh-process-complete-cold-root", "actual": actual})
                save("cold-root-returned", exit=actual["exit"], wall_seconds=actual["elapsed_ns"] / 1e9)
                require(process_ok(actual) and actual["exit"] == 0 and not actual["stderr_hex"],
                    "Complete cold native root failed")
                require(actual["output_bytes"] == RAW_BYTES and actual["output_sha256"] == RAW_SHA256
                    and actual["receipt"] == {"kind": 2, "count": COUNT, "output_bytes": RAW_BYTES,
                        "delta_count": 0, "progresses": 261, "block_hex": BLOCK.hex(), "slot": SLOT,
                        "root_hex": parent["independent_root_hex"], "reserved": 0},
                    "Complete cold bytes or independently checked root differ")
                report["snapshot"] = snapshot_archive(Path(actual["output_path"]), remove=True)
                archive_path = Path(actual["output_path"]).parent / "maximum-state.kv.xz"
                archive_path.rename(output / "maximum-state.kv.xz")
                seed.unlink()
            else:
                corrupt = output / "corrupt-last-byte.input"
                shutil.copyfile(seed, corrupt)
                with corrupt.open("r+b") as stream:
                    stream.seek(-1, os.SEEK_END)
                    stream.write(b"X")
                    stream.flush()
                    os.fsync(stream.fileno())
                corrupt_identity = file_identity(corrupt)
                bad = run(executable, output / "cold-corrupt-last-byte", corrupt, delta(()),
                    observe=False, retain_bytes=False, timeout=ROW_SECONDS, stop_file=output / "STOP")
                controls.append({"name": "physical-final-byte-serde-refusal", "source": corrupt_identity, "actual": bad})
                save("final-byte-control-returned", exit=bad["exit"], wall_seconds=bad["elapsed_ns"] / 1e9)
                require(process_ok(bad) and bad["exit"] == 83 and not bad["stdout_hex"]
                    and bad["output_bytes"] == 0 and bad["diagnostic"][3] == 260
                    and bad["diagnostic"][6] == 0, "Complete cold read missed final value corruption")
                bad_archive = snapshot_archive(corrupt, remove=True)
                (output / "maximum-state.kv.xz").rename(output / "corrupt-last-byte.input.xz")
                bad_archive["filename"] = "corrupt-last-byte.input.xz"
                controls[-1]["source_archive"] = bad_archive
                change = ((b"z" * 160, None, b"1"),)
                refused = run(executable, output / "classic-plus-one", seed, delta(change),
                    root=False, observe=False, retain_bytes=False, timeout=ROW_SECONDS, stop_file=output / "STOP")
                controls.append({"name": "classical-count-plus-one", "actual": refused})
                save("classical-count-control-returned", exit=refused["exit"], wall_seconds=refused["elapsed_ns"] / 1e9)
                require(process_ok(refused) and refused["exit"] == 84 and not refused["stdout_hex"]
                    and refused["output_bytes"] == 0 and refused["diagnostic"][3] == 262
                    and refused["diagnostic"][6] == 0, "Classical count-plus-one admission differs")
                growth = run(executable, output / "growth-classic-plus-one", seed, delta(change),
                    root=False, profile=1, observe=False, retain_bytes=False, timeout=ROW_SECONDS, stop_file=output / "STOP")
                controls.append({"name": "growth-dimension-classical-plus-one", "actual": growth})
                save("growth-count-control-returned", exit=growth["exit"], wall_seconds=growth["elapsed_ns"] / 1e9)
                expected = hashlib.sha256(b"TKVSTR01" + (COUNT + 1).to_bytes(8, "little"))
                with seed.open("rb") as source:
                    source.seek(16)
                    while block := source.read(1 << 20):
                        expected.update(block)
                expected.update((160).to_bytes(8, "little") + (1).to_bytes(8, "little") + b"z" * 160 + b"1")
                require(process_ok(growth) and growth["exit"] == 0 and not growth["stderr_hex"]
                    and growth["output_bytes"] == RAW_BYTES + 177 and growth["output_sha256"] == expected.hexdigest()
                    and growth["receipt"] == {"kind": 1, "count": COUNT + 1, "output_bytes": RAW_BYTES + 177,
                        "delta_count": 1, "progresses": 263, "block_hex": BLOCK.hex(), "slot": SLOT,
                        "root_hex": bytes(32).hex(), "reserved": 0}, "Growth dimension count edge differs")
                growth_archive = snapshot_archive(Path(growth["output_path"]), remove=True)
                growth_archive["filename"] = "growth-classic-plus-one.kv.xz"
                (Path(growth["output_path"]).parent / "maximum-state.kv.xz").rename(output / growth_archive["filename"])
                controls[-1]["output_archive"] = growth_archive
                seed.unlink()
        if prior_bytes is not None:
            require((prior_directory / "report.json").read_bytes() == prior_bytes, "Prior receipt changed")
            require(file_identity(prior_directory / parent["snapshot"]["filename"]) == parent["snapshot"]["archive"],
                "Prior exact snapshot archive changed")
        build.check_sources()
        require(not (output / "STOP").exists(), "Explicit owned qualification stop requested")
        require(current_head() == head, "Checkout head changed during capacity stage")
        require(file_identity(output / "build/staging.elf") == {"bytes": len(executable), "sha256": sha256(executable)},
            "Actual native executable changed during capacity stage")
        report.update(status="PASS", source_inputs_stable=True,
            wall_seconds=(time.monotonic_ns() - start) / 1e9)
        save("stage-complete", controls=len(controls), wall_seconds=report["wall_seconds"])
        return report
    except BaseException as error:
        report.update(status="FAIL", error=repr(error), wall_seconds=(time.monotonic_ns() - start) / 1e9)
        save("stage-failed", error=repr(error))
        raise

def main():
    if not __debug__:
        raise RuntimeError("Optimized Python is not admitted by this qualifier")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("produce", "cold", "bounds"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prior", type=Path)
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID"))
    parser.add_argument("--attempt", type=int, default=int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")))
    args = parser.parse_args()
    execute_stage(args.stage, args.output, run_id=args.run_id, attempt=args.attempt, prior=args.prior)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
