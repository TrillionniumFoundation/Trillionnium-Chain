"""Run unchanged private DA Rust only inside a verified isolated cfg(test) copy."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule, unlinked_path
from hia.tests.test_da_protocol_context import _run

ROOT = Path(__file__).resolve().parents[2]
ORIGINAL = "trillionnium/crates/trnm-data-availability/src/retrieval.rs"
COPY_SCOPE = (
    "trillionnium/Cargo.toml", "trillionnium/Cargo.lock", "trillionnium/crates",
    "config/pon/work-profile-v1.json",
    "formal/pon-nakamoto-v1/vectors/cell-dependency-closure-v1.json",
    "formal/pon-nakamoto-v1/vectors/cell-discovery-epoch-v3.json",
    "formal/pon-nakamoto-v1/vectors/cell-complete-version-v1.json",
    "formal/pon-nakamoto-v1/vectors/cell-version-content-v2.json",
    "formal/pon-nakamoto-v1/vectors/cell-version-retention-v3.json",
    "formal/pon-nakamoto-v1/vectors/cell-model-root-v1.json",
    "formal/pon-nakamoto-v1/vectors/cell-storage-owner-vectors-v1.json",
    "tests/fixtures/cell-content-graph-v3/vectors.json",
)
SOURCE = ROOT / "hia/src/data_availability/chunk_inclusion_path.hepta"
HARNESS = Path(__file__).with_name("rust_da_chunk_inclusion_path_harness.rs")
APPEND = b'\n#[cfg(test)]\n#[path = "hia_da_chunk_path_fixture.rs"]\nmod hia_da_chunk_path_fixture;\n'
MARKER = b"TRNM_DA_MERKLE_COMPARATOR_HARNESS_V1"
TEST = "retrieval::hia_da_chunk_path_fixture::original_private_path_observe"
NAME = "trnm_data_availability"
WORK = 1472
OUTPUT = b"\xa5" * 37
SCRATCH = b"\x6d" * (WORK+13)


def tracked():
    output = _run(["git", "ls-files", "--stage", "-z", "--", *COPY_SCOPE]).stdout
    result = {}
    for record in output.split(b"\0")[:-1]:
        meta, local = record.split(b"\t", 1)
        mode, sha, stage = meta.split()
        relative = Path(local.decode("utf-8"))
        if mode not in {b"100644", b"100755"} or stage != b"0" or relative in result:
            raise ValueError("Unsafe or unresolved original Rust path")
        result[relative] = sha
    if len(result) < 3 or Path(ORIGINAL) not in result:
        raise ValueError("Incomplete tracked original")
    if subprocess.run(["git", "diff", "--quiet", "HEAD", "--", *COPY_SCOPE], cwd=ROOT).returncode != 0:
        raise ValueError("Original Rust source is not the committed original")
    return result


def git_blob(body):
    return hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest().encode()


def file_digest(path):
    return hashlib.sha256(path.read_bytes()).digest()


def observed_artifact(build, temporary, testing):
    rows = [json.loads(line) for line in build.stdout.splitlines()]
    if not rows or rows[-1] != {"reason": "build-finished", "success": True}:
        raise ValueError("No successful original Cargo observation")
    [actual] = [x for x in rows if x.get("reason") == "compiler-artifact"
                and x["target"]["name"] == NAME and x["profile"]["test"] is testing]
    if testing and any(x.get("reason") == "compiler-artifact"
                       and x["target"]["name"] == NAME and not x["profile"]["test"] for x in rows):
        raise ValueError("A non-test DA library was compiled with test augmentation present")
    target = temporary / "target"
    manifest = temporary / "trillionnium/crates/trnm-data-availability/Cargo.toml"
    if (Path(actual["manifest_path"]) != manifest
            or Path(actual["target"]["src_path"]) != manifest.parent / "src/lib.rs"
            or actual["features"] != ["default"]):
        raise ValueError("Unexpected original DA build provenance")
    if testing:
        actual_path = unlinked_path(actual["executable"])
    else:
        [item] = [f for f in actual["filenames"] if f.endswith(".rlib")]
        actual_path = unlinked_path(item)
    if not actual_path.is_relative_to(target) or actual["fresh"]:
        raise ValueError("Original artifact must really be rebuilt in the private target")
    return actual_path


def unchanged_original_observation(directory, *, harness=HARNESS, marker=MARKER, test=TEST,
                                   capture_limit=65536, owner="retrieval"):
    if owner == "retrieval":
        original_path, append, fixture_name = ORIGINAL, APPEND, "hia_da_chunk_path_fixture.rs"
    elif owner == "rs46-committed-slot":
        original_path = "trillionnium/crates/trnm-data-availability/src/cell/erasure/custody.rs"
        fixture_name = "hia_da_rs46_committed_slot_fixture.rs"
        append = (b'\n#[cfg(test)]\n#[path = "hia_da_rs46_committed_slot_fixture.rs"]\n'
                  b"mod hia_da_rs46_committed_slot_fixture;\n")
    else:
        raise ValueError("Unknown private DA witness owner")
    if not 0 < capture_limit <= 4 * 1024 * 1024:
        raise ValueError("Invalid private synthetic capture bound")
    cargo = os.environ.get("TRNM_HIA_CARGO", "cargo")
    rustc = os.environ.get("TRNM_HIA_RUSTC", "rustc")
    version = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if _run([rustc, "--version"]).stdout.decode().split()[1] != version:
        raise ValueError("Original Merkle qualification requires repo pinned Rust")
    blobs = tracked()
    for relative, expected in blobs.items():
        source = unlinked_path(ROOT / relative)
        raw = source.read_bytes()
        if git_blob(raw) != expected:
            raise ValueError("Tracked original was replaced: " + str(relative))
        final = directory / relative
        final.parent.mkdir(parents=True, exist_ok=True)
        with final.open("xb") as out:
            out.write(raw)
    env = {**os.environ, "RUSTC": rustc, "CARGO_INCREMENTAL": "0", "CARGO_PROFILE_DEV_DEBUG": "0"}
    common = ["--manifest-path", str(directory / "trillionnium/Cargo.toml"),
              "--locked", "--offline", "--package", "trnm-data-availability",
              "--lib", "--target-dir", str(directory / "target"), "--message-format=json"]
    clean = observed_artifact(_run([cargo, "build", *common], env=env), directory, False)
    original_rlib = clean.read_bytes()
    if Path(original_path) not in blobs:
        raise ValueError("Incomplete tracked private owner")
    fixture = unlinked_path(harness).read_bytes()
    retrieval = directory / original_path
    original = retrieval.read_bytes()
    private_fixture = retrieval.parent / fixture_name
    capture = directory / "generated.bin"
    with private_fixture.open("xb") as out:
        out.write(fixture)
    try:
        retrieval.write_bytes(original + append)
        if retrieval.read_bytes() != original + append or git_blob(original) != blobs[Path(original_path)]:
            raise ValueError("Private original source body changed")
        executable = observed_artifact(_run([cargo, "test", *common, "--no-run"], env=env),
                                       directory, True)
        if marker not in executable.read_bytes() or clean.read_bytes() != original_rlib:
            raise ValueError("Test marker missing or non-test artifact changed in place")
        result = _run([str(executable), test, "--exact", "--test-threads=1"],
                      env={**env, "TRNM_DA_PRIVATE_PATH_FIXTURE": str(capture)}, timeout=30)
        if result.stderr or b"1 passed" not in result.stdout or test.encode() not in result.stdout:
            raise ValueError("No actual private original Rust call")
        if retrieval.read_bytes() != original + append or private_fixture.read_bytes() != fixture:
            raise ValueError("Private test copy changed during the exact selector")
    finally:
        retrieval.write_bytes(original)
        private_fixture.unlink()
    # Rebuild only after the exact source is restored. In particular, never use
    # a non-test Cargo invocation with the temporary test fixture installed.
    clean.unlink()
    after = observed_artifact(_run([cargo, "build", *common], env=env), directory, False)
    if after.read_bytes() != original_rlib or marker in original_rlib or private_fixture.exists():
        raise ValueError("Non-test Rust library changed or captured the fixture")
    for relative, expected in blobs.items():
        physical = unlinked_path(ROOT / relative).read_bytes()
        private = unlinked_path(directory / relative).read_bytes()
        if git_blob(physical) != expected or private != physical:
            raise ValueError("Original production source changed during qualification")
    if unlinked_path(harness).read_bytes() != fixture:
        raise ValueError("Harness changed during qualification")
    capture = unlinked_path(capture)
    if capture.stat().st_size > capture_limit:
        raise ValueError("Oversized original witness capture")
    wire = capture.read_bytes()
    if not wire.startswith(marker) or len(wire) > capture_limit:
        raise ValueError("Missing or oversized original witness capture")
    return wire[len(marker):], hashlib.sha256(original_rlib).hexdigest()


def records(raw):
    cursor = 0
    while cursor < len(raw):
        status, size = struct.unpack_from("<BI", raw, cursor)
        cursor += 5
        wire = raw[cursor:cursor+size]
        if len(wire) != size or size < 76 or status not in {0, 50, 51, 52, 53, 54, 55}:
            raise ValueError("Invalid original result")
        yield wire, status
        cursor += size
    if cursor != len(raw):
        raise ValueError("Incomplete original result")


class DaChunkInclusionPath(unittest.TestCase):
    def test_actual_private_original_and_both_native_comparators(self):
        with tempfile.TemporaryDirectory(prefix="trnm-original-da-merkle-") as tmp:
            wire, non_test_sha = unchanged_original_observation(Path(tmp))
        self.assertEqual(len(non_test_sha), 64)
        print("Original non-test rlib bytes unchanged:", non_test_sha)
        actual = list(records(wire))
        self.assertEqual(len(actual), 41)
        self.assertEqual(sum(code == 0 for _, code in actual), 31)
        self.assertEqual({code for _, code in actual}, {0, 50, 51, 52, 53, 54, 55})
        bare = actual[0][0]
        one_step = actual[1][0]
        self.assertEqual(struct.unpack_from("<3I", bare, 64), (0, 1, 0))
        self.assertEqual(struct.unpack_from("<3I", one_step, 64), (0, 2, 1))
        private = [(b"", 100, 0), (bare[:-1], 100, WORK), (bare+b"\0", 100, WORK),
                   (one_step[:-1], 100, WORK), (bare[:72]+b"\xff"*4, 100, WORK),
                   (one_step, 102, WORK-1), (one_step, 0, WORK)]
        panel = [(r, code, len(SCRATCH)) for r, code in actual] + private
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                    SOURCE, byte_exports=("f0",), backend=backend) as native:
                result = native.call_many([("f0", [r, OUTPUT, SCRATCH[:s]]) for r, _, s in panel],
                                          timeout=60)
                for i, ((r, code, s), outcome) in enumerate(zip(panel, result, strict=True)):
                    self.assertEqual(outcome.require_returned().value, code, i)
                    self.assertEqual(outcome.arguments[:2], [r, OUTPUT], i)
                    self.assertEqual(outcome.arguments[2][WORK:], SCRATCH[WORK:s], i)
