"""Cross the private Worker filesystem boundary and re-read with the original CLI."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from hia.platform.worker_audit.build import TOOLS, fresh_directory, run
from hia.platform.worker_journal_audit_v3.build import ENTRY, LIBRARY, build
from hia.tests.test_worker_audit_export_transaction import NAMES
from hia.tests.test_worker_audit_select import original_inputs
from hia.tests.test_worker_journal_audit_dto import ROOT, declared_input, raw
from hia.tests.test_worker_journal_audit_dto_reputation_v3 import row, scenarios
from hia.tests.test_worker_journal_audit_export import snapshot
from hia.tests.test_worker_journal_audit_export_v3 import near_raw_cap
from hia.tests.test_worker_journal_audit_owned import RUST_REVISION, RUST_VERSION, rustc_path
from hia.tests.test_worker_journal_line_frame import cli_artifacts

CALLER = ROOT / "hia/tests/rust_worker_journal_audit_owned_files.rs"
FILENAMES = ("audit.jsonl", "audit.md", "audit.jsonl.index.json")


def link_caller(directory, rustc):
    library, proof = build(directory)
    if (proof["dynamic"]["dynamic_exports"] != [ENTRY]
            or proof["dynamic"]["unresolved_imports"] or proof["needed"]
            or not proof["linked_text_equals_relocatable_text"]):
        raise AssertionError("WQX3 named fixture requires one export and zero runtime imports")
    rust = run(rustc, "--version", "--verbose").decode("ascii")
    if (not rust.startswith(RUST_VERSION) or f"commit-hash: {RUST_REVISION}" not in rust
            or "\nhost: x86_64-unknown-linux-gnu\n" not in rust):
        raise AssertionError("Use the pinned Linux Rust compiler for fixture transport")
    caller_hash = sha256(CALLER.read_bytes()).hexdigest()
    exe = directory / "offline-worker-audit-files"
    run(rustc, CALLER, "--edition=2024", "-C", "opt-level=2", "-C", "strip=symbols",
        "-C", "link-arg=-Wl,-rpath,$ORIGIN", "-L", f"native={directory}",
        "-l", "dylib=trnm_worker_journal_audit_v3", "-o", exe)
    dynamic = run(TOOLS["readelf"], "-dW", exe).decode("ascii")
    symbols = run(TOOLS["readelf"], "--dyn-syms", "--wide", exe).decode("ascii")
    if (f"Shared library: [{LIBRARY}]" not in dynamic
            or "Library runpath: [$ORIGIN]" not in dynamic
            or not any(" UND " in s and s.split()[-1] == ENTRY for s in symbols.splitlines() if s.split())
            or sha256(library.read_bytes()).hexdigest() != proof["artifact_sha256"]
            or sha256(CALLER.read_bytes()).hexdigest() != caller_hash):
        raise AssertionError("Rust process did not bind the exact HIA file fixture library")
    return exe, {"native": proof, "rustc": rust, "rustc_sha256": sha256(rustc.read_bytes()).hexdigest(),
                 "rust_source_sha256": caller_hash, "rust_executable_sha256": sha256(exe.read_bytes()).hexdigest()}


def ingress(directory, bytes_in):
    source = directory / "ingress.jsonl"
    with source.open("xb") as writer:
        writer.write(bytes_in)
    source.chmod(0o600)
    return source


def run_fixture(exe, directory):
    return subprocess.run([str(exe)], cwd=directory, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=20, env={"LC_ALL": "C"})


def file_outputs(directory):
    files = [directory / name for name in FILENAMES]
    for path in files:
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600:
            raise AssertionError("Private Rust file artifact metadata changed")
    return tuple(path.read_bytes() for path in files)


def file_signature(path):
    st = path.lstat()
    return st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def query(binary, path, task, *, suffix):
    result = subprocess.run([str(binary), "query-audit", "--output-file", str(path),
                             "--task-id", str(task)], cwd=path.parent, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=25)
    (path.parent / f"query-{suffix}-{task}.stdout.raw").write_bytes(result.stdout)
    (path.parent / f"query-{suffix}-{task}.stderr.raw").write_bytes(result.stderr)
    if result.returncode or result.stderr:
        raise AssertionError(f"Original guarded CLI query refused {suffix}: {result.stderr!r}")
    return result.stdout


def refused_fixtures(exe, directory):
    observed = {}
    kept = raw(row(-1))
    bad = raw({**row(3), "reputation_delta": "3"})
    for tag, payload, reason, existing in (
        ("late-typed-refusal", snapshot(kept, bad), b"WQX profile or capacity refusal", None),
        ("oversized-file", b"\n" * 65_537, b"fixture input metadata or limit", None),
        ("existing-third-name", snapshot(kept), b"fixture output already exists", FILENAMES[2]),
    ):
        case = fresh_directory(directory / tag)
        source = ingress(case, payload)
        if existing:
            saved = case / existing
            saved.write_bytes(b"pre-existing private sentinel")
            saved.chmod(0o600)
            saved_signature = file_signature(saved)
        found = run_fixture(exe, case)
        (case / "rust.stdout.raw").write_bytes(found.stdout)
        (case / "rust.stderr.raw").write_bytes(found.stderr)
        existing_outputs = tuple(f for f in FILENAMES if (case / f).exists())
        if (found.returncode != 1 or found.stdout or reason not in found.stderr or source.read_bytes() != payload
                or existing_outputs != ((existing,) if existing else ())
                or (existing and (saved.read_bytes() != b"pre-existing private sentinel"
                                  or file_signature(saved) != saved_signature))):
            raise AssertionError(f"Existing/failed fixture mutated output: {tag}")
        observed[tag] = {"exit": found.returncode, "output_names": list(existing_outputs), "unchanged_input": True}
    return observed


class WorkerJournalAuditOwnedFiles(unittest.TestCase):
    def test_named_selfhost_real_fixture_files_and_no_clobber(self):
        with tempfile.TemporaryDirectory(prefix="trnm-worker-wqx3-files-") as tmp:
            top = Path(tmp)
            exe, proof = link_caller(top / "build", rustc_path())
            case = fresh_directory(top / "valid")
            source = ingress(case, snapshot(raw(row(-3))))
            before = source.read_bytes()
            found = run_fixture(exe, case)
            self.assertEqual((found.returncode, found.stderr), (0, b""))
            jl, md, idx = file_outputs(case)
            self.assertEqual(json.loads(jl)["reputation_delta"], -3)
            self.assertIn(b"| -3 |", md)
            self.assertEqual(json.loads(idx)["total_records"], 1)
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(sha256((exe.parent / LIBRARY).read_bytes()).hexdigest(),
                             proof["native"]["artifact_sha256"])
            self.assertEqual(len(refused_fixtures(exe, top)), 3)


def qualify(binary, receipt, directory, rustc):
    def bound():
        return (receipt["repository_inputs"] == original_inputs()
                and receipt["executable_sha256"] == sha256(binary.read_bytes()).hexdigest())

    if not bound():
        raise AssertionError("Original source/build pin mismatch")
    declaration = declared_input()
    exe, proof = link_caller(directory / "build", rustc)
    result = {}
    cases = {**scenarios(), "exact_raw_cap": (near_raw_cap(), 2, 2)}
    for label, (payload, rows, selected) in cases.items():
        case = fresh_directory(directory / label)
        original = fresh_directory(case / "original")
        hia_case = fresh_directory(case / "candidate")
        source = ingress(original, payload)
        candidate_source = ingress(hia_case, payload)
        expected = cli_artifacts(binary, source, "original", True, None)
        if (json.loads(expected[2])["total_records"] != selected
                or (original / "original.jsonl.index.json").read_bytes() != expected[2]):
            raise AssertionError("Original export or both original indexes changed")
        found = run_fixture(exe, hia_case)
        (hia_case / "rust.stdout.raw").write_bytes(found.stdout)
        (hia_case / "rust.stderr.raw").write_bytes(found.stderr)
        size = 16 + sum(map(len, expected))
        if (found.returncode or found.stderr or found.stdout != f"WQX3 fixture emitted {size} bytes\n".encode()
                or file_outputs(hia_case) != expected):
            raise AssertionError(f"Private output files differ from actual original export: {label} {found.stderr!r}")
        queries = {}
        task_ids = (0, 17, (1 << 64) - 1)
        if label == "exact_raw_cap":
            task_ids += (63,)
        for task_id in task_ids:
            prior = query(binary, original / "original.jsonl", task_id, suffix="original")
            after = query(binary, hia_case / FILENAMES[0], task_id, suffix="candidate")
            if prior != after:
                raise AssertionError("Original query-audit did not read the same JSONL/index")
            hits = json.loads(after)["hit_indexes"]
            if label == "all_values" and task_id == (1 << 64) - 1 and len(hits) != 6:
                raise AssertionError("Genuine original query did not exercise the expected hit set")
            if label == "exact_raw_cap" and task_id == 63 and hits != [1]:
                raise AssertionError("Guarded original query did not find the near-cap candidate row")
            queries[str(task_id)] = {"hits": hits, "stdout_sha256": sha256(after).hexdigest()}
        if source.read_bytes() != payload or candidate_source.read_bytes() != payload:
            raise AssertionError("Observation changed an owned original input")
        if file_outputs(hia_case) != expected:
            raise AssertionError("Original query mutated the candidate files")
        # A second Rust invocation never rewrites even byte-equivalent files.
        signatures = tuple(file_signature(hia_case / f) for f in FILENAMES)
        second = run_fixture(exe, hia_case)
        if (second.returncode != 1 or b"fixture output already exists" not in second.stderr
                or file_outputs(hia_case) != expected
                or signatures != tuple(file_signature(hia_case / f) for f in FILENAMES)):
            raise AssertionError("Repeat invocation overwrote a previously emitted file")
        result[label] = {"raw_bytes": len(payload), "rows": rows, "selected": selected,
                         "wao_bytes": size, "queries": queries,
                         "files": dict(zip(NAMES, (sha256(x).hexdigest() for x in expected), strict=True))}
    refused = refused_fixtures(exe, directory)
    if (not bound() or declaration != declared_input()
            or sha256(exe.read_bytes()).hexdigest() != proof["rust_executable_sha256"]
            or sha256((exe.parent / LIBRARY).read_bytes()).hexdigest() != proof["native"]["artifact_sha256"]):
        raise AssertionError("Observed source-bound private ELF or original identity changed")
    result = {"pins": original_inputs(), "original_executable_sha256": receipt["executable_sha256"],
              "original_struct_sha256": declaration, "build": proof, "cases": result, "refusals": refused,
              "host_rust_owns_test_file_io": True, "one_wqx3_memory_call": True,
              "actual_original_jsonl_query_compatible": True, "markdown_query_claimed": False,
              "production_dispatch": False, "multi_file_atomic_publication": False}
    (directory / "report.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--original-binary", type=Path, required=True)
    p.add_argument("--original-build-receipt", type=Path, required=True)
    args = p.parse_args()
    r = qualify(args.original_binary.resolve(strict=True), json.loads(args.original_build_receipt.read_bytes()),
                fresh_directory(args.output), rustc_path())
    print(json.dumps({"cases": r["cases"], "refusals": r["refusals"]}, sort_keys=True))


if __name__ == "__main__":
    main()
