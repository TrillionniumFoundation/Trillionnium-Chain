"""WTQ2 native pretty query stdout vs genuine locked Rust stdout bytes."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import re
import unittest

from hia.platform.worker_audit.build import fresh_directory
from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_export_transaction import observe, typed_row
from hia.tests.test_worker_audit_index_wire import parse_native_input, request
from hia.tests.test_worker_audit_jsonl_row import FIELDS, HIA as WJL1, ROOT, frame
from hia.tests.test_worker_audit_select import BACKENDS, FILL, INSUFFICIENT, INVALID, original_inputs
from hia.tests.test_worker_audit_task_query import (NATIVE as WTQ1, LIMIT, MAX_TASK, OUT_MAX, SCRATCH,
    envelope, index_data, journal_cases, query_original)
from hia.tests.test_worker_journal_audit_export_v3 import function as find_function, replace_exact
from hia.tests.test_worker_journal_line_frame import cli_artifacts
from hia.tools.toolchain import checked_source

NATIVE = ROOT / "hia/src/worker_agent/audit_task_query_pretty.hepta"
EMPTY_STDOUT = b'{\n  "hit_indexes": [],\n  "records": []\n}\n'
PREFIXES = {
    "wqp_first_key_prefix": b"    {\n      ",
    "wqp_next_key_prefix": b",\n      ",
}
HELPERS = {"wtq_rows", "wtq_lookup", "wtq_mask", "wtq_offsets", "wtq_task_key"}


def pretty_frame(index, rows, key):
    old = envelope(index, rows, key)
    n = len(index)
    if old[n:n+4] != b"WTQ1":
        raise AssertionError("Unexpected previous frame header")
    return old[:n] + b"WTQ2" + old[n+4:]


def checked_graph():
    current, wire, _, _, sources = checked_source(NATIVE)
    prior, _, _, _, _ = checked_source(WTQ1)
    current_body = NATIVE.read_text()
    old_assembly = WTQ1.read_text()
    row_assembly = WJL1.read_text()

    # A checked thin projection changes the old public marker and publication
    # hooks, but no framing/validation/admission branch, logic, cap or status.
    expected = find_function(old_assembly, "f0")
    marker = int.from_bytes(b"WTQ2", "little")
    expected = replace_exact(expected, 'header_expected_query:u64 = const() {"value":827413591}',
                             'header_expected_query:u64 = const() {"value":'+str(marker)+'}')
    expected = replace_exact(expected,
        '  measure_needed:u64 = call(measure_i,measure_o,measure_frozen,measure_match_at,measure_match_count) {"function":"wtq_output"}',
        '  measure_dry:bool = const() {"value":false}\n'
        '  measure_needed:u64 = call(measure_i,measure_o,measure_frozen,measure_match_at,measure_match_count,measure_dry) {"function":"wqp_output"}')
    start = expected.index("  emit_marker:u64")
    stop = expected.index("  _ = loan.end(emit_frozen)")
    expected = expected[:start] + (
        '  emit_write:bool = const() {"value":true}\n'
        '  emit_frozen:readbuf = borrow.read(emit_s)\n'
        '  emit_actual:u64 = call(emit_i,emit_o,emit_frozen,emit_match_at,emit_match_count,emit_write) {"function":"wqp_output"}\n'
    ) + expected[stop:]
    if find_function(current_body, "f0") != expected:
        raise AssertionError("WTQ2 modified an original admission/lookup operation")
    row = replace_exact(find_function(row_assembly, "wj_row"), "fn wj_row(", "fn wqp_row(")
    row = replace_exact(row, '{"function":"wj_key"}', '{"function":"wqp_pretty_key"}')
    row = replace_exact(row, '{"function":"wj_close"}', '{"function":"wqp_row_end"}')
    if find_function(current_body, "wqp_row") != row:
        raise AssertionError("Pretty renderer changed original typed field logic")

    def literals(body, name):
        found = re.findall(r'^  (?:\w*bytes|\w*literal)_(\d+):u64 = const\(\) \{"value":(\d+)\}\n'
                           r'  (?:\w*len|\w*width)_(\d+):u64 = const\(\) \{"value":(\d+)\}$', body, re.M)
        if not found or [int(a) for a, _, _, _ in found] != list(range(len(found))):
            raise AssertionError(f"Unexpected fixed literal layout: {name}")
        return b"".join(int(v).to_bytes(int(width), "little") for a, v, b, width in found if a == b)

    compact = find_function(row_assembly, "wj_key")
    for i, field in enumerate(FIELDS):
        match = re.search(r"(?ms)^block write_"+field+r"\([^\n]*\n(.*?)(?=^block |^end\n)", compact)
        if match is None:
            raise AssertionError("Missing original compact key")
        expected_key = (b"{" if i == 0 else b",") + ('"'+field+'":').encode("ascii")
        if literals(match.group(1), field) != expected_key:
            raise AssertionError("Original key lacks the exact one disposable prefix byte")
    for name, token in PREFIXES.items():
        if literals(find_function(current_body, name), name) != token or not token.endswith(b" ") or len(token) < 8:
            raise AssertionError("The reused compact prefix can only overlap one allocated indentation byte")
    key = find_function(current_body, "wqp_pretty_key")
    if not all(token in key for token in (
        'key_one:u64 = const() {"value":1}',
        'key_space:u64 = const() {"value":32}',
        'key_overlap:u64 = int.sub.wrap(key_after_prefix,key_one)',
        'call(key_o,key_overlap,key_index,key_write) {"function":"wj_key"}',
        'call(key_o,key_overlap,key_space,key_one,key_write) {"function":"wa_word"}',
        'call(key_o,key_after_colon,key_space,key_one,key_write) {"function":"wa_word"}',
    )):
        raise AssertionError("Unexpected pretty write geometry for reused key")
    fs = {f["name"]: f for f in current.as_dict()["functions"]}
    old = {f["name"]: f for f in prior.as_dict()["functions"]}
    for name, old_f in old.items():
        if name in {"f0", "wtq_output", "wtq_hits"}:
            continue
        if fs.get(name) != old_f:
            raise AssertionError("Unchanged checked WTQ1 helper differs: " + name)
    if not HELPERS <= fs.keys() or fs.keys() & {"wtq_output", "wtq_hits"}:
        raise AssertionError("Unexpected old callable output in pretty variant")
    return fs, wire, sources


class WorkerAuditTaskQueryPretty(unittest.TestCase):
    def test_checked_projection_exact_both_abis_and_atomic_output(self):
        funcs, _, _ = checked_graph()
        self.assertEqual((len(funcs), sum(len(b["ops"]) for f in funcs.values() for b in f["blocks"])), (54, 1680))
        row = typed_row(0, "rejected")
        empty_ix = index_data(0, [])
        ix = index_data(1, [("0", [0])])
        base_size = len(pretty_frame(ix, [row], 0))
        enlarged = typed_row(0, "rejected", reputation_label="\0" * (LIMIT-base_size))
        full = pretty_frame(ix, [enlarged], 0)
        self.assertEqual(len(full), LIMIT)
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(NATIVE, backend=backend, byte_exports=("f0",)) as new:
                cap = 430000
                needed, result = observe(new, full, cap, SCRATCH+9)
                self.assertLess(needed, cap)
                self.assertGreater(needed, 390000)  # Escapes expand under the unchanged cap.
                self.assertEqual(result[needed:], FILL*(cap-needed))
                parsed = json.loads(result[:needed])
                self.assertEqual(parsed["hit_indexes"], [0])
                self.assertEqual(parsed["records"][0]["reputation_label"], "\0"*(LIMIT-base_size))
                self.assertEqual(parsed["records"][0]["settlement_status"], "rejected")
                self.assertTrue(result[:needed].endswith(b"\n  ]\n}\n"))
                self.assertEqual(observe(new, full, needed, scratch_fill=b"\xfe"), (needed, result[:needed]))
                self.assertEqual(observe(new, full, needed-1), (INSUFFICIENT, FILL*(needed-1)))
                self.assertEqual(observe(new, full, needed, SCRATCH-1), (INSUFFICIENT, FILL*needed))
                self.assertEqual(observe(new, pretty_frame(empty_ix, [], 0), len(EMPTY_STDOUT)),
                                 (41, EMPTY_STDOUT))
                wrong_abi = envelope(ix, [row], 0)
                for malformed in (
                    wrong_abi, full[:-4]+b"x"+full[-4:], pretty_frame(ix, [row[:-1]], 0),
                    pretty_frame(index_data(1, [("1", [0])]), [row], 0),
                    pretty_frame(request(1, [[("0",[0])], *([[]]*6), [("opaque",[1])]]), [row], 0),
                    pretty_frame(index_data(65, [("0", list(range(65)))]), [row]*65, 0),
                ):
                    self.assertEqual(observe(new, malformed, 512), (INVALID, FILL*512))
                with NativeModule(WTQ1, backend=backend, byte_exports=("f0",)) as old:
                    self.assertEqual(observe(old, pretty_frame(ix, [row], 0), 512), (INVALID, FILL*512))
                    out_n, out = observe(old, wrong_abi, 512)
                    self.assertGreater(out_n, 8)
                    self.assertEqual(out[:4], b"WTO1")


def qualify(binary, original, prior, directory):
    def bound():
        return (original["repository_inputs"] == original_inputs()
                and original["executable_sha256"] == sha256(binary.read_bytes()).hexdigest())

    if not bound() or prior["original_source_inputs"] != original_inputs():
        raise AssertionError("Original Worker or prior callable source binding differs")
    funcs, wire, captured = checked_graph()
    cases, builds, unchanged = {}, {}, {}
    with ExitStack() as stack:
        modules = {}
        for backend in BACKENDS:
            old = stack.enter_context(NativeModule(WTQ1, backend=backend, byte_exports=("f0",)))
            if old.artifact_sha256 != prior["native_builds"][backend]["artifact_sha256"]:
                raise AssertionError("Prior WTQ1 machine artifact changed")
            unchanged[backend] = old.artifact_sha256
            now = stack.enter_context(NativeModule(NATIVE, backend=backend, byte_exports=("f0",)))
            modules[backend] = now
            raw = now.library.read_bytes()
            if sha256(raw).hexdigest() != now.artifact_sha256:
                raise AssertionError("Observed native machine artifact changed")
            (directory / f"{backend}.so").write_bytes(raw)
            builds[backend] = now.receipt
        for name, (journal, tasks) in journal_cases().items():
            case = fresh_directory(directory / name)
            src = case / "original-ingress.jsonl"
            src.write_bytes(journal)
            src.chmod(0o600)
            exported, _, oracle_index = cli_artifacts(binary, src, "original", True, None)
            sidecar = (case / "original.jsonl.index.json").read_bytes()
            if sidecar != oracle_index:
                raise AssertionError("Original indexes differ")
            ix, _ = parse_native_input(sidecar)
            typed = []
            for line in exported.splitlines():
                row = json.loads(line)
                if tuple(row) != FIELDS or any(row[key] is not None for key in
                        ("provider_request_id", "provenance_fingerprint", "provenance_schema_version")):
                    raise AssertionError("Original row schema or owned non-identity scope changed")
                typed.append(frame(tuple(row[f] for f in FIELDS)))
            result = {}
            for task in tasks:
                oracle, oracle_sha = query_original(binary, case / "original.jsonl", task, case)
                want = (case / f"query-{task}.stdout.raw").read_bytes()
                if len(want) > OUT_MAX or sha256(want).hexdigest() != oracle_sha or not want.endswith(b"\n"):
                    raise AssertionError("Original query stdout is not the exact captured byte oracle")
                if not oracle["hit_indexes"] and want != EMPTY_STDOUT:
                    raise AssertionError("Original empty stdout shape changed")
                request_data = pretty_frame(ix, typed, task)
                (case / f"{task}.wtq2").write_bytes(request_data)
                by_backend = {}
                for backend, mod in modules.items():
                    n, out = observe(mod, request_data, len(want)+13, SCRATCH+11)
                    if (n != len(want) or out[:n] != want or out[n:] != FILL*13):
                        raise AssertionError(f"Actual Rust stdout differs: {name}/{task}/{backend}: got {n}, expected {len(want)}")
                    (case / f"{task}.{backend}.stdout.raw").write_bytes(out[:n])
                    by_backend[backend] = sha256(out[:n]).hexdigest()
                result[str(task)] = {"hits": oracle["hit_indexes"], "stdout_bytes": len(want),
                                     "original_sha256": oracle_sha, "native_sha256": by_backend}
            if name == "maximum-ordered" and result[str(MAX_TASK)]["hits"] != list(range(64)):
                raise AssertionError("Original maximum task did not hit all 64 export ordinals")
            if name == "mixed" and (not result["0"]["hits"] or result["55"]["hits"]):
                raise AssertionError("Genuine original mixed zero and absent controls changed")
            cases[name] = {"rows": len(typed), "queries": result}
    if not bound() or any(p.read_bytes() != b for p, b in captured):
        raise AssertionError("Captured compiled source or original identity changed")
    report = {"schema": "trnm.hia.worker-audit-task-pretty-stdout.v2", "status": "PASS", "cases": cases,
              "original_binary_sha256": original["executable_sha256"], "original_source_inputs": original_inputs(),
              "prior_wtq1_exact_runtime_artifacts": unchanged, "native_builds": builds,
              "checked_core_sha256": sha256(wire).hexdigest(), "functions": len(funcs),
              "operations": sum(len(b["ops"]) for f in funcs.values() for b in f["blocks"]),
              "all_original_stdout_bytes_equal": True, "generic_json_parse": False, "host_formatting": False,
              "path_io": False, "production_routing": False}
    (directory / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--original-binary", type=Path, required=True)
    p.add_argument("--original-build-receipt", type=Path, required=True)
    p.add_argument("--prior-wtq1-report", type=Path, required=True)
    a = p.parse_args()
    report = qualify(a.original_binary.resolve(strict=True), json.loads(a.original_build_receipt.read_bytes()),
                     json.loads(a.prior_wtq1_report.read_bytes()), fresh_directory(a.output))
    print(json.dumps({"status": report["status"], "cases": report["cases"]}, sort_keys=True))


if __name__ == "__main__":
    main()
