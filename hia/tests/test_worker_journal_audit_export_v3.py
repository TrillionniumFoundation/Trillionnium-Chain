"""WQX3 is the scoped one-call typed reputation extension to WQX2."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import re
import unittest

from hia.platform.worker_audit.build import fresh_directory
from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_export_transaction import NAMES, artifacts, observe
from hia.tests.test_worker_audit_select import BACKENDS, FILL, INSUFFICIENT, INVALID, original_inputs
from hia.tests.test_worker_journal_audit_dto import ROOT, declared_input, raw
from hia.tests.test_worker_journal_audit_dto_reputation_v3 import NATIVE as DTO3, refusals, row, scenarios
from hia.tests.test_worker_journal_audit_export import NATIVE as V1, SCRATCH_BYTES, snapshot
from hia.tests.test_worker_journal_audit_export_v2 import NATIVE as V2, scenarios as strict_ordered_cases
from hia.tests.test_worker_journal_line_frame import cli_artifacts
from hia.tools.toolchain import checked_source

NATIVE = ROOT / "hia/src/worker_agent/journal_audit_export_v3.hepta"
HEADER = "hia-asm.v1 hepta.hia.program.v8 trnm_worker_journal_audit_export_wqx3"
ITEMS = ("wq_store_keys", "wq_emit_rows", "wq_select_and_measure")


def function(source, name):
    found = re.findall(r"(?ms)^fn " + name + r"\([^\n]*\n.*?^end\n", source)
    if len(found) != 1:
        raise AssertionError(f"Ambiguous fixed function {name}")
    return found[0]


def replace_exact(text, old, new, count=1):
    if text.count(old) != count:
        raise AssertionError(f"Expected {count} of {old!r}")
    return text.replace(old, new)


def projected_prefix():
    old = V1.read_text()
    v2 = V2.read_text()
    dto3 = DTO3.read_text()
    record = function(dto3, "wd3_record")
    record = replace_exact(record, "wd3_record(", "wd3_record_at(")
    record = replace_exact(record, "output:mutbuf,extent:u64", "output:mutbuf,origin:u64,extent:u64", 2)
    record = replace_exact(record, "call(input,zero,extent)", "call(input,origin,extent)")
    rep = function(dto3, "wd3_emit_reputation")
    rep = replace_exact(rep, "wd3_emit_reputation(", "wd3_emit_reputation_at(")
    rep = replace_exact(rep, "out:mutbuf,delta:u64", "out:mutbuf,row_at:u64,delta:u64", 2)
    rep = replace_exact(rep, '  wrote_mask:u64 = call(out,four,mask,four,yes)',
                        '  mask_at:u64 = int.add.wrap(row_at,four)\n'
                        '  numeric_at:u64 = int.add.wrap(row_at,delta_at)\n'
                        '  label_length_at:u64 = int.add.wrap(row_at,label_slot)\n'
                        '  wrote_mask:u64 = call(out,mask_at,mask,four,yes)')
    rep = replace_exact(rep, "call(out,delta_at,", "call(out,numeric_at,")
    rep = replace_exact(rep, "call(out,label_slot,", "call(out,label_length_at,")
    index = function(old, "wq_store_keys")
    index = replace_exact(index, '  task:u64,request:u64,status:u64 = call(scratch,row) {"function":"wq_load"}',
                          '  task:u64,pair:u64,tagged:u64 = call(scratch,row) {"function":"wq_load"}\n'
                          '  request:u64,status:u64 = call(pair) {"function":"wd3_spans"}')
    emit = function(old, "wq_emit_rows")
    emit = replace_exact(emit, '  task:u64,request:u64,status:u64 = call(es,er) {"function":"wq_load"}\n'
                         '  geometry:u64 = call(ei,es,end_at,task,request,status) {"function":"wq_materialize"}',
                         '  task:u64,pair:u64,tagged:u64 = call(es,er) {"function":"wq_load"}\n'
                         '  geometry:u64,row_size:u64,mask:u64 = call(ei,es,end_at,task,pair,tagged) '
                         '{"function":"wq3_materialize"}')
    emit = replace_exact(emit, '  mask:u64 = const() {"value":0}\n', '')
    measure = function(old, "wq_select_and_measure")
    measure = replace_exact(measure, 'geometry:u64,json_at:u64,md_at:u64)',
                            'geometry:u64,json_at:u64,md_at:u64,presence_mask:u64)', 2)
    measure = replace_exact(measure, 'observe(row,out,geometry,json_at,md_at)',
                            'observe(row,out,geometry,json_at,md_at,presence_mask)')
    measure = replace_exact(measure, 'rg:u64,rj:u64,rm:u64)', 'rg:u64,rj:u64,rm:u64,mask:u64)')
    measure = replace_exact(measure, '  mask:u64 = const() {"value":0}\n', '')
    return "\n".join((HEADER, function(v2, "f0").rstrip(), function(v2, "wq_measure").rstrip(),
                      index.rstrip(), emit.rstrip(), measure.rstrip(), record.rstrip(), rep.rstrip()))+"\n"


def checked_graph():
    def functions(path):
        program, wire, *_ = checked_source(path)
        d = program.as_dict()
        fs = {f["name"]: f for f in d.pop("functions")}
        return d, fs, sha256(wire).hexdigest()

    old, before, v2_hash = functions(V2)
    new, after, _ = functions(NATIVE)
    _, helpers, _ = functions(DTO3)
    old.pop("module")
    if new.pop("module") != HEADER.split()[-1] or old != new:
        raise AssertionError("WQX3 altered profile properties beyond module identity")
    replaced = {*ITEMS, "wq_measure_one"}
    removed = {"wd2_record_at", "wq_length", "wq_materialize"}
    offset = {"wd3_record_at", "wd3_emit_reputation_at"}
    new_dto = {"wd3_spans", "wd3_geometry", "wd3_i32", "wr_values", "wr_metadata", "wr_rank", "wr_label"}
    shared = {k: v for k, v in before.items() if k not in replaced | removed}
    expected = set(shared) | replaced | offset | new_dto | {"wq3_materialize"}
    if set(after) != expected or any(after[k] != v for k, v in shared.items()):
        raise AssertionError("Unapproved Core changes outside listed v3 seams")
    if any(after[k] != helpers[k] for k in new_dto):
        raise AssertionError("Unchanged WJD3 and WJR helpers not reused exactly")
    def block(fn, name):
        return next(b for b in after[fn]["blocks"] if b["id"] == name)

    def producing(b, variable):
        return next(o for o in b["ops"] if any(v["name"] == variable for v in o["out"]))

    def call_arg(b, function, slot):
        (found,) = [o for o in b["ops"] if o["op"] == "call" and o["attrs"]["function"] == function]
        return found["args"][slot]

    entry = block("wq3_materialize", "entry")
    size, max_row, compare = (producing(entry, x) for x in ("size", "max_row", "row_fits"))
    if (size["args"] != ["prefix", "label_len"] or max_row["attrs"] != {"value": 65536 - 8 - 4}
            or compare["op"] != "compare.le" or compare["args"] != ["size", "max_row"]
            or entry["term"]["cond"] != "row_fits" or entry["term"]["then"]["target"] != "stage"
            or entry["term"]["else"] != {"args": ["size"], "target": "oversized"}
            or block("wq3_materialize", "oversized")["term"]["values"] != ["none", "on", "none"]
            or any(o["op"] in {"buffer.store", "buffer.fill_range"}
                   or o["attrs"].get("function") not in {None, "wd3_geometry", "wr_values", "wr_metadata", "wr_rank"}
                   for o in entry["ops"])):
        raise AssertionError("Reputation preflight must count the label and refuse before staging a too-large row")
    if (block("wq_measure_one", "materialize")["term"]["else"]
            != {"args": ["mj", "mm", "row_size"], "target": "too_large"}
            or block("wq_measure_one", "too_large")["term"]["values"] != ["oj", "om", "on"]
            or call_arg(block("wq_measure_one", "measure"), "wq_select_and_measure", 5) != "smask"):
        raise AssertionError("Expected bounded measured-row and original aggregate refusal path")
    for fn, b, callee in (("wq_select_and_measure", "observe", "wj_row"),
                          ("wq_select_and_measure", "markdown", "wm_row"),
                          ("wq_emit_rows", "emit", "wj_row"), ("wq_emit_rows", "emit", "wm_row")):
        if call_arg(block(fn, b), callee, 3) not in {"mask", "mz"}:
            raise AssertionError("Measure and publication must carry the materialized reputation mask")
    if v2_hash != "cde297746ebfecfc15045b6de0cb07f9f2d05eba00aff20cee94b769007c3869":
        raise AssertionError("Prior checked WQX2 source bytes changed")

    return {"functions": len(after), "operations": sum(len(b["ops"]) for f in after.values() for b in f["blocks"]),
            "wqx2_composed_sha256": v2_hash}


def near_raw_cap():
    # The last value carries the longest exact 23-byte audit label.
    early = raw(row(3, ordinal=1))
    late = row(-1, ordinal=63, request="")
    late["request_id"] = "x" * (65536 - len(snapshot(early, raw(late))))
    whole = snapshot(early, raw(late))
    if len(whole) != 65536:
        raise AssertionError("Exact bounded near-cap raw witness changed")
    return whole


class WorkerJournalAuditExportV3(unittest.TestCase):
    def test_exact_generated_projection_and_shared_checked_core(self):
        content = NATIVE.read_text()
        prefix, delimiter, rest = content.partition("fn wq_measure_one(")
        self.assertEqual(prefix, projected_prefix())
        self.assertTrue(delimiter and rest)
        graph = checked_graph()
        self.assertEqual((graph["functions"], graph["operations"]), (86, 2797))
        # Minimum compact raw JSON row, counting physical LF. All decoded
        # request/status bytes add at least their length to these minima.
        minimum = {k: "" for k in ("request_id", "channel", "user_id", "session_id",
                                   "text", "idempotency_key", "status")}
        minimum.update(task_id=0, created_at_unix_ms=0)
        for value, label, raw_min in ((None, 0, 138), (3, 8, 159), (-1, 23, 160),
                                      (-2, 17, 160), (-3, 21, 160)):
            record = minimum if value is None else {**minimum, "reputation_delta": value}
            self.assertEqual(len(raw(record))+1, raw_min)
            self.assertGreaterEqual(raw_min - (108 + 4 + label), 25)

    def test_whole_raw_refusal_full_caps_and_reputation_mask(self):
        source = near_raw_cap()
        kept = raw(row(3))
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(NATIVE, backend=backend, byte_exports=("f0",)) as mod:
                n, out = observe(mod, source, 180000, SCRATCH_BYTES + 13)
                self.assertLess(n, len(out))
                self.assertEqual(out[n:], FILL * (len(out) - n))
                results = [json.loads(r) for r in artifacts(out[:n])[0].splitlines()]
                self.assertEqual([r["reputation_delta"] for r in results], [3, -1])
                self.assertEqual(len(results[1]["reputation_label"]), 23)
                self.assertEqual(observe(mod, source, n, scratch_fill=b"\xe7"), (n, out[:n]))
                self.assertEqual(observe(mod, source, n - 1), (INSUFFICIENT, FILL * (n - 1)))
                self.assertEqual(observe(mod, source, 2048, SCRATCH_BYTES - 1), (INSUFFICIENT, FILL * 2048))
                self.assertEqual(observe(mod, source + b"\n", 2048), (INSUFFICIENT, FILL * 2048))
                for late in refusals().values():
                    self.assertEqual(observe(mod, snapshot(kept, late), 2048), (INVALID, FILL * 2048))


def qualify(binary, receipt, directory):
    def bound():
        return (original_inputs() == receipt["repository_inputs"]
                and sha256(binary.read_bytes()).hexdigest() == receipt["executable_sha256"])

    if not bound():
        raise AssertionError("Pinned original Worker identity mismatch")
    graph = checked_graph()
    fixture_cases = {**scenarios(), "exact_raw_cap": (near_raw_cap(), 2, 2),
                     **{"old_" + k: v for k, v in strict_ordered_cases().items()}}
    old_rows = {k for k in fixture_cases if k.startswith("old_")}
    cases = {}
    declaration = declared_input()
    with ExitStack() as stack:
        mods = {b: stack.enter_context(NativeModule(NATIVE, backend=b, byte_exports=("f0",))) for b in BACKENDS}
        prior = {b: stack.enter_context(NativeModule(V2, backend=b, byte_exports=("f0",))) for b in BACKENDS}
        for kind, (data, rows, selected) in fixture_cases.items():
            case = fresh_directory(directory / kind)
            journal = case / "locked-original-input.jsonl"
            journal.write_bytes(data)
            journal.chmod(0o600)
            expected = cli_artifacts(binary, journal, "original", True, None)
            index = json.loads(expected[2])
            if index["total_records"] != selected or (case / "original.jsonl.index.json").read_bytes() != expected[2]:
                raise AssertionError("Original Worker selected a different fixture set")
            size = 16 + sum(map(len, expected))
            for backend, m in mods.items():
                n, out = observe(m, data, size + 9, SCRATCH_BYTES + 17)
                if (n, out[n:]) != (size, FILL * 9) or artifacts(out[:n]) != expected:
                    raise AssertionError(f"Whole raw WQX3 differed from original files: {backend} {kind}")
                if kind in old_rows and observe(prior[backend], data, size+9) != (n, out):
                    raise AssertionError("Prior WQX2 admitted bytes changed")
                if kind in ("all_values", "mixed_at_cap", "exact_raw_cap") and observe(
                        prior[backend], data, 2048) != (INVALID, FILL * 2048):
                    raise AssertionError("Old WQX2 artifact silently became the reputation profile")
                (case / (backend + ".wao")).write_bytes(out[:n])
            cases[kind] = {"raw_bytes": len(data), "rows": rows, "selected": selected, "wao_bytes": size,
                           "files": dict(zip(NAMES, (sha256(x).hexdigest() for x in expected), strict=True))}
        kept = raw(row(3))
        for label, late in refusals().items():
            case = fresh_directory(directory / label)
            journal = case / "locked-original-input.jsonl"
            data = snapshot(kept, late)
            journal.write_bytes(data)
            journal.chmod(0o600)
            original_accepts = label == "unported_display"
            cli_artifacts(binary, journal, "original", original_accepts, b"invalid worker journal record")
            for m in mods.values():
                if observe(m, data, 4096, SCRATCH_BYTES+17) != (INVALID, FILL * 4096):
                    raise AssertionError("Late WQX3 refusal wrote output")
            cases[label] = {"original_accepts": original_accepts, "native_atomic_refusal": True}
        images = {b: {"artifact_sha256": m.artifact_sha256, "receipt": m.receipt} for b, m in mods.items()}
        prior_images = {b: m.artifact_sha256 for b, m in prior.items()}
    if not bound() or declaration != declared_input():
        raise AssertionError("Original Worker pins changed across WQX3 qualification")
    report = {"pins": original_inputs(), "original_executable_sha256": receipt["executable_sha256"],
              "original_struct_sha256": declaration, "graph": graph, "cases": cases, "native_images": images,
              "prior_wqx2_artifacts": prior_images, "one_raw_memory_call": True, "production_dispatch": False}
    (directory / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--print-projection", action="store_true")
    p.add_argument("--output", type=Path)
    p.add_argument("--original-binary", type=Path)
    p.add_argument("--original-build-receipt", type=Path)
    args = p.parse_args()
    paths = (args.output, args.original_binary, args.original_build_receipt)
    if args.print_projection and not any(paths):
        print(projected_prefix(), end="")
    elif not args.print_projection and all(paths):
        report = qualify(args.original_binary.resolve(strict=True), json.loads(args.original_build_receipt.read_bytes()),
                         fresh_directory(args.output))
        print(json.dumps(report["cases"], sort_keys=True))
    else:
        p.error("Use --print-projection alone or supply all three qualification paths")


if __name__ == "__main__":
    main()
