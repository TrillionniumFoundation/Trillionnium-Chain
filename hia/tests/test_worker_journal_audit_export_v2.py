"""WQX2 is a single grammar replacement in the independently checked WQX program."""
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
from hia.tests.test_worker_journal_audit_dto import ROOT, declared_input, make, raw, unsupported_cases
from hia.tests.test_worker_journal_audit_dto_v2 import permuted, scenarios
from hia.tests.test_worker_journal_audit_export import (
    NATIVE as V1, SCRATCH_BYTES, scenarios as strict_scenarios, snapshot,
)
from hia.tests.test_worker_journal_line_frame import cli_artifacts
from hia.tools.toolchain import checked_source

NATIVE = ROOT / "hia/src/worker_agent/journal_audit_export_v2.hepta"
DTO_V2 = ROOT / "hia/src/worker_agent/journal_audit_dto_ordered_fields_v2.hepta"
SELECTED = (b"f0", b"wq_measure", b"wq_measure_one")
SOURCE_HEADER = b"hia-asm.v1 hepta.hia.program.v8 trnm_worker_journal_audit_export_wqx1"
V2_HEADER = b"hia-asm.v1 hepta.hia.program.v8 trnm_worker_journal_audit_export_wqx2"
OLD_CALL = b'  task:u64,request:u64,status:u64 = call(input,out,start,end_at) {"function":"wd_record_at"}\n'
NEW_CALL = OLD_CALL.replace(b'"wd_record_at"', b'"wd2_record_at"')


def projected_source():
    """Only these three authored functions can cross from the original facade."""
    old = V1.read_bytes()
    if old.splitlines()[0] != SOURCE_HEADER:
        raise AssertionError("Unexpected original WQX module identity")
    lines = [V2_HEADER + b"\n"]
    for name in SELECTED:
        found = re.findall(rb"(?ms)^fn " + name + rb"\([^\n]*\n.*?^end\n", old)
        if len(found) != 1:
            raise AssertionError(f"Ambiguous fixed source function {name!r}")
        block, = found
        replacements = block.count(OLD_CALL)
        if replacements != (1 if name == b"wq_measure_one" else 0):
            raise AssertionError("Expected exactly one approved DTO-call replacement")
        if block.count(b'"wd_record_at"') != replacements or b'"wd2_record_at"' in block:
            raise AssertionError("Unexpected original parser route")
        lines.append(block.replace(OLD_CALL, NEW_CALL))
    return b"".join(lines)


def checked_shape():
    def core(path):
        p, wire, *_ = checked_source(path)
        d = p.as_dict()
        return d, wire, {f["name"]: f for f in d.pop("functions")}

    original, wire, prior = core(V1)
    candidate, _, actual = core(NATIVE)
    _, _, dto = core(DTO_V2)
    if (original.pop("module") != SOURCE_HEADER.decode().split()[-1]
            or candidate.pop("module") != V2_HEADER.decode().split()[-1] or candidate != original):
        raise AssertionError("Core module changed outside the explicit version")
    if sha256(wire).hexdigest() != "0010b5d332937ca2076f48a1b7bfba96b11d0f1642729892bba4278713ed3e60":
        raise AssertionError("Original WQX1 composed source unexpectedly changed")
    prior.pop("wd_record_at")
    changes = [op for b in prior["wq_measure_one"]["blocks"] for op in b["ops"]
               if op["op"] == "call" and op["attrs"]["function"] == "wd_record_at"]
    if len(changes) != 1:
        raise AssertionError("Original Core parser call count differs")
    changes[0]["attrs"]["function"] = "wd2_record_at"
    prior.update({k: dto[k] for k in ("wd2_record_at", "wd2_key")})
    if actual != prior:
        raise AssertionError("New Core graph has changes beyond the sole admitted parser route")
    shape = {"functions": len(actual), "operations": sum(len(b["ops"]) for f in actual.values() for b in f["blocks"])}
    if shape != {"functions": 79, "operations": 2617}:
        raise AssertionError(f"Unexpected fixed WQX2 envelope {shape}")
    return shape


def controls():
    kept = raw(permuted(make("rejected", 1), 7, True))
    excluded = raw(permuted(make("pending", 2), 4, True))
    late = {"duplicate_required": excluded[:-1] + b',"status":"pending"}',
            "duplicate_nullable": excluded[:-1] + b',"adapter_error":null,"adapter_error":null}',
            "nonnull_late_excluded": excluded[:-1] + b',"reputation_delta":0}'}
    for kind in ("unknown", "escaped_key"):
        late[kind] = unsupported_cases()[kind]
    return {k: snapshot(kept, v) for k, v in late.items()}


class WorkerJournalAuditExportV2(unittest.TestCase):
    def test_exact_source_projection_and_full_checked_core_shape(self):
        self.assertEqual(NATIVE.read_bytes(), projected_source())
        self.assertEqual(checked_shape(), {"functions": 79, "operations": 2617})

    def test_refusal_tails_and_versioned_profile(self):
        req = "fixture|" + "a" * 33_000 + "🧾"
        good = snapshot(raw(permuted({**make("reveal_submitted", 10, req), "assigned_worker": None}, 5, True)),
                        raw(permuted(make("pending", 20), 4, True)))
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(NATIVE, backend=backend, byte_exports=("f0",)) as mod:
                n, filled = observe(mod, good, 120000, SCRATCH_BYTES + 19)
                self.assertLess(n, len(filled))
                self.assertEqual(filled[n:], FILL * (len(filled) - n))
                self.assertEqual(json.loads(artifacts(filled[:n])[0])["request_id"], req)
                self.assertEqual(observe(mod, good, n, scratch_fill=b"\xe7"), (n, filled[:n]))
                self.assertEqual(observe(mod, good, n - 1), (INSUFFICIENT, FILL * (n - 1)))
                self.assertEqual(observe(mod, good, 2048, SCRATCH_BYTES - 1), (INSUFFICIENT, FILL * 2048))
                self.assertEqual(observe(mod, b"\n" * 65537, 2048), (INSUFFICIENT, FILL * 2048))
                for src in (*controls().values(), good[:-1], good + b"\xff\n"):
                    self.assertEqual(observe(mod, src, 2048), (INVALID, FILL * 2048))


def qualify(binary, receipt, directory):
    def bound():
        return (original_inputs() == receipt["repository_inputs"]
                and sha256(binary.read_bytes()).hexdigest() == receipt["executable_sha256"])

    if not bound() or NATIVE.read_bytes() != projected_source():
        raise AssertionError("Original executable/source or checked projection differs")
    declaration = declared_input()
    graph = checked_shape()
    cases = {}
    with ExitStack() as stack:
        old = {b: stack.enter_context(NativeModule(V1, backend=b, byte_exports=("f0",))) for b in BACKENDS}
        images = {b: stack.enter_context(NativeModule(NATIVE, backend=b, byte_exports=("f0",))) for b in BACKENDS}
        snapshots = {**scenarios(), **{"strict_" + k: v for k, v in strict_scenarios().items()}}
        for name, (data, rows, selected) in snapshots.items():
            case = fresh_directory(directory / name)
            fixture = case / "original-input.jsonl"
            fixture.write_bytes(data)
            fixture.chmod(0o600)
            expected = cli_artifacts(binary, fixture, "original", True, None)
            if (json.loads(expected[2])["total_records"] != selected
                    or (case / "original.jsonl.index.json").read_bytes() != expected[2]):
                raise AssertionError("Original CLI byte-oracle attendance changed")
            if name == "mixed_at_cap" and (b"known-row-63" not in expected[0] or b"known-row-61" in expected[0]):
                raise AssertionError("High raw ordinal attendance changed")
            exact = 16 + sum(map(len, expected))
            for b, mod in images.items():
                n, out = observe(mod, data, exact + 7, SCRATCH_BYTES + 17)
                if (n, out[n:]) != (exact, FILL * 7) or artifacts(out[:n]) != expected:
                    raise AssertionError(f"{b} WQX2 was not exact one-call original output: {name}")
                if name.startswith("strict_") and observe(old[b], data, exact + 7, SCRATCH_BYTES + 17) != (n, out):
                    raise AssertionError("Strict WQX1 prior admitted behavior changed")
                if name in ("all_layouts", "mixed_at_cap") and observe(old[b], data, 2048) != (INVALID, FILL * 2048):
                    raise AssertionError("Old ABI unexpectedly became the expanded profile")
                (case / (b + ".wao")).write_bytes(out[:n])
            cases[name] = {"rows": rows, "selected": selected, "raw_bytes": len(data), "wao_bytes": exact,
                           "files": dict(zip(NAMES, (sha256(x).hexdigest() for x in expected), strict=True))}
        for name, data in controls().items():
            case = fresh_directory(directory / name)
            fixture = case / "original-input.jsonl"
            fixture.write_bytes(data)
            fixture.chmod(0o600)
            original_accepts = not name.startswith("duplicate_")
            cli_artifacts(binary, fixture, "original", original_accepts, b"duplicate field")
            for b, mod in images.items():
                n, out = observe(mod, data, 4000, SCRATCH_BYTES + 17)
                if (n, out) != (INVALID, FILL * 4000):
                    raise AssertionError("Whole raw refusal modified previously selected output")
                (case / (b + ".status")).write_text(f"{n:#010x}\n")
            cases[name] = {"original_accepts": original_accepts, "native_atomic_refusal": True}
        before = {b: {"artifact_sha256": m.artifact_sha256, "receipt": m.receipt} for b, m in old.items()}
        after = {b: {"artifact_sha256": m.artifact_sha256, "receipt": m.receipt} for b, m in images.items()}
    if not bound() or declaration != declared_input() or NATIVE.read_bytes() != projected_source():
        raise AssertionError("Observed original identity or WQX2 projection changed")
    report = {"original_cli_sha256": receipt["executable_sha256"], "original_source_pins": original_inputs(),
              "original_struct_sha256": declaration, "exact_candidate_core": graph, "cases": cases,
              "old_backends": before, "new_backends": after, "no_host_json_or_intermediate_frames": True,
              "one_memory_call_per_observation": True, "production_dispatch": False}
    (directory / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-source", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--original-binary", type=Path)
    parser.add_argument("--original-build-receipt", type=Path)
    args = parser.parse_args()
    full = (args.output, args.original_binary, args.original_build_receipt)
    if args.print_source and not any(full):
        print(projected_source().decode("ascii"), end="")
    elif not args.print_source and all(full):
        report = qualify(args.original_binary.resolve(strict=True),
                         json.loads(args.original_build_receipt.read_bytes()), fresh_directory(args.output))
        print(json.dumps(report["cases"], sort_keys=True))
    else:
        parser.error("Use --print-source alone or supply all three qualification paths")


if __name__ == "__main__":
    main()
