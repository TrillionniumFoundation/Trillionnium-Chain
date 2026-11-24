"""WJD3 audit-only signed delta from genuine ordered raw Worker journal files."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import struct
import unittest

from hia.platform.worker_audit.build import fresh_directory
from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_export_preselection import NATIVE as WAT2
from hia.tests.test_worker_audit_export_transaction import NAMES, artifacts, observe
from hia.tests.test_worker_audit_reputation_projection import REPUTATION_FIELDS
from hia.tests.test_worker_audit_select import BACKENDS, FILL, INSUFFICIENT, INVALID, observed_call, original_inputs
from hia.tests.test_worker_journal_audit_dto import ROOT, declared_input, make, ordinary_wjl_values, raw
from hia.tests.test_worker_journal_audit_dto_v2 import permuted, traverse
from hia.tests.test_worker_journal_audit_export import snapshot
from hia.tests.test_worker_journal_line_frame import NATIVE as WJF1, cli_artifacts

NATIVE = ROOT / "hia/src/worker_agent/journal_audit_dto_reputation_v3.hepta"
DELTA = "reputation_delta"
LIMIT = 1 << 31
RECOGNIZED = (3, -1, -2, -3)
MISSING = object()


def row(value, status="rejected", ordinal=0, request=None):
    label = f"private-{ordinal} 🧾" if request is None else request
    data = make(status, (1 << 64) - 1 if ordinal % 2 == 0 else ordinal, label, stamp=(1 << 128) - 1)
    data["assigned_worker"] = None
    if value is not MISSING:
        data[DELTA] = value
    return permuted(data, ordinal % len(data), reverse=ordinal % 2 == 0)


def raw_delta(token):
    base = raw(row(None, status="pending", ordinal=2))
    before = b'"reputation_delta":null'
    if base.count(before) != 1:
        raise AssertionError("Synthetic delta token site changed")
    return base.replace(before, b'"reputation_delta":' + token)


def refusals():
    return {"negative_zero": raw_delta(b"-0"), "float": raw_delta(b"3.0"), "exponent": raw_delta(b"3e0"),
            "negative_overflow": raw_delta(str(-LIMIT - 1).encode()),
            "positive_overflow": raw_delta(str(LIMIT).encode()), "quoted": raw_delta(b'"-3"'),
            "duplicate": raw_delta(b'null,"reputation_delta":-3'),
            "unported_display": raw_delta(b'3,"provenance_schema_version":"llm.v1"')}


class WorkerJournalDtoReputationV3(unittest.TestCase):
    def test_width_sign_masks_full_geometry_and_late_refusal(self):
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(NATIVE, backend=backend, byte_exports=("f0",)) as m:
                for value in (MISSING, None, 0, -LIMIT, LIMIT - 1, 2, -40):
                    d = row(value)
                    expected = ordinary_wjl_values(d["request_id"], d["task_id"], d["status"])
                    self.assertEqual(observed_call(m, raw(d), len(expected)), (len(expected), expected))
                for ordinal, value in enumerate(RECOGNIZED):
                    d = row(value, ordinal=ordinal, request="")
                    source = raw(d, escape=True)
                    n, out = observed_call(m, source, 512)
                    self.assertEqual(n, 108 + len(d["status"]) + (8, 23, 17, 21)[ordinal])
                    self.assertEqual(out[n:], FILL * (512 - n))
                    self.assertEqual(struct.unpack_from("<IQ", out, 4), (0x7f00, d["task_id"]))
                    self.assertEqual(struct.unpack_from("<Q", out, 16)[0], value & ((1 << 32) - 1))
                    self.assertEqual(observed_call(m, source, n), (n, out[:n]))
                    self.assertEqual(observed_call(m, source, n - 1), (INSUFFICIENT, FILL * (n - 1)))
                for source in refusals().values():
                    self.assertEqual(observed_call(m, source, 512), (INVALID, FILL * 512))
                d = row(-1, request="")
                d["request_id"] = "x" * (65536 - len(raw(d)))
                source = raw(d)
                self.assertEqual(len(source), 65536)
                size, found = observed_call(m, source, 66000)
                self.assertEqual(size, 108 + len(d["request_id"]) + len(d["status"]) + 23)
                self.assertEqual(found[108:108 + len(d["request_id"])], d["request_id"].encode())
                self.assertEqual(found[size:], FILL * (66000 - size))
                self.assertEqual(observed_call(m, source + b" ", 512), (INSUFFICIENT, FILL * 512))
                # Near-cap raw quote offsets exercise the other half of each
                # 16-bit lane, independently of the large decoded length.
                late_strings = row(-3, request="late")
                late_strings = {k: v for k, v in late_strings.items() if k not in ("request_id", "status")}
                late_strings.update({"request_id": "late", "status": "rejected"})
                late_strings["text"] = ""
                late_strings["text"] = "x" * (65536 - len(raw(late_strings)))
                late_source = raw(late_strings)
                self.assertEqual(len(late_source), 65536)
                self.assertGreater(late_source.index(b'"late"'), 65500)
                n, emitted = observed_call(m, late_source, 256)
                self.assertEqual(n, 108 + len("laterejected") + 21)
                self.assertEqual(emitted[108:120], b"laterejected")
                self.assertEqual(emitted[n:], FILL * (256 - n))



def scenarios():
    values = (*RECOGNIZED, MISSING, None, 0, -LIMIT, LIMIT - 1, 1, -42)
    all_values = [raw(row(value, ordinal=i), escape=i % 2 == 1) for i, value in enumerate(values)]
    mixed = [raw(row(values[i % len(values)], status=("pending" if i % 4 == 0 else "reveal_submitted"),
                     ordinal=i), escape=i % 2 == 0) for i in range(64)]
    return {"all_values": (snapshot(*all_values), len(values), len(values)),
            "mixed_at_cap": (b"\r\n".join(mixed) + b"\r\n", 64, 48),
            "empty": (b"", 0, 0)}


def qualify(binary, receipt, directory):
    def bound():
        return (original_inputs() == receipt["repository_inputs"]
                and sha256(binary.read_bytes()).hexdigest() == receipt["executable_sha256"])

    if not bound():
        raise AssertionError("Original Rust executable/source lock identity differs")
    declaration = declared_input()
    source = ROOT / "trillionnium/crates/trnm-worker-agent/src/main.rs"
    dto = source.read_text().split("pub(crate) struct MessageIngressRecord {", 1)[1].split("\n}", 1)[0]
    if "#[serde(default)]\n    pub(crate) reputation_delta: Option<i32>," not in dto:
        raise AssertionError("Original optional signed declaration changed")
    observed = {}
    with ExitStack() as stack:
        modules = {b: {k: stack.enter_context(NativeModule(s, backend=b, byte_exports=("f0",)))
                       for k, s in (("framer", WJF1), ("dto", NATIVE), ("transaction", WAT2))}
                   for b in BACKENDS}
        for name, (data, rows, selected) in scenarios().items():
            case = fresh_directory(directory / name)
            journal = case / "locked-original-input.jsonl"
            journal.write_bytes(data)
            journal.chmod(0o600)
            expected = cli_artifacts(binary, journal, "original", True, None)
            output_rows = [json.loads(line) for line in expected[0].splitlines()]
            if (len(output_rows) != selected or json.loads(expected[2])["total_records"] != selected
                    or (case / "original.jsonl.index.json").read_bytes() != expected[2]):
                raise AssertionError("Original CLI fixture output attendance changed")
            if name == "all_values":
                for i, record in enumerate(output_rows):
                    projected = i < len(RECOGNIZED)
                    if ((projected and record[DELTA] != RECOGNIZED[i])
                            or any((record[f] is not None) != projected for f in REPUTATION_FIELDS)):
                        raise AssertionError("Original recognized reputation fields changed")
            if name == "mixed_at_cap" and (b"private-63" not in expected[0] or b"private-60" in expected[0]):
                raise AssertionError("Original CLI mixed fixture did not preserve row 63")
            size = 16 + sum(map(len, expected))
            for backend, module in modules.items():
                staged = traverse(module, data, rows)
                if staged is None:
                    raise AssertionError("Native typed admission rejected a scoped original-valid snapshot")
                n, out = observe(module["transaction"], staged, size + 9)
                if (n, out[n:]) != (size, FILL * 9) or artifacts(out[:n]) != expected:
                    raise AssertionError(f"Original three-artifact exact comparison failed: {backend} {name}")
                (case / (backend + ".wao")).write_bytes(out[:n])
            observed[name] = {"rows": rows, "selected": selected, "wao_bytes": size,
                              "files": dict(zip(NAMES, (sha256(x).hexdigest() for x in expected), strict=True))}
        kept = raw(row(-1))
        for name, line in refusals().items():
            case = fresh_directory(directory / name)
            journal = case / "locked-original-input.jsonl"
            data = snapshot(kept, line)
            journal.write_bytes(data)
            journal.chmod(0o600)
            original_accepts = name == "unported_display"
            cli_artifacts(binary, journal, "original", original_accepts, b"invalid worker journal record")
            for mod in modules.values():
                if observed_call(mod["dto"], line, 256) != (INVALID, FILL * 256) or traverse(mod, data, 2) is not None:
                    raise AssertionError("Refused row wrote bytes or reached the typed transaction")
            observed[name] = {"original_accepts": original_accepts, "native_refusal_atomic": True,
                              "transaction_dispatched": False}
        images = {b: {k: {"artifact_sha256": m.artifact_sha256, "receipt": m.receipt}
                      for k, m in mods.items()} for b, mods in modules.items()}
    if not bound() or declaration != declared_input():
        raise AssertionError("Original executable/source identity changed during qualification")
    report = {"pins": original_inputs(), "original_executable_sha256": receipt["executable_sha256"],
              "original_struct_sha256": declaration, "audit_reputation_only": True, "one_raw_call": False,
              "host_offsets_and_lengths_only": True, "production_dispatch": False, "scenarios": observed,
              "native_images": images}
    (directory / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--original-binary", type=Path, required=True)
    p.add_argument("--original-build-receipt", type=Path, required=True)
    args = p.parse_args()
    report = qualify(args.original_binary.resolve(strict=True), json.loads(args.original_build_receipt.read_bytes()),
                     fresh_directory(args.output))
    print(json.dumps(report["scenarios"], sort_keys=True))


if __name__ == "__main__":
    main()
