"""Construct all eight Worker audit index maps from ordered selected rows."""
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
import argparse
import json
import struct
import subprocess
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_index_wire import MAPS
from hia.tests.test_worker_audit_jsonl_row import ROOT
from hia.tests.test_worker_audit_select import (
    BACKENDS, FILL, INCLUDED, INSUFFICIENT, INVALID, ingress_rows, original_inputs,
)

NATIVE = ROOT / "hia/src/worker_agent/audit_index_group.hepta"
WIRE = ROOT / "hia/src/worker_agent/audit_index_wire.hepta"
KEYS = ("status", "provider", "model", "agent_protocol", "compliance_profile",
        "provenance_fingerprint")
SCRATCH_BYTES = 102400
SCRATCH_FILL = b"\x53"


def request(rows):
    # Format-only adapter. It neither groups nor orders keys or ordinals,
    # classifies phase, calculates fingerprints, trims, or rewrites a field.
    out = bytearray(struct.pack("<4sI", b"WIG1", len(rows)))
    for row in rows:
        raw = []
        for key in KEYS:
            val = row[key]
            raw.append(val.encode("utf-8") if isinstance(val, str)
                       else b"" if val is None else val)
        out += struct.pack("<Q6B", row["task_id"], *(len(s) for s in raw))
        out += b"".join(raw)
    return bytes(out)


def row(task_id=0, status="rejected", **labels):
    return {"task_id": task_id, "status": status,
            **dict.fromkeys(KEYS[1:]), **labels}


def observed(module, frame, output, scratch=SCRATCH_BYTES):
    initial = SCRATCH_FILL * scratch
    result = module.call("f0", [frame, FILL * output, initial]).require_returned()
    original, found, workspace = result.arguments
    if original != frame or workspace[SCRATCH_BYTES:] != initial[SCRATCH_BYTES:]:
        raise AssertionError("Source or scratch tail changed")
    return result.value, found, workspace


class WorkerIndexGroupTests(unittest.TestCase):
    def test_native_groups_all_maps_with_opaque_fields_and_stable_offsets(self):
        rows = [row(2, "failed_adapter", provider="Acme", model="A", agent_protocol="mcp",
                    compliance_profile="audit-readonly-v1", provenance_fingerprint="a"*64),
                row(10, provider="Acme West", model="B", agent_protocol="a2a"),
                row(2, "reveal_submitted", provider="Acme", model="A", agent_protocol="mcp",
                    compliance_profile="audit-readonly-v1", provenance_fingerprint="a"*64),
                row((1 << 64)-1, "failed_submission", provider="Acme!"),
                row(0)]
        data = request(rows)
        with ExitStack() as stack:
            for backend in BACKENDS:
                with self.subTest(backend=backend):
                    group = stack.enter_context(NativeModule(NATIVE, backend=backend, byte_exports=("f0",)))
                    wire = stack.enter_context(NativeModule(WIRE, backend=backend, byte_exports=("f0",)))
                    size, buf, scratch = observed(group, data, 4096, SCRATCH_BYTES + 7)
                    payload = buf[:size]
                    index = json.loads(payload)
                    self.assertEqual(tuple(index), ("version", "total_records", *MAPS))
                    self.assertEqual(index["total_records"], 5)
                    self.assertEqual(list(index["by_task_id"].items()),
                                     [("0", [4]), ("10", [1]), ("18446744073709551615", [3]), ("2", [0, 2])])
                    self.assertEqual(index["by_status"], {"failed_adapter": [0], "failed_submission": [3],
                                                        "rejected": [1, 4], "reveal_submitted": [2]})
                    self.assertEqual(index["by_status_phase"], {"active": [0, 2, 3], "terminal": [1, 4]})
                    self.assertEqual(list(index["by_provider"].items()), [("Acme", [0, 2]), ("Acme West", [1]), ("Acme!", [3])])
                    self.assertEqual(index["by_model"], {"A": [0, 2], "B": [1]})
                    self.assertEqual(index["by_agent_protocol"], {"a2a": [1], "mcp": [0, 2]})
                    self.assertEqual(index["by_compliance_profile"], {"audit-readonly-v1": [0, 2]})
                    self.assertEqual(index["by_provenance_fingerprint"], {"a"*64: [0, 2]})
                    self.assertEqual(buf[size:], FILL * (4096-size))
                    self.assertEqual(observed(group, data, size)[:2], (size, payload))
                    self.assertEqual(observed(group, data, size-1)[:2],
                                     (INSUFFICIENT, FILL * (size-1)))
                    staged_extent = len(scratch[:32768].rstrip(SCRATCH_FILL))
                    self.assertEqual(scratch[:4], b"WIX1")
                    out = wire.call("f0", [scratch[:staged_extent], FILL*size, b""]).require_returned()
                    self.assertEqual((out.value, out.arguments[1]), (size, payload))

    def test_boundary_bit_63_and_whole_output_refusal(self):
        first_63 = [row(2, "failed_submission", model="A"*128)]*63
        data = request([*first_63, row(2, "rejected", model="A"*128, provenance_fingerprint="b"*64)])
        invalid = [
            request([*first_63, row(2, "pending")]),
            request([*first_63, row(2, model="Z"*129)]),
            request([*first_63, row(2, provenance_fingerprint=b"\x01")]),
            request([*first_63, row(2, provider=b"\xff")]),
            request([row()]*65), data + b"x", data[:-1], b"", b"WIG2"+data[4:],
            b"WIG1" + b"\xff"*22661,
        ]
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE, backend=backend, byte_exports=("f0",)) as module:
                size, data_out, _ = observed(module, data, 8192)
                result = json.loads(data_out[:size])
                self.assertEqual(result["by_task_id"]["2"], list(range(64)))
                self.assertEqual(result["by_model"]["A"*128], list(range(64)))
                self.assertEqual(result["by_status_phase"]["terminal"], [63])
                self.assertEqual(result["by_provenance_fingerprint"], {"b"*64: [63]})
                self.assertEqual(observed(module, data, 8192, SCRATCH_BYTES-1)[:2],
                                 (INSUFFICIENT, FILL*8192))
                for item in invalid:
                    self.assertEqual(observed(module, item, 512)[:2], (INVALID, FILL*512))


def scenarios():
    status_roster = sorted(INCLUDED)
    count = 64
    rows = ingress_rows(["waiting", *[status_roster[i % 4] for i in range(count)],
                         "Rejected", "rejected "])
    for i, source in enumerate(rows):
        source["task_id"] = (2, 10, 20, 2, (1 << 64) - 1, 0)[i % 6]
        source.pop("provider_request_id", None)
        source.pop("provenance_schema_version", None)
        source.pop("llm_provenance", None)
        if i % 7:
            source["provenance_schema_version"] = "llm.v1" if i % 5 == 0 else "llm.v2"
            source["llm_provenance"] = {
                "provider": (r'Acme "Display"\West' if i % 2 else "acme display"),
                "model": (("X" * 125) + f"{i:03}" if i % 5 else "X"),
                "agent_protocol": ("a2a" if i % 3 else "mcp"),
                "compliance_profile": "audit-readonly-v1" if i % 2 else "research.local-v2",
            }
    return {"maximum": rows, "empty": [], "excluded": ingress_rows(["pending", "Rejected"])}


def observe_original(binary, build, directory):
    def bound():
        return (build["repository_inputs"] == original_inputs()
                and sha256(binary.read_bytes()).hexdigest() == build["executable_sha256"])
    if not bound():
        raise AssertionError("Exact original Worker source/lock/executable binding differs")
    proof = {}
    with ExitStack() as stack:
        native = {backend: stack.enter_context(NativeModule(
            NATIVE, backend=backend, byte_exports=("f0",))) for backend in BACKENDS}
        for name, rows in scenarios().items():
            d = directory / name
            d.mkdir(mode=0o700)
            journal = d / "synthetic-ingress.jsonl"
            journal.write_bytes(b"".join((json.dumps(rec, ensure_ascii=False) + "\n").encode()
                                         for rec in rows))
            journal.chmod(0o600)
            source_hash = sha256(journal.read_bytes()).hexdigest()
            for ext in ("jsonl", "md"):
                dest = d / ("original." + ext)
                call = subprocess.run([str(binary), "export-audit", "--ingress-file", str(journal),
                                       "--output-file", str(dest)], cwd=d, capture_output=True,
                                      timeout=25)
                (d / f"original.{ext}.stdout.raw").write_bytes(call.stdout)
                (d / f"original.{ext}.stderr.raw").write_bytes(call.stderr)
                if call.returncode or call.stderr or sha256(journal.read_bytes()).hexdigest() != source_hash:
                    raise AssertionError("Unchanged original Worker export did not complete")
            # Row bytes only. No contents from either original index file are
            # used to build the HIA input; the untouched .md index is the oracle.
            typed = [json.loads(line) for line in (d / "original.jsonl").read_bytes().splitlines()]
            frame = request(typed)
            want = (d / "original.md.index.json").read_bytes()
            (d / "ordered-typed-input.raw").write_bytes(frame)
            hashes = {}
            for backend, module in native.items():
                n, out, scratch = observed(module, frame, len(want)+7, SCRATCH_BYTES+7)
                if n != len(want) or out != want + FILL*7:
                    raise AssertionError(f"{name}: {backend} native output differs from original index")
                (d / f"{backend}.index.json").write_bytes(out[:n])
                hashes[backend] = sha256(out[:n]).hexdigest()
            details = json.loads(want)
            counts = dict((k,len(details[k])) for k in MAPS)
            expected = 64 if name == "maximum" else 0
            if len(typed) != expected or details["total_records"] != expected:
                raise AssertionError("Actual original selected row size changed")
            if name == "maximum":
                ids = list(details["by_task_id"])
                if (not all(counts.values()) or ids.index("10") >= ids.index("2")
                        or len(details["by_task_id"]["2"]) < 2
                        or set(details["by_status_phase"]) != {"active","terminal"}
                        or set(details["by_agent_protocol"]) != {"a2a","mcp"}
                        or max(i for hits in details["by_task_id"].values() for i in hits) != 63
                        or not any(val is None for val in (r["provenance_fingerprint"] for r in typed))
                        or not any(len(r.get("model") or "") == 128 for r in typed)):
                    raise AssertionError("Genuine original fixture lost required shapes")
            proof[name] = {"ingress_rows": len(rows), "selected_rows": len(typed),
                           "typed_input_sha256": sha256(frame).hexdigest(),
                           "index_bytes": len(want), "original_sha256": sha256(want).hexdigest(),
                           "native_sha256": hashes, "entries_by_map": counts}
    if not bound():
        raise AssertionError("Original source/executable identity changed during observation")
    report = {
        "original_cli_sha256": build["executable_sha256"], "original_source_bindings": original_inputs(),
        "native_single_call_including_all_eight_index_maps": True,
        "typed_rows_from_original_jsonl": True, "grouping_from_original_index_or_host": False,
        "full_markdown_index_byte_oracle": True, "production_dispatch_changed": False,
        "native_backends": {b: {"artifact_sha256": m.artifact_sha256, "receipt": m.receipt} for b,m in native.items()},
        "scenarios": proof,
    }
    (directory / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--original-binary", type=Path, required=True)
    parser.add_argument("--original-build-receipt", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT):
        parser.error("Store private proof outside the checkout")
    output.mkdir(mode=0o700)
    data = observe_original(args.original_binary.resolve(strict=True),
                            json.loads(args.original_build_receipt.read_bytes()), output)
    print(json.dumps(data["scenarios"], sort_keys=True))


if __name__ == "__main__":
    main()
