"""Serialize a typed Worker export index and compare independent Rust CLI files."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_jsonl_row import ROOT
from hia.tests.test_worker_audit_select import (
    BACKENDS, FILL, INCLUDED, INSUFFICIENT, INVALID, MAX_RECORDS,
    ingress_rows, observed_call, original_inputs,
)

NATIVE = ROOT / "hia/src/worker_agent/audit_index_wire.hepta"
MAPS = (
    "by_task_id", "by_status", "by_status_phase", "by_provider", "by_model",
    "by_agent_protocol", "by_compliance_profile", "by_provenance_fingerprint",
)


def words(*items):
    return struct.pack("<" + "I" * len(items), *items)


def request(total, maps):
    if len(maps) != 8:
        raise ValueError("A typed WIX1 value has exactly eight maps")
    out = bytearray(b"WIX1" + words(total))
    for pairs in maps:
        out += words(len(pairs))
        for key, hits in pairs:
            raw = key.encode("utf-8") if isinstance(key, str) else key
            out += words(len(raw), len(hits)) + raw + words(*hits)
    return bytes(out)


def parse_native_input(raw):
    def unique(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise AssertionError("Duplicate original index field or key")
        return result

    index = json.loads(raw, object_pairs_hook=unique)
    if (tuple(index) != ("version", "total_records", *MAPS)
            or type(index["version"]) is not int or index["version"] != 1
            or type(index["total_records"]) is not int):
        raise AssertionError("Original CLI index shape differs")
    maps = []
    for field in MAPS:
        entries = index[field]
        if not isinstance(entries, dict):
            raise AssertionError("Original CLI index map type differs")
        pairs = list(entries.items())
        for key, hits in pairs:
            if not isinstance(key, str) or not isinstance(hits, list) or any(type(o) is not int for o in hits):
                raise AssertionError("Original CLI index value type differs")
        maps.append(pairs)
    return request(index["total_records"], maps), index


class WorkerAuditIndexWire(unittest.TestCase):
    def test_lexical_key_order_empty_maps_output_tail_and_capacity(self):
        maps = [[("10", [0, 2]), ("2", [1]), ("20", [3])], *([[]] * 7)]
        frame = request(4, maps)
        empty = request(0, [[]] * 8)
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE, backend=backend, byte_exports=("f0",)) as native:
                n, found = observed_call(native, frame, 1024)
                self.assertLess(n, 1024)
                self.assertEqual(found[n:], FILL * (1024 - n))
                data = found[:n]
                parsed = json.loads(data)
                self.assertEqual(tuple(parsed), ("version", "total_records", *MAPS))
                self.assertEqual(list(parsed["by_task_id"].items()), maps[0])
                self.assertTrue(data.endswith(b"\n}"))
                self.assertEqual(observed_call(native, frame, n - 1), (INSUFFICIENT, FILL * (n - 1)))
                self.assertEqual(observed_call(native, frame, n), (n, data))
                n, out = observed_call(native, empty, 236)
                self.assertEqual((n, len(out)), (236, 236))

    def test_late_invalid_map_is_atomic_even_after_valid_prefix(self):
        prefix = [[("10", [0]), ("2", [2])], *([[]] * 6)]
        malformed = [
            request(3, prefix + [tail]) for tail in (
                [("2", [0]), ("10", [1])], [("same", [0]), ("same", [2])],
                [(b"", [0])], [(b"\xc3", [1])], [("none", [])],
                [("rank", [3])], [("rank", [2, 1])], [("rank", [1, 1])],
                [("a", [0, 1]), ("b", [1, 2])],
            )
        ]
        ok = request(3, prefix + [[("last", [0, 2])]])
        malformed += [b"", ok[:-1], ok + b"x", b"WIX2" + ok[4:],
                      request(MAX_RECORDS + 1, [[]] * 8), request(0, prefix + [[]])]
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(
                    NATIVE, backend=backend, byte_exports=("f0",)) as native:
                for item in malformed:
                    self.assertEqual(observed_call(native, item, 0), (INVALID, b""))
                    self.assertEqual(observed_call(native, item, 2048), (INVALID, FILL * 2048))


def scenarios():
    statuses = ["waiting", "Rejected", *[INCLUDED[i % 4] for i in range(14)], "rejected "]
    rows = ingress_rows(statuses)
    for i, row in enumerate(rows):
        # Only synthetic existing original CLI fixture values. The index
        # encoder never handles fingerprint/protocol normalization.
        row["task_id"] = (2, 10, 20, 2, (1 << 64) - 1)[i % 5]
        row.pop("provider_request_id", None)
        row.pop("provenance_schema_version", None)
        row.pop("llm_provenance", None)
        if i in (2, 7, 11):
            row["provenance_schema_version"] = "llm.v2"
            row["llm_provenance"] = {
                "provider": ('Acme "Demo"\\West' if i != 7 else "acme"),
                "model": ("Model-2" if i != 7 else "Model-10"),
                "adapter": "local",
                "agent_protocol": "a2a",
                "compliance_profile": "audit-readonly-v1",
            }
    return {"mixed": rows, "excluded": ingress_rows(["pending", "Rejected"]), "empty": []}


def observe_original_index(binary, build, directory):
    def bound():
        return (build["repository_inputs"] == original_inputs()
                and sha256(binary.read_bytes()).hexdigest() == build["executable_sha256"])
    if not bound():
        raise AssertionError("Actual Worker source binding differs")
    proof = {}
    with ExitStack() as stack:
        emitters = {backend: stack.enter_context(NativeModule(
            NATIVE, backend=backend, byte_exports=("f0",))) for backend in BACKENDS}
        for name, rows in scenarios().items():
            d = directory / name
            d.mkdir(mode=0o700)
            journal = d / "synthetic-ingress.jsonl"
            journal.write_bytes(b"".join((json.dumps(row, ensure_ascii=False) + "\n").encode()
                                         for row in rows))
            journal.chmod(0o600)
            same_input = sha256(journal.read_bytes()).hexdigest()
            for ext in ("jsonl", "md"):
                dest = d / ("original." + ext)
                call = subprocess.run([str(binary), "export-audit", "--ingress-file", str(journal),
                                       "--output-file", str(dest)], cwd=d, capture_output=True,
                                      timeout=25)
                (d / f"original.{ext}.stdout.raw").write_bytes(call.stdout)
                (d / f"original.{ext}.stderr.raw").write_bytes(call.stderr)
                if call.returncode or call.stderr or sha256(journal.read_bytes()).hexdigest() != same_input:
                    raise AssertionError("Original index source/byte oracle failed")
            # These are two independently executed original commands.
            # The JSONL index supplies only typed scalars and raw key bytes.
            # The untouched Markdown index is the direct full-byte oracle.
            wire, facts = parse_native_input((d / "original.jsonl.index.json").read_bytes())
            want = (d / "original.md.index.json").read_bytes()
            (d / "typed-index-input.raw").write_bytes(wire)
            for backend, module in emitters.items():
                n, array = observed_call(module, wire, len(want) + 5)
                if n != len(want) or array != want + FILL * 5:
                    raise AssertionError(f"Native index byte difference: {name} {backend}")
                (d / f"{backend}.index.json").write_bytes(array[:n])
            if name == "mixed":
                keys = list(facts["by_task_id"])
                if (keys.index("10") > keys.index("2") or keys == sorted(keys, key=int)
                        or not all(facts[k] for k in MAPS)
                        or max(o for groups in facts["by_task_id"].values() for o in groups) < 10
                        or not any(len(v) > 1 for v in facts["by_task_id"].values())):
                    raise AssertionError("Genuine mixed original did not exercise required index shape")
            proof[name] = {"ingress_rows": len(rows), "selected_records": facts["total_records"],
                           "maps": {k: len(facts[k]) for k in MAPS}, "index_bytes": len(want),
                           "sha256": sha256(want).hexdigest(), "trailing_lf": want.endswith(b"\n")}
    if not bound():
        raise AssertionError("Original Worker binding changed")
    report = {
        "original_cli_executed": True, "original_binary_sha256": build["executable_sha256"],
        "typed_facts_from_original_jsonl_index": True, "byte_oracle_original_markdown_index": True,
        "native_grouping_query_file_or_policy": False, "production_dispatch_changed": False,
        "backends": {backend: module.artifact_sha256 for backend, module in emitters.items()},
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
    report = observe_original_index(args.original_binary.resolve(strict=True),
                                    json.loads(args.original_build_receipt.read_bytes()), output)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
