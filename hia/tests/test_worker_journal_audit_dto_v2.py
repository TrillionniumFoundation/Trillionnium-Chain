"""Observe WJD2 order and nullable-field parity with genuine locked Worker files."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_export_preselection import NATIVE as WAT2, wat2
from hia.tests.test_worker_audit_export_transaction import NAMES, artifacts, observe
from hia.tests.test_worker_audit_select import BACKENDS, FILL, INSUFFICIENT, INVALID, observed_call, original_inputs
from hia.tests.test_worker_journal_audit_dto import (
    FIELDS, MAX_RAW, OPTIONS, ROOT, declared_input, make, ordinary_wjl_values, raw, unsupported_cases,
)
from hia.tests.test_worker_journal_line_frame import NATIVE as WJF1, cli_artifacts, unpack_bytes

NATIVE = ROOT / "hia/src/worker_agent/journal_audit_dto_ordered_fields_v2.hepta"
REQUIRED = tuple(name.split(":")[0] for name in FIELDS)


def permuted(row, shift=0, reverse=False):
    items = list(row.items())
    shift %= len(items)
    items = items[shift:] + items[:shift]
    return dict(reversed(items) if reverse else items)


def geometries():
    req = "ordinary|\u0000 café 🧾\r\n\\"
    record = make("rejected", (1 << 64) - 1, req, stamp=(1 << 128) - 1, null_suffix=True)
    for i in range(22):
        yield dict(permuted(record, i, i % 3 == 1))
    base = make("reveal_submitted", 0, "", stamp=0)
    for i, option in enumerate(OPTIONS):
        yield permuted({**base, option: None}, i, i % 2 == 0)


def malformed():
    row = make("failed_adapter", 7, "ordinary")
    base = raw(row)
    for field in REQUIRED:
        yield raw({k: v for k, v in row.items() if k != field})
        token = raw({field: row[field]})[1:-1]
        yield base[:-1] + b"," + token + b"}"
    for key in OPTIONS:
        token = raw({key: None})[1:-1]
        yield base[:-1] + b"," + token + b"," + token + b"}"
    for field, value in (("text", 1), ("channel", None), ("task_id", 1 << 64),
                         ("created_at_unix_ms", 1 << 128)):
        yield raw({**row, field: value})
    yield base[:-1] + b",}"
    yield base + b"\n"
    yield base.replace(b'"ordinary"', b'"\xff"')
    yield base.replace(b'"ordinary"', b'"\\ud800"')
    for key in ("unknown", "escaped_key", "present_optional"):
        yield unsupported_cases()[key]


class WorkerJournalDtoV2(unittest.TestCase):
    def test_permuted_typecheck_exact_projection_and_limits(self):
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(NATIVE, backend=backend, byte_exports=("f0",)) as mod:
                for i, record in enumerate(geometries()):
                    source = b"\t " + raw(record, escape=i % 2 == 0, compact=i % 3 == 0) + b" \r"
                    want = ordinary_wjl_values(record["request_id"], record["task_id"], record["status"])
                    self.assertEqual(observed_call(mod, source, len(want) + 3), (len(want), want + FILL * 3))
                for data in malformed():
                    self.assertEqual(observed_call(mod, data, 128), (INVALID, FILL * 128))
                max_record = permuted(make("", 0, "", null_suffix=True), 17, True)
                max_record["text"] = ""
                max_record["text"] = "x" * (MAX_RAW - len(raw(max_record)))
                source = raw(max_record)
                self.assertEqual(len(source), MAX_RAW)
                self.assertEqual(observed_call(mod, source, 108), (108, ordinary_wjl_values("", 0, "")))
                self.assertEqual(observed_call(mod, source, 107), (INSUFFICIENT, FILL * 107))
                self.assertEqual(observed_call(mod, source + b" ", 108), (INSUFFICIENT, FILL * 108))


def scenarios():
    mixed = []
    for i in range(64):
        status = ("rejected", "pending", "failed_adapter", "Rejected")[i % 4]
        if i == 63:
            status = "reveal_submitted"
        row = make(status, (1 << 64) - 1 if i in (0, 63) else i % 3,
                   f"known-row-{i}|café🧾", stamp=(1 << 128) - 1 if i % 2 else 0)
        for j, name in enumerate(OPTIONS):
            if (i + j) % 4 < 2:
                row[name] = None
        mixed.append(raw(permuted(row, i, i % 2 == 0), escape=i % 3 == 0))
    geometry = b"\n".join(raw(r, escape=i % 2 == 0) for i, r in enumerate(geometries())) + b"\n"
    return {"all_layouts": (geometry, 35, 35), "mixed_at_cap": (b"\r\n".join(mixed) + b"\r\n", 64, 33),
            "blank": (b"\r\n\t \n", 0, 0), "empty": (b"", 0, 0)}


def traverse(module, data, count):
    size, raw_spans = observed_call(module["framer"], data, 789)
    if not 8 <= size <= 776 or raw_spans[size:] != FILL * (789 - size):
        raise AssertionError("Native WJF framing did not return complete exact spans")
    spans = unpack_bytes(raw_spans[:size])
    if len(spans) != count or [i for i, _, _ in spans] != list(range(count)):
        raise AssertionError("Native WJF attendance changed")
    frames = []
    for _, start, extent in spans:
        length, found = observed_call(module["dto"], data[start:start + extent], 108 + extent)
        if length == INVALID:
            return None
        if not 108 <= length <= 108 + extent or found[length:] != FILL * (108 + extent - length):
            raise AssertionError("WJD2 did not return an intact WJL1")
        frames.append(found[:length])
    # This test coordinator transports offsets and lengths only. It has no
    # JSON/DTO parser, status selector, or producer of audit artifacts.
    return wat2(frames)


def qualify(binary, receipt, directory):
    def bound():
        return (original_inputs() == receipt["repository_inputs"]
                and sha256(binary.read_bytes()).hexdigest() == receipt["executable_sha256"])
    if not bound():
        raise AssertionError("Original locked Rust identity changed")
    declaration = declared_input()
    if (ROOT / "trillionnium/crates/trnm-worker-agent/src/main.rs").read_text().split(
            "pub(crate) struct MessageIngressRecord {", 1)[1].split("\n}", 1)[0].count("#[serde(default)]") != 13:
        raise AssertionError("Ordinary optional defaults changed")
    reports = {}
    with ExitStack() as stack:
        modules = {b: {key: stack.enter_context(NativeModule(src, backend=b, byte_exports=("f0",)))
                       for key, src in (("framer", WJF1), ("dto", NATIVE), ("transaction", WAT2))}
                   for b in BACKENDS}
        for name, (data, count, selected) in scenarios().items():
            case = directory / name
            case.mkdir(mode=0o700)
            source = case / "original-input.jsonl"
            source.write_bytes(data)
            source.chmod(0o600)
            original = cli_artifacts(binary, source, "original", True, None)
            if (json.loads(original[2])["total_records"] != selected
                    or label_ordinal_changed(name, original[0])
                    or (case / "original.jsonl.index.json").read_bytes() != original[2]):
                raise AssertionError("Actual original CLI selected an unexpected fixture set")
            extent = 16 + sum(map(len, original))
            for backend, module in modules.items():
                encoded = traverse(module, data, count)
                if encoded is None:
                    raise AssertionError("Native candidate rejected admitted whole snapshot")
                size, packet = observe(module["transaction"], encoded, extent + 7)
                if size != extent or artifacts(packet[:size]) != original or packet[size:] != FILL * 7:
                    raise AssertionError(f"Genuine CLI full outputs differ: {backend} {name}")
                (case / (backend + ".wao")).write_bytes(packet[:size])
            reports[name] = {"raw_bytes": len(data), "candidates": count, "selected": selected,
                             "artifacts": dict(zip(NAMES, (sha256(x).hexdigest() for x in original), strict=True))}
        valid = raw(make("rejected", 1))
        excluded = raw(permuted(make("pending", 2), 4, True))
        outside = {k: unsupported_cases()[k] for k in ("unknown", "escaped_key", "present_optional")}
        outside["nonnull_late_excluded"] = excluded[:-1] + b',"reputation_delta":0}'
        duplicate = {"duplicate_required": excluded[:-1] + b',"status":"pending"}',
                     "duplicate_nullable": excluded[:-1] + b',"adapter_error":null,"adapter_error":null}'}
        for name, line in {**outside, **duplicate}.items():
            case = directory / name
            case.mkdir(mode=0o700)
            source = case / "original-input.jsonl"
            data = valid + b"\n" + line + b"\n"
            source.write_bytes(data)
            source.chmod(0o600)
            expected_accept = name in outside
            cli_artifacts(binary, source, "original", expected_accept, b"duplicate field")
            for backend, module in modules.items():
                if observed_call(module["dto"], line, 256) != (INVALID, FILL * 256):
                    raise AssertionError(f"WJD2 rejection was not atomic: {backend} {name}")
                if traverse(module, data, 2) is not None:
                    raise AssertionError("Invalid candidate reached the typed WAT2 transaction")
            reports[name] = {"original_accepts": expected_accept, "native_refuses": True,
                             "no_transaction_published": True}
        images = {b: {k: {"artifact_sha256": mod.artifact_sha256, "receipt": mod.receipt}
                      for k, mod in entries.items()} for b, entries in modules.items()}
    if not bound() or declaration != declared_input():
        raise AssertionError("Actual original pins changed during qualification")
    result = {"original_executable_sha256": receipt["executable_sha256"], "pins": original_inputs(),
              "original_struct_sha256": declaration, "images": images, "cases": reports,
              "host_transports_only_offsets_and_lengths": True, "one_call_raw": False,
              "production_dispatch": False}
    (directory / "report.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return result


def label_ordinal_changed(name, rows):
    return name == "mixed_at_cap" and (b"known-row-63" not in rows or b"known-row-61" in rows)


def main():
    from hia.platform.worker_audit.build import fresh_directory
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary", required=True, type=Path)
    parser.add_argument("--original-build-receipt", required=True, type=Path)
    opts = parser.parse_args()
    result = qualify(opts.original_binary.resolve(strict=True),
                     json.loads(opts.original_build_receipt.read_bytes()), fresh_directory(opts.output))
    print(json.dumps(result["cases"], sort_keys=True))


if __name__ == "__main__":
    main()
