"""WTQ1 bounded typed task lookup versus the actual locked Worker query CLI."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import unittest

from hia.platform.worker_audit.build import fresh_directory
from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_export_transaction import observe, typed_row
from hia.tests.test_worker_audit_index_wire import parse_native_input, request
from hia.tests.test_worker_audit_jsonl_row import FIELDS, ROOT, frame
from hia.tests.test_worker_audit_select import BACKENDS, FILL, INCLUDED, INSUFFICIENT, INVALID, original_inputs
from hia.tests.test_worker_journal_audit_dto import declared_input, raw
from hia.tests.test_worker_journal_audit_dto_reputation_v3 import row
from hia.tests.test_worker_journal_audit_export import snapshot
from hia.tests.test_worker_journal_line_frame import cli_artifacts
from hia.tools.toolchain import checked_source

NATIVE = ROOT / "hia/src/worker_agent/audit_task_query.hepta"
LIMIT, MAX_TASK = 65536, (1 << 64) - 1
SCRATCH, OUT_MAX = 102400, 1 << 20
DECORATOR_FIELDS = ("proof_type", "settlement_status", "timestamp_unix_ms")


def envelope(index, rows, task):
    return (index + struct.pack("<4sQI", b"WTQ1", task, len(rows))
            + b"".join(struct.pack("<I", len(r)) + r for r in rows) + struct.pack("<I", len(index)))


def index_data(count, tasks, *, tail=()):
    return request(count, [tasks, *([[]] * 6), tail])


def split_result(out):
    tag, count = struct.unpack_from("<4sI", out)
    if tag != b"WTO1" or count > 64:
        raise AssertionError("Unexpected typed query result header")
    items = []
    position = 8
    for _ in range(count):
        ordinal, n = struct.unpack_from("<II", out, position)
        position += 8
        if n <= 1 or n > len(out) - position or not out[position:position+n].endswith(b"\n"):
            raise AssertionError("Unexpected Worker query row extent")
        items.append((ordinal, out[position:position+n]))
        position += n
    if position != len(out):
        raise AssertionError("Unexpected trailing bytes in query result")
    return items


class WorkerAuditTaskQuery(unittest.TestCase):
    def test_full_canonical_ownership_order_bounds_and_atomic_refusal(self):
        rows = [typed_row(task, INCLUDED[i % 4], reputation_delta=-i)
                for i, task in enumerate([0, 2, 10, 2, MAX_TASK])]
        good = index_data(5, [("0", [0]), ("10", [2]), (str(MAX_TASK), [4]), ("2", [1, 3])])
        valid = envelope(good, rows, 2)
        empty = envelope(index_data(0, []), [], MAX_TASK)
        at_count_cap = envelope(index_data(64, [("0", list(range(64)))]), [rows[0]] * 64, 0)
        at_extent_cap_row = typed_row(2, "rejected", provider="a" * 128)
        # The case grows a non-authority display field in the last row and ends at exactly 64 KiB.
        lone_index = index_data(1, [("2", [0])])
        want = LIMIT - len(envelope(lone_index, [at_extent_cap_row], 2))
        at_extent_cap = envelope(lone_index, [
            typed_row(2, "rejected", provider="a" * 128, reputation_label="x" * want)], 2)
        self.assertEqual(len(at_extent_cap), LIMIT)
        corrupt = [
            b"", valid[:59], valid + b"\0", valid[:-1], b"WIX2" + valid[4:],
            envelope(good, [*rows[:-1], rows[-1][:-1]], 2),
            envelope(good, [*rows[:-1], typed_row(MAX_TASK, "waiting")], 2),
            envelope(good, rows[:-1], 2),
            envelope(index_data(5, [("0", [0]), ("10", [2]), (str(MAX_TASK), [4]), ("2", [1])]), rows, 2),
            envelope(index_data(5, [("0", [0]), ("10", [1]), (str(MAX_TASK), [4]), ("2", [2, 3])]), rows, 2),
            envelope(index_data(5, [("0", [0]), ("10", [2]), (str(MAX_TASK), [4]), ("2", [1, 2, 3])]), rows, 2),
            envelope(index_data(5, [("00", [0]), ("10", [2]), (str(MAX_TASK), [4]), ("2", [1, 3])]), rows, 2),
            envelope(index_data(5, [("0", [0]), ("10", [2]), (str(MAX_TASK+1), [4]), ("2", [1, 3])]), rows, 2),
            envelope(index_data(5, [("0", [0]), ("10", [2]), (str(MAX_TASK), [4]), ("2", [1, 3])],
                                tail=[("opaque", [5])]), rows, 2),
            envelope(index_data(5, [("0", [0]), ("10", [2]), (str(MAX_TASK), [4]), ("2", [1, 3])],
                                tail=[("z", [0]), ("a", [1])]), rows, 2),
            envelope(index_data(65, [("0", list(range(65)))]), [rows[0]] * 65, 0),
            at_extent_cap[:-4] + b"x" + at_extent_cap[-4:],
        ]
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(NATIVE, backend=backend, byte_exports=("f0",)) as mod:
                n, out = observe(mod, valid, 4096, SCRATCH + 13)
                self.assertEqual(out[n:], FILL * (4096 - n))
                selected = split_result(out[:n])
                self.assertEqual([i for i, _ in selected], [1, 3])
                self.assertEqual([json.loads(r)["task_id"] for _, r in selected], [2, 2])
                self.assertEqual(observe(mod, valid, n, scratch_fill=b'\xec'), (n, out[:n]))
                self.assertEqual(observe(mod, valid, n-1), (INSUFFICIENT, FILL * (n-1)))
                self.assertEqual(observe(mod, valid, n, SCRATCH-1), (INSUFFICIENT, FILL*n))
                self.assertEqual(observe(mod, empty, 8), (8, b"WTO1\0\0\0\0"))
                n, out = observe(mod, at_count_cap, 40000)
                self.assertEqual([i for i, _ in split_result(out[:n])], list(range(64)))
                n, out = observe(mod, at_extent_cap, 66000)
                self.assertEqual(json.loads(split_result(out[:n])[0][1])["reputation_label"], "x" * want)
                for probe in corrupt:
                    self.assertEqual(observe(mod, probe, 4096), (INVALID, FILL * 4096))


def journal_cases():
    task_ids = (0, 2, 10, 2, MAX_TASK, 17, MAX_TASK)
    mixed = []
    for i in range(64):
        status = ("pending" if i % 7 == 0 and i != 7 else ("Rejected" if i % 10 == 0 else INCLUDED[i % 4]))
        fields = row((3, -1, -2, -3, None, 0, -2147483648, 2147483647)[i % 8],
                     status, ordinal=i, request=f'synthetic-{i}-"é\\ü😀"')
        fields["task_id"] = task_ids[i % len(task_ids)]
        mixed.append(raw(fields))
    repeated = [raw({**row(-1, INCLUDED[t % 4], ordinal=t), "task_id": MAX_TASK}) for t in range(64)]
    return {"mixed": (b"\r\n".join(mixed) + b"\r\n", (0, 2, 10, MAX_TASK, 17, 55)),
            "maximum-ordered": (snapshot(*repeated), (MAX_TASK, 0)),
            "empty": (b"", (0,)),
            "all-excluded": (snapshot(raw({**row(3, "waiting"), "task_id": 2})), (2,))}


def query_original(binary, output, task, directory):
    found = subprocess.run([str(binary), "query-audit", "--output-file", str(output),
                            "--task-id", str(task)], cwd=directory, capture_output=True, timeout=25)
    (directory / f"query-{task}.stdout.raw").write_bytes(found.stdout)
    (directory / f"query-{task}.stderr.raw").write_bytes(found.stderr)
    if found.returncode or found.stderr:
        raise AssertionError(f"Actual original query refused ({task}): {found.stderr!r}")
    decoded = json.loads(found.stdout)
    if tuple(decoded) != ("hit_indexes", "records"):
        raise AssertionError("Task filter unexpectedly gained fields or fingerprint interpretation")
    return decoded, sha256(found.stdout).hexdigest()


def qualify(binary, receipt, directory):
    def bound():
        return (receipt["repository_inputs"] == original_inputs()
                and receipt["executable_sha256"] == sha256(binary.read_bytes()).hexdigest())

    if not bound():
        raise AssertionError("Original locked Worker source/binary pins differ")
    before, _, _, _, closure = checked_source(NATIVE)
    declaration = declared_input()
    report = {}
    builds = {}
    with ExitStack() as stack:
        kernels = {b: stack.enter_context(NativeModule(NATIVE, backend=b, byte_exports=("f0",))) for b in BACKENDS}
        for backend, module in kernels.items():
            artifact = module.library.read_bytes()
            if sha256(artifact).hexdigest() != module.artifact_sha256:
                raise AssertionError("Native query artifact identity changed")
            (directory / (backend + ".so")).write_bytes(artifact)
            builds[backend] = module.receipt
        for name, (journal, tasks) in journal_cases().items():
            case = fresh_directory(directory / name)
            src = case / "original-ingress.jsonl"
            src.write_bytes(journal)
            src.chmod(0o600)
            exported, _, index_oracle = cli_artifacts(binary, src, "original", True, None)
            same_index = (case / "original.jsonl.index.json").read_bytes()
            if same_index != index_oracle:
                raise AssertionError("Original JSONL and Markdown index bytes differ")
            ix, _ = parse_native_input(same_index)
            # Both inputs are the complete original CLI products, not computed from query results.
            original_lines = exported.splitlines(keepends=True)
            typed = []
            for line in original_lines:
                row_record = json.loads(line)
                if tuple(row_record) != FIELDS:
                    raise AssertionError("Unexpected active original row schema")
                typed.append(frame(tuple(row_record[f] for f in FIELDS)))
            rows_report = {}
            for task in tasks:
                oracle, stdout_sha = query_original(binary, case / "original.jsonl", task, case)
                payload = envelope(ix, typed, task)
                (case / f"{task}.wtq").write_bytes(payload)
                by_backend = {}
                for backend, module in kernels.items():
                    n, data = observe(module, payload, OUT_MAX, SCRATCH+13)
                    if n > OUT_MAX or data[n:] != FILL*(OUT_MAX-n):
                        raise AssertionError("Query result escaped output prefix")
                    data = data[:n]
                    (case / f"{task}.{backend}.wto").write_bytes(data)
                    observed = split_result(data)
                    if [ordinal for ordinal, _ in observed] != oracle["hit_indexes"]:
                        raise AssertionError("Native hit ordinals differ from actual original CLI")
                    if len(observed) != len(oracle["records"]):
                        raise AssertionError("Native and original row attendance differs")
                    for (ordinal, emitted), original_row in zip(observed, oracle["records"], strict=True):
                        expected_extra = (None, original_row["status"], None)
                        if tuple(original_row[x] for x in DECORATOR_FIELDS) != expected_extra:
                            raise AssertionError("Rust-only query decoration changed")
                        expected_record = {key: original_row[key] for key in FIELDS}
                        if (emitted != original_lines[ordinal] or json.loads(emitted) != expected_record
                                or len(original_row) != len(FIELDS)+len(DECORATOR_FIELDS)):
                            raise AssertionError("Complete query row differs from independent Rust oracle")
                    by_backend[backend] = sha256(data).hexdigest()
                if len(set(by_backend.values())) != 1:
                    raise AssertionError("Two native backends disagree")
                rows_report[str(task)] = {"ordinals": oracle["hit_indexes"], "stdout_sha256": stdout_sha,
                                          "native_result_sha256": by_backend}
            if name == "maximum-ordered" and rows_report[str(MAX_TASK)]["ordinals"] != list(range(64)):
                raise AssertionError("Actual original maximum case did not reach its final row")
            if name == "mixed" and (not rows_report["0"]["ordinals"] or rows_report["55"]["ordinals"]):
                raise AssertionError("Original mixed must exercise positive zero and an absent task")
            report[name] = {"records": len(typed), "lookup": rows_report}

    if not bound() or declared_input() != declaration or any(p.read_bytes() != b for p, b in closure):
        raise AssertionError("Bound source inputs changed during actual comparison")
    compiled = before.as_dict()["functions"]
    result = {"schema": "trnm.hia.worker-audit-task-query.v1", "status": "PASS", "cases": report,
              "source_inputs": {p.relative_to(ROOT).as_posix(): sha256(b).hexdigest() for p, b in closure},
              "functions": len(compiled), "core_operations": sum(len(b["ops"]) for f in compiled for b in f["blocks"]),
              "original_source_inputs": original_inputs(), "original_struct_sha256": declaration,
              "original_binary_sha256": receipt["executable_sha256"], "native_builds": builds,
              "all_eight_maps_structurally_validated": True,
              "task_rows_exactly_covered": True, "compact_export_rows_byte_exact": True,
              "pretty_query_stdout_byte_claimed": False, "original_general_sidecar_acceptance": False,
              "production_dispatch": False}
    (directory / "report.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--original-binary", type=Path, required=True)
    p.add_argument("--original-build-receipt", type=Path, required=True)
    args = p.parse_args()
    result = qualify(args.original_binary.resolve(strict=True), json.loads(args.original_build_receipt.read_bytes()),
                     fresh_directory(args.output))
    print(json.dumps({"status": result["status"], "cases": result["cases"]}, sort_keys=True))


if __name__ == "__main__":
    main()
