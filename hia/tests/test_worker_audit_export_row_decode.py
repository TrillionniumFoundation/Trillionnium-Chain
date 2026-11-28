"""Compile native WER1 from raw original export JSONL through unchanged WTQ2."""
import argparse
from contextlib import ExitStack
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile
import unittest

from hia.platform.worker_audit.build import fresh_directory
from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_export_transaction import NATIVE as WAT1, artifacts, observe, wire
from hia.tests.test_worker_audit_index_decode import NATIVE as WID1, STAGE_MAX, fixture_cases as base_cases
from hia.tests.test_worker_audit_jsonl_row import FIELDS, HIA as WJL1, ROOT, frame
from hia.tests.test_worker_audit_select import BACKENDS, FILL, INSUFFICIENT, INVALID, original_inputs
from hia.tests.test_worker_audit_task_query import MAX_TASK, OUT_MAX, SCRATCH, query_original
from hia.tests.test_worker_audit_task_query_pretty import NATIVE as WTQ2
from hia.tests.test_worker_journal_audit_dto import raw
from hia.tests.test_worker_journal_audit_dto_reputation_v3 import row
from hia.tests.test_worker_journal_audit_export import snapshot
from hia.tests.test_worker_journal_line_frame import cli_artifacts
from hia.tools import toolchain
from hia.tools.toolchain import checked_source

NATIVE = ROOT / "hia/src/worker_agent/audit_export_row_decode.hepta"
RAW_MAX = 65536
CONTROL_REQUEST = 'syntax\x00\b\t\n\f\r\x1f é𝄞/"\\'


def sha(data):
    return sha256(data).hexdigest()


def transfer(wix, wat, task):
    """Byte bridge only: reuse WAT's little-endian count and its full row extent."""
    if len(wat) < 8 or wat[:4] != b"WAT1" or len(wix) < 40 or wix[:4] != b"WIX1":
        raise ValueError("Unexpected native batch/sidecar envelope")
    if len(wix) + 16 + len(wat) - 8 + 4 > RAW_MAX:
        raise ValueError("Existing WTQ2 combined input cap")
    return wix + b"WTQ2" + struct.pack("<Q", task) + wat[4:] + struct.pack("<I", len(wix))


def export_row(task=0, status="rejected", **values):
    record = dict.fromkeys(FIELDS)
    record.update(request_id="", task_id=task, status=status)
    record.update(values)
    return record


def compact(record):
    # Construct structural test inputs only. The actual qualifier never uses this encoder.
    return json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


def fixture_cases():
    controlled = row(-3, "rejected", request=CONTROL_REQUEST)
    controlled["task_id"] = 2
    return {**base_cases(), "original-control-escapes": (snapshot(raw(controlled)), (2, 0))}


def checked_graph():
    p, wire_bytes, _, _, sources = checked_source(NATIVE)
    fs = {f["name"]: f for f in p.as_dict()["functions"]}
    expected = {"wj_key": WJL1, "wid_key": WID1, "wid_equal": WID1, "wid_copy": WID1}
    for name, source in expected.items():
        old = {f["name"]: f for f in checked_source(source)[0].as_dict()["functions"]}
        if fs.get(name) != old.get(name) or name not in old:
            raise AssertionError(f"Shared {name} helper differs")
    def block(fn, name):
        return next(b for b in fs[fn]["blocks"] if b["id"] == name)
    def use_const(fn, name, variable):
        return next(op["attrs"]["value"] for op in block(fn,name)["ops"]
                    if op["op"]=="const" and [v["name"] for v in op["out"]] == [variable])
    if (use_const("wer_row","literal","literal_window") != RAW_MAX
        or use_const("wer_batch","bounds","bounds_stage_cap") != RAW_MAX
        or use_const("wer_batch","bounds","bounds_head_len") != 112
        or use_const("f0","scratch","scratch_wanted") != SCRATCH
        or use_const("wer_batch","bounds","bounds_row_cap") != 64
        or block("f0","fit")["term"]["then"]["target"] != "publish"):
        raise AssertionError("Changed whole-batch publication or stage/token separation")
    fixed = sum(len(k) + 3 for k in FIELDS) + len(FIELDS)-1 + 3
    if fixed != 354 or not fixed > 8+112:
        raise AssertionError("Changed raw-versus-typed fixed framing bound")
    return fs, wire_bytes, sources


class WorkerAuditExportRowDecode(unittest.TestCase):
    def test_native_exact_frames_generated_subset_and_refusals(self):
        fs, _, _ = checked_graph()
        self.assertEqual((len(fs), sum(len(b["ops"]) for f in fs.values() for b in f["blocks"])), (27, 1131))
        control = export_row(MAX_TASK, "failed_adapter", request_id=CONTROL_REQUEST,
                             provider='Panel "local"\\display', model="Research only",
                             reputation_label="strong", reputation_delta=-2147483648,
                             reputation_tier=255, reputation_weight_bps=65535,
                             reputation_score_bps=2147483647, reputation_rank_ordinal=0,
                             reputation_gap_bps_from_best=-2147483648)
        plain = export_row()
        original = compact(control) + compact(plain)
        expected = wire([frame(tuple(r[k] for k in FIELDS)) for r in (control, plain)])
        padded = export_row(request_id="z"*(RAW_MAX-len(compact(plain))))
        maximum = compact(padded)
        maximum_wire = wire([frame(tuple(padded[k] for k in FIELDS))])
        self.assertEqual(len(maximum), RAW_MAX)
        self.assertLess(len(maximum_wire), RAW_MAX)
        fake_index = b"WIX1" + b"\0"*36
        exact_query_padding = b"WAT1" + b"\0"*(RAW_MAX-len(fake_index)-16)
        self.assertEqual(len(transfer(fake_index, exact_query_padding, 0)), RAW_MAX)
        with self.assertRaisesRegex(ValueError,"combined input cap"):
            transfer(fake_index, exact_query_padding+b"\0", 0)
        wrong = (
            b"[]\n", b"null\n", b"true\n", b"{}\n", b"\n", original[:-1],
            original.replace(b"}\n", b"}\r\n", 1), original+b"\n", b" "+original,
            original.replace(b'"task_id":', b'"task_id": ', 1),
            original.replace(b'"task_id":', b'"taskId":', 1),
            original.replace(b'"task_id":0', b'"task_id":00'),
            original.replace(str(MAX_TASK).encode(), str(MAX_TASK+1).encode()),
            original.replace(b"\\u001f", b"\\u001F"), original.replace(b"\\b", b"\\u0008"),
            original.replace("é".encode(), b"\\u00e9"), original.replace(b'/\\', b'\\/\\', 1),
            original.replace("𝄞".encode(), b"\\ud834\\udd1e"),
            original.replace("é".encode(), b"\xc0\xa9", 1),
            compact({**plain, "status":"waiting"}),
            compact({**plain, "provider":""}), compact({**plain, "model":"x"*129}),
            compact({**plain, "provider":" wrapped"}), compact({**plain, "model":"é"}),
            *(compact({**plain, k:"not-supported"}) for k in ("adapter","provider_request_id",
              "provenance_fingerprint","provenance_schema_version","agent_protocol","compliance_profile")),
            compact({**control, "reputation_delta":2147483648}),
            compact({**control, "reputation_weight_bps":65536}),
            compact({**control, "reputation_rank_ordinal":256}),
            compact({**control, "reputation_label":None}),
            compact({**control, "reputation_tier":None}),
            compact(control).replace(b'"reputation_delta":-2147483648', b'"reputation_delta":-0'),
            compact(plain)*65, maximum+b"x",
            compact(plain)+compact({**control, "reputation_gap_bps_from_best":None}),
        )
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(NATIVE, backend=backend, byte_exports=("f0",)) as mod:
                got_n, got = observe(mod, original, len(expected)+17, SCRATCH+15)
                self.assertEqual((got_n, got), (len(expected), expected+FILL*17))
                self.assertEqual(observe(mod, original, got_n, scratch_fill=b"\x99"), (got_n, expected))
                self.assertEqual(observe(mod, original, got_n-1), (INSUFFICIENT, FILL*(got_n-1)))
                self.assertEqual(observe(mod, original, got_n, SCRATCH-1), (INSUFFICIENT, FILL*got_n))
                self.assertEqual(observe(mod, b"", 8), (8, b"WAT1\0\0\0\0"))
                self.assertEqual(observe(mod, maximum, len(maximum_wire)), (len(maximum_wire), maximum_wire))
                n, data = observe(mod, compact(plain)*64, 10000)
                self.assertGreater(n, 8)
                self.assertEqual(data[:8], b"WAT1\x40\0\0\0")
                for probe in wrong:
                    self.assertEqual(observe(mod, probe, 4096), (INVALID, FILL*4096), repr(probe[:64]))



def require_headroom(path):
    disk = os.statvfs(path)
    if disk.f_bavail * disk.f_frsize < 152 * 1024 * 1024:
        raise RuntimeError("Qualification stopped before the 150 MiB disk floor")


def exact_anchor(official, paths, output):
    """Recompile the exact old source from Git without mutating the checkout."""
    require_headroom(output)
    if re.fullmatch(r"[0-9a-f]{40}", official) is None:
        raise ValueError("Exact approved baseline commit SHA required")

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, timeout=15,
                                       env={**os.environ, "GIT_NO_LAZY_FETCH":"1"})

    if git("rev-parse", f"{official}^{{commit}}").decode().strip() != official:
        raise AssertionError("Exact baseline commit is not present locally")
    manifest = git("cat-file", "blob", f"{official}:hia/components.json")
    pin = git("cat-file", "blob", f"{official}:hia/toolchain.lock.json")
    data = json.loads(manifest)
    current = json.loads((ROOT/"hia/components.json").read_bytes())
    assert current["includes"].pop("src/worker_agent/audit_export_row_decode.hepta")
    if current != data or pin != (ROOT/"hia/toolchain.lock.json").read_bytes():
        raise AssertionError("The candidate changed another include or the compiler pin")
    registered = set(data["includes"])
    registered.update(d["source"] for entries in data["includes"].values() for d in entries)
    file_roles = {name:path.relative_to(ROOT/"hia").as_posix() for name,path in paths.items()}
    registered.update(file_roles.values())
    raw_tree = git("ls-tree", "-r", "-z", official, "--", "hia")
    tree = {}
    for entry in raw_tree.decode().split("\0"):
        if not entry:
            continue
        meta, name = entry.split("\t")
        mode, kind, identity = meta.split()
        tree[name] = mode, kind, identity
    before = {}
    pins = {"compiler_lock_sha256":sha(pin), "registry_sha256":sha(manifest)}
    # Hard links avoid duplicating large source bytes. Every linked regular
    # file is first checked against the committed Git blob object ID.
    with tempfile.TemporaryDirectory(prefix="exact-anchor-", dir=output) as tmp:
        mirror = Path(tmp)/"hia"
        mirror.mkdir()
        for relative in sorted(registered):
            path = ROOT/"hia"/relative
            mode, kind, identity = tree["hia/"+relative]
            if (mode,kind)!=("100644","blob") or not stat.S_ISREG(path.lstat().st_mode):
                raise AssertionError("Unexpected old source kind: "+relative)
            raw = path.read_bytes()
            blob = sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
            if blob != identity or path.resolve(strict=True)!=path:
                raise AssertionError("Candidate changed an exact old source: "+relative)
            destination=mirror/relative
            destination.parent.mkdir(parents=True,exist_ok=True)
            os.link(path,destination)
        (mirror/"components.json").write_bytes(manifest)
        (mirror/"toolchain.lock.json").write_bytes(pin)
        previous=(toolchain.HIA_ROOT,toolchain.LOCK)
        try:
            toolchain.HIA_ROOT,toolchain.LOCK=mirror,mirror/"toolchain.lock.json"
            for backend in BACKENDS:
                before[backend]={}
                for role,relative in file_roles.items():
                    require_headroom(output)
                    with NativeModule(mirror/relative,backend=backend,byte_exports=("f0",)) as mod:
                        before[backend][role]={
                            "artifact_sha256":mod.artifact_sha256,
                            "core_sha256":mod.receipt["core_sha256"] if "core_sha256" in mod.receipt
                                           else mod.receipt["chain_migration"]["core_sha256"],
                            "compiler_wire_sha256":mod.receipt.get("compiler_wire_sha256"),
                        }
        finally:
            toolchain.HIA_ROOT,toolchain.LOCK=previous
    return {"exact_commit":official,**pins,"builds":before}


def qualify(binary, original, prior_index, prior_query, prior_batch, prior_row, official, output):
    def bound():
        return (original["repository_inputs"] == original_inputs()
                and original["executable_sha256"] == sha(binary.read_bytes()))

    if not bound():
        raise AssertionError("Original Worker's locked source and executable differ")
    fs, wire_bytes, sources = checked_graph()
    runs, published, current_builds, history = {}, {}, {}, {}
    paths = {"row":WJL1, "batch":WAT1, "sidecar":WID1, "query":WTQ2}
    anchor = exact_anchor(official, paths, output)
    with ExitStack() as stack:
        paths = {**paths, "decode":NATIVE}
        modules = {}
        for backend in BACKENDS:
            require_headroom(output)
            ready = {name: stack.enter_context(NativeModule(source, backend=backend, byte_exports=("f0",)))
                     for name, source in paths.items()}
            prior = {
                "row": prior_row["native"][backend]["artifact_sha256"],
                "batch": prior_batch["native_builds"][backend]["artifact_sha256"],
                "sidecar": prior_index["native_builds"][backend]["artifact_sha256"],
                "query": prior_query["native_builds"][backend]["artifact_sha256"],
            }
            observed = {}
            history[backend] = {}
            for name in prior:
                build = ready[name].receipt
                identity = {"artifact_sha256":ready[name].artifact_sha256,
                            "core_sha256":build.get("core_sha256",build["chain_migration"]["core_sha256"]),
                            "compiler_wire_sha256":build.get("compiler_wire_sha256")}
                if identity != anchor["builds"][backend][name]:
                    raise AssertionError(f"Exact anchor machine/core identity changed: {backend}/{name}")
                observed[name] = identity["artifact_sha256"]
                if name in ("sidecar","query") and observed[name] != prior[name]:
                    raise AssertionError(f"Recent published {name} bytes changed")
                if observed[name] != prior[name]:
                    comparison = {"older_artifact_sha256":prior[name],**identity}
                    if name == "batch":
                        older = prior_batch["native_builds"][backend]["receipt"]
                        actual_inputs={a["path"]:a["sha256"] for a in build["chain_migration"]["inputs"]}
                        before_inputs={a["path"]:a["sha256"] for a in older["chain_migration"]["inputs"]}
                        comparison["older_compiler_wire_sha256"] = older.get("compiler_wire_sha256")
                        comparison["comparison_capture_diffs"] = sorted(path for path in
                            actual_inputs.keys()|before_inputs.keys() if actual_inputs.get(path)!=before_inputs.get(path))
                    history[backend][name] = comparison
            published[backend] = observed
            current_builds[backend] = ready["decode"].receipt
            raw_elf = ready["decode"].library.read_bytes()
            if sha(raw_elf) != ready["decode"].artifact_sha256:
                raise AssertionError("New checked native artifact changed")
            (output / (backend+".so")).write_bytes(raw_elf)
            modules[backend] = ready
        for name,(journal,tasks) in fixture_cases().items():
            require_headroom(output)
            case = fresh_directory(output / name)
            ingress = case / "original-ingress.jsonl"
            ingress.write_bytes(journal)
            ingress.chmod(0o600)
            original_jsonl, original_md, original_index = cli_artifacts(binary, ingress, "original", True, None)
            raw_sidecar = (case / "original.jsonl.index.json").read_bytes()
            if raw_sidecar != original_index:
                raise AssertionError("Independent original sidecars differ")
            if name == "original-control-escapes" and not all(token in original_jsonl for token in
                    (b"\\b", b"\\t", b"\\n", b"\\f", b"\\r", b"\\u0000", b"\\u001f", "𝄞".encode())):
                raise AssertionError("Actual original did not exercise all canonical scalar spellings")
            typed = {}
            for backend, stages in modules.items():
                n, wat = observe(stages["decode"], original_jsonl, RAW_MAX+7, SCRATCH+11)
                ix_n, wix = observe(stages["sidecar"], raw_sidecar, STAGE_MAX+1, SCRATCH+11)
                if (n>RAW_MAX or ix_n>STAGE_MAX or wat[n:] != FILL*(RAW_MAX+7-n)
                        or wix[ix_n:] != FILL*(STAGE_MAX+1-ix_n)):
                    raise AssertionError("Native row or sidecar result escaped its exact prefix")
                typed[backend] = (wix[:ix_n], wat[:n])
                (case / (backend+".wat1")).write_bytes(wat[:n])
                (case / (backend+".wix1")).write_bytes(wix[:ix_n])
                # The host never decodes a raw row or map and never assembles its own typed values.
                complete = (original_jsonl, original_md, original_index)
                cap = 16 + sum(map(len, complete)) + 3
                size, trio = observe(stages["batch"], wat[:n], cap, SCRATCH+5)
                if size != cap-3 or artifacts(trio[:size]) != complete or trio[size:] != FILL*3:
                    raise AssertionError("Old WAT1 fails exact original three-file reconstruction from native WER1")
            if len(set(typed.values())) != 1:
                raise AssertionError("Both native row and sidecar results did not agree")
            decisions = {}
            for task in tasks:
                oracle, stdout_sha = query_original(binary, case / "original.jsonl", task, case)
                stdout = (case / f"query-{task}.stdout.raw").read_bytes()
                receipts = {}
                for backend, kernel in modules.items():
                    native_input = transfer(*typed[backend], task)
                    (case / f"{task}.{backend}.wtq2").write_bytes(native_input)
                    n, found = observe(kernel["query"], native_input, len(stdout)+7, SCRATCH+5)
                    if n!=len(stdout) or found[:n]!=stdout or found[n:]!=FILL*7:
                        raise AssertionError("Bytes-only typed handoff differs from original query")
                    (case / f"{task}.{backend}.stdout.raw").write_bytes(found[:n])
                    receipts[backend] = sha(found[:n])
                decisions[str(task)] = {"hits":oracle["hit_indexes"], "original_sha256":stdout_sha,
                                        "bytes":len(stdout), "native_sha256":receipts}
            sample = next(iter(typed.values()))
            if name == "maximum-ordered" and decisions[str(MAX_TASK)]["hits"] != list(range(64)):
                raise AssertionError("Actual original did not reach row 63")
            runs[name] = {"raw_jsonl_bytes":len(original_jsonl), "raw_index_bytes":len(raw_sidecar),
                          "typed_wat1_bytes":len(sample[1]),
                          "typed_rows":int.from_bytes(sample[1][4:8],"little"), "queries":decisions}
    if not bound() or any(p.read_bytes()!=data for p,data in sources):
        raise AssertionError("Original or checked native input changed during qualification")
    result = {"schema":"trnm.hia.worker-audit-export-row-native-decode.v1", "status":"PASS",
              "cases":runs, "existing_artifacts":published, "native_builds":current_builds,
      "exact_predecessor_artifacts":anchor, "historical_differences":history,
              "original_source_inputs":original_inputs(), "original_executable_sha256":original["executable_sha256"],
              "checked_core_sha256":sha(wire_bytes), "functions":len(fs),
              "operations":sum(len(b["ops"]) for f in fs.values() for b in f["blocks"]),
              "host_parses_rows_or_sidecar":False, "host_handoff_envelope_only":True,
              "existing_wat1_all_three_exact":True, "generic_serde":False, "path_or_production":False}
    (output/"report.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("output","original-binary","original-build-receipt","prior-wid1-report",
                 "prior-wtq2-report","prior-wat1-report","prior-wjl1-log"):
        p.add_argument("--"+name, required=True, type=Path)
    p.add_argument("--anchor-commit", required=True)
    a=p.parse_args()
    def load(path):
        return json.loads(path.read_bytes())
    prior_row = [json.loads(line) for line in a.prior_wjl1_log.read_text().splitlines() if line.startswith('{"actual_locked_packages"')]
    if len(prior_row)!=1:
        raise AssertionError("Ambiguous retained old WJL1 receipt")
    r=qualify(a.original_binary.resolve(strict=True), load(a.original_build_receipt),load(a.prior_wid1_report),
              load(a.prior_wtq2_report),load(a.prior_wat1_report),prior_row[0],a.anchor_commit,fresh_directory(a.output))
    print(json.dumps({"status":r["status"],"cases":r["cases"]},sort_keys=True))


if __name__=="__main__":
    main()
