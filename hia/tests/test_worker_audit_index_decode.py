"""Consume genuine canonical Worker sidecar bytes without host-built map facts."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import unittest

from hia.platform.worker_audit.build import fresh_directory
from hia.tests.native_support import NativeModule
from hia.tests.test_worker_audit_export_transaction import observe
from hia.tests.test_worker_audit_index_wire import MAPS, NATIVE as WIX1, request
from hia.tests.test_worker_audit_jsonl_row import FIELDS, ROOT, frame
from hia.tests.test_worker_audit_select import BACKENDS, FILL, INSUFFICIENT, INVALID, observed_call, original_inputs
from hia.tests.test_worker_audit_task_query import NATIVE as WTQ1, MAX_TASK, journal_cases, query_original
from hia.tests.test_worker_audit_task_query_pretty import NATIVE as WTQ2, pretty_frame
from hia.tests.test_worker_journal_audit_dto import raw
from hia.tests.test_worker_journal_audit_dto_reputation_v3 import row
from hia.tests.test_worker_journal_audit_export import snapshot
from hia.tests.test_worker_journal_line_frame import cli_artifacts
from hia.tools.toolchain import checked_source

NATIVE = ROOT / "hia/src/worker_agent/audit_index_decode.hepta"
RAW_MAX, STAGE_MAX, SCRATCH = 65536, 29736, 102400
DISPLAY_PROVIDER, DISPLAY_MODEL = 'Synthetic "panel"\\display', 'Model / "lab"\\only'


def synthetic_index(count, *maps):
    """Unit-test syntax cases only, not used in the locked CLI byte oracle."""
    payload = {"version": 1, "total_records": count}
    payload.update((k, dict(m)) for k, m in zip(MAPS, maps, strict=True))
    return json.dumps(payload, indent=2, ensure_ascii=False).encode()


def checked_graph():
    new, wire, _, _, sources = checked_source(NATIVE)
    old = checked_source(WIX1)[0]
    fs = {f["name"]: f for f in new.as_dict()["functions"]}
    prior = {f["name"]: f for f in old.as_dict()["functions"]}
    if any(fs.get(k) != v for k, v in prior.items() if k != "f0"):
        raise AssertionError("Native input uses a changed WIX1 validator/renderer")
    def block(function, name):
        return next(b for b in fs[function]["blocks"] if b["id"] == name)
    def consts(function, name):
        return {v["name"]: op["attrs"].get("value")
                for op in block(function, name)["ops"] if op["op"] == "const" for v in op["out"]}
    validate = block("f0", "validate")
    call = next(x for x in validate["ops"] if x["op"] == "call")
    if (call["attrs"] != {"function": "wx_index"} or call["args"][-1] != "validate_dry"
        or consts("f0","validate").get("validate_dry") is not False
        or validate["term"]["then"]["target"] != "fit"
        or validate["term"]["else"]["target"] != "malformed"):
        raise AssertionError("Shared all-map validation must be dry and precede output")
    if (consts("wid_stage", "header").get("header_token_base") != 32768
        or any(consts(f, b)[b+"_stage_cap"] != STAGE_MAX for f,b in
               (("wid_map", "entry"), ("wid_map", "entry_key"), ("wid_offsets", "read")))):
        raise AssertionError("Fixed token window and WIX1 staging lost disjoint bounds")
    assert consts("f0", "work")["work_scratch_min"] == SCRATCH
    return fs, wire, sources


class WorkerAuditIndexDecode(unittest.TestCase):
    def test_canonical_profile_outputs_and_full_refusals(self):
        funcs, _, _ = checked_graph()
        self.assertEqual((len(funcs), sum(len(b["ops"]) for f in funcs.values() for b in f["blocks"])), (31, 1010))
        maps = [
            [("0", [0]), ("10", [2]), ("2", [1])],
            [("failed_adapter", [2]), ("rejected", [0, 1])],
            [("active", [2]), ("terminal", [0, 1])],
            [(DISPLAY_PROVIDER, [0, 2])],
            [(DISPLAY_MODEL, [1])], [], [], [],
        ]
        canonical = synthetic_index(3, *maps)
        intended = request(3, maps)
        empty = synthetic_index(0, *([[]] * 8))
        full_maps = [
            [(str(MAX_TASK), list(range(64)))],
            [("failed_submission", list(range(64)))],
            [("active", list(range(64)))],
            [(f"{i:02d}"+'\\' * 62, [i]) for i in range(64)],
            [(f"{i:02d}"+'"' * 126, [i]) for i in range(64)], [], [], [],
        ]
        full = synthetic_index(64, *full_maps)
        full_wix = request(64, full_maps)
        self.assertLess(len(full), RAW_MAX)
        self.assertLess(len(full_wix), STAGE_MAX)
        bad = (
            b"", b"[]", b"null", b"true", b"{}",
            canonical[:-1], canonical + b"\n", canonical + b"x", b" " + canonical,
            canonical.replace(b'"version": 1', b'"version": 2'),
            canonical.replace(b'"total_records": 3', b'"total_records": 03'),
            canonical.replace(b'"total_records": 3', b'"total_records": 65'),
            canonical.replace(b'"total_records": 3', b'"total_records": 1.0'),
            canonical.replace(b'"by_status": {', b'"by_model": {'),
            canonical.replace(b'    "0": [', b'    "\\u0030": ['),
            canonical.replace(b'    "0": [', b'    "00": ['),
            canonical.replace(b'"failed_adapter"', b'"pending"'),
            canonical.replace(b'"terminal"', b'"complete"'),
            canonical.replace(b'"by_provider": {', b'"by_provider": { '),
            synthetic_index(3, [("0",[0]), ("2",[1]), ("10",[2])], *maps[1:]),
            synthetic_index(3, [("0",[0]), ("2",[1])], *maps[1:]),
            synthetic_index(3, maps[0], [("failed_adapter",[1]), ("rejected",[0, 1])], *maps[2:]),
            synthetic_index(3, *maps[:3], [("a",[3])], *maps[4:]),
            synthetic_index(3, *maps[:3], [("a",[2, 0])], *maps[4:]),
            synthetic_index(3, *maps[:3], [("a",[])], *maps[4:]),
            synthetic_index(3, *maps[:3], [(" a",[0])], *maps[4:]),
            synthetic_index(3, *maps[:3], [("a ",[0])], *maps[4:]),
            synthetic_index(3, *maps[:3], [("é",[0])], *maps[4:]),
            synthetic_index(3, *maps[:3], [("x"*65,[0])], *maps[4:]),
            synthetic_index(3, *maps[:4], [("x"*129,[0])], *maps[5:]),
            *(synthetic_index(3, *maps[:j], [("fixture",[0])], *maps[j+1:]) for j in range(5,8)),
            canonical + b" "*(RAW_MAX-len(canonical)),
            canonical + b" "*(RAW_MAX+1-len(canonical)),
        )
        for backend in BACKENDS:
            with self.subTest(backend=backend), NativeModule(NATIVE, backend=backend, byte_exports=("f0",)) as mod:
                n, data = observe(mod, canonical, len(intended)+17, SCRATCH+13)
                self.assertEqual((n, data), (len(intended), intended+FILL*17))
                self.assertEqual(observe(mod, canonical, n, scratch_fill=b"\xe3"), (n, intended))
                self.assertEqual(observe(mod, canonical, n-1), (INSUFFICIENT, FILL*(n-1)))
                self.assertEqual(observe(mod, canonical, n, SCRATCH-1), (INSUFFICIENT, FILL*n))
                empty_wix = request(0, [[]]*8)
                self.assertEqual(observe(mod, empty, 40), (40, empty_wix))
                self.assertEqual(observe(mod, full, len(full_wix)), (len(full_wix), full_wix))
                for probe in bad:
                    self.assertEqual(observe(mod, probe, 2048), (INVALID, FILL*2048))


def fixture_cases():
    def display_record(ordinal, task, status):
        item = row(-3, status, ordinal=ordinal)
        item["task_id"] = task
        item["llm_provenance"] = {"provider": DISPLAY_PROVIDER, "model": DISPLAY_MODEL}
        # No schema means neither fingerprint nor protocol/profile may enter the DTO.
        item.pop("provenance_schema_version", None)
        item.pop("provider_request_id", None)
        return raw(item)
    display = snapshot(display_record(1, 10, "rejected"),
                       display_record(2, 2, "reveal_submitted"),
                       display_record(3, 10, "failed_adapter"))
    return {**journal_cases(), "escaped-display-no-schema": (display, (10, 2, 0))}


def qualify(binary, original, prior_wire, prior_query, prior_pretty, output):
    def bound():
        return (original["repository_inputs"] == original_inputs()
                and original["executable_sha256"] == sha256(binary.read_bytes()).hexdigest())

    if not bound():
        raise AssertionError("Original Worker's locked source and executable differ")
    funcs, wire, sources = checked_graph()
    case_results, new_artifacts, old_artifacts = {}, {}, {}
    with ExitStack() as stack:
        stages = {}
        for backend in BACKENDS:
            kernels = {role: stack.enter_context(NativeModule(path, backend=backend, byte_exports=("f0",)))
                       for role, path in (("decode", NATIVE), ("reserialize", WIX1), ("query", WTQ2), ("wtq1", WTQ1))}
            if (kernels["reserialize"].artifact_sha256 != prior_wire["backends"][backend]
                or kernels["query"].artifact_sha256 != prior_pretty["native_builds"][backend]["artifact_sha256"]
                or kernels["wtq1"].artifact_sha256 != prior_query["native_builds"][backend]["artifact_sha256"]):
                raise AssertionError("Previously measured WIX1/WTQ1/WTQ2 machine bytes changed")
            old_artifacts[backend] = {k: kernels[k].artifact_sha256 for k in kernels if k != "decode"}
            new_artifacts[backend] = kernels["decode"].receipt
            seen = kernels["decode"].library.read_bytes()
            if sha256(seen).hexdigest() != kernels["decode"].artifact_sha256:
                raise AssertionError("New native parser artifact changed")
            (output / (backend + ".so")).write_bytes(seen)
            stages[backend] = kernels

        for name, (journal, task_ids) in fixture_cases().items():
            case = fresh_directory(output / name)
            ingress = case / "original-ingress.jsonl"
            ingress.write_bytes(journal)
            ingress.chmod(0o600)
            source_rows, _, original_index = cli_artifacts(binary, ingress, "original", True, None)
            real_sidecar = (case / "original.jsonl.index.json").read_bytes()
            if real_sidecar != original_index or real_sidecar.endswith(b"\n"):
                raise AssertionError("Independent original sidecar bytes differ")
            # Only rows are typed here. No metadata or map is decoded by the host.
            converted = []
            for line in source_rows.splitlines():
                record = json.loads(line)
                if tuple(record) != FIELDS or any(record[key] is not None for key in (
                    "provider_request_id", "provenance_schema_version", "provenance_fingerprint",
                    "agent_protocol", "compliance_profile")):
                    raise AssertionError("Fixture exercised unsupported provenance fields")
                converted.append(frame(tuple(record[f] for f in FIELDS)))
            if name == "escaped-display-no-schema" and (b'\\\"panel\\\"\\\\display' not in real_sidecar
                    or b'  "by_provider": {\n' not in real_sidecar or b'  "by_model": {\n' not in real_sidecar):
                raise AssertionError("Actual original escaped display maps did not populate")
            answers = {}
            wix = {}
            for backend, kernels in stages.items():
                n, data = observe(kernels["decode"], real_sidecar, STAGE_MAX+13, SCRATCH+7)
                if n > STAGE_MAX or data[n:] != FILL*(STAGE_MAX+13-n):
                    raise AssertionError(f"Native decoder output extent differs: {name}/{backend} {n}")
                wix[backend] = data[:n]
                (case / (backend + ".wix1")).write_bytes(data[:n])
                before_serialize, rendered = observed_call(kernels["reserialize"], data[:n], len(real_sidecar)+7)
                if before_serialize != len(real_sidecar) or rendered != real_sidecar+FILL*7:
                    raise AssertionError("Old native WIX1 did not reproduce the actual raw sidecar")
            if len(set(wix.values())) != 1:
                raise AssertionError("Both real decoders did not yield the same WIX1 bytes")
            for task in task_ids:
                oracle, sha = query_original(binary, case / "original.jsonl", task, case)
                want = (case / f"query-{task}.stdout.raw").read_bytes()
                result = {}
                for backend, kernels in stages.items():
                    wired = pretty_frame(wix[backend], converted, task)
                    (case / f"{task}.{backend}.wtq2").write_bytes(wired)
                    n, got = observe(kernels["query"], wired, len(want)+11, SCRATCH+7)
                    if n != len(want) or got[:n] != want or got[n:] != FILL*11:
                        raise AssertionError("Native raw sidecar -> unchanged WTQ2 differs from real query stdout")
                    (case / f"{task}.{backend}.stdout.raw").write_bytes(got[:n])
                    result[backend] = sha256(got[:n]).hexdigest()
                answers[str(task)] = {"hits": oracle["hit_indexes"], "original_sha256": sha,
                                      "bytes": len(want), "native_sha256": result}
            if name == "maximum-ordered" and answers[str(MAX_TASK)]["hits"] != list(range(64)):
                raise AssertionError("Actual original did not hit index 63")
            case_results[name] = {"queries": answers, "raw_index_bytes": len(real_sidecar),
                                  "rows": len(converted), "raw_index_sha256": sha256(real_sidecar).hexdigest(),
                                  "wix_bytes": len(next(iter(wix.values()))),
                                  "wix_sha256": sha256(next(iter(wix.values()))).hexdigest()}
    if not bound() or any(p.read_bytes() != b for p,b in sources):
        raise AssertionError("Compiled source closure or original changed during observation")
    report = {
        "schema": "trnm.hia.worker-audit-raw-canonical-index.v1", "status": "PASS",
        "cases": case_results, "native_builds": new_artifacts, "prior_artifacts": old_artifacts,
        "checked_core_sha256": sha256(wire).hexdigest(), "functions": len(funcs),
        "operations": sum(len(b["ops"]) for f in funcs.values() for b in f["blocks"]),
        "original_source_inputs": original_inputs(), "original_executable_sha256": original["executable_sha256"],
        "host_parse_sidecar": False, "host_typed_rows_transport_only": True,
        "generic_serde": False, "fingerprint_protocol_custody_scope": False, "production_dispatch": False,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--original-binary", required=True, type=Path)
    p.add_argument("--original-build-receipt", required=True, type=Path)
    p.add_argument("--prior-wix1-report", required=True, type=Path)
    p.add_argument("--prior-wtq1-report", required=True, type=Path)
    p.add_argument("--prior-wtq2-report", required=True, type=Path)
    a = p.parse_args()
    decode_json = lambda path: json.loads(path.read_bytes())
    report = qualify(a.original_binary.resolve(strict=True), decode_json(a.original_build_receipt),
                     decode_json(a.prior_wix1_report), decode_json(a.prior_wtq1_report),
                     decode_json(a.prior_wtq2_report), fresh_directory(a.output))
    print(json.dumps({"status": report["status"], "cases": report["cases"]}, sort_keys=True))


if __name__ == "__main__":
    main()
