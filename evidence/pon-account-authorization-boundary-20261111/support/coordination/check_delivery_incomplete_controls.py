#!/usr/bin/env python3
"""Exercise only evidence-reader controls in new, private fixture copies.

No collected command, project checker, Cargo process or stage operation runs.
Original archives, records, repository source and delivery plan are read-only.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tarfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HELPER = HERE / "prepare_delivery_evidence.py"
spec = importlib.util.spec_from_file_location("delivery_evidence_under_review", HELPER)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_bytes((json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    original_plan = json.loads(args.plan.read_text())
    original = next(x for x in original_plan["inputs"] if x["id"] == module.EMPTY_RESULT_INPUT)
    original_root = Path(original["path"])
    if not args.output_dir.is_absolute() or args.output_dir.exists():
        raise ValueError("controls require a fresh absolute fixture directory")
    for entry in original_plan["inputs"]:
        root = Path(entry["path"])
        if module.within(args.output_dir, root) or module.within(root, args.output_dir):
            raise ValueError("fixture output overlaps an original input")
    module.outside_sources(args.output_dir, [Path(x) for x in original_plan["protected_source_roots"]])
    args.output_dir.mkdir(parents=True, exist_ok=False)
    frozen = {p: digest(p) for p in [args.plan, HELPER, Path(original["archive"]["path"]),
                                    *sorted(p for p in original_root.rglob("*") if p.is_file())]}
    source = original["source_commit"]
    relative_record = Path("primary/validation") / source / "node-retained-all-targets"
    relative_preflight = Path("primary/validation") / source / "node-retained-preflight"
    outcomes = []

    def make_case(name, alter_files=None, alter_manifest=None, alter_plan=None):
        work = args.output_dir / name
        work.mkdir()
        bundle = work / "bundle"
        shutil.copytree(original_root, bundle)
        for file in bundle.rglob("*"):
            if file.is_file():
                file.chmod(0o600)
        manifest_path = bundle / original["manifest"]
        manifest = json.loads(manifest_path.read_text())
        if alter_files:
            alter_files(bundle)
        old_entries = {x["archive_member"]: x for x in manifest["entries"]}
        manifest["entries"] = []
        for file in sorted(p for p in bundle.rglob("*") if p.is_file() and p != manifest_path):
            name_in_archive = file.relative_to(bundle).as_posix()
            row = copy.deepcopy(old_entries.get(name_in_archive, {
                "archive_member": name_in_archive,
                "remote_source": "CONTROL_FIXTURE_ONLY/" + name_in_archive,
            }))
            row.update(bytes=file.stat().st_size, sha256=digest(file))
            manifest["entries"].append(row)
        if alter_manifest:
            alter_manifest(manifest)
        write_json(manifest_path, manifest)
        archive = work / "fixture.tar.gz"
        with tarfile.open(archive, "w:gz") as stream:
            for file in sorted(p for p in bundle.rglob("*") if p.is_file()):
                stream.add(file, arcname=file.relative_to(bundle).as_posix(), recursive=False)
        plan = copy.deepcopy(original_plan)
        selected = copy.deepcopy(original)
        selected.update(path=str(bundle), destination=f"hosts/desktop/sources/{source}/packages/control")
        selected.pop("transfer_report", None)
        selected["archive"] = {"path": str(archive),
                               "destination": f"hosts/desktop/sources/{source}/imports/control.tar.gz",
                               "sha256": digest(archive)}
        plan["inputs"] = [selected]
        plan["support_files"] = []
        inventory = work / "inventory.json"
        write_json(inventory, {"records": []})
        plan["validation_inventory"] = {"path": str(inventory), "destination": "support/control-inventory.json"}
        plan["required_records"] = [{"host": "desktop", "source_commit": source,
                                     "id": "node-retained-preflight"}]
        if alter_plan:
            alter_plan(plan)
        plan_path = work / "plan.json"
        write_json(plan_path, plan)
        return work, plan_path

    def run_case(name, expected_codes=(), accept=False, **changes):
        work, plan_path = make_case(name, **changes)
        index = None
        error = None
        try:
            collection = module.Collection(plan_path, None)
            index = collection.collect()
            collection.check_unchanged()
            codes = {x["code"] for x in collection.blocks}
            rejected = bool(codes)
            write_json(work / "inspection.json", index)
        except module.EvidenceError as caught:
            error = str(caught)
            codes = {"EvidenceError"}
            rejected = True
        if accept:
            assert not rejected, (name, codes, error)
            assert index["terminal_record_count"] == 1
            assert index["terminal_pass_record_count"] == 1
            assert index["terminal_fail_record_count"] == 0
            assert index["approved_archival_incomplete_record_count"] == 1
            record = next(x for x in index["records"] if x["id"] == "node-retained-all-targets")
            assert record["classification"] == "INCOMPLETE_EMPTY_RESULT" and not record["completed_result"]
            assert all(record[x] is None for x in ("recorded_pass", "returncode", "finished_utc", "source_identity_intact"))
            staged = record["staged_receipt_paths"]["result.json"]
            assert len(staged) == 1 and staged[0].endswith("/result.json.empty")
            assert "result.json.empty" in record["all_file_hashes"] and "result.json" not in record["all_file_hashes"]
            assert "result.json" in record["original_file_hashes"]
            assert record["receipt_hashes"]["result.json"] == module.EMPTY_SHA256
            assert not any(x["path"].endswith("/node-retained-all-targets/result.json") for x in index["payload_files"])
            assert (work / "bundle" / relative_record / "result.json").read_bytes() == b""
            assert not (work / "bundle" / relative_record / "result.json.empty").exists()
            assert all(value is False for value in index["interpretation"].values())
        else:
            assert rejected and any(code in codes for code in expected_codes), (name, codes, error)
        outcomes.append({"case": name, "expected": "ACCEPT_AS_NONTERMINAL_ARCHIVE_ONLY" if accept else "REFUSE",
                         "observed": "REFUSED" if rejected else "ARCHIVAL_EXCEPTION_VERIFIED",
                         "block_codes": sorted(codes), "exception": error,
                         "control_satisfied": True, "project_test_execution": False,
                         "fixture_plan_sha256": digest(plan_path)})

    run_case("exact-original-positive", accept=True)
    run_case("wrong-stderr-hash", ["INCOMPLETE_ARCHIVE_RECEIPT_MISMATCH"],
             alter_plan=lambda p: p["incomplete_record_archive_exceptions"][0]["receipts"]["stderr.log"].update(sha256="0" * 64))
    run_case("missing-whitelist", ["UNAPPROVED_EMPTY_RESULT"],
             alter_plan=lambda p: p.update(incomplete_record_archive_exceptions=[]))
    for field, wrong in [("host", "different-host"), ("source_commit", "1" * 40),
                         ("id", "different-record"), ("input_id", "different-input"),
                         ("origin_job_id", "different-job")]:
        run_case("wrong-" + field.replace("_", "-"), ["EvidenceError"],
                 alter_plan=lambda p, k=field, v=wrong: p["incomplete_record_archive_exceptions"][0].update({k: v}))
    run_case("nonempty-malformed-result", ["INPUT_ERROR"],
             alter_files=lambda b: (b / relative_record / "result.json").write_bytes(b"{broken"))
    run_case("missing-original-result", ["INCOMPLETE_RECORD"],
             alter_files=lambda b: (b / relative_record / "result.json").unlink())
    run_case("ordinary-missing-result", ["INCOMPLETE_RECORD"],
             alter_files=lambda b: (b / relative_preflight / "result.json").unlink())
    run_case("ordinary-malformed-result", ["INPUT_ERROR"],
             alter_files=lambda b: (b / relative_preflight / "result.json").write_bytes(b"{broken"))
    run_case("projection-destination-collision", ["INCOMPLETE_RECEIPT_PROJECTION_COLLISION"],
             alter_files=lambda b: (b / relative_record / "result.json.empty").write_bytes(b""))
    run_case("manifest-claims-complete", ["INPUT_ERROR"],
             alter_manifest=lambda m: m["complete_command_ids"].append("node-retained-all-targets"))
    run_case("manifest-claims-terminal-result", ["INPUT_ERROR"],
             alter_manifest=lambda m: m.update(record_results={"node-retained-all-targets": {"pass": True, "returncode": 0}}))
    run_case("global-terminal-policy-disabled", ["EvidenceError"],
             alter_plan=lambda p: p.update(require_terminal_records=False))
    run_case("duplicate-whitelist-entry", ["EvidenceError"],
             alter_plan=lambda p: p["incomplete_record_archive_exceptions"].append(copy.deepcopy(p["incomplete_record_archive_exceptions"][0])))

    def duplicate_consumer(plan):
        second = copy.deepcopy(plan["inputs"][0])
        second["destination"] += "-duplicate"
        plan["inputs"].append(second)

    run_case("duplicate-exception-consumption", ["DUPLICATE_INCOMPLETE_ARCHIVE_EXCEPTION"], alter_plan=duplicate_consumer)
    run_case("required-incomplete-record-removed", ["REQUIRED_INCOMPLETE_ARCHIVE_NOT_OBSERVED"],
             alter_files=lambda b: shutil.rmtree(b / relative_record))

    # Preserve the pre-existing reader contract: duplicate exact terminal copies
    # are inventoried in both paths and counted as only one terminal record.
    work, plan_path = make_case("exact-terminal-copies-regression")
    plan = json.loads(plan_path.read_text())
    plan["inputs"] = []
    plan["incomplete_record_archive_exceptions"] = []
    for suffix in ("a", "b"):
        copy_root = work / ("terminal-copy-" + suffix)
        shutil.copytree(original_root / relative_preflight, copy_root / "node-retained-preflight")
        plan["inputs"].append({"id": "terminal-copy-" + suffix, "kind": "record-tree", "host": "desktop",
                               "source_commit": source, "path": str(copy_root), "record_roots": ["."],
                               "destination": f"hosts/desktop/sources/{source}/terminal-copy-{suffix}"})
    write_json(plan_path, plan)
    collection = module.Collection(plan_path, None)
    index = collection.collect()
    collection.check_unchanged()
    assert not collection.blocks, collection.blocks
    assert index["terminal_record_count"] == index["terminal_pass_record_count"] == 1
    assert len(index["records"][0]["paths"]) == 2
    assert all(len(paths) == 2 for paths in index["records"][0]["staged_receipt_paths"].values())
    write_json(work / "inspection.json", index)
    outcomes.append({"case": "exact-terminal-copies-regression", "control_satisfied": True,
                     "observed": "TWO_RAW_COPIES_ONE_TERMINAL_RECORD", "project_test_execution": False})

    assert all(digest(path) == before for path, before in frozen.items()), "an original input changed"
    report = {"schema": "trnm-incomplete-archive-helper-controls-v1",
              "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "helper_sha256": digest(HELPER), "delivery_plan_sha256": digest(args.plan),
              "control_script_sha256": digest(Path(__file__)), "controls": outcomes,
              "controls_satisfied": len(outcomes), "original_inputs_unchanged": True,
              "fixture_data_only": True, "project_tests_executed": False, "cargo_executed": False,
              "stage_executed": False, "collected_commands_executed": False,
              "full_ci_acceptance_granted": False, "production_qualification_granted": False}
    write_json(args.output_dir / "report.json", report)
    print(json.dumps({"controls_satisfied": len(outcomes), "report": str(args.output_dir / "report.json"),
                      "report_sha256": digest(args.output_dir / "report.json"),
                      "helper_sha256": report["helper_sha256"], "original_inputs_unchanged": True,
                      "project_tests_executed": False, "stage_executed": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
