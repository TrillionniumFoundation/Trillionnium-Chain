#!/usr/bin/env python3
"""Read already-downloaded workspace CPU artifacts; never execute native code.

The exact committed repository readers validate named libtest transcripts and
growth JSONL.  Runner ELF hash receipts are retained, not promoted to independent
binary rehashes: these ZIPs contain no ELF bytes.
"""
from __future__ import annotations
import argparse
from collections import Counter
import csv
import datetime
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import tempfile
import types
import zipfile

sys.dont_write_bytecode = True
COHORTS = {
    "c5dd7c": dict(head="c5dd7c7718925b951dc6e4d5ccc5a86ccfa8e3c1", tree="30f59a8ec2abdc269bf91e228c58206b23add43d", merge="7a3e125cb343bd85fb806aba87a21f99eac082de", base="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0", run=41728500384, tracked_entries=7723, tracked_bytes=882506480),
    "b4bdf": dict(head="b4bdf142f513081715ecc8d1f9674291e85302cc", tree="3e141fb9bcec9bf2a49d55647f46f12bd3ca28bb", merge="d9efb0f3bc4dfdbfd8fcb609375dfeb852407bfb", base="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0", run=41732370067, tracked_entries=7757, tracked_bytes=884109821),
}
SOURCE_PATHS = [
    ".github/workflows/pon-original-workspace-large-state-cpu.yml",
    "scripts/ci/check_required_native_test.py",
    "scripts/ci/check_growth_scale_observation.py",
    "scripts/ci/test_growth_scale_observation.py",
    "scripts/ci/verify_ci_source.py",
    "scripts/ci/prepare_pq_provider.sh",
    "trillionnium/Cargo.toml",
    "trillionnium/Cargo.lock",
    "trillionnium/crates/trnm-pon-node/src/store/detached_admission/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/growth/tests/scale_observation.rs",
]
BUILD = ["cargo", "+1.95.0", "test", "--locked", "--manifest-path", "trillionnium/Cargo.toml", "--workspace", "--all-targets", "--all-features", "--no-run", "--message-format=json"]
CPU = [
    "store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner",
    "store::detached_admission::tests::authenticated_large_parent_original_schedule_supplementary_denominator",
    "ingress::public_v2::tests::public_loop_exit_records_lifetime_before_internal_stop",
    "ingress::public_v2::tests::public_loop_exit_records_external_stop_after_signed_read",
]
GROWTH = "store::growth::tests::scale_observation::native_growth_v2_fixed_owner_account_history_scale_observation"
NATIVE_SUMMARY = re.compile(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; ([0-9]+) filtered out; finished in ([0-9]+(?:\.[0-9]+)?)s$", re.M)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()

def entry(name, raw):
    text = raw.decode("utf-8", errors="strict")
    assert text.encode("utf-8") == raw
    return dict(path=name, bytes=len(raw), sha256=sha(raw), text=text)

def write_json(path, data):
    assert not path.exists(), f"refuse overwrite: {path}"
    path.write_bytes(canonical(data))

def write_gzip(path, data):
    assert not path.exists(), f"refuse overwrite: {path}"
    raw = canonical(data)
    path.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    assert gzip.decompress(path.read_bytes()) == raw
    restored = json.loads(gzip.decompress(path.read_bytes()))
    for r in restored["records"]:
        b = r["text"].encode("utf-8")
        assert len(b) == r["bytes"] and sha(b) == r["sha256"]
    return dict(file=path.name, bytes=path.stat().st_size, sha256=sha(path.read_bytes()), records=len(data["records"]), original_record_bytes=sum(r["bytes"] for r in data["records"]))

def tsv(text):
    return list(csv.DictReader(io.StringIO(text), delimiter="\t"))

def unwrap(path, key):
    d = json.loads(path.read_bytes())
    value = d["tool_result"]["value"]
    assert not value.get("isError", False)
    s = value["structuredContent"]
    if key not in s and isinstance(s.get("content"), str):
        s = json.loads(s["content"])
    return s[key]

def resource(text):
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Command being timed:"):
            command = line.split(": ", 1)[1]
            assert command[0] == command[-1] == '"'
            out["argv"] = shlex.split(command[1:-1])
        elif line.startswith("Exit status:"):
            out["exit"] = int(line.rsplit(":", 1)[1])
        elif line.startswith("Elapsed (wall clock)"):
            out["elapsed_wall_clock"] = line.split("): ", 1)[1]
        elif line.startswith("User time (seconds):"):
            out["user_seconds"] = line.rsplit(":", 1)[1].strip()
        elif line.startswith("System time (seconds):"):
            out["system_seconds"] = line.rsplit(":", 1)[1].strip()
        elif line.startswith("Maximum resident set size (kbytes):"):
            out["max_rss_kbytes"] = int(line.rsplit(":", 1)[1])
    assert out["exit"] == 0
    return out

def log_json(text):
    out = []
    for line in text.splitlines():
        if "{" in line:
            try:
                obj = json.loads(line[line.index("{"):])
            except ValueError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cohort", choices=COHORTS, required=True)
    ap.add_argument("--source-dir", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--repo", type=Path, required=True)
    args = ap.parse_args()
    c = COHORTS[args.cohort]
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    assert not (out / "readback.json").exists(), "refuse overwrite of frozen readback"
    before = subprocess.run(["bash", "scripts/project-preflight.sh"], cwd=args.repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    write_json(out / "preflight.json", {"exit_code": before.returncode, "stdout": before.stdout.decode(), "stderr": before.stderr.decode(), "native_executed": False})
    def git(*argv):
        return subprocess.run(["git", *argv], cwd=args.repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    assert git("rev-parse", c["head"] + "^{tree}").decode().strip() == c["tree"]
    # Actual GitHub merge commits need not exist in this local object store.
    # Use the already-retained original Git API receipt, not a fabricated local merge.
    binding_path = args.source_dir / "source-binding.json"
    binding = json.loads(binding_path.read_bytes())
    merge_metadata = binding.get("actual_merge_git_metadata", binding.get("actual_merge_metadata"))
    assert merge_metadata["sha"] == c["merge"] and merge_metadata["tree"]["sha"] == c["tree"]
    assert [p["sha"] for p in merge_metadata["parents"]] == [c["base"], c["head"]]
    binding_records = [entry("original-metadata/source-binding.json", binding_path.read_bytes())]
    refs = binding.get("receipts", [binding.get("candidate_remote_receipt"), binding.get("actual_merge_remote_receipt_from_root")])
    merge_raw_verified = False
    for ref in refs:
        assert ref is not None
        p = Path(ref.get("path", ref.get("file")))
        raw = p.read_bytes()
        assert sha(raw) == ref["sha256"]
        if "bytes" in ref:
            assert len(raw) == ref["bytes"]
        obj = json.loads(raw)
        if obj.get("sha") == c["merge"]:
            assert obj == merge_metadata
            merge_raw_verified = True
        binding_records.append(entry("original-metadata/source-binding-receipt-" + str(len(binding_records)) + "-" + p.name, raw))
    assert merge_raw_verified, "missing original actual-merge Git API receipt"
    source = {p: git("show", c["head"] + ":" + p) for p in SOURCE_PATHS}
    # Execute only exact source-pinned Python data readers, never the Rust tests.
    named = types.ModuleType("evidence_required_native")
    exec(compile(source["scripts/ci/check_required_native_test.py"], "exact-committed-check_required_native_test.py", "exec"), named.__dict__)
    growth = types.ModuleType("evidence_growth_scale")
    exec(compile(source["scripts/ci/check_growth_scale_observation.py"], "exact-committed-check_growth_scale_observation.py", "exec"), growth.__dict__)
    workflow = source[SOURCE_PATHS[0]].decode()
    for selector in CPU + [GROWTH]:
        assert selector in workflow
    assert "timeout-minutes: 180" in workflow and "cancel-in-progress: false" in workflow
    metadata_path = sorted(args.source_dir.glob("*workspace-cpu-artifacts.json"))[-1]
    jobs_path = sorted(args.source_dir.glob("*workspace-cpu-jobs.json"))[-1]
    artifacts = {x["id"]: x for x in unwrap(metadata_path, "artifacts")}
    jobs = unwrap(jobs_path, "jobs")
    assert len(artifacts) == len(jobs) == 4
    assert all(j["run_id"] == c["run"] and j["status"] == "completed" and j["conclusion"] == "success" for j in jobs)
    assert all(s["status"] == "completed" and s["conclusion"] == "success" for j in jobs for s in j["steps"])
    context = binding_records + [entry("original-metadata/" + metadata_path.name, metadata_path.read_bytes()), entry("original-metadata/" + jobs_path.name, jobs_path.read_bytes())]
    context += [entry("source/" + p, raw) for p, raw in source.items()]
    lanes = []
    found = sorted(args.source_dir.glob(args.cohort + "-workspace-cpu-*.zip"))
    assert len(found) == 4, [x.name for x in found]
    for zp in found:
        match = re.fullmatch(re.escape(args.cohort) + r"-workspace-cpu-(x64|arm)-(head|merge)-([0-9]+)\.zip", zp.name)
        assert match
        arch, role, aid = match[1], match[2], int(match[3])
        lane = arch + "-" + role
        meta = artifacts[aid]
        receipt_path = args.source_dir / f"{aid}-download-receipt.json"
        receipt = json.loads(receipt_path.read_bytes())
        context.append(entry("original-metadata/" + receipt_path.name, receipt_path.read_bytes()))
        rawzip = zp.read_bytes()
        digest = sha(rawzip)
        assert meta["digest"] == "sha256:" + digest and meta["size_in_bytes"] == len(rawzip)
        assert receipt["matched"] is True and receipt["actual_sha256"] == digest and receipt["actual_bytes"] == len(rawzip)
        assert receipt["metadata"] == meta and receipt["artifact_id"] == aid
        assert meta["workflow_run"]["id"] == c["run"] and meta["workflow_run"]["head_sha"] == c["head"]
        runner = "ubuntu-24.04-arm" if arch == "arm" else "ubuntu-24.04"
        kind = "prospective-merge" if role == "merge" else "head"
        job = [j for j in jobs if j["name"] == f"original workspace test CPU ({runner}, {kind})"]
        assert len(job) == 1
        with zipfile.ZipFile(io.BytesIO(rawzip)) as z:
            assert z.testzip() is None
            names = z.namelist()
            assert len(names) == len(set(names)) == 316
            assert all(not PurePosixPath(n).is_absolute() and ".." not in PurePosixPath(n).parts for n in names)
            data = {n: z.read(n) for n in names}
        assert not any(raw.startswith(b"\x7fELF") for raw in data.values())
        text = {n: raw.decode("utf-8", errors="strict") for n, raw in data.items()}
        js = lambda n: json.loads(text[n])
        s = js("source-before.json")
        assert data["source-before.json"] == data["source-after.json"]
        expected_source = dict(schema="trnm-ci-source-v1", base=c["base"] if role == "merge" else None, candidate=c["head"], kind=kind, prospective_merge=c["merge"] if role == "merge" else None, tested_commit=c["merge"] if role == "merge" else c["head"], tested_tree=c["tree"], tests_executed_by_identity_check=False, tracked_bytes=c["tracked_bytes"], tracked_entries=c["tracked_entries"], tracked_worktree_verified=True)
        assert s == expected_source
        build = js("build-command.json")
        assert build["argv"] == BUILD and build["process_measurement_wrapper"] == ["/usr/bin/time", "-v"]
        env = build["environment"]
        assert env["CI"] == "true" and env["CARGO_BUILD_JOBS"] == "2" and env["CARGO_INCREMENTAL"] == "0" and env["RUST_TEST_THREADS"] == "1"
        for key, value in env.items():
            if key.startswith("RUST") or (key.startswith("CARGO_BUILD_") and key != "CARGO_BUILD_JOBS") or key.startswith("CARGO_ENCODED_") or key.startswith("CARGO_PROFILE_") or (key.startswith("CARGO_TARGET_") and key != "CARGO_TARGET_DIR"):
                if key != "RUST_TEST_THREADS":
                    assert value is None, (key, value)
        assert "1.95.0" in text["rustc.txt"] and "1.95.0" in text["cargo.txt"]
        assert ("aarch64" if arch == "arm" else "x86_64") in text["host.txt"]
        assert env["OPENSSL_STATIC"] == "1" and env["TRNM_PQ_OPENSSL_VERSION"] == "3.5.9"
        provider = js("pq-provider/provider.json")
        assert provider["version"] == "3.5.9" and provider["result"] == "PREPARED_AND_SMOKE_VERIFIED" and provider["exit_code"] == 0
        assert provider["preparation_script_sha256"] == sha(source["scripts/ci/prepare_pq_provider.sh"])
        rows = [json.loads(line) for line in text["build.jsonl"].splitlines() if line.strip()]
        assert [r for r in rows if r.get("reason") == "build-finished"] == [{"reason": "build-finished", "success": True}]
        local_packages = sorted({r["package_id"] for r in rows if r.get("reason") == "compiler-artifact" and r.get("package_id", "").startswith("path+")})
        assert len(local_packages) == 26
        build_time = resource(text["build.resources.txt"])
        assert build_time["argv"] == BUILD
        for n in ["build.exit", "build-input-check.exit", "build-artifact-check.exit", "binary-before.exit", "binary-after.exit", "m06-binary-after.exit", "test-step.exit", "semantic-controls/registry-check.exit", "semantic-controls/semantic-step.exit"]:
            assert text[n].strip() == "0", n
        binaries = {}
        for key, stem, crate, opt in [("node", "binary", "trnm-pon-node", "3"), ("m06", "m06-binary", "trnm-mvcc-fee", "1")]:
            b = js(stem + ".json")
            a = b["artifact"]
            assert a in rows and a["profile"] == dict(opt_level=opt, debuginfo=2, debug_assertions=True, overflow_checks=True, test=True)
            assert a["features"] == ["default", "pq-native-openssl"]
            executable = text[stem + ".txt"].strip()
            assert a["executable"] == executable and executable.startswith(env["CARGO_TARGET_DIR"] + "/debug/deps/")
            expected = b["sha256"] + "  " + executable + "\n"
            assert text[stem + ".sha256"] == text[stem + "-after.sha256"] == expected
            assert text["semantic-controls/" + key + "-binary-before.sha256"] == expected
            for n in [stem + "-after.log", "semantic-controls/" + key + "-binary-before.log"]:
                assert text[n] == executable + ": OK\n"
            if key == "node":
                assert text["binary-before.sha256"] == expected and text["binary-before.log"] == executable + ": OK\n"
                assert text["growth-scale.binary-after.log"] == executable + ": OK\n"
            else:
                assert b["dependency_artifact"] in rows and b["dependency_artifact"]["profile"] == dict(opt_level=opt, debuginfo=2, debug_assertions=True, overflow_checks=True, test=False)
            assert build["test_profile_packages"][crate] == {"opt-level": int(opt), "debug-assertions": True, "overflow-checks": True}
            binaries[key] = dict(executable=executable, runner_reported_sha256=b["sha256"], independent_binary_sha256=None, binary_bytes_in_artifact=False, profile=a["profile"], features=a["features"], runner_before_after_hash_receipts_equal=True)
        ac = js("build-artifact-check.json")
        assert ac["result"] == "PASS" and ac["binary_sha256"] == binaries["node"]["runner_reported_sha256"] and ac["m06_binary_sha256"] == binaries["m06"]["runner_reported_sha256"]
        registry = js("semantic-controls/registry-check.json")
        actual_registry = {crate: sorted(line[:-6] for line in text[f"semantic-controls/{crate}-registry.log"].splitlines() if line.endswith(": test")) for crate in ("node", "m06")}
        assert {k: len(v) for k, v in actual_registry.items()} == registry["registry_counts"] == {"node": 974, "m06": 108}
        assert all(len(v) == len(set(v)) for v in actual_registry.values())
        assert registry["selected_count"] == 45 and int(text["semantic-controls/executed-selector-count.txt"]) == 45
        expected_group_counts = {"full-root-arithmetic": 5, "canonical-ascii": 7, "reorg-tail": 6, "current-sql-root": 1, "prepared-current-history": 3, "postwrite-readback": 23}
        assert {g["group"]: len(g["tests"]) for g in registry["groups"]} == expected_group_counts
        selected = [tuple(line.split("\t")) for line in text["semantic-controls/selected-tests.tsv"].splitlines()]
        assert len(selected) == len(set(selected)) == 45
        assert selected == [(g["crate"], g["group"], n) for g in registry["groups"] for n in g["tests"]]
        for g in registry["groups"]:
            assert all(n in actual_registry[g["crate"]] for n in g["tests"])
            if "prefix" in g:
                assert g["tests"] == [n for n in actual_registry[g["crate"]] if n.startswith(g["prefix"])]
        basic = tsv(text["test-exits.tsv"])
        sem = tsv(text["semantic-controls/test-exits.tsv"])
        assert [r["selector"] for r in basic] == CPU
        assert [(r["crate"], r["group"], r["selector"]) for r in sem] == selected
        for r in basic + sem:
            assert all(r[k] == "0" for k in ["native_exit", "log_exit", "reader_exit"])
        assert dict(line.split("=", 1) for line in text["growth-scale.exits.txt"].splitlines()) == {k: "0" for k in ["native_exit", "execution_reader", "observation_reader", "binary_reader"]}
        assert all(set(r.values()) <= {"node", "m06", "0"} for r in tsv(text["semantic-controls/elf-before-exits.tsv"]))
        native = []
        executions = sorted(n for n in names if n.endswith(".execution.json"))
        assert len(executions) == 50
        for n in executions:
            r = js(n)
            stem = n[:-len(".execution.json")]
            selector = r["test"]
            crate = "m06" if "/" in stem and "-m06-" in stem else "node"
            assert selector in actual_registry[crate]
            independently_read = named.validate(text[stem + ".log"].splitlines(), selector)
            assert independently_read == r
            assert text[stem + ".execution.stderr"] == ""
            counts = NATIVE_SUMMARY.findall(text[stem + ".log"])
            assert len(counts) == 1 and int(counts[0][0]) == len(actual_registry[crate]) - 1
            res = resource(text[stem + ".resources.txt"])
            expected_argv = [binaries[crate]["executable"], selector, "--exact"] + (["--ignored"] if selector == GROWTH else []) + ["--nocapture", "--test-threads=1"]
            assert res["argv"] == expected_argv
            if stem.startswith("semantic-controls/"):
                assert text[stem + ".cwd.txt"].strip().endswith("/trillionnium/crates/" + ("trnm-mvcc-fee" if crate == "m06" else "trnm-pon-node"))
            native.append(dict(crate=crate, selector=selector, log=stem + ".log", summary=dict(passed=1, failed=0, ignored=0, measured=0, filtered_out=int(counts[0][0]), elapsed_seconds=counts[0][1]), resources=res, original_process_exit=0, original_reader=r, independent_reader=independently_read))
        assert len({n["selector"] for n in native}) == 50
        assert {n["selector"] for n in native} == set(CPU + [n for _, _, n in selected] + [GROWTH])
        # Native output explicitly preserves original policy and qualification limits.
        cpu = []
        for selector in CPU[:2]:
            records = log_json(text[selector.rsplit("::", 1)[1] + ".log"])
            ds = [r for r in records if r.get("schema") == "native-large-parent-original-dispatch-diagnostic-v1"]
            ps = [r for r in records if r.get("schema") == "native-large-parent-schedule-parity-v1"]
            expected_backends = [False, True] if selector == CPU[0] else [True]
            assert [d["authenticated_backend"] for d in ds] == [p["authenticated_backend"] for p in ps] == expected_backends
            for d, p in zip(ds, ps):
                for budget in [d["cpu_budget_before"], d["cpu_budget_after"]]:
                    assert {k: budget[k] for k in ["burst_ns", "refill_ns_per_second", "start_reserve_ns", "worker_limit"]} == dict(burst_ns=2000000000, refill_ns_per_second=250000000, start_reserve_ns=100000000, worker_limit=2)
                    assert budget["accounting_unavailable"] is False and budget["in_flight"] == 0
                assert d["cpu_budget_before"]["stored_credit_ns"] == 2000000000
                assert d["original_dispatch_result"] == d["original_native_result"] == p["native_result"] == {"Ok": "ok"}
                assert d["complete_key_utf8_and_canonical_value_bytes"] == p["complete_key_utf8_and_canonical_value_bytes"] == 8625548 > 8 * 1024 * 1024
                assert d["observed_held_capacity_lower_bound_bytes"] == p["early_capacity_observed_lower_bound_bytes"] == 8391103 > 8 * 1024 * 1024
                flow, paid = d["actual_cpu_flow_after"], p["original_cpu_receipt"]
                assert flow["balance_identity_verified"] is True and flow["live_owners"] == 0 and flow["unsettled_known_live_cpu_ns"] == 0
                assert flow["settled_full_cpu_ns"] == flow["paid_cpu_debit_ns"] == paid["total_cpu_ns"] > 0
                assert paid["accounting_unavailable"] is False and paid["live_refused"] is False
                assert paid["started_workers"] == paid["finished_workers"] == paid["known_workers"] == paid["spawned_workers"] == 2
                assert not any(p[k] for k in ["host_qualified", "budget_depletion_demonstrated", "all_honest_service_qualified"])
                cpu.append(dict(selector=selector, authenticated_backend=d["authenticated_backend"], complete_bytes=p["complete_key_utf8_and_canonical_value_bytes"], held_capacity_lower_bound_bytes=p["early_capacity_observed_lower_bound_bytes"], original_cpu_receipt=paid, cpu_budget_before=d["cpu_budget_before"], cpu_budget_after=d["cpu_budget_after"], actual_cpu_flow_after=flow, native_result=p["native_result"], host_qualified=False, budget_depletion_demonstrated=False, all_honest_service_qualified=False))
        with tempfile.TemporaryDirectory(prefix="growth-text-reader-") as tmp:
            d = Path(tmp)
            for n in names:
                if n.startswith("growth-scale/"):
                    assert len(PurePosixPath(n).parts) == 2
                    (d / PurePosixPath(n).name).write_bytes(data[n])
            growth_readback = growth.check(d)
        assert growth_readback == js("growth-scale.readback.json")
        assert growth_readback["completed_cohorts"] == growth_readback["cancelled_admissions"] == growth_readback["cold_reopens"] == 9
        assert growth_readback["measured_native_blocks"] == 72 and growth_readback["p99_ns"] is None
        assert growth_readback["result"] == "COMPLETE_LOCAL_OBSERVATION" and not growth_readback["throughput_qualified"] and not growth_readback["public_network_ready"] and not growth_readback["production_activation"]
        assert re.search(r"Ran 23 tests in [0-9.]+s\n\nOK\n", text["growth-scale.reader-controls.log"])
        archived = write_gzip(out / f"{lane}-original-records.json.gz", dict(schema="trnm-workspace-cpu-original-text-records-v1", zip_filename=zp.name, artifact_id=aid, zip_bytes=len(rawzip), zip_sha256=digest, records=[entry(n, data[n]) for n in sorted(data)]))
        # Verify restored bytes against every original ZIP member, not only self-consistent hashes.
        restored = json.loads(gzip.decompress((out / archived["file"]).read_bytes()))
        assert {r["path"]: r["text"].encode("utf-8") for r in restored["records"]} == data
        lanes.append(dict(lane=lane, job_id=job[0]["id"], job_conclusion=job[0]["conclusion"], artifact=meta, zip_sha256=digest, zip_bytes=len(rawzip), source=s, source_before_after_bytes_identical=True, build_argv=BUILD, build_resources=build_time, complete_workspace_build_path_package_count=len(local_packages), complete_workspace_build_package_ids=local_packages, binaries=binaries, registry_counts=registry["registry_counts"], semantic_groups=expected_group_counts, selected_native_executions=native, selected_native_unique_test_count=50, passed=50, failed=0, cpu_policy_outcomes=cpu, growth_observation=growth_readback, growth_original_python_reader_controls=dict(passed=23, new_execution_in_this_readback=False), original_records=archived))
    assert len(lanes) == 4 and len({l["lane"] for l in lanes}) == 4
    assert len({tuple(sorted(n["selector"] for n in l["selected_native_executions"])) for l in lanes}) == 1
    context_archived = write_gzip(out / "source-and-original-metadata.json.gz", dict(schema="trnm-workspace-cpu-source-and-metadata-text-records-v1", exact_source_commit=c["head"], records=context))
    report = dict(schema="trnm-workspace-cpu-four-lane-terminal-readback-v1", observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), cohort=c, result="PASS_FOR_NAMED_ORIGINAL_WORKSPACE_CPU_LANES", lanes=lanes, lane_count=4, distinct_native_selectors_across_lanes=50, repeated_native_execution_count=200, total_original_zip_records=sum(l["original_records"]["records"] for l in lanes), total_original_zip_record_bytes=sum(l["original_records"]["original_record_bytes"] for l in lanes), source_and_metadata=context_archived, native_executed_by_readback=False, new_downloads_by_readback=False, independent_elf_rehash_performed=False, complete_workspace_test_execution=False, complete_runtime_suite_qualified=False, public_host_qualified=False, public_confirmation_target_qualified=False, growth_throughput_qualified=False, original_65536_signed_growth_gate_replaced=False, p99_qualified=False, release_qualified=False, production_activation=False, source_paths=[dict(path=p, bytes=len(raw), sha256=sha(raw)) for p, raw in source.items()], caveats=["The four jobs build the original complete workspace with --no-run, then execute the same 50 distinct named selectors each; 200 is repeated executions, not 200 unique tests.", "Full Rust test execution and public Host/client-confirmation gates are separate. These local CPU-policy examples explicitly do not certify Host availability, all honest service, budget depletion or production.", "Runner ELF SHA and before/after check receipts are consistent; the original ZIPs contain no ELF bytes. Independent ELF digest is null.", "Growth is 9 account/history cohorts at 64/1024/16384 accounts and 0/16/128 warmup blocks with fixed three witness owners, 8 measured blocks per cohort, 9 cancelled admissions and 9 cold reopens per lane. It has no p99, wall-time acceptance or throughput qualification and does not replace the original 65536 signed growth gate.", "All raw ZIP members are losslessly retained with byte lengths and SHA-256, and independently replayed data readers match the original readbacks. Existing Python reader-controls logs are original hosted evidence, not newly executed tests."])
    write_json(out / "readback.json", report)
    summary = {k: v for k, v in report.items() if k not in ["lanes"]}
    summary["lanes"] = [{k: l[k] for k in ["lane", "job_id", "job_conclusion", "zip_sha256", "zip_bytes", "source", "build_resources", "selected_native_unique_test_count", "passed", "failed", "binaries", "original_records"]} | {"artifact_id": l["artifact"]["id"], "growth_cohorts": l["growth_observation"]["completed_cohorts"], "growth_native_blocks": l["growth_observation"]["measured_native_blocks"]} for l in lanes]
    summary["full_readback"] = dict(file="readback.json", bytes=(out / "readback.json").stat().st_size, sha256=sha((out / "readback.json").read_bytes()))
    write_json(out / "summary.json", summary)
    files = [dict(file=p.name, bytes=p.stat().st_size, sha256=sha(p.read_bytes())) for p in sorted(out.iterdir()) if p.is_file()]
    write_json(out / "index.json", dict(schema="trnm-workspace-cpu-readback-file-index-v1", cohort=c, result="PASS", files=files, immutable_outputs=True, native_executed=False))
    print(json.dumps(dict(result=report["result"], source=c["head"], lane_count=4, distinct_native_selectors=50, repeated_native_executions=200, original_zip_records=report["total_original_zip_records"], summary_sha256=sha((out / "summary.json").read_bytes()), readback_sha256=sha((out / "readback.json").read_bytes()), index_sha256=sha((out / "index.json").read_bytes())), sort_keys=True))

if __name__ == "__main__":
    main()
