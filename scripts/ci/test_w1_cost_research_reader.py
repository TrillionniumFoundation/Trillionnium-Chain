#!/usr/bin/env python3
"""Reader controls over captured real native tiny logs, not new timing evidence.

The compact fixtures preserve every original byte after expanding canonical
public matrices/proof prefixes. Their original SHA256 binds this expansion, and
the default positive control independently replays the retained W1 certificates.
Captured binary: 5a7d566ab4832104dd466e4d17756f8df3cd360fa654a9dc95b92e81a9212535.
These are pre-freeze functional fixtures, not source/hardware qualification.
Synthetic bundle receipts below exercise provenance parsing only; no compiler,
node, or physical cost execution is claimed by those unit-test receipts.
"""
from __future__ import annotations

import base64
import copy
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zlib

SCRIPT = Path(__file__).resolve().parents[1] / "read_w1_cost_research.py"
SPEC = importlib.util.spec_from_file_location("w1_research_reader", SCRIPT)
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)

FIXTURE_DATA = (
    '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'
)


def encode_rows(rows):
    return ("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows)).encode()


def fixtures():
    cases = json.loads(zlib.decompress(base64.b64decode(FIXTURE_DATA)))
    for case in cases.values():
        family = None
        for row in case["rows"]:
            if row["kind"] == "material":
                a, b, _, _, _ = reader.material_recipe(row["family"])
                row["a_hex"], row["b_hex"] = a.hex(), b.hex()
            elif row["kind"] == "cohort-start":
                family = row["family"]
            elif row["kind"] == "attempt" and row["proof_hex"] is not None:
                row["proof_hex"] = (reader.material_recipe(family)[4] + bytes.fromhex(row["trace"])).hex()
        if reader.digest(encode_rows(case["rows"])) != case["sha256"]:
            raise AssertionError("native fixture reconstruction differs from captured bytes")
    return cases


def record(rows, kind, index=0):
    return [row for row in rows if row["kind"] == kind][index]


def remove_record(rows, kind, index=0):
    rows.remove(record(rows, kind, index))


class ReaderControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = fixtures()

    def validate(self, rows, *, replay=False, expected_options=None):
        with tempfile.TemporaryDirectory(prefix="w1-reader-test-") as directory:
            path = Path(directory) / "raw.jsonl"
            path.write_bytes(encode_rows(rows))
            return reader.validate_raw(path, replay=replay, expected_options=expected_options)

    def reject(self, name, change, label):
        rows = copy.deepcopy(self.cases[name]["rows"])
        change(rows)
        with self.assertRaisesRegex(ValueError, label):
            self.validate(rows)

    def test_eight_real_native_cases_and_retained_certificate_replays(self):
        expected_replays = {"hot-repeat": 1, "cold-repeat": 1, "adaptive": 1, "native": 1}
        for name, case in self.cases.items():
            with self.subTest(name=name):
                value = self.validate(case["rows"], replay=True,
                                      expected_options=reader.options_from_args(case["args"]))
                self.assertEqual(value["python_full_relation_replays"], expected_replays.get(name, 0))
                self.assertFalse(value["all_native_reported_attempts_independently_verified"])
                self.assertFalse(value["native_execution_attested_by_reader"])
                self.assertIn("target_hits", value["native_reported"])
                self.assertEqual(value["native_reported"]["target_hits"],
                                 sum(row["target_hits"] for row in case["rows"] if row["kind"] == "cohort-end"))
                summaries = reader.derive([value])
                if name == "native":
                    self.assertEqual(value["native_reported"]["auxiliary_original_node_work"], 5)
                    self.assertEqual(value["native_reported"]["all_work_unique_target_hits"], 6)
                    self.assertEqual(summaries[0]["inclusive_cpu_per_all_work_inclusive_budget_winner"]["numerator"],
                                     summaries[0]["inclusive_cpu_ns"] // __import__('math').gcd(summaries[0]["inclusive_cpu_ns"], 6))

    def test_plan_options_independently_decode_defaults_and_all_registered_jobs(self):
        default = reader.options_from_args([])
        self.assertEqual(default["arms"], [1, 5, 13])
        self.assertEqual(default["nonce_space"], 8)
        self.assertEqual(reader.options_from_args(["--scope", "maintenance-parent"])["families"],
                         ["continuity-maintenance-v1"])
        plan = reader.decode((reader.ROOT / "formal/pon-nakamoto-v1/experiments/w1_cost_campaign_v1.json").read_bytes())
        for job in reader.validate_plan(plan):
            self.assertEqual(reader.options_from_args(job["args"])["samples"],
                             int(job["args"][job["args"].index("--samples") + 1]))
        for args in (["--scope", "maintenance-parent", "--target", "ff" * 32],
                     ["--samples", "1", "--samples", "2"], ["--nonce-space", "0"],
                     ["--arms", "prepared-generic,prepared-generic"], ["--seed", str(1 << 64)]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                reader.options_from_args(args)

    def test_plan_denominator_and_cohort_id_mutants(self):
        rows = self.cases["hot-repeat"]["rows"]
        expected = reader.options_from_args(self.cases["hot-repeat"]["args"])
        expected["samples"] = 2
        with self.assertRaisesRegex(ValueError, "REGISTERED_OPTIONS_CHANGED"):
            self.validate(rows, expected_options=expected)
        mutants = [
            (lambda r: record(r,"campaign")["options"].update(families=[]), "OPTION_FAMILIES"),
            (lambda r: record(r,"cohort-start").update(sample=99), "COHORT_GRID_IDENTITY"),
            (lambda r: record(r,"cohort-start").update(arm="unregistered"), "COHORT_ARM"),
            (lambda r: record(r,"cohort-start").update(cohort="different-id"), "COHORT_CANONICAL_ID"),
            (lambda r: record(r,"end").update(cohorts=0), "INCOMPLETE_END"),
        ]
        for change, label in mutants:
            with self.subTest(label=label):self.reject("hot-repeat", change, label)

    def test_required_preparation_and_generation_charges(self):
        self.reject("hot-repeat", lambda r: remove_record(r,"charge"), "COHORT_STATE_MACHINE")
        self.reject("cold-repeat", lambda r: r.remove([x for x in r if x["kind"]=="charge" and x["stage"]=="prepare"][1]), "COHORT_STATE_MACHINE")
        self.reject("batch-zero-target", lambda r: r.remove(next(x for x in r if x["kind"]=="charge" and x["stage"]=="batch-buffer")), "COHORT_STATE_MACHINE")
        self.reject("hot-repeat", lambda r: record(r,"attempt",1).update(charge_seq=record(r,"attempt")["charge_seq"]), "REUSED_GENERATION_CHARGE")
        self.reject("hot-repeat", lambda r: record(r,"charge")["detail"].update(supported=False), "PREPARE_PUBLIC_SUPPORT_RECIPE")
        self.reject("hot-repeat", lambda r: record(r,"cohort-end").update(status="unknown-complete"), "COHORT_STATE_MACHINE")
        self.reject("hot-repeat", lambda r: record(r,"charge")["cumulative"].update(cpu_ns=0), "CHARGE_SUM")
        self.reject("budget-prepare", lambda r: record(r,"cohort-end").update(overrun_cpu_ns=0), "END_BUDGET")

    def test_adaptive_training_selection_and_dispatch_cannot_be_removed(self):
        self.reject("adaptive", lambda r: r.remove(next(x for x in r if x["kind"]=="charge" and x["stage"]=="select")), "COHORT_STATE_MACHINE")
        self.reject("adaptive", lambda r: record(r,"selection")["scores"].pop(), "SELECTION_CANDIDATE_SET")
        self.reject("adaptive", lambda r: record(r,"selection").update(selected_arm="scalar-original"), "COHORT_STATE_MACHINE")
        self.reject("adaptive", lambda r: record(r,"selection").update(training_stream_disjoint=False), "SELECTION_SCOPE_FLAGS")
        self.reject("adaptive", lambda r: next(x for x in r if x["kind"]=="attempt" and x["phase"]=="evaluation").update(arm="scalar-original"), "COHORT_STATE_MACHINE")
        self.reject("adaptive", lambda r: record(r,"selection")["scores"][0]["training_generation_timing"].update(wall_ns=0), "SELECTION_TRAINING_TIMING")

    def test_certificate_retention_and_material_family_are_binding(self):
        self.reject("hot-repeat", lambda r: record(r,"attempt").update(proof_hex=None), "FIRST_WINNING_CERTIFICATE_RETENTION")
        self.reject("hot-repeat", lambda r: record(r,"attempt",1).update(proof_hex=record(r,"attempt")["proof_hex"]), "FIRST_WINNING_CERTIFICATE_RETENTION")
        self.reject("batch-zero-target", lambda r: record(r,"attempt").update(proof_hex="00"), "FIRST_WINNING_CERTIFICATE_RETENTION")
        self.reject("hot-repeat", lambda r: record(r,"attempt").update(proof_sha256="00"*32), "CANONICAL_PROOF_PRODUCT_HASH")
        def rename_zero_as_full_rank(rows):
            record(rows,"campaign")["options"]["families"]=["full-rank-field"]
            record(rows,"material")["family"]="full-rank-field"
        self.reject("hot-repeat",rename_zero_as_full_rank,"MATERIAL_PUBLIC_RECIPE")

    def test_claimed_native_verifier_success_does_not_replace_retained_full_replay(self):
        rows=copy.deepcopy(self.cases["hot-repeat"]["rows"])
        for row in rows:
            if row["kind"]!="attempt":continue
            trace=bytes(32);challenge=bytes.fromhex(row["challenge"]);task=bytes.fromhex(row["task"])
            ticket=reader.H("ticket",challenge,trace);proof=reader.material_recipe("zero")[4]+trace
            row.update(trace=trace.hex(),ticket=ticket.hex(),proof_sha256=reader.digest(proof),
                       semantic_id=reader.H("w1-cost-game-semantic-ticket-v1",task,challenge,ticket).hex())
            if row["proof_hex"] is not None:row["proof_hex"]=proof.hex()
        with self.assertRaisesRegex(ValueError,"TRANSCRIPT"):
            self.validate(rows,replay=True)

    def test_duplicates_and_zero_winner_denominators(self):
        self.reject("hot-repeat",lambda r:record(r,"attempt",1).update(unique_ticket=True),"DUPLICATE_TICKET_CREDIT")
        self.reject("hot-repeat",lambda r:record(r,"cohort-end").update(unique_target_hits=2),"END_COUNT")
        value=self.validate(self.cases["batch-zero-target"]["rows"])
        summary=reader.derive([value])[0]
        self.assertEqual(summary["native_reported"]["target_hits"],0)
        self.assertIsNone(summary["inclusive_cpu_per_inclusive_budget_winner"])
        self.assertEqual(value["python_replayed"]["full_relation_attempts"],0)

    def test_auxiliary_five_ticket_union_and_single_timeline(self):
        def context(rows):return next(r for r in rows if r["kind"]=="charge" and r["stage"]=="context")["detail"]
        def duplicate_with_later_timestamps(rows):
            entries=context(rows)["acquisition"]
            old=entries[1];duplicate=copy.deepcopy(entries[0])
            for key in ("inclusive_producer_cpu_ns","admission_completion_inclusive_cpu_ns"):
                duplicate[key]=old[key]
            entries[1]=duplicate
        self.reject("native",lambda r:context(r)["acquisition"].pop(),"AUXILIARY_CONTEXT_COMPLETENESS")
        self.reject("native",duplicate_with_later_timestamps,"DUPLICATE_AUXILIARY_WORK")
        self.reject("native",lambda r:context(r)["acquisition"][0].update(proof_sha256="00"*32),"AUXILIARY_CANONICAL_PROOF_HASH")
        self.reject("native",lambda r:context(r)["acquisition"][-1].update(admission_completion_inclusive_cpu_ns=record(r,"cohort-end")["inclusive_producer_timing"]["cpu_ns"]+1),"INCLUSIVE_CPU_ORDER")
        self.reject("native",lambda r:record(r,"attempt").update(inclusive_producer_cpu_ns=context(r)["acquisition"][-1]["admission_completion_inclusive_cpu_ns"]-1),"INCLUSIVE_CPU_ORDER")
        self.reject("native",lambda r:record(r,"cohort-end").update(all_work_unique_target_hits=1),"END_ALL_WORK_COUNT")

    def test_comparisons_require_exact_task_seed_sample_identity_sets(self):
        value=self.validate(self.cases["hot-repeat"]["rows"])
        baseline=copy.deepcopy(value)
        baseline["cohorts"][0]["arm"]="prepared-generic"
        reader.derive([value,baseline])
        for key,changed in (("task","ab"*32),("seed",999),("sample",999)):
            other=copy.deepcopy(baseline);other["cohorts"][0][key]=changed
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,"UNPAIRED_BASELINE_DENOMINATOR"):
                reader.derive([value,other])
        with self.assertRaisesRegex(ValueError,"REPEATED_COUNTERFACTUAL_COHORT"):
            reader.derive([value,value])

    def test_duplicate_json_keys_truncated_input_and_authority_flags(self):
        with self.assertRaisesRegex(ValueError,"DUPLICATE_JSON_KEY"):
            reader.decode('{"a":1,"a":2}')
        with self.assertRaisesRegex(ValueError,"NON_INTEGER_JSON_NUMBER"):
            reader.decode('{"a":NaN}')
        self.reject("hot-repeat",lambda r:record(r,"campaign").update(hardness_accepted=True),"AUTHORITY_PROMOTION")
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"truncated.jsonl";path.write_bytes(encode_rows(self.cases["hot-repeat"]["rows"])[:-1])
            with self.assertRaisesRegex(ValueError,"TRUNCATED_OR_OVERLONG_RECORD"):reader.validate_raw(path,replay=False)

    @contextmanager
    def bundle(self):
        with tempfile.TemporaryDirectory(prefix="w1-bundle-test-") as d:
            base=Path(d);source=base/"source";out=base/"bundle";source.mkdir();out.mkdir()
            args=self.cases["hot-repeat"]["args"]
            plan={"schema":"pon-w1-cost-research-plan-v1","baseline_source":"63"*20,
                  "production_activation":False,"hardness_accepted":False,"work_function_changed":False,
                  "jobs":[{"name":"tiny","args":args,"timeout_seconds":60}]}
            plan_rel="formal/pon-nakamoto-v1/experiments/w1_cost_campaign_v1.json"
            plan_bytes=(json.dumps(plan,sort_keys=True,indent=2)+"\n").encode()
            runner_bytes=(reader.ROOT/"scripts/run_w1_cost_research.py").read_bytes()
            for name,raw in ((plan_rel,plan_bytes),("scripts/run_w1_cost_research.py",runner_bytes)):
                path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
            def git(*args):return subprocess.check_output(["git","-C",str(source),*args],stderr=subprocess.PIPE).decode().strip()
            git("init","-q");git("add","--",plan_rel,"scripts/run_w1_cost_research.py")
            git("-c","user.name=Reader fixture","-c","user.email=reader@example.invalid","-c","commit.gpgsign=false","commit","-qm","reader fixture")
            head,tree,branch=git("rev-parse","HEAD"),git("rev-parse","HEAD^{tree}"),git("branch","--show-current")
            compiler="/fixture/toolchain/rustc";cargo="/fixture/toolchain/cargo";target=str(base/"target")
            binary=target+"/release/examples/pon_w1_cost_game";cargo_home=str(base/"cargo-home")
            source_receipt={"head":head,"tree":tree,"branch":branch,"status":""}
            raw_receipt={"schema":"trnm-ci-source-v1","kind":"head","tested_commit":head,"tested_tree":tree,"candidate":head,"base":None,"prospective_merge":None,"tracked_worktree_verified":True,"tracked_entries":2,"tracked_bytes":len(plan_bytes)+len(runner_bytes),"tests_executed_by_identity_check":False}
            hw={"requested_child_cpu":0,"allowed_affinity":[0],"machine":"x86_64","cpu_models":["unit-test receipt"],"hardware_attested":False,"exclusive_cpu":False,"energy_joules":None,"network_transfer_measured":False}
            for name in ("hardware-before.json","hardware-after.json"):(out/name).write_text(json.dumps(hw))
            artifact={"reason":"compiler-artifact","target":{"name":"pon_w1_cost_game","kind":["example"],"src_path":str(source/"trillionnium/crates/trnm-pon-node/examples/pon_w1_cost_game.rs")},"executable":binary,"fresh":False}
            env={"RUSTC":compiler,"CARGO_HOME":cargo_home,"CARGO_TARGET_DIR":target,"CARGO_NET_OFFLINE":"true","CARGO_BUILD_JOBS":"2","CARGO_INCREMENTAL":"0","PYTHONDONTWRITEBYTECODE":"1"}
            configs={Path(cargo_home)/"config",Path(cargo_home)/"config.toml"}
            for ancestor in (source,*source.parents):configs.update((ancestor/".cargo/config",ancestor/".cargo/config.toml"))
            setup=[
              ("preflight",["bash","scripts/project-preflight.sh"],60,json.dumps({"result":"PASS","project":"trillionnium-chain","remote_policy_mutated":False,"branch":branch}).encode()),
              ("rustc-version",[compiler,"-Vv"],60,b"rustc 1.95.0 (fixture)\n"),
              ("cargo-version",[cargo,"-Vv"],60,b"cargo fixture\n"),
              ("metadata",[cargo,"metadata","--offline","--locked","--format-version","1","--manifest-path","trillionnium/Cargo.toml"],120,json.dumps({"workspace_root":str(source/"trillionnium"),"target_directory":target}).encode()),
              ("build",[cargo,"build","--offline","--locked","--release","--jobs","2","--manifest-path","trillionnium/Cargo.toml","-p","trnm-pon-node","--example","pon_w1_cost_game","--message-format=json"],1200,(json.dumps(artifact)+"\n"+json.dumps({"reason":"build-finished","success":True})+"\n").encode()),
              ("tiny",["/usr/bin/taskset","-c","0",binary,*args],60,encode_rows(self.cases["hot-repeat"]["rows"]))]
            steps=[]
            for name,command,timeout,raw in setup:
                (out/(name+".stdout")).write_bytes(raw);(out/(name+".stderr")).write_bytes(b"")
                row=dict(name=name,command=command,cwd=str(source),timeout_seconds=timeout,output_limit_bytes=64*1024*1024,returncode=0,error=None,stdout_truncated=False,stderr_truncated=False,stdout=name+".stdout",stderr=name+".stderr",wall_ns=1,stdout_bytes=len(raw),stderr_bytes=0,stdout_sha256=reader.digest(raw),stderr_sha256=reader.digest(b""),complete_success=True)
                steps.append(row);(out/(name+".step.json")).write_text(json.dumps(row))
            (out/"preregistered-plan.json").write_bytes(plan_bytes)
            manifest=dict(schema="pon-w1-cost-research-bundle-v1",complete_success=True,source_unchanged=True,failure=None,source_before=source_receipt,source_after=source_receipt,raw_source_before=raw_receipt,raw_source_after=raw_receipt,hardness_accepted=False,production_activation=False,independent_hardware_qualification=False,profile="release",inherited_build_overrides={},target_directory_was_new=True,runner_sha256=reader.digest(runner_bytes),plan_source_path=plan_rel,plan_sha256=reader.digest(plan_bytes),binary={"path":binary,"sha256":"bb"*32,"bytes":1},compiler={"path":compiler,"sha256":"cc"*32},cargo={"path":cargo,"sha256":"dd"*32},declared_build_environment=env,hardware_before_sha256=reader.sha(out/"hardware-before.json"),hardware_after_sha256=reader.sha(out/"hardware-after.json"),steps=steps,cargo_configurations=[{"path":str(path),"exists":False,"sha256":None} for path in sorted(configs)],toolchain="rustc 1.95.0 (fixture)\n",cargo_executable_artifact=artifact)
            (out/"campaign.json").write_text(json.dumps(manifest))
            pins=dict(expected_head=head,expected_tree=tree,expected_plan_sha256=reader.digest(plan_bytes),expected_binary_sha256="bb"*32,expected_manifest_sha256=reader.sha(out/"campaign.json"))
            with patch.object(reader,"ROOT",source):yield out,manifest,pins

    def test_complete_bundle_with_external_pins_and_real_git_objects(self):
        with self.bundle() as (out,manifest,pins):
            value=reader.read_bundle(out,**pins)
            self.assertTrue(value["external_identity_pins_checked"])
            self.assertEqual(value["native_reported"]["attempts"],2)
            self.assertEqual(value["python_replayed"]["full_relation_attempts"],1)
            self.assertFalse(value["native_execution_attested_by_reader"])

    def test_external_identity_pins_cannot_be_inferred_from_bundle(self):
        with self.bundle() as (out,manifest,pins):
            for key in pins:
                altered=dict(pins);altered[key]="00"*(20 if key in ("expected_head","expected_tree") else 32)
                with self.subTest(key=key),self.assertRaises((ValueError,subprocess.SubprocessError)):
                    reader.read_bundle(out,**altered)

    def test_bundle_missing_steps_plan_hash_binary_and_raw_source_mutants(self):
        changes=[
          (lambda m:m["steps"].pop(0),"EXACT_REGISTERED_STEPS"),
          (lambda m:m["raw_source_after"].update(tracked_worktree_verified=False),"RAW_SOURCE_PIN"),
          (lambda m:m.update(target_directory_was_new=False),"FRESH_BUILD_DIRECTORY_REQUIRED"),
          (lambda m:m["binary"].update(sha256="00"*32),"BINARY_EXTERNAL_PIN"),
          (lambda m:m.update(runner_sha256="00"*32),"SOURCE_BLOB_BINDING"),
          (lambda m:m["steps"][-1]["command"].__setitem__(0,"/usr/bin/echo"),"DIVERGENT_STEP_RECEIPT"),
          (lambda m:m.update(plan_sha256="00"*32),"BUNDLE_PLAN_PIN"),
        ]
        for change,label in changes:
            with self.subTest(label=label),self.bundle() as (out,manifest,pins):
                change(manifest);(out/"campaign.json").write_text(json.dumps(manifest));pins["expected_manifest_sha256"]=reader.sha(out/"campaign.json")
                with self.assertRaisesRegex(ValueError,label):reader.read_bundle(out,**pins)

    def test_plan_is_nonempty_and_binding_even_if_manifest_is_repinned(self):
        with self.bundle() as (out,manifest,pins):
            (out/"preregistered-plan.json").write_text(json.dumps({"schema":"pon-w1-cost-research-plan-v1","baseline_source":"63"*20,"production_activation":False,"hardness_accepted":False,"work_function_changed":False,"jobs":[]}))
            manifest["plan_sha256"]=reader.sha(out/"preregistered-plan.json")
            (out/"campaign.json").write_text(json.dumps(manifest));pins.update(expected_plan_sha256=manifest["plan_sha256"],expected_manifest_sha256=reader.sha(out/"campaign.json"))
            with self.assertRaisesRegex(ValueError,"PLAN_JOB_COUNT"):reader.read_bundle(out,**pins)

    def test_raw_stream_loss_and_step_receipt_hashes(self):
        with self.bundle() as (out,manifest,pins):
            with (out/"tiny.stdout").open("ab") as stream:stream.write(b"\n")
            with self.assertRaisesRegex(ValueError,"CHANGED_RAW_STREAM"):reader.read_bundle(out,**pins)

    def test_consistently_rewritten_command_and_build_receipts_are_rejected(self):
        for name in ("command", "fresh-artifact"):
            with self.subTest(name=name),self.bundle() as (out,manifest,pins):
                if name=="command":
                    step=manifest["steps"][-1];step["command"][0]="/usr/bin/echo"
                    label="REGISTERED_JOB_COMMAND_BINDING"
                else:
                    artifact=manifest["cargo_executable_artifact"];artifact["fresh"]=True
                    raw=(json.dumps(artifact)+"\n"+json.dumps({"reason":"build-finished","success":True})+"\n").encode()
                    (out/"build.stdout").write_bytes(raw)
                    step=next(row for row in manifest["steps"] if row["name"]=="build")
                    step["stdout_bytes"]=len(raw);step["stdout_sha256"]=reader.digest(raw)
                    label="CARGO_EXECUTABLE_ARTIFACT_BINDING"
                (out/(step["name"]+".step.json")).write_text(json.dumps(step))
                (out/"campaign.json").write_text(json.dumps(manifest));pins["expected_manifest_sha256"]=reader.sha(out/"campaign.json")
                with self.assertRaisesRegex(ValueError,label):reader.read_bundle(out,**pins)

    def test_child_resource_observations_do_not_become_producer_cost_or_network_bytes(self):
        value={key:0 for key in ("user_cpu_ns","system_cpu_ns","minor_page_faults","major_page_faults",
               "input_blocks","output_blocks","voluntary_context_switches","involuntary_context_switches","runner_lifetime_max_child_rss_kib")}
        value.update(rss_scope="Linux cumulative maximum over waited children, including setup; not this step's peak or a sum",
                     cpu_scope="whole waited child including all observers, logging and teardown; not producer-only",
                     block_counts_are_network_bytes=False)
        reader.validate_child_resources(value)
        negative=copy.deepcopy(value);negative["user_cpu_ns"]=-1
        with self.assertRaisesRegex(ValueError,"CHILD_RESOURCE_VALUE"):reader.validate_child_resources(negative)
        promoted=copy.deepcopy(value);promoted["block_counts_are_network_bytes"]=True
        with self.assertRaisesRegex(ValueError,"CHILD_RESOURCE_SCOPE"):reader.validate_child_resources(promoted)


if __name__ == "__main__":
    unittest.main()
