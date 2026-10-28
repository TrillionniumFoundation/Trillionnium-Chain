#!/usr/bin/env python3
"""Pure orchestration controls; these never fabricate or execute proof work."""
import json
from pathlib import Path
import tempfile
import unittest
import runner

class Controls(unittest.TestCase):
    def test_exact_original_leaf_and_contiguous_join_graph(self):
        levels=runner.batches();known=set()
        self.assertEqual(len(levels[0]),62)
        for level in levels:
            for t in level:
                a,m,b=(t[k] for k in ("start","split","end"))
                if t["op"]=="lift":self.assertEqual((m,b),(a+1,a+1))
                else:
                    self.assertIn((a,m),known);self.assertIn((m,b),known)
                self.assertNotIn((a,b),known);known.add((a,b))
        self.assertEqual(len(known),123);self.assertIn((0,62),known)
        self.assertEqual(sum(t["op"]=="join" for level in levels for t in level),61)
    def test_original_policy_and_unchanged_budget(self):
        p=runner.policy();self.assertEqual(p["budgets"]["complete_new_recursion_work_stop_seconds"],3500)
        self.assertEqual(p["budgets"]["complete_new_recursion_outer_seconds"],3600)
        self.assertFalse(p["additional_pow"]);self.assertFalse(p["groth16_allowed"])
    def test_duplicate_json_is_not_last_key_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"value.json";p.write_text('{"complete":false,"complete":true}')
            with self.assertRaises(ValueError):runner.read_json(p)
    def test_nonfinite_json_and_nonregular_inputs_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"value.json"
            for value in ('NaN','Infinity','-Infinity','1e9999','-1e9999'):
                p.write_text('{"cost":'+value+'}')
                with self.assertRaises(ValueError):runner.read_json(p)
            q=Path(directory)/"link";q.symlink_to(p)
            with self.assertRaises((ValueError,OSError)):runner.read_json(q)
    def test_native_log_duplicates_and_overflow_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/"native.log"
            for value in ('{"schema":"reader-control","cost":1e9999}',
                          '{"schema":"reader-control","cost":0,"cost":1}',
                          '{"schema":"reader-control"}\n{"schema":"reader-control"}'):
                p.write_text(value)
                with self.assertRaises(ValueError):runner.read_single_result(p,"reader-control")
    def test_audit_reader_rejects_substituted_cases_and_unmeasured_costs(self):
        # Shape-only negative controls: no fixture here claims an actual proof.
        base={"schema":"pon-w1-succinct-audit-v1","all_tested_rejected":True,
              "actual_complete_certificate_positive_verified":True,
              "global_worst_invalid_proven":False,"consensus_authority":False,
              "cases":[{"case":name,"rejected":True,"wall_ns":0,"process_cpu_ns":0,
                        "error":"synthetic reader boundary only"} for name in sorted(runner.AUDIT_CASES)],
              "certificate_cases":[{"case":name,"rejected":True,"wall_ns":0,"process_cpu_ns":0,
                        "error":"synthetic reader boundary only"} for name in sorted(runner.CERTIFICATE_CASES)]}
        for key,bad in (("case","foreign_case"),("rejected",False),("wall_ns",-1),
                        ("wall_ns",float("inf")),("process_cpu_ns",True),("error","")):
            changed=json.loads(json.dumps(base));changed["cases"][0][key]=bad
            with self.assertRaises(ValueError):runner.checked_audit(changed)
    def test_invalid_terminal_cannot_close_stage(self):
        row={"schema":"pon-w1-segment-worker-process-v1","returncode":0,"child_reaped":True,
             "source_sha":"a"*40,"timeout_seconds":300,"wall_seconds":1.,
             "user_cpu_seconds":1.,"system_cpu_seconds":0.}
        runner.terminal(row,"a"*40)
        for key,bad in [("returncode",1),("child_reaped",False),("source_sha","b"*40),
                        ("timeout_seconds",301),("wall_seconds",301.),("user_cpu_seconds",float("inf")),
                        ("system_cpu_seconds",True)]:
            changed=dict(row);changed[key]=bad
            with self.assertRaises(ValueError):runner.terminal(changed,"a"*40)
    def test_measured_nanoseconds_refuse_negative_boolean_and_nonfinite(self):
        for value in (-1,True,float("nan"),float("inf"),None,"1"):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):runner.nanosecond_costs({"elapsed":value},"elapsed")
    def test_actual_tcp_component_records_refuse_cost_and_terminal_substitution(self):
        # This uses actual cheap TCP bytes and actual supervisors. It creates
        # no native or synthetic Succinct proof and never calls final report.
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);(out/"loopback").mkdir();payload=out/"component-only.bin"
            payload.write_bytes(b"transport-reader-control; never a proof\n"*64)
            expected=runner.digest(payload);record={}
            runner._transfer(payload,expected,out/"loopback/transport",record)
            runner.check_transport(out,record,expected)
            paths=[out/"loopback/transport/transport.json",
                   out/"loopback/transport/sender/supervisor.json"]
            originals={p:p.read_bytes() for p in paths}
            for key in ("negative_wall","negative_cpu","failed_child"):
                with self.subTest(mutation=key):
                    changed=json.loads(json.dumps(record))
                    if key=="negative_wall":changed["observed_wall_ns"]=-1
                    elif key=="negative_cpu":changed["parent_observer_cpu_ns"]=-1
                    else:
                        changed["roles"]["sender"]["process"]["exit_code"]=1
                        paths[1].write_text(json.dumps(changed["roles"]["sender"]["process"]))
                    paths[0].write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):runner.check_transport(out,changed,expected)
                    for path,raw in originals.items():path.write_bytes(raw)
    def test_after_cleanup_file_anchor_refuses_changed_missing_and_extra_bytes(self):
        # A byte-inventory component only; these dummy files cannot pass the
        # native receipt/certificate/process validators and confer no authority.
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory)
            for relative in runner.LOOPBACK_FILES:
                path=out/"loopback"/relative;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(b"not-a-proof\n")
            material={"schema":"pon-w1-succinct-loopback-output-material-v1",
                      "files":runner.loopback_inventory(out),"complete_proof_authority":False}
            runner.write(out/"loopback-output-material.json",material)
            printed={"schema":"pon-w1-succinct-loopback-v1","outcome":"complete","output_files":16,
                     "output_material":runner.digest(out/"loopback-output-material.json")}
            (out/"loopback.stdout.log").write_text(json.dumps(printed)+"\n")
            phase={"owned_process_group_empty":True}
            target=out/"loopback/result.json";target.write_bytes(b"changed\n")
            with self.assertRaises(ValueError):runner.check_loopback_anchor(out,phase)
            target.write_bytes(b"not-a-proof\n");target.unlink()
            with self.assertRaises(ValueError):runner.check_loopback_anchor(out,phase)
            target.write_bytes(b"not-a-proof\n");(out/"loopback/extra").write_bytes(b"unaccounted")
            with self.assertRaises(ValueError):runner.check_loopback_anchor(out,phase)

if __name__=="__main__":
    unittest.main(verbosity=2)
