"""Source-only admission/model controls; none executes a native or Rust process."""
from __future__ import annotations
import copy
import json
import struct
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from . import paid_faults as subject
from .paid_fault_evidence import clock_shape, layout, budget_flow, native_shape, control_specs
from .build import ROOT

class PaidFaultControls(unittest.TestCase):
    def test_exact_fifteen_faults_have_separate_typed_profiles(self):
        rows=subject.profiles()
        self.assertEqual(len(rows),16)
        self.assertEqual(sum(row["fault"] is not None for row in rows),15)
        self.assertEqual(len({r["name"] for r in rows}),16)
        self.assertEqual([r["name"] for r in rows if r["fault"] and "clock_ordinals" in r["fault"]],
                         ["begin-clock3-persistent-eio"])
        self.assertEqual(sum(r["fault"].get("clock_invalid") is True for r in rows[1:]),2)
        for row in rows:
            subject.admit_profile(row)
            self.assertEqual([clock for _,clock in layout(row)],row["worker_clock_ids"])
            for path,value in ((("domain",),float(row["domain"])),(("in_flight",),False),
                               (("poison",0),False),(("unbound",),True)):
                bad=copy.deepcopy(row);target=bad
                for key in path[:-1]:target=target[key]
                target[path[-1]]=value
                with self.subTest(name=row["name"],path=path),self.assertRaises(ValueError):subject.admit_profile(bad)

    def test_original_zero_target_projection_cannot_gain_a_control(self):
        native,original=subject.input_case()
        self.assertEqual(original["request_hex"],native["request_hex"])
        self.assertEqual(original["name"],"zero-target")
        for field,value in (("gate_stage",1),("signal",1),("delay_ms",0.0),("actions",[{"kind":"replace_parent"}])):
            changed=copy.deepcopy(original);changed[field]=value
            cases=[changed if row["name"]=="zero-target" else row for row in subject.original_cases()]
            with self.subTest(field=field),patch.object(subject,"original_cases",return_value=cases),self.assertRaises(ValueError):
                subject.input_case()

    def test_unbound_native_image_is_rejected_before_any_exec_or_output(self):
        request=bytes.fromhex(subject.input_case()[0]["request_hex"])
        with tempfile.TemporaryDirectory() as folder:
            out=Path(folder)/"out"
            with patch.object(subject,"trace_owned",side_effect=AssertionError("must not execute")):
                with self.assertRaises(ValueError):subject.native_one(b"not an admitted native ELF",request,out,subject.profiles()[0])
            self.assertFalse(out.exists())
        from .paid_fault_evidence import collect, native_input
        payload=struct.pack("<8Q",int.from_bytes(b"WOFIX001","little"),0,0,0,0,0,0,0)+request
        stat_bytes=bytearray(144);struct.pack_into("<I",stat_bytes,24,0x8180);struct.pack_into("<Q",stat_bytes,48,len(payload))
        entries={1:{"sequence":1,"tid":91,"nr":72,"args":[0,1034,0,0,0,0]},
                 3:{"sequence":3,"tid":91,"nr":5,"args":[0,4096,0,0,0,0]},
                 5:{"sequence":5,"tid":91,"nr":17,"args":[0,8192,len(payload),0,0,0]}}
        exits={1:{"sequence":2,"result":15},3:{"sequence":4,"result":0,"stat_bytes_hex":stat_bytes.hex()},
               5:{"sequence":6,"result":len(payload),"read_bytes_hex":payload.hex()}}
        ledger={"root":91,"entries":entries,"exits":exits,"input":payload}
        native_input(ledger,payload)
        for changed in ("seal","type","size","offset","fd","tid","repeated","bytes"):
            bad=copy.deepcopy(ledger)
            if changed=="seal":bad["exits"][1]["result"]=14
            elif changed=="type":
                value=bytearray(stat_bytes);struct.pack_into("<I",value,24,0x2180);bad["exits"][3]["stat_bytes_hex"]=value.hex()
            elif changed=="size":
                value=bytearray(stat_bytes);struct.pack_into("<Q",value,48,len(payload)+1);bad["exits"][3]["stat_bytes_hex"]=value.hex()
            elif changed=="offset":bad["entries"][5]["args"][3]=1
            elif changed=="fd":bad["entries"][5]["args"][0]=1
            elif changed=="tid":bad["entries"][5]["tid"]=92
            elif changed=="repeated":bad["entries"][7]=dict(bad["entries"][5],sequence=7)
            elif changed=="bytes":bad["input"]=payload[:-1]+bytes([payload[-1]^1])
            with self.subTest(input=changed),self.assertRaises(ValueError):native_input(bad,payload)
        # Exercise the collector's pread/read distinction with a complete synthetic lifetime.
        events=[{"sequence":1,"kind":"syscall-entry","tid":91,"nr":59,"args":[0]*6},
                {"sequence":2,"kind":"exec","tid":91,"actual_executable":"/synthetic-never-executed","auxv":{}},
                {"sequence":3,"kind":"syscall-exit","tid":91,"entry":1,"nr":59,"result":0,"kernel_result_before_injection":0},
                {"sequence":4,"kind":"syscall-entry","tid":91,"nr":17,"args":[0,4096,2,0,0,0]},
                {"sequence":5,"kind":"syscall-exit","tid":91,"entry":4,"nr":17,"result":2,"kernel_result_before_injection":2,"read_bytes_hex":"0102"},
                {"sequence":6,"kind":"syscall-entry","tid":91,"nr":60,"args":[0]*6},
                {"sequence":7,"kind":"exit-stop","tid":91,"status":0},
                {"sequence":8,"kind":"terminal","tid":91,"exit_code":0,"signal":None}]
        self.assertEqual(collect(events,b"",b"",native=True)["input"],b"\x01\x02")
        for kind in ("read","offset"):
            changed=copy.deepcopy(events)
            if kind=="read":changed[3]["nr"]=changed[4]["nr"]=0
            else:changed[3]["args"][3]=1
            with self.subTest(kind=kind),self.assertRaises(ValueError):collect(changed,b"",b"",native=True)

    def test_original_invocation_and_environment_are_closed_before_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);binary=root/"binary";binary.write_bytes(b"admission-only file; never executed")
            case=root/"case.jsonl";case.write_bytes((json.dumps(subject.input_case()[1],sort_keys=True,separators=(",",":"))+"\n").encode())
            argv=[str(binary),"--exact",subject.TEST,"--nocapture","--test-threads=1"]
            env={"PATH":"/usr/bin:/bin","TRNM_HIA_WORK_OWNER_CORPUS":str(case)}
            out=root/"out";profile=subject.profiles()[0]
            self.assertEqual(subject.original_arguments(argv,env,profile,False,out),out)
            for args,e,p,private in ((argv[:-1],env,profile,True),
                 (argv,{**env,"LD_PRELOAD":"/foreign"},profile,True),
                 (argv,{**env,"PATH":""},profile,True),
                 (argv,env,profile,1),(argv,env,subject.profiles()[1],False)):
                with self.subTest(args=args,env=e),self.assertRaises(ValueError):
                    subject.original_arguments(args,e,p,private,out)
            case.write_bytes(case.read_bytes()+b"{}\n")
            with self.assertRaises(ValueError):subject.original_arguments(argv,env,profile,True,out)
            self.assertFalse(out.exists())

    def clock_fixture(self,profile,*,native=True):
        # Deliberately synthetic helper input, never an audit artifact.
        plan=layout(profile);calls=[];constructor=profile["name"]=="constructor-clock1-eio"
        main=[("deadline",1),("budget-constructor",1)] if native else [
            ("deadline",1),("intake-constructor",1),("budget-constructor",1)]
        if constructor:main=main[:2]
        for role,tid,kinds in ((1,101,main),(2,102,plan)):
            for ordinal,(_,clock) in enumerate(kinds,1):
                fault=profile["fault"];selected=fault is not None and role in fault["clock_roles"] and ordinal in fault.get("clock_ordinals",[fault.get("clock_when")])
                rule=None if not selected else {"kind":"clock","error":fault.get("clock_error"),
                    "invalid_timespec":fault.get("clock_invalid",False),"original_syscall_skipped":True}
                calls.append({"tid":tid,"role":role,"role_index":0,"role_clock_ordinal":ordinal,
                    "clock_id":clock,"entry":len(calls)*2+10,"exit":len(calls)*2+11,
                    "result":0 if rule is None or rule["invalid_timespec"] else -rule["error"],
                    "injected":rule,"seconds":0 if clock==3 else 1,
                    "nanoseconds":1_000_000_000 if rule and rule["invalid_timespec"] else ordinal*100})
        roles=[{"tid":101,"role":1}]+([] if constructor else ([{"tid":101,"role":4}] if not native else [])+[{"tid":102,"role":2}])
        return {"root":101 if native else 100,"role_history":roles,
                "roster":{101:{"parent":None if native else 100},**({} if native else {100:{"parent":None}}),
                          **({} if constructor else {102:{"parent":101,"clone_entry":1}})},
                "entries":{1:{"actual_clone":{"flags":0x310100,"child_tid":4096}}},
                "clocks":calls,"injections":[{"entry":r["entry"]} for r in calls if r["injected"]]}

    def test_complete_constructor_and_real_fallback_clock_roles(self):
        for profile in subject.profiles():
            for native in (True,False):
                ledger=self.clock_fixture(profile,native=native)
                clock_shape(ledger,profile,native=native,private=not native)
                bad=copy.deepcopy(ledger);bad["clocks"][1]["role_clock_ordinal"]=2.0
                with self.subTest(name=profile["name"],native=native),self.assertRaises(ValueError):
                    clock_shape(bad,profile,native=native,private=not native)
                if not native and profile["name"]!="constructor-clock1-eio":
                    bad=copy.deepcopy(ledger);del bad["clocks"][2]
                    with self.subTest(name=profile["name"]),self.assertRaises(ValueError):
                        clock_shape(bad,profile,native=False,private=True)
        profile=next(p for p in subject.profiles() if p["name"]=="begin-clock3-eio-fallback")
        ledger=self.clock_fixture(profile)
        bad=copy.deepcopy(ledger);del bad["clocks"][3]
        with self.assertRaises(ValueError):clock_shape(bad,profile,native=True,private=False)
        bad=copy.deepcopy(ledger);bad["clocks"].insert(2,copy.deepcopy(bad["clocks"][1]))
        with self.assertRaises(ValueError):clock_shape(bad,profile,native=True,private=False)
        bad=copy.deepcopy(ledger);bad["clocks"][3]["clock_id"]=1
        with self.assertRaises(ValueError):clock_shape(bad,profile,native=True,private=False)

    def model_fixture(self):
        shape={"main":101,"worker":102,"constructor":1_000_000_000,"labels":layout(subject.profiles()[0]),
            "times":{"begin":100,"reserve":1_000_000_400,"work":1_000_000_800,"checkpoint":200,
                     "checkpoint-wall":1_000_001_200,"finish":300,"finish-wall":1_000_001_600,
                     "outer":310,"settle":1_000_002_000}}
        result=budget_flow(shape,subject.profiles()[0])
        owner=[0]*64;owner[0]=int.from_bytes(b"PCOWN001","little")
        owner[4:14]=[1,210,1,0,1,210,1,200,1,10];owner[20:22]=[102,2]
        flow=result["flow"];seconds,nanos=divmod(result["updated"],1_000_000_000)
        epoch=[0x3130303055504350,0,result["credit"],0,seconds,nanos,0,0,0,1,2_000_000_000,0,
               *[flow[k] for k in ("credited_refill_ns","discarded_refill_ns","booked_reservation_ns",
                 "live_debited_cpu_ns","settlement_residual_cpu_ns","settled_full_cpu_ns","settlement_discard_ns")],0]
        frame={"header":{"fixture":1,"host_fixture":1,"main_tid":101,"worker_tid":102,"joins":1,
                        "domain":1,"code":7,"post_checks":5,"aggregate_samples":2},
               "progress":[],"product_bytes":0,"paid":{"owner":owner,"epoch":epoch,
                "binding":[0,3,3,2,1,0,0,0,1,1],"meta":[0,0,3,3,0,0,0,0],"global_poison":0,"request_poison":0}}
        return shape,frame,result

    def test_same_thread_budget_counts_real_refill_reserve_live_and_residual_once(self):
        shape,frame,result=self.model_fixture()
        self.assertEqual(result,{"credit":1_999_999_990,"updated":1_000_002_000,"in_flight":0,
            "flow":{"initial_credit_ns":"2000000000","credited_refill_ns":200,"discarded_refill_ns":300,
                    "booked_reservation_ns":0,"live_debited_cpu_ns":200,"settlement_residual_cpu_ns":10,
                    "settled_full_cpu_ns":210,"settlement_discard_ns":0}})
        native_shape(frame,shape,subject.profiles()[0])
        bad=copy.deepcopy(frame);bad["paid"]["epoch"][2]+=1;bad["paid"]["epoch"][12]+=1
        with self.assertRaises(ValueError):native_shape(bad,shape,subject.profiles()[0])

    def test_native_some_and_cleanup_receipts_are_bound_to_actual_cpu_intervals(self):
        shape,frame,_=self.model_fixture()
        for area,index,value in (("owner",4,0),("owner",9,211),("owner",11,201),
             ("owner",19,1),("owner",20,101),("owner",22,1),("binding",4,0),
             ("meta",2,2),("epoch",6,1),("epoch",13,301),("epoch",17,211)):
            changed=copy.deepcopy(frame);changed["paid"][area][index]=value
            with self.subTest(area=area,index=index),self.assertRaises(ValueError):
                native_shape(changed,shape,subject.profiles()[0])

    def test_native_and_original_full_raw_control_rosters_are_distinct(self):
        native=control_specs(True);original=control_specs(False)
        self.assertEqual((len(native),sum(x[2] for x in native)),(27,2))
        self.assertEqual((len(original),sum(x[2] for x in original)),(27,2))
        self.assertEqual(native[0][1],"normal-zero-target")
        self.assertEqual(original[0][1],"private-raw-positive")
        self.assertEqual([r[1] for r in native[1:16]],[p["name"] for p in subject.profiles()[1:]])
        self.assertEqual([r[1] for r in original[1:16]],[p["name"] for p in subject.profiles()[1:]])
        self.assertEqual(len({r[0] for r in native}),27)
        self.assertEqual(native[-1],("positive-restored-fallback","begin-clock3-eio-fallback",True))

if __name__=="__main__":unittest.main()
