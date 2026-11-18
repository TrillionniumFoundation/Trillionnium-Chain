"""Non-provisioning production Work controller admission controls.

Synthetic frames below test validation only. They are never executed and never
stand for an actual fixed-parent, Node, Paid, or service qualification.
"""
from __future__ import annotations
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
if not __debug__:
    raise RuntimeError("Production Work controls refuse optimized Python")
MODULE_PATH=Path(__file__).with_name("qualify_production.py")
_spec=importlib.util.spec_from_file_location("hia.platform.work_owner.qualify_production",MODULE_PATH)
subject=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(subject)

class ProductionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case=subject.cases.corpus()[0]
        if cls.case["name"]!="dense-positive":raise ValueError("Corpus changed")
        cls.service="trnm-hia-work-123-1-native-host-99.service"
        cls.image="a"*64
        cls.namespace={k:k+":[123]" for k in subject.NAMESPACES}
        cls.pid=101
        cls.worker=102
        cls.uid=1000
        cls.parent=(2,3,0)

    def header(self):
        values=[0]*64
        rows={"magic":int.from_bytes(b"HIAWO001","little"),"fixture":0,"domain":0,"code":0,
              "work_code":0,"progress_count":1099,"worker_host_calls":1101,"pre_checks":3,
              "post_checks":5,"aggregate_samples":2,"main_tid":self.pid,"worker_tid":self.worker,
              "generation":1,"joins":1,"alive_clocks":2200,"gates":0,"post_sample_error":0,
              "parent_dev":2,"parent_ino":3,"parent_uid":0,"cpu_quota":25000,"cpu_period":100000,
              "memory_limit":2147483648,"pids_limit":256,"boot_bytes":36,"host_fixture":0,
              "acquirer_tid":self.pid}
        for index,name in enumerate(subject.native_io.FIELDS):values[index]=rows[name]
        values[44]=16384
        return values

    def receipts(self):
        before=[0]*32
        before[0]=int.from_bytes(b"HIAKR001","little")
        before[2:8]=[0,1,3,1,1,1]
        before[8:14]=[10,20,3,40,64,2]
        before[18:24]=[39,60,322,0,0,self.pid]
        before[24]=8192
        before[28:31]=[3,0,1]
        after=before.copy()
        after[2:8]=[0,2,5,2,2,1]
        after[8:14]=[14,25,4,42,100,3]
        after[14:18]=[4,5,1,2]
        worker=before.copy()
        worker[2:8]=[0,1102,1104,1,0,0]
        worker[23]=self.worker
        worker[28:31]=[0,0,1]
        return before,after,worker

    def raw(self,headers=None,receipts=None):
        words=self.header() if headers is None else headers
        raw=bytearray(struct.pack("<64Q",*words))
        request=bytes.fromhex(self.case["request_hex"])
        raw[256:352]=request[:96]
        for receipt in self.receipts() if receipts is None else receipts:
            raw.extend(struct.pack("<32Q",*receipt))
        for row in self.case["progress"]:raw.extend(struct.pack("<5Q",*row))
        raw.extend(bytes.fromhex(self.case["product_hex"]))
        return bytes(raw)

    def observations(self):
        return {tid:{"tid":tid,"tgid":self.pid,"membership":"0::/trnmponpublic.slice/"+self.service,
                     "namespaces":dict(self.namespace),"executable_sha256":self.image,"uid":self.uid}
                for tid in (self.pid,self.worker)}

    def admit(self,raw=None,observations=None,**overrides):
        values={"namespace":self.namespace,"image_hash":self.image,"uid":self.uid}
        values.update(overrides)
        return subject.validate_native(self.raw() if raw is None else raw,self.case,self.pid,
            self.observations() if observations is None else observations,self.parent,self.service,**values)

    def lease(self):
        return {"schema":"trnm-ci-public-fixture-parent-binding-v1","seal_sha256":"b"*64,
                "seal_file":"/run/trnm-test/seal.json","parent_identity":{"parent":{"dev":2,"ino":3,"uid":0}},
                "creator_service":"trnm-hia-host-123-1-native-host-88.service",
                "current_service":"trnm-hia-host-123-1-native-host-88.service",
                "host_readiness_only":True,"consensus_or_model_authority":False}

    def priors(self):
        base=self.lease()
        host={"creator_service":base["creator_service"],"parent_lease":copy.deepcopy(base),
              "final_parent_lease":copy.deepcopy(base)}
        resource={**base,"current_service":"trnm-hia-resource-123-1-native-host-89.service"}
        return host,{"parent_lease":resource,"final_parent_lease":copy.deepcopy(resource)}

    def test_01_service_names_are_exact_owned_names(self):
        subject.validate_service(self.service)
        for name in ("x"+self.service,self.service+"/x",self.service+"\n",True,123,
                     "trnm-hia-work-123-1-bad.job-1.service","trnm-hia-work-123-1--1.service"):
            with self.subTest(name=name),self.assertRaises(ValueError):subject.validate_service(name)
        self.assertEqual(subject.service_name({"GITHUB_RUN_ID":"123","GITHUB_RUN_ATTEMPT":"1","GITHUB_JOB":"native-host"},99),self.service)

    def test_02_service_profile_never_changes_the_fixed_budget(self):
        args=subject.service_argv(self.service,Path("/tmp/build"),Path("/tmp/lease"),
                                 Path("/tmp/lease/resource"),Path("/tmp/lease/work"),1000,1000,{})
        self.assertEqual(args[:3],["sudo","-n","systemd-run"])
        for flag in ("--slice=trnmponpublic.slice","--property=Delegate=no","--property=NoNewPrivileges=yes",
                     "--property=CapabilityBoundingSet=","--uid=1000","--gid=1000","--service-type=exec"):
            self.assertIn(flag,args)
        self.assertFalse(any("CPUQuota" in a or "MemoryMax" in a or "TasksMax" in a for a in args))
        self.assertNotIn("start",args)
        for uid,gid in ((0,1000),(True,1000),(1000,False),(1000,-1)):
            with self.subTest(uid=uid,gid=gid),self.assertRaises(ValueError):
                subject.service_argv(self.service,Path("/b"),Path("/l"),Path("/r"),Path("/o"),uid,gid,{})

    def test_03_public_entry_rejects_local_and_optimized_before_any_output(self):
        with tempfile.TemporaryDirectory(prefix="hia-work-prod-cli-") as td:
            out=Path(td)/"never-created"
            arguments=["--build",str(Path(td)/"build"),"--lease-receipts",td,
                       "--resource-receipts",str(Path(td)/"resource"),"--output",str(out)]
            environment={k:v for k,v in os.environ.items() if not k.startswith(("GITHUB_","RUNNER_","TRNM_","PYTHON"))}
            environment["PYTHONDONTWRITEBYTECODE"]="1"
            environment["PYTHONPATH"]=str(subject.ROOT)
            environment["CI"]="false"
            for flags,marker in ((["-B"],"HOSTED_CI_ONLY_NO_LOCAL_PROVISION"),
                                 (["-B","-O"],"refuses optimized Python"),
                                 (["-B","-OO"],"refuses optimized Python")):
                done=subprocess.run([sys.executable,*flags,str(MODULE_PATH),*arguments],cwd=td,
                    env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
                evidence=os.environ.get("HIA_WORK_PRODUCTION_TEST_EVIDENCE")
                if evidence:
                    directory=Path(evidence)/("python-"+("normal" if len(flags)==1 else flags[-1].replace("-","")))
                    directory.mkdir()
                    (directory/"stdout.raw").write_bytes(done.stdout)
                    (directory/"stderr.raw").write_bytes(done.stderr)
                    (directory/"receipt.json").write_text(json.dumps({"argv":done.args,"exit_code":done.returncode,
                        "expected_refusal":marker,"output_created":out.exists()},sort_keys=True)+"\n")
                self.assertNotEqual(done.returncode,0)
                self.assertIn(marker,done.stderr.decode())
                self.assertFalse(out.exists())

    def test_04_source_and_build_shapes_reject_before_execution(self):
        with patch.object(subject,"__file__","/outside/qualify_production.py"):
            with self.assertRaisesRegex(ValueError,"HOSTED_MODULE_AT_FINAL_SOURCE_REQUIRED"):
                subject.source_inputs()
        with tempfile.TemporaryDirectory(prefix="hia-work-prod-build-") as td:
            with self.assertRaisesRegex(ValueError,"CANONICAL_COMPLETE_BUILD_DIRECTORY_REQUIRED"):
                subject.validate_build(Path(td))
            alternate=Path(td)/"alternate";alternate.mkdir()
            (Path(td)/"build").symlink_to(alternate,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,"CANONICAL_COMPLETE_BUILD_DIRECTORY_REQUIRED"):
                subject.validate_build(Path(td)/"build")

    def test_05_prior_lease_must_be_exact_same_root_seal(self):
        host,resource=self.priors();current={**host["parent_lease"],"current_service":self.service}
        subject.bind_prior(host,resource,current,self.service)
        mutations=(("seal_sha256","c"*64),("seal_file","/run/other/seal"),("creator_service","trnm-hia-host-124-1-native-host-88.service"),
                   ("host_readiness_only",1),("consensus_or_model_authority",0),("current_service","trnm-hia-work-124-1-native-host-99.service"))
        for key,value in mutations:
            altered=copy.deepcopy(current);altered[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                subject.bind_prior(host,resource,altered,self.service)
        altered=copy.deepcopy(current);altered["parent_identity"]["parent"]["ino"]=3.0
        with self.assertRaises(ValueError):subject.bind_prior(host,resource,altered,self.service)

    def test_06_previous_and_final_leases_cannot_diverge(self):
        host,resource=self.priors();current={**host["parent_lease"],"current_service":self.service}
        for where in ("host","resource"):
            changed=copy.deepcopy(host if where=="host" else resource)
            changed["final_parent_lease"]["parent_identity"]["parent"]["uid"]=False
            with self.subTest(where=where),self.assertRaises(ValueError):
                subject.bind_prior(changed if where=="host" else host,changed if where=="resource" else resource,current,self.service)

    def test_07_synthetic_full_frame_accepts_only_as_validation_fixture(self):
        got=self.admit()
        self.assertEqual(got["product_bytes"],16384)
        self.assertEqual(got["header"]["worker_tid"],self.worker)

    def test_08_actual_lifetime_and_fresh_boundaries_cannot_be_removed(self):
        for key,value in (("fixture",1),("host_fixture",1),("domain",3),("code",1),("work_code",1),
                          ("post_sample_error",1),("main_tid",103),("worker_tid",0),("worker_tid",101),
                          ("acquirer_tid",102),("generation",2),("joins",0),("worker_host_calls",1100),
                          ("pre_checks",2),("post_checks",4),("aggregate_samples",1),("alive_clocks",2199),("gates",1)):
            words=self.header();words[subject.native_io.FIELDS.index(key)]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):self.admit(raw=self.raw(words))

    def test_09_budget_parent_and_whole_product_are_not_metadata_only(self):
        for key,value in (("parent_dev",3),("parent_ino",4),("parent_uid",1000),
                          ("cpu_quota",100000),("cpu_period",50000),("memory_limit",4294967296),("pids_limit",512)):
            words=self.header();words[subject.native_io.FIELDS.index(key)]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.admit(raw=self.raw(words))
        raw=self.raw()
        for other in (raw[:-1],raw+b"\0",raw[:-1]+bytes([raw[-1]^1])):
            with self.assertRaises(ValueError):self.admit(raw=other)

    def test_10_challenge_task_ticket_and_every_progress_point_are_bound(self):
        for at in (256,288,320,1280,1280+1098*40):
            raw=bytearray(self.raw());raw[at]^=1
            with self.subTest(offset=at),self.assertRaises(ValueError):self.admit(raw=bytes(raw))

    def test_11_observations_must_name_exact_live_roster(self):
        for which in ("missing","extra","same","bool_tid","float_tgid","bool_uid","outside","prefix-lookalike"):
            obs=self.observations()
            if which=="missing":obs.pop(self.worker)
            elif which=="extra":obs[103]=dict(obs[self.worker],tid=103)
            elif which=="same":obs[self.worker]["tid"]=self.pid
            elif which=="bool_tid":obs[self.pid]["tid"]=True
            elif which=="float_tgid":obs[self.pid]["tgid"]=101.0
            elif which=="bool_uid":obs[self.pid]["uid"]=True
            elif which=="outside":obs[self.worker]["membership"]="0::/somewhere"
            else:obs[self.worker]["membership"]+="other"
            with self.subTest(which=which),self.assertRaises(ValueError):self.admit(observations=obs)

    def test_12_namespace_and_actual_executable_are_bound_per_thread(self):
        for field in (*subject.NAMESPACES,"image"):
            obs=self.observations()
            if field=="image":obs[self.worker]["executable_sha256"]="b"*64
            else:obs[self.worker]["namespaces"][field]=field+":[456]"
            with self.subTest(field=field),self.assertRaises(ValueError):self.admit(observations=obs)
        for arguments in ({"namespace":{**self.namespace,"mnt":True}},{"uid":1000.0},{"image_hash":"a"*63}):
            with self.assertRaises(ValueError):self.admit(**arguments)

    def test_13_resource_samples_and_clone_baseline_are_complete(self):
        for row,index,value in ((0,4,2),(1,5,1),(2,3,1101),(2,4,1103),(0,23,self.worker),
                                (2,23,self.pid),(0,28,2),(1,29,1),(2,30,0),(0,22,1),(1,25,1)):
            receipts=[r.copy() for r in self.receipts()];receipts[row][index]=value
            with self.subTest(row=row,index=index),self.assertRaises(ValueError):self.admit(raw=self.raw(receipts=receipts))

    def test_14_resource_delta_preserves_all_four_checked_fields(self):
        for which in ("rewind","bad_delta","worker_changed","baseline_nonzero"):
            receipts=[r.copy() for r in self.receipts()]
            if which=="rewind":receipts[1][8]=9
            elif which=="bad_delta":receipts[1][17]=1
            elif which=="worker_changed":receipts[2][9]+=1
            else:receipts[0][14]=1
            with self.subTest(which=which),self.assertRaises(ValueError):self.admit(raw=self.raw(receipts=receipts))

    def test_15_inside_failure_still_collects_both_final_fences(self):
        class Primary(RuntimeError):pass
        class Observation:
            def capture(self,label,service):return {"label":label}
            def validate(self,row,**kwargs):return ["changed"] if "after" in row["label"] else []
        with tempfile.TemporaryDirectory(prefix="hia-work-prod-finally-") as td:
            root=Path(td);out=root/"out";out.mkdir()
            subject.write(root/"source.json",{"source":1})
            calls=[]
            def verify(*args,**kwargs):
                calls.append(1)
                if len(calls)>1:raise ValueError("synthetic final source failure")
                return {"source":1}
            with patch.object(subject.host,"hosted_context"),patch.object(subject,"source_inputs",return_value={}),\
                 patch.object(subject,"ROOT",Path.cwd()),patch.object(subject,"directories",return_value=(root,root/"resource",out)),\
                 patch.object(subject.resource_host,"ci_modules",return_value=(Observation(),None,verify)),\
                 patch.object(subject,"native_positive",side_effect=Primary("native primary")),\
                 patch.dict(os.environ,{"TRNM_EXPECTED_SOURCE_SHA":"a"*40}):
                with self.assertRaisesRegex(Primary,"native primary"):
                    subject.inside(root/"build",root,root/"resource",out,self.service)
            result=json.loads((out/"inside-report.json").read_bytes())
            self.assertEqual(len(calls),2)
            self.assertEqual(result["status"],"FAIL")
            self.assertEqual(len(result["cleanup_errors"]),2)
            self.assertTrue(any(e.startswith("HOST_AFTER:") for e in result["cleanup_errors"]))
            self.assertTrue(any(e.startswith("SOURCE_AFTER:") for e in result["cleanup_errors"]))
            self.assertIn("native primary",result["failure"])

    def test_16_prior_success_refusal_precedes_any_service_command(self):
        with tempfile.TemporaryDirectory(prefix="hia-work-prod-prior-") as td:
            root=Path(td);out=root/"not-created"
            with patch.object(subject.host,"hosted_context"),patch.object(subject,"source_inputs",return_value={}),\
                 patch.object(subject,"ROOT",Path.cwd()),patch.object(subject,"directories",return_value=(root,root/"resource",out)),\
                 patch.object(subject,"validate_build",return_value=(b"ELF",{},"a"*64)),\
                 patch.object(subject.resource_host,"ci_modules",return_value=(None,None,lambda *a,**k:{"source":1})),\
                 patch.object(subject.resource_host,"previous_host",side_effect=ValueError("missing prior success")),\
                 patch.object(subject.subprocess,"run",side_effect=AssertionError("privileged call reached")),\
                 patch.dict(os.environ,{"TRNM_EXPECTED_SOURCE_SHA":"a"*40}):
                with self.assertRaisesRegex(ValueError,"missing prior success"):
                    subject.outer(root/"build",root,root/"resource",out)
            self.assertFalse(out.exists())


    def make_capture(self,directory):
        image=b"synthetic image for capture-reader controls only"
        built={"source_inputs":{}}
        raw=self.raw();decoded=subject.native_io.decode(raw)
        record={
            "schema":"trnm.hia.production-work-native-positive.v1","status":"PASS",
            "qualified_scope":subject.SCOPE,"source_inputs":{},"native_build_source_inputs":{},
            "executable_sha256":subject.digest(image),"build_report_sha256":"a"*64,"fixture":False,
            "independent_complete_syscall_trace":"NOT_RUN","normal_production_CLOCK_fault_qualified":False,
            "Node_or_Paid_embedding_qualified":False,"original_4s_16_service_qualified":False,
            "original_1800s_history_qualified":False,"retirement_accepted":False,"native_deadline_seconds":4,
            "observed_actual_tasks":[dict(row,executable_sha256=subject.digest(image)) for row in self.observations().values()],"controller_namespaces":self.namespace,
            "actual_process_pid":self.pid,"actual_fixed_parent_positive":True,"decoded":decoded,
            "parent_identity":{"dev":2,"ino":3,"uid":0},"source_after":"MATCH","cleanup_errors":[],
            "exit_code":0,"elapsed_wall_ns":1,
        }
        for name,data in (("stdin",bytes.fromhex(self.case["request_hex"])),("stdout",raw),("stderr",b"")):
            (directory/(name+".raw")).write_bytes(data)
            record[name]={"bytes":len(data),"sha256":subject.digest(data)}
        (directory/"native.json").write_text(json.dumps(record,sort_keys=True)+"\n")
        return record,image,built

    def capture_admit(self,directory,image,built):
        return subject.read_native_capture(directory,image,built,"a"*64,{},self.service,self.parent,self.uid)

    def test_17_complete_boot_extent_is_mandatory(self):
        for value in (0,35,37):
            words=self.header();words[subject.native_io.FIELDS.index("boot_bytes")]=value
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,"BOOT_ID_EXTENT"):
                self.admit(raw=self.raw(words))

    def test_18_complete_capture_reader_accepts_only_as_synthetic_control(self):
        with tempfile.TemporaryDirectory(prefix="hia-work-capture-control-") as td:
            directory=Path(td);record,image,built=self.make_capture(directory)
            self.assertEqual(self.capture_admit(directory,image,built),record)

    def test_19_raw_cannot_be_omitted_or_coherently_replaced(self):
        for mutation in ("missing-stdin","missing-stdout","missing-stderr","input","stderr","product","boot"):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory(prefix="hia-work-capture-control-") as td:
                directory=Path(td);record,image,built=self.make_capture(directory)
                if mutation.startswith("missing-"):
                    (directory/(mutation.removeprefix("missing-")+".raw")).unlink()
                else:
                    name="stdin" if mutation=="input" else "stderr" if mutation=="stderr" else "stdout"
                    data=bytearray((directory/(name+".raw")).read_bytes())
                    if mutation=="stderr":data.extend(b"unexpected error")
                    elif mutation=="boot":
                        struct.pack_into("<Q",data,8*subject.native_io.FIELDS.index("boot_bytes"),0)
                    else:data[-1]^=1
                    (directory/(name+".raw")).write_bytes(data)
                    record[name]={"bytes":len(data),"sha256":subject.digest(data)}
                    if name=="stdout":record["decoded"]=subject.native_io.decode(bytes(data))
                    (directory/"native.json").write_text(json.dumps(record,sort_keys=True)+"\n")
                with self.assertRaises((ValueError,OSError)):
                    self.capture_admit(directory,image,built)

    def test_20_scope_and_exact_observation_types_are_not_promoted(self):
        mutations=(("fixture",0),("native_deadline_seconds",4.0),("exit_code",False),
                   ("elapsed_wall_ns",True),("actual_process_pid",101.0),
                   ("retirement_accepted",True),("original_4s_16_service_qualified",True),
                   ("Node_or_Paid_embedding_qualified",True),("source_after","CHANGED"),
                   ("executable_sha256","f"*64),("build_report_sha256","f"*64),
                   ("unknown_authority",True))
        for key,value in mutations:
            with self.subTest(key=key),tempfile.TemporaryDirectory(prefix="hia-work-capture-control-") as td:
                directory=Path(td);record,image,built=self.make_capture(directory)
                record[key]=value
                (directory/"native.json").write_text(json.dumps(record,sort_keys=True)+"\n")
                with self.assertRaises(ValueError):self.capture_admit(directory,image,built)

    def test_21_cache_and_actual_task_roster_are_reread(self):
        for mutation in ("decoded","empty","duplicate","uid","parent"):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory(prefix="hia-work-capture-control-") as td:
                directory=Path(td);record,image,built=self.make_capture(directory)
                if mutation=="decoded":record["decoded"]["header"]["boot_bytes"]=0
                elif mutation=="empty":record["observed_actual_tasks"]=[]
                elif mutation=="duplicate":record["observed_actual_tasks"][1]=record["observed_actual_tasks"][0].copy()
                elif mutation=="uid":record["observed_actual_tasks"][1]["uid"]=1001
                else:record["parent_identity"]["ino"]=4
                (directory/"native.json").write_text(json.dumps(record,sort_keys=True)+"\n")
                with self.assertRaises(ValueError):self.capture_admit(directory,image,built)

    def test_22_capture_aliases_and_duplicate_fields_are_refused(self):
        for mutation in ("symlink","hardlink","duplicate-json","nonfinite"):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory(prefix="hia-work-capture-control-") as td:
                directory=Path(td);record,image,built=self.make_capture(directory)
                if mutation in ("symlink","hardlink"):
                    original=directory/"stdout.raw";other=directory/"saved-stdout.raw"
                    original.rename(other)
                    if mutation=="symlink":original.symlink_to(other)
                    else:os.link(other,original)
                else:
                    text=(directory/"native.json").read_text()
                    text=("{\"status\":\"PASS\","+text[1:]) if mutation=="duplicate-json" else text.replace('"elapsed_wall_ns": 1','"elapsed_wall_ns": NaN')
                    (directory/"native.json").write_text(text)
                with self.assertRaises((ValueError,OSError)):self.capture_admit(directory,image,built)

if __name__=="__main__":
    unittest.main()
