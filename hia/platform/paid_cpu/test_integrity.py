"""Concrete source, ABI, original-entry and owned-process refusal controls."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from .build import ROOT,HERE,source_manifest,validate_source_bindings,validate_layout,read_json
from .cases import owner_cases,boundary_cases,fault_cases,original_fault_cases
from .native_io import frame,plan_from_frame
from .dependency import environment,FORBIDDEN
from .rust_oracle import target_directory
from .owned_ptrace import run

def bad_bindings():
 current=source_manifest()
 def base():return {"source_inputs":copy.deepcopy(current),"build":{"source_inputs":copy.deepcopy(current)}}
 key="hia/platform/paid_cpu/rust_reference.rs"
 cases=[]
 a=base();a.pop("source_inputs");cases.append(("missing-top",a))
 a=base();a["build"].pop("source_inputs");cases.append(("missing-build",a))
 a=base();a["source_inputs"].pop(key);cases.append(("top-omits-original-hook",a))
 a=base();a["build"]["source_inputs"].pop(key);cases.append(("build-omits-original-hook",a))
 a=base();a["source_inputs"].pop(key);a["build"]["source_inputs"].pop(key);cases.append(("both-omit-original-hook",a))
 shared="hia/platform/thread_cpu/trace_audit.py"
 a=base();a["source_inputs"].pop(shared);a["build"]["source_inputs"].pop(shared);cases.append(("both-omit-shared-parser",a))
 a=base();a["source_inputs"]["invented"]={"bytes":0,"sha256":"0"*64};a["build"]["source_inputs"]=copy.deepcopy(a["source_inputs"]);cases.append(("both-add-unbound-source",a))
 a=base();a["source_inputs"][key]["sha256"]="0"*64;a["build"]["source_inputs"]=copy.deepcopy(a["source_inputs"]);cases.append(("both-substitute-source",a))
 return current,cases

class PaidCpuIntegrity(unittest.TestCase):
 def test_complete_current_source_set_and_omission_refusals(self):
  current,cases=bad_bindings()
  self.assertEqual(validate_source_bindings({"source_inputs":current,"build":{"source_inputs":current}}),current)
  for name,value in cases:
   with self.subTest(name=name),self.assertRaisesRegex(ValueError,"complete source sets differ"):validate_source_bindings(value)

 def test_public_original_cli_rejects_bad_source_before_cargo_or_copy(self):
  _,cases=bad_bindings()
  with tempfile.TemporaryDirectory(prefix="paid-source-refusals-") as temp:
   base=Path(temp)
   for name,value in cases:
    with self.subTest(name=name):
     bundle=base/(name+"-bundle");bundle.mkdir();(bundle/"native-comparison.json").write_text(json.dumps(value))
     output=base/(name+"-output")
     env={"PATH":"","PYTHONDONTWRITEBYTECODE":"1","PYTHONPATH":str(ROOT)}
     process=subprocess.run([sys.executable,"-B","-m","hia.platform.paid_cpu.rust_oracle",
       "--bundle",str(bundle),"--output",str(output)],cwd=ROOT,capture_output=True,env=env,timeout=30)
     self.assertNotEqual(process.returncode,0)
     self.assertIn("complete source sets differ",(process.stdout+process.stderr).decode())
     self.assertFalse((output/"isolated-source").exists())
     self.assertFalse((output/"cargo-original-test-build").exists())
     self.assertFalse((output/"original-test-binary").exists())

 def test_optimized_public_entries_refuse_before_execution(self):
  with tempfile.TemporaryDirectory(prefix="paid-optimized-refusals-") as temp:
   for module in ("build","qualify","rust_oracle"):
    with self.subTest(module=module):
     process=subprocess.run([sys.executable,"-O","-B","-m","hia.platform.paid_cpu."+module,"--help"],
      cwd=ROOT,capture_output=True,env={"PATH":"","PYTHONDONTWRITEBYTECODE":"1","PYTHONPATH":str(ROOT)},timeout=30)
     self.assertNotEqual(process.returncode,0);self.assertIn("refuses optimized Python",process.stderr.decode())

 def test_work_plan_has_no_counter_identity_or_outcome_input(self):
  plan=owner_cases()[0]["plan"]
  self.assertEqual(plan_from_frame(frame(plan)),plan)
  for field in ("measured_ns","monotonic_ns","tid","generation","joined","successful"):
   changed=copy.deepcopy(plan);changed[field]=1
   with self.subTest(field=field),self.assertRaises(ValueError):frame(changed)
  for workers in (0,3,5,6,7,9):
   for profile in (0,1):
    changed=copy.deepcopy(plan);changed["profiles"][profile]["workers"]=workers
    with self.subTest(workers=workers,profile=profile),self.assertRaises(ValueError):frame(changed)
  changed=copy.deepcopy(plan);changed["cold"]=True
  with self.assertRaises(ValueError):frame(changed)
  for payload in (frame(plan)[:-1],frame(plan)+b"\0"):
   with self.assertRaises(ValueError):plan_from_frame(payload)

 def test_private_and_production_corpora_remain_distinct_and_complete(self):
  owners=owner_cases();boundaries=boundary_cases();faults=fault_cases();original=original_fault_cases()
  self.assertEqual(len(owners),6);self.assertEqual(len(boundaries),67);self.assertEqual(len(faults),13)
  self.assertEqual([c["name"] for c in faults],[c["name"] for c in original])
  self.assertEqual(len({c["name"] for c in boundaries}),67)
  for case in boundaries:
   raw=bytes.fromhex(case["frame_hex"]);self.assertEqual(len(raw),512)
   self.assertTrue(case["qualification_only_caller_counters"])
   with self.assertRaises(ValueError):plan_from_frame(raw)
  for case in owners:self.assertEqual(len(frame(case["plan"])),192)

 def test_actual_v2_private_field_overlap_cannot_return(self):
  layout=read_json(HERE/"private_layout.json");validate_layout(layout)
  failed=copy.deepcopy(layout)
  next(row for row in failed["fields"] if row["name"]=="observe_remove")["offset"]=500
  with self.assertRaisesRegex(ValueError,"overlap"):validate_layout(failed)
  for field in ("begin_result","observe_remove","observe_enforce","observe_next","observe_baseline"):
   self.assertEqual(len([row for row in layout["fields"] if row["name"]==field]),1)

 def test_unbound_dynamic_or_compilation_override_refuses(self):
  for key in (*FORBIDDEN,"CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
   "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER","CARGO_PROFILE_TEST_OVERFLOW_CHECKS"):
   with self.subTest(key=key),patch.dict(os.environ,{key:"unbound-private-negative"}):
    with self.assertRaisesRegex(ValueError,"Unbound original"):environment()


 def test_public_original_cli_refuses_compiler_overrides_before_copy_or_cargo(self):
  overrides=("RUSTC","CARGO_BUILD_RUSTC","CARGO_BUILD_RUSTFLAGS","CARGO_BUILD_RUSTC_WRAPPER",
   "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER","CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS")
  with tempfile.TemporaryDirectory(prefix="paid-compiler-refusals-") as temp:
   base=Path(temp);bundle=base/"never-read-bundle";bundle.mkdir()
   for key in overrides:
    with self.subTest(key=key):
     output=base/key
     env={"PATH":"","PYTHONDONTWRITEBYTECODE":"1","PYTHONPATH":str(ROOT),key:"unbound-private-negative"}
     process=subprocess.run([sys.executable,"-B","-m","hia.platform.paid_cpu.rust_oracle",
       "--bundle",str(bundle),"--output",str(output)],cwd=ROOT,capture_output=True,env=env,timeout=30)
     self.assertNotEqual(process.returncode,0)
     self.assertIn("Unbound original compilation/runtime override: "+key,(process.stdout+process.stderr).decode())
     self.assertFalse((output/"isolated-source").exists())
     self.assertFalse((output/"cargo-original-test-build").exists())

 def test_public_original_cli_refuses_source_target_and_symlink_alias_before_copy(self):
  with tempfile.TemporaryDirectory(prefix="paid-target-refusals-") as temp:
   base=Path(temp);original=base/"original";original.mkdir()
   bundle=base/"never-read-bundle";bundle.mkdir();output=base/"output"
   isolated=output/"isolated-source";alias=base/"alias";alias.symlink_to(isolated,target_is_directory=True)
   denied=(original,original/"child",ROOT,ROOT/"child",isolated,isolated/"child",alias/"child")
   for index,target in enumerate(denied):
    with self.subTest(target=str(target)):
     with self.assertRaisesRegex(ValueError,"outside source repositories and isolated source"):
      target_directory(target,original,output)
   self.assertEqual(target_directory(None,original,output),(output/"cargo-target").resolve())
   for label,relative in (("same","isolated-source"),("child","isolated-source/child")):
    actual=base/("public-"+label)
    env={"PATH":"","PYTHONDONTWRITEBYTECODE":"1","PYTHONPATH":str(ROOT)}
    process=subprocess.run([sys.executable,"-B","-m","hia.platform.paid_cpu.rust_oracle",
     "--bundle",str(bundle),"--output",str(actual),"--original-root",str(original),
     "--target-dir",str(actual/relative)],cwd=ROOT,capture_output=True,env=env,timeout=30)
    self.assertNotEqual(process.returncode,0)
    self.assertIn("outside source repositories and isolated source",(process.stdout+process.stderr).decode())
    self.assertFalse((actual/"isolated-source").exists())
    self.assertFalse((actual/"cargo-original-test-build").exists())

 def test_owned_tracer_timeout_reaps_actual_child(self):
  sleep=shutil.which("sleep")
  self.assertIsNotNone(sleep,"Mandatory owned-process timeout control needs the host sleep executable")
  with tempfile.TemporaryDirectory(prefix="paid-tracer-timeout-") as temp:
   out=Path(temp)/"actual"
   with self.assertRaises(TimeoutError):run([str(Path(sleep).resolve()),"30"],out,timeout=1)
   report=read_json(out/"report.json")
   self.assertEqual(report["status"],"FAIL")
   self.assertTrue(report["failure_cleanup"]["complete"])
   self.assertEqual(report["failure_cleanup"]["owned_tids_after"],[])
   for pid in report["failure_cleanup"]["owned_tids_before"]:
    with self.assertRaises(ChildProcessError):os.waitpid(pid,os.WNOHANG)

if __name__=="__main__":unittest.main()
