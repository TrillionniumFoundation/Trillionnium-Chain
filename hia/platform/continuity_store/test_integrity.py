"""Negative source/corpus admission tests; zero native or Rust executions.

The positive artifacts below are explicitly synthetic controller fixtures.
Their PASS fields exercise admission and never certify a product execution.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys

from hia.platform.continuity_store import rust_oracle as oracle

ROOT = Path(__file__).resolve().parents[3]
FIXTURE_CASES = b'''class Fixture:
    def __init__(self, name): self.name = name
    def corpus(self):
        return {"name":self.name,"base_hex":"544b5653545230310000000000000000",
                "delta_hex":"","detach":False,"root":False,"profile":0,
                "variant":0,"height":0,"cancel":None,"cancel_class":2,"token":0}
def cases(): return [Fixture("fixture-a"), Fixture("fixture-b")]
def capacity_cases(): return iter(())
'''

def need(condition, message):
    if not condition: raise ValueError(message)

def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

def main():
    if not __debug__: raise RuntimeError("Optimized integrity qualification is not supported")
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    output=args.output.absolute()
    output.mkdir(mode=0o700)
    controls=[]
    scope={"schema":"trnm.hia.continuity-source-corpus-integrity.v1",
           "native_executions":0,"rust_executions":0,
           "positive_artifacts_are_synthetic_admission_fixtures":True,
           "native_or_original_qualification_authority":False}
    def passed(name, **details):
        controls.append(dict(name=name,status="PASS",**details))
        write_json(output/"running-controls.json",{"controls":controls,**scope})
    def reject(name, operation, contains=None):
        try: operation()
        except (ValueError,FileNotFoundError,lzma.LZMAError) as error:
            if contains is not None:
                need(contains in str(error),name+" failed for an unrelated reason: "+repr(error))
            passed(name,refusal=type(error).__name__,message=str(error))
        else: raise ValueError("Invalid fixture was accepted: "+name)
    try:
        actual_manifest=oracle.complete_source_manifest(ROOT)
        fixture=output/"fixture";fixture.mkdir(mode=0o700)
        selected=set(actual_manifest)
        components=json.loads((ROOT/"hia/components.json").read_bytes())
        for name,rows in components["includes"].items():
            selected.add("hia/"+name)
            for row in rows: selected.add("hia/"+row["source"])
        selected.add("trillionnium/Cargo.lock")
        for relative in sorted(selected):
            destination=fixture/relative
            destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(oracle.canonical_path(ROOT,relative),destination)
        (fixture/"hia/platform/continuity_store/cases.py").write_bytes(FIXTURE_CASES)
        # This entire copied input generator is a source-bound controller fixture.
        manifest=oracle.complete_source_manifest(fixture)
        raw=oracle.canonical_corpus(fixture)
        from hia.platform.typed_store.build import original_manifest
        original=original_manifest(fixture)
        names=[json.loads(line)["name"] for line in raw.splitlines()]
        comparison={"schema":"trnm.hia.native-continuity-staging-comparison.v1","status":"PASS",
            "fixture_only":True,"build":{"schema":"trnm.hia.continuity-staging-build.v1","status":"PASS",
                "source_inputs":manifest,"source_set_sha256":oracle.canonical_json_hash(manifest),
                "original_sources":original},
            "corpus":oracle.bytes_identity(raw),"cases":[{"name":name} for name in names]}
        bundle=output/"bundle";bundle.mkdir(mode=0o700)
        target=bundle/"native-comparison.json"
        corpus=bundle/"corpus.jsonl"
        write_json(target,comparison);corpus.write_bytes(raw)
        observed,captured,sources,actual=oracle.validate_bundle(fixture,bundle)
        need(observed==comparison and sources==manifest and actual==raw,"Valid fixture differs")
        passed("complete-positive-admission-fixture",sources=len(manifest),cases=len(names))
        for relative in manifest:
            bad=copy.deepcopy(comparison)
            del bad["build"]["source_inputs"][relative]
            bad["build"]["source_set_sha256"]=oracle.canonical_json_hash(bad["build"]["source_inputs"])
            reject("missing-bound-input:"+relative,lambda bad=bad:oracle.validate_source_bindings(fixture,bad),
                   "Incomplete or extra native source dependency closure")
        relative="hia/platform/continuity_store/context.hepta"
        for name,value in (("source-length",{"bytes":manifest[relative]["bytes"]+1,"sha256":manifest[relative]["sha256"]}),
                           ("source-digest",{"bytes":manifest[relative]["bytes"],"sha256":"0"*64}),
                           ("source-boolean-length",{"bytes":True,"sha256":manifest[relative]["sha256"]})):
            bad=copy.deepcopy(comparison);bad["build"]["source_inputs"][relative]=value
            reject(name,lambda bad=bad:oracle.validate_source_bindings(fixture,bad))
        for name,field,value in (("native-status","status","FAIL"),("native-schema","schema","unknown")):
            bad=copy.deepcopy(comparison);bad[field]=value
            reject(name,lambda bad=bad:oracle.validate_source_bindings(fixture,bad))
        for name,field,value in (("build-status","status","FAIL"),("build-schema","schema","unknown"),
                                 ("source-set-digest","source_set_sha256","0"*64)):
            bad=copy.deepcopy(comparison);bad["build"][field]=value
            reject(name,lambda bad=bad:oracle.validate_source_bindings(fixture,bad))
        for name,path in (("absolute-path","/tmp/escape"),("parent-path","../escape"),
                          ("dot-path","./hia/components.json"),("double-slash","hia//components.json")):
            bad=copy.deepcopy(comparison)
            bad["build"]["source_inputs"][path]={"bytes":0,"sha256":hashlib.sha256(b"").hexdigest()}
            reject(name,lambda bad=bad:oracle.validate_source_bindings(fixture,bad))
        owned=fixture/"hia/platform/continuity_store"
        extra=owned/"unexpected.py";extra.write_bytes(b"# extra owned source\n")
        try: reject("new-owned-source",lambda:oracle.validate_source_bindings(fixture,comparison))
        finally:extra.unlink()
        required=owned/"rust_reference.rs";saved=required.read_bytes();required.unlink()
        try:reject("mandatory-source-absent",lambda:oracle.complete_source_manifest(fixture))
        finally:required.write_bytes(saved)
        leaf=owned/"context.hepta";saved=leaf.read_bytes();leaf.unlink()
        leaf.symlink_to(ROOT/"hia/platform/continuity_store/context.hepta")
        try:reject("source-leaf-symlink",lambda:oracle.complete_source_manifest(fixture),"Symlinked source path")
        finally:leaf.unlink();leaf.write_bytes(saved)
        moved=fixture/"moved-owner";owned.rename(moved);owned.symlink_to(moved,target_is_directory=True)
        try:reject("source-ancestor-symlink",lambda:oracle.complete_source_manifest(fixture),"Symlinked source path")
        finally:owned.unlink();moved.rename(owned)
        fifo=owned/"unexpected.py";os.mkfifo(fifo,0o600)
        try:reject("owned-special-file",lambda:oracle.complete_source_manifest(fixture),"regular file/directory")
        finally:fifo.unlink()
        includes=owned/"includes.json";saved=includes.read_bytes()
        bad=json.loads(saved);bad["includes"]["continuity_policy.hepta"][0]["functions"][0]="missing_owned_callee"
        includes.write_text(json.dumps(bad))
        try:reject("unknown-transitive-callee",lambda:oracle.complete_source_manifest(fixture),"Unknown, re-exported or duplicate")
        finally:includes.write_bytes(saved)
        bad=json.loads(saved);bad["includes"]["continuity_policy.hepta"].append(
            {"source":"platform/continuity_store/continuity_policy.hepta","functions":["f0"]})
        includes.write_text(json.dumps(bad))
        try:reject("cyclic-private-include",lambda:oracle.complete_source_manifest(fixture),"Cyclic")
        finally:includes.write_bytes(saved)
        components_path=fixture/"hia/components.json";saved=components_path.read_bytes()
        components_path.write_bytes(saved.replace(b"{",b'{"schema":"duplicate",',1))
        try:reject("duplicate-component-json-key",lambda:oracle.complete_source_manifest(fixture),"Duplicate")
        finally:components_path.write_bytes(saved)
        need(oracle.complete_source_manifest(fixture)==manifest,"Source fixture was not restored")
        passed("source-fixture-restored")
        for name,value in (("case-missing",comparison["cases"][:-1]),
                           ("case-extra",comparison["cases"]+[{"name":"extra"}]),
                           ("case-reordered",list(reversed(comparison["cases"]))),
                           ("case-duplicate",[comparison["cases"][0]]*2)):
            bad=copy.deepcopy(comparison);bad["cases"]=value
            reject(name,lambda bad=bad:oracle.validate_corpus(fixture,bundle,bad),"cases are missing")
        bad=copy.deepcopy(comparison);bad["corpus"]["sha256"]="0"*64
        reject("corpus-declared-digest",lambda:oracle.validate_corpus(fixture,bundle,bad),"corpus identity differs")
        for name,value in (("raw-truncated",raw[:-1]),("raw-overlong",raw+b"x"),
                           ("raw-reordered",b"".join(reversed(raw.splitlines(keepends=True))))):
            corpus.write_bytes(value)
            reject(name,lambda:oracle.validate_corpus(fixture,bundle,comparison),"corpus bytes differ")
        corpus.unlink()
        archived=bundle/"corpus.jsonl.xz";compressed=lzma.compress(raw,preset=1);archived.write_bytes(compressed)
        need(oracle.validate_corpus(fixture,bundle,comparison)==raw,"Valid bounded XZ fixture differs")
        passed("xz-complete-positive-fixture")
        for name,value in (("xz-truncated",compressed[:-1]),("xz-trailing",compressed+b"x"),
                           ("xz-second-stream",compressed+lzma.compress(b"extra",preset=1)),
                           ("xz-overlength",lzma.compress(raw+b"x"*(1<<20),preset=1)),
                           ("xz-mismatch",lzma.compress(raw.replace(b"fixture-a",b"fixture-c"),preset=1))):
            archived.write_bytes(value)
            reject(name,lambda:oracle.validate_corpus(fixture,bundle,comparison))
        archived.unlink()
        reject("corpus-absent",lambda:oracle.validate_corpus(fixture,bundle,comparison))
        corpus.write_bytes(raw)
        # Exercise the public CLI on the copied, explicitly synthetic fixture.
        script=owned/"rust_oracle.py"
        environment=dict(os.environ,PATH="",PYTHONPATH=str(fixture),PYTHONDONTWRITEBYTECODE="1")
        def cli(name,document,optimized=False):
            write_json(target,document)
            out=output/("cli-"+name)
            argv=[sys.executable,"-B"]+(["-O"] if optimized else[])+[str(script),
                "--repository",str(fixture),"--bundle",str(bundle),"--output",str(out)]
            result=subprocess.run(argv,env=environment,cwd=fixture,capture_output=True,timeout=30)
            (output/(name+".stdout")).write_bytes(result.stdout)
            (output/(name+".stderr")).write_bytes(result.stderr)
            need(result.returncode!=0,"Fixture CLI unexpectedly certified execution")
            report=json.loads((out/"report.json").read_bytes()) if (out/"report.json").exists() else None
            return result,report,out
        result,report,out=cli("valid-no-tools",comparison)
        need(report and report["status"]=="NOT_RUN" and set(report["missing_tools"])=={"cargo","rustc"},
             "Valid admission did not reach explicit missing-tools result")
        need(not(out/"isolated-source").exists(),"No-tools fixture copied original source")
        passed("actual-cli-valid-not-run",exit_code=result.returncode,status_observed=report["status"])
        bad=copy.deepcopy(comparison);del bad["build"]["source_inputs"][relative]
        result,report,out=cli("missing-source",bad)
        need(report and report["status"]=="FAIL" and not report.get("stages")
             and not(out/"isolated-source").exists(),"Missing-source CLI did not refuse before work")
        passed("actual-cli-missing-source-before-tools",exit_code=result.returncode,error=report["error"])
        result,report,out=cli("optimized",comparison,True)
        need(report is None and b"Optimized Python" in result.stderr and not out.exists(),
             "Optimized CLI did not refuse before output")
        passed("actual-cli-optimized-refused",exit_code=result.returncode)
        write_json(target,comparison)
        need(oracle.validate_bundle(fixture,bundle)[3]==raw,"Final admission fixture differs")
        passed("complete-fixture-restored")
        report=dict(scope,status="PASS",control_count=len(controls),controls=controls,
            production_source_inputs=actual_manifest,fixture_source_inputs=manifest,
            fixture_corpus=oracle.bytes_identity(raw))
        write_json(output/"report.json",report)
        print(json.dumps({"status":"PASS","controls":len(controls),"native_executions":0,
                          "rust_executions":0,"report":str(output/"report.json")}))
        return 0
    except BaseException as error:
        write_json(output/"report.json",dict(scope,status="FAIL",error=repr(error),controls=controls))
        raise
if __name__=="__main__":raise SystemExit(main())
