"""Complete native/original qualification and independent raw-byte readback."""
from __future__ import annotations
import argparse,json,os,re,struct,sys,traceback
from pathlib import Path
from hia.platform.build import inspect_executable
from .contract import (ROOT,OWNED,ORIGINAL,COMPILER_SHA,TOOLCHAIN_REVISION,need,identity,file_bytes,
    file_identity,source_manifest,original_manifest,manifest_sha,write_json,fresh_output,preflight,load_json)
from .build import Build
from .runtime import run as run_native_histories
from .physical import run_physical,verify_physical
from .guarded import run as run_guarded,verify_guarded
from .rust_oracle import run as run_original,compare,isolated_manifest,DECLARATION,HOOK

def files_manifest(root):
    result={}
    for path in sorted(root.rglob("*")):
        need(not path.is_symlink(),"Symbolic qualification member")
        need(path.is_dir() or path.is_file(),"Special qualification member")
        if path.is_file():
            relative=path.relative_to(root).as_posix()
            if relative not in ("report.json","public-verification.json"):
                result[relative]=file_identity(path)
    return result

def verify(root,repository=ROOT):
    root=Path(root).absolute();need(root==root.resolve(strict=True),"Noncanonical bundle path")
    repository=Path(repository).resolve(strict=True)
    summary=load_json(file_bytes(root/"report.json"))
    need(summary["schema"]=="trnm.hia.mempool-typed-qualification.v1" and summary["status"]=="PASS",
         "Qualification is not complete")
    current=source_manifest(repository);original=original_manifest(repository)
    need(summary["source_inputs"]==current and summary["original_sources"]==original,"Current source closure differs")
    need(summary["source_set_sha256"]==manifest_sha(current) and summary["source_after"]=="MATCH","Source binding differs")
    need(files_manifest(root)==summary["files"],"Complete qualification file inventory differs")
    build=load_json(file_bytes(root/"build/build.json"))
    need(build["status"]=="PASS" and build["source_after"]=="MATCH","Native build did not pass")
    need(build["source_inputs"]==current and build["original_sources"]==original,"Build source closure differs")
    need(build["compiler_sha256"]==COMPILER_SHA and build["toolchain"]["revision"]==TOOLCHAIN_REVISION,
         "Native compiler identity differs")
    for name,value in current.items():
        need(file_identity(root/"build/source-snapshot"/name)==value,"Source snapshot differs")
    owner=file_bytes(root/"build/owner.flat");emitter=file_bytes(root/"build/emitter.elf")
    executable=file_bytes(root/"build/typed-owner.elf");executable_id=identity(executable)
    need(build["image"]==identity(owner) and build["emitter"]==identity(emitter),"Compiled image identity differs")
    inspect_executable(emitter);profile=inspect_executable(executable)
    need(build["executable"]==executable_id|profile and len(executable)==1992+len(owner)
         and executable[1992:]==owner,"Native executable differs")
    stages=build["stages"]
    expected=[("compile-typed",COMPILER_SHA,file_bytes(repository/OWNED/"typed_fixture.hepta"),owner),
        ("compile-emitter",COMPILER_SHA,file_bytes(repository/OWNED/"linux_emitter.hepta"),emitter),
        ("emit-owner",identity(emitter)["sha256"],struct.pack("<Q",len(owner))+owner,executable)]
    need(len(stages)==len(expected),"Incomplete native compiler execution")
    for row,(name,compiler,payload,result) in zip(stages,expected,strict=True):
        directory=root/"build/pinned-native"/name
        need(load_json(file_bytes(directory/"receipt.json"))==row,"Build receipt differs")
        need(row["stage"]==name and row["executable_sha256"]==compiler and row["exit_code"]==0
             and row["timed_out"] is False and row["cleanup"] is None and row["stderr_hex"]=="","Build stage failed")
        need(file_bytes(directory/"stdin.raw")==payload and file_bytes(directory/"stdout.raw")==result
             and file_bytes(directory/"stderr.raw")==b"","Native compiler raw bytes differ")
        need(row["input_bytes"]==len(payload) and row["input_sha256"]==identity(payload)["sha256"]
             and row["output_bytes"]==len(result) and row["output_sha256"]==identity(result)["sha256"],"Build receipt byte identities differ")
    oracle=load_json(file_bytes(root/"original/report.json"))
    need(oracle["status"]=="PASS" and oracle["source_after"]=="MATCH" and
         oracle["compiler_after"]=="MATCH" and oracle["binary_after"]=="MATCH","Actual original fences did not pass")
    need(oracle["source_inputs"]==current and oracle["original_sources"]==original,"Original source binding differs")
    need(oracle["retained_tests"]==153 and len(set(oracle["retained_test_names"]))==153
         and oracle["actual_histories"]==323 and oracle["actual_commands"]==9332,"Original coverage incomplete")
    need(file_identity(root/"original/original-tests")==oracle["original_binary"],"Independent original binary differs")
    need(isolated_manifest(root/"original/isolated-crate")==oracle["isolated_sources"],"Isolated original copy differs")
    for name,entry in original.items():
        if not name.startswith(ORIGINAL+"/"):continue
        suffix=name[len(ORIGINAL)+1:];raw=file_bytes(root/"original/isolated-crate"/suffix)
        expected_raw=file_bytes(repository/name)+(DECLARATION if suffix=="src/typed_admission.rs" else b"")
        need(raw==expected_raw,"Original production prefix changed")
    need(file_bytes(root/"original/isolated-crate/src/hia_reference.rs")==file_bytes(repository/OWNED/"rust_reference.rs"),
         "Original test hook differs")
    original_labels=["rustc-version","rustc-sysroot","compile-original","list-original","retained-original","actual-original-corpus"]
    need(len(oracle["stages"])==len(original_labels),"Incomplete original execution stages")
    for label,row in zip(original_labels,oracle["stages"],strict=True):
        directory=root/"original"/label
        need(load_json(file_bytes(directory/"receipt.json"))==row,"Original receipt differs")
        need(row["exit_code"]==0 and row["timed_out"] is False and row["cleanup"] is None,"Original process did not complete")
        need(file_identity(directory/"stdout.raw")==row["stdout"] and file_identity(directory/"stderr.raw")==row["stderr"]
             and file_bytes(directory/"stderr.raw")==b"","Original stage bytes differ")
        if label in ("list-original","retained-original","actual-original-corpus"):
            need(row["actual_executable"]==oracle["original_binary"],"Original stage executed a different binary")
    retained=file_bytes(root/"original/retained-original/stdout.raw")
    need(b"test result: ok. 153 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;" in retained,"Retained tests incomplete")
    original_raw=file_bytes(root/"original/actual-original-corpus/stdout.raw")
    need(b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 153 filtered out;" in original_raw,"Original corpus incomplete")
    compared=compare(root/"native",executable_id,original_raw)
    need(compared==load_json(file_bytes(root/"original/comparison.json"))==oracle["comparison"],"Raw actual comparison differs")
    try:
        physical=verify_physical(root/"physical",executable)
    except (ValueError,OSError,KeyError,TypeError,OverflowError) as error:
        raise ValueError("Physical evidence refused: "+str(error)) from error
    need(physical["actual_native_processes"]==38 and physical["actual_completed_commands"]==50,
         "Mandatory physical coverage differs")
    try:
        guarded=verify_guarded(root/"guarded",owner)
    except (ValueError,OSError,KeyError,TypeError,OverflowError) as error:
        raise ValueError("Guarded evidence refused: "+str(error)) from error
    need(guarded["actual_native_calls"]==26 and guarded["handle_exhaustion_calls"]==11,
         "Mandatory guarded coverage differs")
    need(source_manifest(repository)==current and original_manifest(repository)==original,"Sources changed during readback")
    return {"schema":"trnm.hia.mempool-typed-independent-readback.v1","status":"PASS",
        "source_set_sha256":manifest_sha(current),"actual_native_processes_read":323,
        "actual_original_histories_read":323,"actual_commands_compared":9332,"retained_tests_read":153,
        "physical_processes_read":38,"guarded_native_calls_read":26,"actual_runtime_reexecuted":False}

def qualify(output,compiler,*,audit=False):
    out=fresh_output(output);preflight_result=preflight(ROOT,out,audit=audit)
    source=source_manifest(ROOT);original=original_manifest(ROOT)
    report={"schema":"trnm.hia.mempool-typed-qualification.v1","status":"FAIL",
        "source_inputs":source,"original_sources":original,"source_set_sha256":manifest_sha(source),
        "preflight":preflight_result,"native_test_traits_only":True,"node_or_persistent_pool_authority":False,
        "package_retirement":False}
    builder=None
    def fence():
        need(source_manifest(ROOT)==source and original_manifest(ROOT)==original,"Qualification source closure changed")
        if builder is not None:builder.check_sources()
    try:
        builder=Build(out/"build");executable,build=builder.build()
        need(build["status"]=="PASS","Native build failed")
        native=run_native_histories(executable,out/"native",fence)
        guarded=run_guarded(file_bytes(out/"build/owner.flat"),out/"guarded",fence)
        physical=run_physical(executable,out/"physical",fence)
        original_result=run_original(ROOT,out/"native",identity(executable),out/"original",compiler,fence)
        fence();report.update(status="PASS",source_after="MATCH",
            coverage={"native_histories":native["actual_processes"],"native_commands":native["actual_commands"],
                "physical_processes":physical["actual_native_processes"],"guarded_calls":guarded["actual_native_calls"],
                "original_histories":original_result["actual_histories"],"retained_tests":original_result["retained_tests"]})
    except BaseException as error:
        report["failure"]={"error":repr(error),"traceback":traceback.format_exc()};raise
    finally:
        failure=None
        try:fence();report["source_after"]="MATCH"
        except BaseException as error:report["status"]="FAIL";report["source_after"]="FAIL";failure=error;report["source_failure"]=repr(error)
        report["files"]=files_manifest(out);write_json(out/"report.json",report)
        if failure is not None:raise failure
    readback=verify(out);write_json(out/"public-verification.json",readback)
    return report,readback

def main():
    need(__debug__ and not os.environ.get("PYTHONOPTIMIZE"),"Optimized Python is not admitted")
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--output",type=Path);modes.add_argument("--verify",type=Path)
    parser.add_argument("--rustc",type=Path)
    parser.add_argument("--audit",action="store_true",help="Use the existing read-only project audit boundary for a detached CI checkout")
    args=parser.parse_args()
    if args.verify:
        need(args.rustc is None and not args.audit,"Readback does not execute a compiler or preflight")
        result=verify(args.verify)
    else:
        need(args.rustc is not None,"Complete qualification requires explicit original rustc")
        _,result=qualify(args.output,args.rustc,audit=args.audit)
    print(json.dumps(result,sort_keys=True))

if __name__=="__main__":main()
