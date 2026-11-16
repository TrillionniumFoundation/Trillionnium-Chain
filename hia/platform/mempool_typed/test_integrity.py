"""Mandatory source and public-byte integrity controls, distinct from native execution."""
from __future__ import annotations
import argparse,copy,hashlib,json,os,shutil,struct,subprocess,sys,tempfile,traceback
from pathlib import Path
from .contract import ROOT,OWNED,need,file_bytes,source_manifest,load_json,write_json,identity
from .native_io import parse
from .rust_oracle import compare_observations
from .qualify import verify,files_manifest

def source_controls(output):
    output=Path(output);output.mkdir(mode=0o700);base=source_manifest(ROOT);rows=[]
    def case(name,mutation=None):
        with tempfile.TemporaryDirectory(prefix="trnm-mempool-source-control-") as directory:
            root=Path(directory)
            for relative in base:
                p=root/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(file_bytes(ROOT/relative))
            if mutation is not None:mutation(root)
            error=None
            try:need(source_manifest(root)==base,"Source identity changed")
            except (ValueError,OSError,SyntaxError) as exc:error=repr(exc)
            need((error is None)==(mutation is None),"Source control produced the wrong result: "+name)
            rows.append({"name":name,"status":"PASS","expected_rejection":mutation is not None,"observed_error":error})
    case("exact-full-source")
    case("missing-owner-source",lambda r:(r/OWNED/"typed_fixture.hepta").unlink())
    case("unbound-owner-source",lambda r:(r/OWNED/"unexpected.hepta").write_bytes(b"unbound\n"))
    case("stale-python-cache",lambda r:(r/OWNED/"__pycache__").mkdir())
    case("nested-owned-source",lambda r:(r/OWNED/"nested").mkdir())
    case("changed-hia-source",lambda r:(r/OWNED/"typed_fixture.hepta").write_bytes(file_bytes(r/OWNED/"typed_fixture.hepta")+b"\n"))
    case("changed-host-oracle",lambda r:(r/OWNED/"rust_oracle.py").write_bytes(file_bytes(r/OWNED/"rust_oracle.py")+b"\n"))
    case("changed-shared-platform",lambda r:(r/"hia/platform/build.py").write_bytes(file_bytes(r/"hia/platform/build.py")+b"\n"))
    def symlink(r):
        p=r/OWNED/"abi.json";raw=p.read_bytes();p.unlink();target=r/"outside.json";target.write_bytes(raw);p.symlink_to(target)
    case("symbolic-owned-source",symlink)
    def hardlink(r):
        p=r/OWNED/"abi.json";os.link(p,r/"hardlink.json")
    case("hardlinked-owned-source",hardlink)
    def duplicate_inputs(r):
        p=r/"hia/platform/build.py";p.write_bytes(file_bytes(p)+b"\nINPUTS=('toolchain.lock.json',)\n")
    case("ambiguous-pinned-input-list",duplicate_inputs)
    for name,raw in (("duplicate-json-key",b'{"a":1,"a":2}'),):
        error=None
        try:load_json(raw)
        except ValueError as exc:error=repr(exc)
        need(error is not None,"Duplicate key accepted")
        rows.append({"name":name,"status":"PASS","observed_error":error,"expected_rejection":True})
    for name,raw in (("truncated-native-prefix",b"\x00"),("zero-native-frame",bytes(8))):
        error=None
        try:parse(raw)
        except ValueError as exc:error=repr(exc)
        need(error is not None,"Malformed native output accepted")
        rows.append({"name":name,"status":"PASS","observed_error":error,"expected_rejection":True})
    a={"op":22,"events":[[15,1],[15,2]],"value":3};b={"op":22,"events":[[15,2],[15,1]],"value":3}
    need(compare_observations(a,b,22) is not None,"Permitted unordered destruction rejected")
    rows.append({"name":"unordered-original-drop-only","status":"PASS","expected_rejection":False})
    for name,right,op in (
        ("ordered-callbacks-must-match",b,14),
        ("lost-drop-callback-rejected",{"op":22,"events":[[15,1]],"value":3},22),
        ("non-event-drift-rejected",dict(b,value=4),22)):
        error=None
        try:compare_observations(a,right,op)
        except ValueError as exc:error=repr(exc)
        need(error is not None,"Semantic drift accepted")
        rows.append({"name":name,"status":"PASS","observed_error":error,"expected_rejection":True})
    need(source_manifest(ROOT)==base,"Live source changed during tests")
    result={"schema":"trnm.hia.mempool-typed-source-controls.v1","status":"PASS",
        "controls":rows,"control_count":len(rows),"actual_native_runtime_executed":False}
    write_json(output/"report.json",result);return result

def _replace_json(path,value):
    path.chmod(0o600)
    path.write_bytes((json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode())

def _truncated_flat_witness(root):
    changed=[]
    def put(name,raw):
        path=root/name;path.chmod(0o600);path.write_bytes(raw);changed.append(name)
    def put_json(name,value):
        put(name,(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode())
    owner=file_bytes(root/"build/owner.flat")[1:]
    need(bool(owner),"Truncated-flat fixture has no remaining bytes")
    build=load_json(file_bytes(root/"build/build.json"))
    typed=next(row for row in build["stages"] if row["stage"]=="compile-typed")
    typed.update(output_bytes=len(owner),output_sha256=identity(owner)["sha256"])
    put("build/owner.flat",owner)
    put("build/pinned-native/compile-typed/stdout.raw",owner)
    put_json("build/pinned-native/compile-typed/receipt.json",typed)
    payload=struct.pack("<Q",len(owner))+owner
    emit=next(row for row in build["stages"] if row["stage"]=="emit-owner")
    emit.update(input_bytes=len(payload),input_sha256=identity(payload)["sha256"])
    put("build/pinned-native/emit-owner/stdin.raw",payload)
    put_json("build/pinned-native/emit-owner/receipt.json",emit)
    build["image"]=identity(owner);put_json("build/build.json",build)
    guarded=load_json(file_bytes(root/"guarded/report.json"))
    guarded["image"]=identity(owner);put_json("guarded/report.json",guarded)
    return sorted(changed)

def _empty_guarded_calls_witness(root):
    path=root/"guarded/report.json";report=load_json(file_bytes(path));report["actual_calls"]=[]
    _replace_json(path,report)
    return ["guarded/report.json"]

def _witness_identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

def _witness_apply(bundle, kind):
    root = Path(bundle)
    changed = []
    def put(relative, raw):
        (root / relative).write_bytes(raw)
        changed.append(relative)
    def write(relative, value):
        put(relative, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())
    if kind.startswith("physical-"):
        value = json.loads((root / "physical/report.json").read_bytes())
        wanted = {
            "physical-protocol-exit-cleanup": "clean-exact-close",
            "physical-cleanup-tag": "unexpected-eof-releases-once",
            "physical-trace": "actual-moving-mremap-with-owned-bodies",
            "physical-input": "clean-exact-close",
        }[kind]
        row = next(row for row in value["controls"] if row["name"] == wanted)
        prefix = "physical/" + wanted + "/"
        if kind == "physical-protocol-exit-cleanup":
            raw = b"not-a-native-response\n"
            put(prefix + "stdout.raw", raw)
            row["files"]["stdout.raw"] = _witness_identity(raw)
            row.update(exit_code=-9, cleanup="SIGKILL_TIMEOUT", returned_commands=0, actual_semantic=[])
        elif kind == "physical-cleanup-tag":
            raw = b"MTFAIL01" + struct.pack("<5Q", 74, 0, 1, 15, 999)
            put(prefix + "stderr.raw", raw)
            row["files"]["stderr.raw"] = _witness_identity(raw)
            row["actual_native_cleanup_events"] = [[15, 999]]
        elif kind == "physical-trace":
            raw = b"THIS IS NOT A SYSCALL TRACE\n"
            put(prefix + "syscalls.raw", raw)
            row["syscall_trace"] = _witness_identity(raw)
        elif kind == "physical-input":
            raw = b"not-source-derived-input"
            put(prefix + "stdin.raw", raw)
            row["files"]["stdin.raw"] = _witness_identity(raw)
        # observed_mremaps was appended after this separate receipt was written.
        write(prefix + "receipt.json", {k: v for k, v in row.items() if k != "observed_mremaps"})
        write("physical/report.json", value)
    elif kind == "guarded-exhaustion":
        value = json.loads((root / "guarded/report.json").read_bytes())
        row = next(row for row in value["actual_calls"] if row["name"] == "handle-exhausted-pop")
        relative = "guarded/handle-exhausted-pop/context-after.raw"
        raw = bytearray((root / relative).read_bytes()); raw[112] ^= 1
        put(relative, bytes(raw)); row["context-after.raw"] = _witness_identity(bytes(raw))
        row["context_unchanged"] = False
        write("guarded/handle-exhausted-pop/receipt.json", row)
        write("guarded/report.json", value)
    elif kind == "guarded-extra-fixture-write":
        value = json.loads((root / "guarded/report.json").read_bytes())
        relative = "guarded/private-write-after.raw"
        raw = bytearray((root / relative).read_bytes()); raw[112] ^= 1
        put(relative, bytes(raw))
        value["test_only_private_writes"][0]["after"] = _witness_identity(bytes(raw))
        write("guarded/report.json", value)
    else:
        raise ValueError("Unknown witnessed mutation")
    if len(set(changed)) != len(changed) or "report.json" in changed:
        raise ValueError("Mutation changed an unexpected path")
    return sorted(changed)

def witness_invalid_protocol_exit_cleanup(bundle):
    return _witness_apply(bundle, "physical-protocol-exit-cleanup")

def witness_wrong_lease_cleanup_tag(bundle):
    return _witness_apply(bundle, "physical-cleanup-tag")

def witness_non_syscall_moving_trace(bundle):
    return _witness_apply(bundle, "physical-trace")

def witness_noncanonical_control_input(bundle):
    return _witness_apply(bundle, "physical-input")

def witness_exhaustion_mutates_context(bundle):
    return _witness_apply(bundle, "guarded-exhaustion")

def witness_private_fixture_extra_write(bundle):
    return _witness_apply(bundle, "guarded-extra-fixture-write")

WITNESS_MUTATORS = {
    "invalid-protocol-exit-cleanup": witness_invalid_protocol_exit_cleanup,
    "wrong-real-lease-cleanup-tag": witness_wrong_lease_cleanup_tag,
    "non-syscall-moving-trace": witness_non_syscall_moving_trace,
    "noncanonical-control-input": witness_noncanonical_control_input,
    "guarded-exhaustion-mutates-context": witness_exhaustion_mutates_context,
    "guarded-private-fixture-extra-write": witness_private_fixture_extra_write,
}


WITNESS_CONTROLS = (
    ("self-consistent-truncated-flat-retains-original-elf", _truncated_flat_witness, "Native executable differs"),
    ("guarded-count-fields-with-no-call-rows", _empty_guarded_calls_witness, "Guarded evidence refused"),
    *((name, function, "Guarded evidence refused" if name.startswith("guarded-") else "Physical evidence refused")
      for name, function in WITNESS_MUTATORS.items()),
)

def public_controls(bundle,output):
    bundle=Path(bundle).absolute()
    need(bundle==bundle.resolve(strict=True),"Noncanonical control bundle")
    output=Path(output);output.mkdir(mode=0o700)
    rows=[];witness_rows=[];cli_rows=[]
    result={"schema":"trnm.hia.mempool-typed-public-controls.v2","status":"FAIL",
        "controls":rows,"control_count":0,"witness_controls":witness_rows,"witness_control_count":0,
        "public_cli":cli_rows,"actual_public_cli_processes":0,"actual_native_runtime_executed":False}
    baseline=None;baseline_report=None
    def cli(name,arguments,success,*,optimized=False,expected_error=None):
        directory=output/("cli-"+name);directory.mkdir(mode=0o700)
        argv=[sys.executable,"-B"]+(["-O"] if optimized else [])+[
            "-m","hia.platform.mempool_typed.qualify",*map(str,arguments)]
        timed_out=False
        try:
            p=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=60)
            stdout,stderr,exit_code=p.stdout,p.stderr,p.returncode
        except subprocess.TimeoutExpired as error:
            stdout,stderr,exit_code=error.stdout or b"",error.stderr or b"",None;timed_out=True
        (directory/"stdout.raw").write_bytes(stdout);(directory/"stderr.raw").write_bytes(stderr)
        row={"name":name,"status":"FAIL","argv":argv,"exit_code":exit_code,
            "stdout":identity(stdout),"stderr":identity(stderr),"expected_success":success,
            "expected_error":expected_error,"timed_out":timed_out,"actual_runtime_executed":False}
        cli_rows.append(row)
        try:
            need(not timed_out and (exit_code==0)==success,"Wrong public CLI result: "+name)
            if success:
                need(load_json(stdout)["status"]=="PASS" and stderr==b"","Public CLI did not verify")
            else:
                need(b'"status": "PASS"' not in stdout,"Rejected CLI published success")
                need(expected_error is None or expected_error.encode() in stderr,
                    "Public CLI refused a different witness invariant: "+name)
            row["status"]="PASS"
        finally:write_json(directory/"receipt.json",row)
    def case(name,relative,replacement):
        case_dir=output/name;case_dir.mkdir(mode=0o700)
        row={"name":name,"status":"FAIL","path":relative,"actual_runtime_executed":False}
        rows.append(row)
        try:
            with tempfile.TemporaryDirectory(prefix="trnm-mempool-public-control-") as directory:
                copied=Path(directory)/"bundle";shutil.copytree(bundle,copied)
                target=copied/relative;before=file_bytes(target);after=replacement(before)
                target.chmod(0o600);target.write_bytes(after)
                row.update(before=identity(before),after=identity(after))
                (case_dir/"mutated.raw").write_bytes(after)
                error=None
                try:verify(copied)
                except (ValueError,OSError,KeyError,TypeError,OverflowError) as exc:error=repr(exc)
                row["observed_error"]=error
                need(error is not None,"Modified public bundle accepted: "+name)
                cli(name,["--verify",copied],False)
                row["status"]="PASS"
        finally:write_json(case_dir/"receipt.json",row)
    def witness(name,mutation,expected_error):
        case_dir=output/name;case_dir.mkdir(mode=0o700)
        row={"name":name,"status":"FAIL","expected_error":expected_error,
             "actual_runtime_executed":False,"changed_files":{}}
        witness_rows.append(row)
        try:
            with tempfile.TemporaryDirectory(prefix="trnm-mempool-witness-control-") as directory:
                copied=Path(directory)/"bundle";shutil.copytree(bundle,copied)
                need(files_manifest(copied)==baseline,"Witness copy differs from the actual baseline")
                changed=mutation(copied)
                after=files_manifest(copied)
                need(type(changed) is list and changed==sorted(set(changed)) and changed,
                    "Invalid witness mutation inventory")
                need(set(after)==set(baseline),"Witness added or omitted evidence")
                need(changed==[name for name in sorted(after) if after[name]!=baseline[name]],
                    "Witness changed an undeclared file")
                for relative in changed:
                    path=case_dir/"overlay"/relative;path.parent.mkdir(parents=True,exist_ok=True)
                    path.write_bytes(file_bytes(copied/relative))
                    row["changed_files"][relative]={"before":baseline[relative],"after":after[relative]}
                summary=load_json(baseline_report);summary["files"]=after
                _replace_json(copied/"report.json",summary)
                mutated=file_bytes(copied/"report.json")
                (case_dir/"mutated-summary.json").write_bytes(mutated);row["mutated_summary"]=identity(mutated)
                need(file_bytes(copied/"public-verification.json")==file_bytes(bundle/"public-verification.json"),
                    "Witness changed the prior readback record")
                error=None
                try:verify(copied)
                except (ValueError,OSError,KeyError,TypeError,OverflowError) as exc:error=repr(exc)
                row["observed_error"]=error
                need(error is not None and expected_error in error,
                    "Self-consistent witness was accepted or refused elsewhere: "+name+": "+str(error))
                cli(name,["--verify",copied],False,expected_error=expected_error)
                row["status"]="PASS"
        finally:write_json(case_dir/"receipt.json",row)
    try:
        verify(bundle);baseline=files_manifest(bundle);baseline_report=file_bytes(bundle/"report.json")
        result.update(baseline_qualification_report=identity(baseline_report),baseline_file_count=len(baseline),
            baseline_source_set_sha256=load_json(baseline_report)["source_set_sha256"])
        cli("valid-readback",["--verify",bundle],True)
        cli("no-compiler-during-readback",["--verify",bundle,"--rustc","/bin/false"],False)
        omitted=output/"must-not-be-created"
        cli("missing-original-compiler",["--output",omitted],False)
        need(not omitted.exists(),"Invalid invocation created an output")
        cli("optimized-python-refused",["--verify",bundle],False,optimized=True)
        with tempfile.TemporaryDirectory(prefix="trnm-mempool-public-link-") as directory:
            link=Path(directory)/"symbolic-bundle";link.symlink_to(bundle,target_is_directory=True)
            cli("symbolic-bundle-refused",["--verify",link],False)
        case("changed-native-output","native/history-000/stdout.raw",lambda b:b[:-1])
        case("changed-native-input","native/history-000/stdin.raw",lambda b:b[:-1]+bytes([b[-1]^1]))
        case("changed-compiled-image","build/owner.flat",lambda b:b[:-1]+bytes([b[-1]^1]))
        case("changed-original-output","original/actual-original-corpus/stdout.raw",lambda b:b.replace(b"HIA_TYPED_OBS ",b"HIA_TYPED_BAD ",1))
        case("changed-physical-trace","physical/actual-moving-mremap-with-owned-bodies/syscalls.raw",lambda b:b+b"unexecuted\n")
        for name,mutation,expected_error in WITNESS_CONTROLS:witness(name,mutation,expected_error)
        need(len(rows)==5 and len(witness_rows)==8 and len(cli_rows)==18,"Incomplete public control execution")
        need(files_manifest(bundle)==baseline and file_bytes(bundle/"report.json")==baseline_report,
            "Actual baseline changed during public controls")
        result["status"]="PASS"
    except BaseException as error:
        result["failure"]={"error":repr(error),"traceback":traceback.format_exc()};raise
    finally:
        result.update(control_count=len(rows),witness_control_count=len(witness_rows),
            actual_public_cli_processes=len(cli_rows))
        write_json(output/"report.json",result)
    return result


def main():
    need(__debug__ and not os.environ.get("PYTHONOPTIMIZE"),"Optimized Python is not admitted")
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--output",required=True,type=Path)
    parser.add_argument("--bundle",type=Path);args=parser.parse_args()
    result=public_controls(args.bundle,args.output) if args.bundle else source_controls(args.output)
    print(json.dumps({"status":result["status"],"control_count":result["control_count"]}))

if __name__=="__main__":main()
