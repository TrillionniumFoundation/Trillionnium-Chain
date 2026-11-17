"""Execute the complete original Rust library and compare its actual observations."""
from __future__ import annotations
import collections,json,os,re,shutil,signal,stat,subprocess,time,traceback
from pathlib import Path
from hia.platform.build import sealed_executable
from .cases import complete
from .contract import (ROOT,OWNED,ORIGINAL,need,identity,file_bytes,file_identity,load_json,
    canonical_path,original_manifest,source_manifest,manifest_sha,write_json)
from .native_io import commands_wire,parse,original_corpus
from .runtime import CORPUS_ID

HOOK="typed_admission::hia_reference::complete_typed_owner_actual_corpus"
DECLARATION=b'\n#[cfg(test)]\n#[path = "hia_reference.rs"]\nmod hia_reference;\n'

def capture(argv,cwd,environment,output,label,*,timeout=120,exact=None):
    directory=output/label;directory.mkdir(mode=0o700);fd=None
    actual=list(map(str,argv))
    if exact is not None:
        fd=sealed_executable(exact,"mempool-original");actual[0]="/proc/self/fd/"+str(fd)
    started=time.monotonic_ns();cleanup=None;timed_out=False;stdout=b"";stderr=b"";process=None
    try:
        process=subprocess.Popen(actual,cwd=cwd,env=environment,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,
            pass_fds=() if fd is None else (fd,),umask=0o077)
        try:stdout,stderr=process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out=True
            try:os.killpg(process.pid,signal.SIGKILL);sent="sent"
            except ProcessLookupError:sent="already_exited"
            stdout,stderr=process.communicate(timeout=3)
            cleanup={"signal":"SIGKILL","outcome":sent,"reaped":process.returncode is not None}
    finally:
        if fd is not None:os.close(fd)
    (directory/"stdout.raw").write_bytes(stdout);(directory/"stderr.raw").write_bytes(stderr)
    row={"argv":actual,"requested_argv":list(map(str,argv)),"cwd":str(cwd),
        "environment":environment,"exit_code":process.returncode,"timed_out":timed_out,"cleanup":cleanup,
        "elapsed_ns":time.monotonic_ns()-started,"stdout":identity(stdout),"stderr":identity(stderr),
        "actual_executable":identity(exact) if exact is not None else file_identity(Path(argv[0]))}
    write_json(directory/"receipt.json",row)
    need(row["exit_code"]==0 and not timed_out and cleanup is None,"Original stage failed: "+label)
    need(stderr==b"","Original stage emitted stderr: "+label)
    return stdout,row

def compiler_manifest(compiler,sysroot):
    result={str(compiler):file_identity(compiler)}
    for current,children,files in os.walk(sysroot/"lib",followlinks=False):
        children.sort()
        for name in children:need(not (Path(current)/name).is_symlink(),"Symbolic sysroot directory")
        for name in sorted(files):
            path=Path(current)/name
            if name.endswith((".rlib",".rmeta")) or ".so" in name:
                need(not path.is_symlink(),"Symbolic consumed sysroot file")
                result[str(path)]=file_identity(path)
    need(len(result)>10,"Incomplete compiler/sysroot closure")
    return dict(sorted(result.items()))

def isolated_manifest(isolated):
    result={}
    for path in sorted(isolated.rglob("*")):
        need(not path.is_symlink(),"Symbolic isolated original")
        if path.is_file():result[path.relative_to(isolated).as_posix()]=file_identity(path)
    return result

def read_original(raw):
    observations=[]
    for line in raw.splitlines():
        marker=b"HIA_TYPED_OBS "
        if marker in line:
            need(line.count(marker)==1,"Duplicate original observation marker")
            observations.append(load_json(line.split(marker,1)[1]))
    return observations

def typed_value(value):
    """Preserve JSON types in equality and unordered callback multiset keys."""
    if type(value) is dict:
        need(all(type(key) is str for key in value),"Observation keys must be strings")
        return (dict,tuple((key,typed_value(item)) for key,item in sorted(value.items())))
    if type(value) is list:
        return (list,tuple(typed_value(item) for item in value))
    need(type(value) in (str,int,float,bool,type(None)),"Unsupported observation value")
    return (type(value),value)

def compare_observations(native,original,operation):
    need(isinstance(native,dict) and isinstance(original,dict),"Malformed observation")
    if operation not in (20,21,22):
        need(typed_value(native)==typed_value(original),"Actual native and original semantics differ");return None
    need(set(native)==set(original),"Observation field set differs")
    left={k:v for k,v in native.items() if k!="events"};right={k:v for k,v in original.items() if k!="events"}
    need(typed_value(left)==typed_value(right),"Destruction operation semantics differ")
    need(type(native["events"]) is list and type(original["events"]) is list,
         "Actual destruction callbacks differ")
    need(collections.Counter(typed_value(x) for x in native["events"])==
         collections.Counter(typed_value(x) for x in original["events"]),"Actual destruction callbacks differ")
    if native["events"]!=original["events"]:
        return {"native_events":native["events"],"original_events":original["events"],
                "only_original_hashmap_destruction_order_is_unordered":True}
    return None

def validate_native(runtime_root,executable_identity):
    report=load_json(file_bytes(runtime_root/"report.json"));histories=complete()
    need(report["status"]=="PASS" and report["source_after"]=="MATCH","Native report not qualified")
    need(report["executable"]==executable_identity and report["corpus"]==CORPUS_ID,"Native binding differs")
    need(report["actual_processes"]==323 and report["actual_commands"]==9332,"Incomplete native execution")
    corpus=file_bytes(runtime_root/"corpus.bin")
    need(identity(corpus)==CORPUS_ID and corpus==original_corpus(histories),"Native/original corpus mismatch")
    need(len(report["histories"])==len(histories),"Native history list incomplete")
    values=[]
    for index,(history,row) in enumerate(zip(histories,report["histories"],strict=True)):
        need(row["index"]==index and row["name"]==history["name"] and row["status"]=="PASS","Native history order differs")
        directory=runtime_root/f"history-{index:03d}"
        raw=file_bytes(directory/"stdout.raw");stderr=file_bytes(directory/"stderr.raw")
        payload=file_bytes(directory/"stdin.raw");receipt=load_json(file_bytes(directory/"receipt.json"))
        need(payload==commands_wire(history),"Native input bytes differ")
        need(receipt==row["receipt"],"Native receipt differs")
        need(receipt["executable_sha256"]==executable_identity["sha256"] and
             receipt["executable_bytes"]==executable_identity["bytes"],"Native executable provenance differs")
        need(receipt["input_sha256"]==identity(payload)["sha256"] and receipt["input_bytes"]==len(payload),"Native input receipt differs")
        need(receipt["output_sha256"]==identity(raw)["sha256"] and receipt["output_bytes"]==len(raw),"Native output receipt differs")
        need(receipt["stderr_hex"]=="" and stderr==b"" and receipt["exit_code"]==0 and
             receipt["timed_out"] is False and receipt["cleanup"] is None,"Actual native stage failed")
        observed=parse(raw)
        need(len(observed)==len(history["commands"])==row["actual_commands"],"Native command count differs")
        saved=file_bytes(directory/"observations.json")
        need(identity(saved)==row["observations"] and load_json(saved)==observed,"Decoded observations differ from actual native bytes")
        values.append((history["name"],observed))
    return values

def compare(runtime_root,executable_identity,original_raw):
    native=validate_native(runtime_root,executable_identity)
    original=read_original(original_raw)
    need(len(original)==9332,"Original observation count differs")
    cursor=0;variations=[]
    for name,observations in native:
        for index,actual in enumerate(observations):
            row=original[cursor];cursor+=1
            need(set(row)=={"history","index","returned"} and type(row["history"]) is str
                 and row["history"]==name and type(row["index"]) is int and row["index"]==index,
                 "Actual original order or history differs")
            variance=compare_observations(actual,row["returned"],actual["op"])
            if variance is not None:variations.append({"history":name,"index":index,**variance})
    return {"status":"PASS","actual_histories":323,"actual_commands":cursor,
        "unordered_destruction_variations":variations,"all_other_fields_and_orders_exact":True}

def run(repository,runtime_root,executable_identity,output,compiler,check_sources):
    repository=Path(repository).resolve(strict=True);out=Path(output);out.mkdir(mode=0o700)
    compiler=Path(compiler)
    need(compiler.is_absolute() and compiler==compiler.resolve(strict=True),"Explicit canonical rustc path required")
    need(stat.S_ISREG(compiler.lstat().st_mode) and os.access(compiler,os.X_OK),"Invalid rustc executable")
    native_source=source_manifest(repository);original=original_manifest(repository)
    reference=file_bytes(repository/OWNED/"rust_reference.rs")
    corpus=file_bytes(runtime_root/"corpus.bin");need(identity(corpus)==CORPUS_ID,"Wrong original corpus")
    report={"schema":"trnm.hia.mempool-typed-original.v1","status":"FAIL",
        "source_inputs":native_source,"original_sources":original,"corpus":identity(corpus),
        "test_hook":identity(reference),"appended_declaration_hex":DECLARATION.hex(),
        "original_production_source_changed":False,"shared_cargo_target_used":False,"stages":[]}
    start=time.monotonic_ns();toolchain=None;isolated_snapshot=None;binary=None;sysroot=None
    environment={"PATH":str(compiler.parent)+":/usr/bin:/bin","RUST_BACKTRACE":"0"}
    try:
        check_sources()
        validate_native(runtime_root,executable_identity)
        version,stage=capture([compiler,"-Vv"],repository,environment,out,"rustc-version");report["stages"].append(stage)
        need(b"host: x86_64-unknown-linux-gnu\n" in version,"Original compiler target differs")
        report["rustc_version"]=version.decode("utf-8")
        root_raw,stage=capture([compiler,"--print","sysroot"],repository,environment,out,"rustc-sysroot");report["stages"].append(stage)
        sysroot=Path(root_raw.decode().strip())
        need(sysroot.is_absolute() and sysroot==sysroot.resolve(strict=True),"Noncanonical sysroot")
        toolchain=compiler_manifest(compiler,sysroot);report["compiler_inputs"]=toolchain
        system_linker=Path(shutil.which("cc",path=environment["PATH"]) or "")
        need(system_linker.is_absolute(),"Required system linker cc is absent")
        system_linker=system_linker.resolve(strict=True)
        report["system_linker"]={"path":str(system_linker),**file_identity(system_linker)}
        isolated=out/"isolated-crate";isolated.mkdir(mode=0o700)
        for name,expected in original.items():
            prefix=ORIGINAL+"/"
            if not name.startswith(prefix):continue
            raw=file_bytes(repository/name);need(identity(raw)==expected,"Original source changed before copy")
            target=isolated/name[len(prefix):];target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        import tomllib
        manifest=tomllib.loads((isolated/"Cargo.toml").read_text())
        need(not manifest.get("dependencies") and not manifest.get("build-dependencies"),"Standalone original gained dependencies")
        typed=isolated/"src/typed_admission.rs";original_typed=file_bytes(typed)
        need(b"mod hia_reference" not in original_typed,"Original already declares test hook")
        typed.write_bytes(original_typed+DECLARATION)
        (isolated/"src/hia_reference.rs").write_bytes(reference)
        isolated_snapshot=isolated_manifest(isolated);report["isolated_sources"]=isolated_snapshot
        env=environment|{"CARGO_MANIFEST_DIR":str(isolated)}
        target=out/"original-tests"
        _,stage=capture([compiler,"--sysroot",sysroot,"-C","linker="+str(system_linker),"--edition=2021","--crate-name","trnm_mempool",
            "--test","src/lib.rs","-o",target],isolated,env,out,"compile-original",timeout=180)
        report["stages"].append(stage);target.chmod(0o500)
        binary=file_bytes(target);report["original_binary"]=identity(binary)
        listed,stage=capture([target,"--list"],isolated,env,out,"list-original",exact=binary);report["stages"].append(stage)
        tests=[line[:-6].decode() for line in listed.splitlines() if line.endswith(b": test")]
        need(len(tests)==154 and tests.count(HOOK)==1 and len(set(tests))==154,"Retained original test set differs")
        report["retained_test_names"]=[name for name in tests if name!=HOOK]
        retained,stage=capture([target,"--skip",HOOK,"--test-threads=1"],isolated,env,out,"retained-original",exact=binary)
        report["stages"].append(stage)
        need(b"test result: ok. 153 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;" in retained,
             "Retained original tests incomplete")
        observed,stage=capture([target,"--exact",HOOK,"--nocapture","--test-threads=1"],isolated,
            env|{"TRNM_TYPED_CORPUS":str(runtime_root/"corpus.bin")},out,"actual-original-corpus",exact=binary)
        report["stages"].append(stage)
        need(b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 153 filtered out;" in observed,
             "Original corpus test did not complete")
        compared=compare(runtime_root,executable_identity,observed)
        write_json(out/"comparison.json",compared)
        report.update(status="PASS",comparison=compared,actual_histories=323,actual_commands=9332,
            retained_tests=153,elapsed_ns=time.monotonic_ns()-start)
        check_sources()
        return report
    except BaseException as error:
        report["failure"]={"error":repr(error),"traceback":traceback.format_exc()};raise
    finally:
        failure=None
        try:
            check_sources()
            need(source_manifest(repository)==native_source and original_manifest(repository)==original,"Original source fence changed")
            if toolchain is not None:need(compiler_manifest(compiler,sysroot)==toolchain,"Compiler/sysroot fence changed")
            if "system_linker" in report:
                need(file_identity(Path(report["system_linker"]["path"]))==
                    {k:report["system_linker"][k] for k in ("bytes","sha256")},"System linker changed")
            if isolated_snapshot is not None:need(isolated_manifest(out/"isolated-crate")==isolated_snapshot,"Isolated original source changed")
            if binary is not None:need(file_bytes(out/"original-tests")==binary,"Independent original binary changed")
            need(file_bytes(runtime_root/"corpus.bin")==corpus,"Original input corpus changed")
            report["source_after"]="MATCH";report["compiler_after"]="MATCH" if toolchain is not None else "NOT_CAPTURED"
            report["binary_after"]="MATCH" if binary is not None else "NOT_BUILT"
        except BaseException as error:
            failure=error;report["status"]="FAIL";report["source_after"]="FAIL";report["fence_failure"]=repr(error)
        write_json(out/"report.json",report)
        if failure is not None:raise failure
