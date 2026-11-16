"""Bind complete typed-mempool CI evidence and retain every actual byte on failure."""
from __future__ import annotations
import argparse,copy,hashlib,json,os,shutil,stat,tarfile,traceback
from pathlib import Path
from hia.tools import qualify_foundation_ci as base
from hia.tools import qualify_genesis_ci as transfer

ROOT=base.ROOT
STAGE="mempool-typed"
SCHEMA="trnm.hia.mempool-typed-ci-binding.v1"
PACKAGE="trnm.hia.mempool-typed-ci-evidence.v1"
require,read,identity,write_new=base.require,base.read,base.identity,base.write_new

WITNESS_SPECS = {
    "self-consistent-truncated-flat-retains-original-elf": ("Native executable differs", (
        "build/build.json", "build/owner.flat", "build/pinned-native/compile-typed/receipt.json",
        "build/pinned-native/compile-typed/stdout.raw", "build/pinned-native/emit-owner/receipt.json",
        "build/pinned-native/emit-owner/stdin.raw", "guarded/report.json")),
    "guarded-count-fields-with-no-call-rows": ("Guarded evidence refused", ("guarded/report.json",)),
    "invalid-protocol-exit-cleanup": ("Physical evidence refused", (
        "physical/clean-exact-close/receipt.json", "physical/clean-exact-close/stdout.raw", "physical/report.json")),
    "wrong-real-lease-cleanup-tag": ("Physical evidence refused", (
        "physical/report.json", "physical/unexpected-eof-releases-once/receipt.json",
        "physical/unexpected-eof-releases-once/stderr.raw")),
    "non-syscall-moving-trace": ("Physical evidence refused", (
        "physical/actual-moving-mremap-with-owned-bodies/receipt.json",
        "physical/actual-moving-mremap-with-owned-bodies/syscalls.raw", "physical/report.json")),
    "noncanonical-control-input": ("Physical evidence refused", (
        "physical/clean-exact-close/receipt.json", "physical/clean-exact-close/stdin.raw", "physical/report.json")),
    "guarded-exhaustion-mutates-context": ("Guarded evidence refused", (
        "guarded/handle-exhausted-pop/context-after.raw", "guarded/handle-exhausted-pop/receipt.json", "guarded/report.json")),
    "guarded-private-fixture-extra-write": ("Guarded evidence refused", (
        "guarded/private-write-after.raw", "guarded/report.json")),
}

def witness_reports(public_directory,complete_directory,public):
    original=read(complete_directory/"report.json")
    require(public.get("baseline_qualification_report")==identity(complete_directory/"report.json")
        and public.get("baseline_source_set_sha256")==original["source_set_sha256"]
        and type(public.get("baseline_file_count")) is int
        and public["baseline_file_count"]==len(original["files"]),"Witness baseline binding differs")
    rows=public.get("witness_controls")
    require(type(rows) is list and [row.get("name") for row in rows]==list(WITNESS_SPECS)
        and type(public.get("witness_control_count")) is int and public["witness_control_count"]==8,
        "Witness control inventory differs")
    for row in rows:
        name=row["name"];expected_error,paths=WITNESS_SPECS[name];directory=public_directory/name
        require(row.get("status")=="PASS" and row.get("actual_runtime_executed") is False
            and row.get("expected_error")==expected_error and type(row.get("observed_error")) is str
            and expected_error in row["observed_error"],"Witness invariant refusal was not observed")
        require(read(directory/"receipt.json")==row,"Witness receipt differs")
        changes=row.get("changed_files")
        require(type(changes) is dict and sorted(changes)==list(paths),"Witness changed path inventory differs")
        observed={}
        for path in sorted((directory/"overlay").rglob("*")):
            require(not path.is_symlink(),"Symbolic witness overlay")
            if path.is_dir():continue
            relative=path.relative_to(directory/"overlay").as_posix();observed[relative]=identity(path)
        require(sorted(observed)==list(paths),"Witness overlay omits or adds a mutation")
        expected=copy.deepcopy(original)
        for path,transition in changes.items():
            require(set(transition)=={"before","after"}
                and transition["before"]==original["files"].get(path)==identity(complete_directory/path)
                and transition["after"]==observed[path] and transition["before"]!=transition["after"],
                "Witness baseline-to-overlay bytes differ")
            expected["files"][path]=transition["after"]
        require(identity(directory/"mutated-summary.json")==row.get("mutated_summary")
            and read(directory/"mutated-summary.json")==expected,
            "Witness summary changed anything other than declared file identities")
    return 8


def gate_reports(source_directory,public_directory,complete_directory):
    source=read(source_directory/"report.json");public=read(public_directory/"report.json")
    require(source.get("schema")=="trnm.hia.mempool-typed-source-controls.v1"
        and source.get("status")=="PASS" and source.get("control_count")==18
        and source.get("actual_native_runtime_executed") is False,"Source controls incomplete")
    source_names=[
        "exact-full-source","missing-owner-source","unbound-owner-source","stale-python-cache",
        "nested-owned-source","changed-hia-source","changed-host-oracle","changed-shared-platform",
        "symbolic-owned-source","hardlinked-owned-source","ambiguous-pinned-input-list","duplicate-json-key",
        "truncated-native-prefix","zero-native-frame","unordered-original-drop-only",
        "ordered-callbacks-must-match","lost-drop-callback-rejected","non-event-drift-rejected"]
    require([row.get("name") for row in source["controls"]]==source_names
        and all(row.get("status")=="PASS" for row in source["controls"]),"Source control inventory differs")
    for row in source["controls"]:
        rejected=row["name"] not in ("exact-full-source","unordered-original-drop-only")
        require(row.get("expected_rejection") is rejected,"Source control expectation differs")
        require(not rejected or isinstance(row.get("observed_error"),str) and row["observed_error"],
            "Source refusal was not observed")
    public_names=["changed-native-output","changed-native-input","changed-compiled-image",
                  "changed-original-output","changed-physical-trace"]
    require(public.get("schema")=="trnm.hia.mempool-typed-public-controls.v2"
        and public.get("status")=="PASS" and public.get("control_count")==5
        and public.get("actual_native_runtime_executed") is False
        and [row.get("name") for row in public.get("controls",[])]==public_names,"Public byte controls incomplete")
    for row in public["controls"]:
        require(row.get("status")=="PASS" and row.get("actual_runtime_executed") is False
            and row.get("observed_error") and row["before"]!=row["after"],"Altered public bytes were not refused")
        directory=public_directory/row["name"]
        require(read(directory/"receipt.json")==row and identity(directory/"mutated.raw")==row["after"],
            "Public mutation receipt differs")
    witness_reports(public_directory,complete_directory,public)
    cli_names=["valid-readback","no-compiler-during-readback","missing-original-compiler",
        "optimized-python-refused","symbolic-bundle-refused",*public_names,*WITNESS_SPECS]
    require(public.get("actual_public_cli_processes")==18
        and [row.get("name") for row in public.get("public_cli",[])]==cli_names,"Public CLI inventory differs")
    for row in public["public_cli"]:
        directory=public_directory/("cli-"+row["name"]);success=row["name"]=="valid-readback"
        require(read(directory/"receipt.json")==row and row.get("status")=="PASS"
            and row.get("expected_success") is success and row.get("actual_runtime_executed") is False
            and row.get("timed_out") is False
            and row.get("expected_error")== (WITNESS_SPECS[row["name"]][0] if row["name"] in WITNESS_SPECS else None)
            and type(row.get("exit_code")) is int and (row["exit_code"]==0)==success,
            "Public CLI did not produce the expected actual outcome")
        for name in ("stdout","stderr"):
            require(identity(directory/(name+".raw"))==row[name],"Public CLI captured bytes differ")
        output=base.regular(directory/"stdout.raw").read_bytes()
        if success:
            decoded=json.loads(output,object_pairs_hook=base.unique_object)
            require(decoded.get("status")=="PASS" and decoded.get("actual_runtime_reexecuted") is False
                and base.regular(directory/"stderr.raw").read_bytes()==b"","Positive public CLI did not verify")
        else:
            require(b'"status": "PASS"' not in output,"Rejected CLI emitted success")
            if row["name"] in WITNESS_SPECS:
                require(WITNESS_SPECS[row["name"]][0].encode() in base.regular(directory/"stderr.raw").read_bytes(),
                    "Actual CLI refused a different witness invariant")
    return {"source_controls":18,"public_byte_controls":5,"public_witness_controls":8,"actual_public_cli_processes":18,
        "source_control_report":identity(source_directory/"report.json"),
        "public_control_report":identity(public_directory/"report.json")}


def evidence_roots(root):
    return {"observations":root/"hia-mempool-typed-observations","bootstrap":root/"hia-bootstrap",
        "complete":root/"hia-mempool-typed-complete","source-controls":root/"hia-mempool-typed-source-controls",
        "public-controls":root/"hia-mempool-typed-public-controls"}

def in_progress(name):
    return name in ("observations/binding.json","observations/binding.log")

def special_record(path, st):
    result={"mode":stat.S_IMODE(st.st_mode),"bytes":0}
    if stat.S_ISLNK(st.st_mode):result.update(type="symlink",linkname=os.readlink(path))
    elif stat.S_ISFIFO(st.st_mode):result["type"]="fifo"
    elif stat.S_ISSOCK(st.st_mode):result["type"]="socket"
    elif stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
        result.update(type="character" if stat.S_ISCHR(st.st_mode) else "block",
            device_major=os.major(st.st_rdev),device_minor=os.minor(st.st_rdev))
    else:raise ValueError("Unknown evidence node kind")
    return result

def evidence_inventory(roots):
    files={};special={}
    def visit(path,name):
        st=path.lstat()
        if stat.S_ISDIR(st.st_mode):
            children=sorted(path.iterdir(),key=lambda p:p.name)
            for child in children:visit(child,name+"/"+child.name)
            require([p.name for p in children]==[p.name for p in sorted(path.iterdir(),key=lambda p:p.name)],
                "Evidence directory changed during inventory")
        elif stat.S_ISREG(st.st_mode):
            if not in_progress(name):files[name]=identity(path)
        else:special[name]=special_record(path,st)
    for label,directory in roots.items():
        if not directory.exists() and not directory.is_symlink():continue
        require(directory.resolve(strict=True)==directory and directory.is_dir(),"Aliased evidence root")
        visit(directory,label)
    return files,special

def verify_archive(archive,entries,metadata_only):
    # A tar reader alone can accept a trailing or concatenated compressed stream.
    import lzma
    dec=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=512<<20)
    with open(base.regular(archive),"rb") as raw:
        while True:
            block=raw.read(1<<20)
            if not block:break
            require(not dec.eof,"Trailing compressed archive bytes")
            dec.decompress(block,max_length=1<<20)
            while not dec.eof and not dec.needs_input:dec.decompress(b"",max_length=1<<20)
            require(not dec.unused_data,"Concatenated compressed archive bytes")
        require(dec.eof,"Truncated compressed archive")
    seen=set()
    with tarfile.open(archive,"r:xz") as stream:
        for member in stream:
            require(member.name in entries and member.name not in seen,"Unexpected archive member")
            seen.add(member.name);entry=entries[member.name]
            require(member.mode==entry["mode"],"Archive mode differs")
            if member.isfile():
                require(entry["type"]=="regular" and member.size==entry["bytes"],"Archive payload type or size differs")
                digest=hashlib.sha256();size=0
                with stream.extractfile(member) as incoming:
                    while block:=incoming.read(1<<20):digest.update(block);size+=len(block)
                require(size==entry["bytes"] and digest.hexdigest()==entry["sha256"],"Archive payload differs")
            elif member.isdir():require(entry["type"]=="directory" and member.size==0,"Archive directory differs")
            elif member.issym():require(entry["type"]=="symlink" and member.linkname==entry["linkname"],"Archive link metadata differs")
            elif member.isfifo():require(entry["type"]=="fifo" and member.size==0,"Archive FIFO metadata differs")
            elif member.ischr() or member.isblk():
                require(entry["type"]==("character" if member.ischr() else "block")
                    and member.devmajor==entry["device_major"] and member.devminor==entry["device_minor"],
                    "Archive device metadata differs")
            else:raise ValueError("Unsupported archive member")
    require(seen==set(entries)-set(metadata_only),"Archive member inventory differs")

def check_binding(value,expected):
    require(value.get("schema")==SCHEMA and value.get("lineage")==expected,
        "Binding lineage differs while packaging")
    require(value.get("status")=="PASS" and value.get("stage")==STAGE,
        "Binding is not a successful typed-mempool qualification")
    for name,count in (("native_histories",323),("native_commands",9332),("actual_original_histories",323),
        ("retained_original_library_tests",153),("actual_physical_processes",38),("actual_guarded_native_calls",26),
        ("source_controls",18),("public_byte_controls",5),("public_witness_controls",8),("actual_public_cli_processes",18),("old_packages_retired",0)):
        require(type(value.get(name)) is int and value[name]==count,"Binding finite coverage differs: "+name)
    require(value.get("native_test_traits_only") is True and value.get("node_or_persistent_pool_authority") is False,
        "Binding broadened component authority")
    for key,digest in (("source_inputs","source_set_sha256"),("original_sources","original_source_set_sha256"),
                       ("evidence_files","evidence_set_sha256")):
        require(type(value.get(key)) is dict and value[key] and base.object_hash(value[key])==value.get(digest),
            "Binding source or evidence inventory differs: "+key)
    require(type(value.get("ci_reader_sources")) is dict and len(value["ci_reader_sources"])==4
        and type(value.get("special_evidence_metadata")) is dict,"Binding reader or special-node inventory absent")

def check_bound_archive(value,entries):
    files={name:{key:row[key] for key in ("bytes","sha256")}
        for name,row in entries.items() if row["type"]=="regular" and not in_progress(name)}
    special={name:row for name,row in entries.items() if row["type"] not in ("regular","directory")}
    require(files==value["evidence_files"],"Bound evidence omitted added or changed before packaging")
    require(special==value["special_evidence_metadata"],"Bound special-node metadata changed before packaging")

def bind(root):
    from hia.platform.mempool_typed.qualify import verify
    from hia.platform.mempool_typed.contract import source_manifest,original_manifest
    expected=base.lineage();observed=root/"hia-mempool-typed-observations"
    pair=transfer.source_pair(observed,expected)
    directory=root/"hia-mempool-typed-complete"
    replay=verify(directory,ROOT)
    source=source_manifest(ROOT);original=original_manifest(ROOT)
    require(all(source[name]==original[name] for name in set(source)&set(original)),
        "Overlapping native/original identities differ")
    readers={name:identity(ROOT/name) for name in ("hia/tools/qualify_mempool_ci.py",
        "hia/tests/test_mempool_ci.py","hia/tools/qualify_foundation_ci.py","hia/tools/qualify_genesis_ci.py")}
    base.check_committed_sources({**original,**source,**readers},ROOT)
    gates=gate_reports(root/"hia-mempool-typed-source-controls",root/"hia-mempool-typed-public-controls",directory)
    original_report=read(directory/"original/report.json");build=read(directory/"build/build.json")
    result={"schema":SCHEMA,"stage":STAGE,"status":"PASS","lineage":expected,
        "source_observations":pair,"source_inputs":source,"source_set_sha256":base.object_hash(source),
        "original_sources":original,"original_source_set_sha256":base.object_hash(original),"readback":replay,
        "ci_reader_sources":readers,"qualification_report":identity(directory/"report.json"),
        "native_executable":build["executable"],"original_binary":original_report["original_binary"],
        "native_histories":323,"native_commands":9332,"actual_original_histories":323,
        "retained_original_library_tests":153,"actual_physical_processes":38,
        "actual_guarded_native_calls":26,"native_test_traits_only":True,
        "node_or_persistent_pool_authority":False,"old_packages_retired":0,**gates}
    require(source_manifest(ROOT)==source and original_manifest(ROOT)==original,
        "Source closure changed during binding")
    require(transfer.source_pair(observed,expected)==pair,"Source proof changed during binding")
    files,special=evidence_inventory(evidence_roots(root))
    result.update(evidence_files=files,evidence_set_sha256=base.object_hash(files),special_evidence_metadata=special)
    check_binding(result,expected)
    write_new(observed/"binding.json",result);return result

def pack(root):
    output=root/"hia-mempool-typed-artifact";output.mkdir(mode=0o700)
    roots=evidence_roots(root);archive=output/"complete-evidence.tar.xz";entries={};metadata_only=[]
    record={"schema":PACKAGE,"stage":STAGE,"packing_status":"FAIL","qualification_status":"NOT_BOUND",
        "entries":entries,"metadata_only":metadata_only,"capture_errors":[],
        "original_test_binary_and_isolated_source_excluded":False,
        "qualification_status_not_changed_by_packaging":True}
    def add(stream,path,name):
        require(name not in entries,"Duplicate evidence member")
        st=path.lstat();mode=stat.S_IMODE(st.st_mode)
        row={"mode":mode,"bytes":0};member=tarfile.TarInfo(name);member.mode=mode;member.mtime=0
        if stat.S_ISREG(st.st_mode):
            require(st.st_nlink==1,"Hard-linked evidence payload")
            before=identity(path);row.update(type="regular",**before);member.size=before["bytes"]
            fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,"rb") as data:
                opened=os.fstat(data.fileno())
                require(stat.S_ISREG(opened.st_mode) and (opened.st_dev,opened.st_ino)==(st.st_dev,st.st_ino),
                    "Evidence changed before archive")
                stream.addfile(member,data)
                after=os.fstat(data.fileno())
                require((opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)==
                    (after.st_size,after.st_mtime_ns,after.st_ctime_ns),"Evidence changed during archive")
            require(identity(path)==before,"Evidence changed while archiving")
        elif stat.S_ISDIR(st.st_mode):
            row["type"]="directory";member.type=tarfile.DIRTYPE;stream.addfile(member)
        else:
            row=special_record(path,st)
            if row["type"]=="symlink":member.type=tarfile.SYMTYPE;member.linkname=row["linkname"]
            elif row["type"]=="fifo":member.type=tarfile.FIFOTYPE
            elif row["type"]=="socket":metadata_only.append(name)
            else:
                member.type=tarfile.CHRTYPE if row["type"]=="character" else tarfile.BLKTYPE
                member.devmajor=row["device_major"];member.devminor=row["device_minor"]
            if row["type"]!="socket":stream.addfile(member)
        entries[name]=row
        if stat.S_ISDIR(st.st_mode):
            children=sorted(path.iterdir(),key=lambda p:p.name)
            for child in children:add(stream,child,name+"/"+child.name)
            require([p.name for p in children]==[p.name for p in sorted(path.iterdir(),key=lambda p:p.name)],
                "Evidence directory changed during capture")
    try:
        try:record["lineage"]=base.lineage()
        except BaseException as error:
            record["lineage"]=None;record["capture_errors"].append({"stage":"lineage","error":repr(error)})
        with tarfile.open(archive,"x:xz",preset=1,dereference=False) as stream:
            for label,directory in roots.items():
                if not directory.exists() and not directory.is_symlink():continue
                try:
                    require(directory.resolve(strict=True)==directory and directory.is_dir(),"Aliased evidence root")
                    add(stream,directory,label)
                except BaseException as error:
                    record["capture_errors"].append({"stage":"capture-"+label,"error":repr(error)})
        verify_archive(archive,entries,metadata_only)
        record["every_regular_payload_reopened"]=True;record["archive"]=identity(archive)
        binding=roots["observations"]/"binding.json"
        if binding.exists() or binding.is_symlink():
            value=read(binding);check_binding(value,record["lineage"])
            require(transfer.source_pair(roots["observations"],record["lineage"])==value["source_observations"],
                "Bound source observations changed before packaging")
            check_bound_archive(value,entries)
            from hia.platform.mempool_typed.contract import source_manifest,original_manifest
            require(source_manifest(ROOT)==value["source_inputs"] and original_manifest(ROOT)==value["original_sources"],
                "Bound source closure changed before packaging")
            require(all(identity(ROOT/name)==expected for name,expected in value["ci_reader_sources"].items()),
                "CI reader source changed before packaging")
            base.check_committed_sources({**value["original_sources"],**value["source_inputs"],
                **value["ci_reader_sources"]},ROOT)
            shutil.copyfile(base.regular(binding),output/"binding.json")
            require(identity(output/"binding.json")==identity(binding),"Binding changed during copy")
            record["binding"]=identity(output/"binding.json")
            record["qualification_status"]="PASS"
        else:record["binding_status"]="ABSENT_OR_FAILED; packaging grants no qualification"
        require(not record["capture_errors"],"Evidence capture failed: "+repr(record["capture_errors"]))
        record["packing_status"]="PASS"
    except BaseException as error:
        record["capture_errors"].append({"stage":"package","error":repr(error),"traceback":traceback.format_exc()})
        if archive.is_file() and not archive.is_symlink():record["partial_archive"]=identity(archive)
        raise
    finally:write_new(output/"package-manifest.json",record)
    return {"stage":STAGE,"files":len(entries),"archive":record["archive"],
        "packing_status":record["packing_status"],"qualification_status":record["qualification_status"],
        "metadata_only_nodes":len(metadata_only),"qualification_status_not_changed_by_packaging":True}

def main():
    require(__debug__ and not os.environ.get("PYTHONOPTIMIZE"),"Optimized Python is not admitted")
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("action",choices=("bind","pack"))
    args=parser.parse_args();root=Path(os.environ["RUNNER_TEMP"]).absolute()
    require(root.resolve(strict=True)==root,"Aliased runner evidence root")
    result=globals()[args.action](root)
    print(json.dumps({k:v for k,v in result.items() if k not in
        ("source_inputs","original_sources","ci_reader_sources","evidence_files","special_evidence_metadata","entries","source_observations")},sort_keys=True))

if __name__=="__main__":main()
