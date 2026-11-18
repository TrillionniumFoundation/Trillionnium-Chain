"""Concrete CI reader/transport controls; no native or original execution."""
from __future__ import annotations
import argparse,copy,hashlib,json,os,pathlib,shutil,socket,struct,subprocess,sys,tempfile,time,traceback,unittest
from unittest.mock import patch
from hia.tools import qualify_node_pool_ci as ci
P=pathlib.Path
OPTIONS=None;WORK=None;ARTIFACTS={};CONTROLS=0;CLIS=0;TEST_REPORT=None
SYNTHETIC={"TRNM_EXPECTED_SOURCE_SHA":"0"*40,"GITHUB_RUN_ID":"1","GITHUB_RUN_ATTEMPT":"1"}
def reject(fn):
    global CONTROLS
    CONTROLS+=1
    try:fn()
    except (ValueError,OSError,KeyError,TypeError,AssertionError):return
    raise AssertionError("Malformed evidence was accepted")
def ok(value):
    global CONTROLS
    CONTROLS+=1
    if not value:raise AssertionError("Positive control failed")
def save(path,value):
    path=P(path);path.parent.mkdir(parents=True,exist_ok=True)
    ci.write(path,value)
def invoke(label,args,expected=0,report=True):
    global CLIS
    CLIS+=1;out=WORK/"cli"/label;out.mkdir(parents=True)
    target=out/"result.json"
    driver="import runpy,sys;sys.path.insert(0,"+repr(str(ci.REPOSITORY))+");sys.argv=sys.argv[1:];runpy.run_path(sys.argv[0],run_name='__main__')"
    argv=[sys.executable,"-B","-c",driver,str(P(ci.__file__).absolute()),*args]
    if report:argv+=["--report",str(target)]
    start=time.monotonic_ns();failure=None;child=None;rc=None
    with (out/"stdout.raw").open("xb") as stdout,(out/"stderr.raw").open("xb") as stderr:
        try:
            child=subprocess.Popen(argv,cwd=ci.REPOSITORY,env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1",LC_ALL="C"),stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
            rc=child.wait(timeout=120)
        except BaseException as e:
            failure=repr(e)
            if child is not None and child.poll() is None:child.kill();child.wait(timeout=3)
    receipt={"argv":argv,"exit_code":rc,"failure":failure,"elapsed_ns":time.monotonic_ns()-start,
             "stdout":ci.file_identity(out,"stdout.raw"),"stderr":ci.file_identity(out,"stderr.raw")}
    save(out/"receipt.json",receipt)
    ok(failure is None and ((rc==0) if expected==0 else (type(rc) is int and rc!=0)))
    if report:ok(ci.load(out,"result.json")["status"]==("PASS" if expected==0 else "FAIL"))
    return receipt
def args_for(kind,artifacts,original=None,capture=False):
    args=["validate","--kind",kind]
    for name,path in artifacts.items():args+=["--"+name,str(path)]
    if original is not None:args+=["--original",str(original)]
    if capture:args+=["--capture"]
    return args

class ReaderControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.before=ci.sources()
        cls.native_shadow=None;cls.original_shadow=None
    def test01_strict_values_and_lineage(self):
        ok(not ci.same(0,False));ok(not ci.same(0,0.0));ok(not ci.same({"x":0},{"x":False}))
        reject(lambda:ci.safe.parse(b'{"x":1,"x":2}'))
        reject(lambda:ci.safe.parse(b'{"x":NaN}'))
        reject(lambda:ci.relative("../escape"));reject(lambda:ci.absolute("/tmp/../escape"))
        value=ci.lineage(SYNTHETIC);ok(value=={"git_head":"0"*40,"run_id":"1","attempt":1})
        for field,value in (("TRNM_EXPECTED_SOURCE_SHA","0"*39),("GITHUB_RUN_ID","0"),("GITHUB_RUN_ATTEMPT","01"),("GITHUB_RUN_ATTEMPT",True)):
            env={**SYNTHETIC,field:value};reject(lambda env=env:ci.lineage(env))
        # Exercise the actual git subprocess/HEAD blob gate on an explicit
        # one-file synthetic repository; this is transport qualification only.
        repo=WORK/"git-source-fixture";repo.mkdir()
        def git(*args):
            result=subprocess.run(["git",*args],cwd=repo,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            ok(result.returncode==0);return result.stdout.decode().strip()
        git("init","--quiet","--initial-branch=fixture")
        data=b"exact source fixture\\n";(repo/"input.txt").write_bytes(data)
        git("add","--","input.txt")
        git("-c","user.name=HIA transport fixture","-c","user.email=fixture@example.invalid","commit","--quiet","-m","synthetic transport fixture")
        head=git("rev-parse","HEAD");tree=git("rev-parse","HEAD^{tree}")
        obs=WORK/"git-source-observations";obs.mkdir()
        row={"tested_commit":head,"candidate":head,"tested_tree":tree,"kind":"head","tracked_worktree_verified":True,"tracked_entries":1}
        save(obs/"source-before.json",row);save(obs/"source-after.json",row)
        expected={"git_head":head,"run_id":"1","attempt":1}
        ok(set(ci.source_pair(repo,obs,expected))=={"source-before.json","source-after.json"})
        inventory={"input.txt":ci.identity(data)}
        ok(ci.committed_sources(repo,inventory)==1)
        reject(lambda:ci.committed_sources(repo,{"input.txt":{"bytes":len(data),"sha256":"0"*64}}))
        reject(lambda:ci.source_pair(repo,obs,{**expected,"git_head":"0"*40}))
        ci.safe.write_json(obs/"source-after.json",{**row,"tracked_worktree_verified":1})
        reject(lambda:ci.source_pair(repo,obs,expected))
    def test02_actual_descriptor_special_controls(self):
        root=WORK/"special-read";root.mkdir()
        (root/"value").write_bytes(b"exact\0bytes\n");ok(ci.read(root,"value")==b"exact\0bytes\n")
        os.mkfifo(root/"pipe")
        reject(lambda:ci.file_identity(root,"pipe"))
        (root/"alias").symlink_to("value")
        reject(lambda:ci.file_identity(root,"alias"))
        (root/"directory").mkdir();(root/"directory"/"value").write_bytes(b"x")
        (root/"ancestor").symlink_to("directory",target_is_directory=True)
        reject(lambda:ci.file_identity(root,"ancestor/value"))
        os.link(root/"value",root/"second")
        reject(lambda:ci.file_identity(root,"value"))
        reject(lambda:ci.file_identity(root,"../value"))
    def test03_complete_transport_special_metadata(self):
        root=WORK/"pack-fixture";root.mkdir();(root/"nested").mkdir()
        (root/"a").write_bytes(b"a"*4097);(root/"nested"/"b").write_bytes(bytes(range(256)))
        os.mkfifo(root/"pipe");(root/"alias").symlink_to("/never/opened/fixture")
        previous=os.open(".",os.O_RDONLY|os.O_DIRECTORY)
        sock=socket.socket(socket.AF_UNIX)
        try:
            os.chdir(root);sock.bind("socket")
        finally:
            sock.close();os.fchdir(previous);os.close(previous)
        destination=WORK/"packed-fixture"
        with patch.dict(os.environ,SYNTHETIC):
            manifest=ci.pack({"fixture":root},destination,"smoke",WORK,"failure")
        ok(manifest["binding"] is None and manifest["stage_status"]=="failure")
        ok(manifest["entries"]["fixture/pipe"]["type"]=="fifo-metadata")
        ok(manifest["entries"]["fixture/socket"]["type"]=="socket-metadata")
        unpacked=WORK/"unpacked-fixture";ci.verify_archive(destination,unpacked)
        ok(ci.read(unpacked,"fixture/a")==b"a"*4097 and ci.read(unpacked,"fixture/nested/b")==bytes(range(256)))
        ok(not (unpacked/"fixture/pipe").exists() and not (unpacked/"fixture/alias").exists() and not (unpacked/"fixture/socket").exists())
        self.__class__.pack_manifest=manifest;self.__class__.pack_directory=destination
    def test04_exact_archive_corruption_controls(self):
        base=self.pack_manifest
        mutations=[
            lambda m:m["entries"]["fixture/a"].update(bytes=True),
            lambda m:m["entries"]["fixture/a"].update(sha256="0"*63),
            lambda m:m["entries"].update({"../escape":{"type":"file","mode":384,"bytes":0,"sha256":"0"*64}}),
            lambda m:m["entries"]["fixture/a"].update(extra=True),
            lambda m:m.update(stage_status="success"),
            lambda m:m.update(special_objects_are_metadata_only=1),
            lambda m:m["tar"].update(bytes=False),
            lambda m:m["entries"].pop("fixture/nested")]
        for change in mutations:
            value=copy.deepcopy(base);change(value);reject(lambda value=value:ci.validate_manifest(value))
        clone=WORK/"packed-trailing";shutil.copytree(self.pack_directory,clone)
        with (clone/"evidence.tar.xz").open("ab") as f:f.write(b"trailing")
        value=copy.deepcopy(base);value["archive"]=ci.file_identity(clone,"evidence.tar.xz")
        ci.safe.write_json(clone/"manifest.json",value)
        reject(lambda:ci.verify_archive(clone,None))
        invoke("archive-trailing-public",["verify-archive","--artifact",str(clone)],expected=1)
    def test05_native_actual_readback(self):
        result=ci.validate(OPTIONS.kind,ARTIFACTS)
        ok(result["kind"]==OPTIONS.kind and result["source_set_sha256"]==ci.digest(ci.build.source_manifest()))
        invoke("native-actual-positive",args_for(OPTIONS.kind,ARTIFACTS))
    def test06_native_actual_bad_records(self):
        original=ARTIFACTS[OPTIONS.kind];shadow=WORK/"native-shadow";shutil.copytree(original,shadow)
        self.__class__.native_shadow=shadow
        baseline=ci.object_inventory(shadow);save(WORK/"native-shadow-baseline.json",baseline)
        mutations=[]
        def outer_source(rows):rows["report.json"]["source_set_sha256"]="0"*64
        def status_bool(rows):rows["native/report.json"]["status"]=True
        def cleanup(rows):rows["native/report.json"]["cleanup_errors"]=["actual cleanup failed"]
        def count_bool(rows):
            row=rows["native/report.json"]
            if "controls_total" in row:row["controls_total"]=False
            else:row["real_processes"]=True
        def missing_control(rows):
            row=rows["native/report.json"]
            row["m05_controls" if OPTIONS.kind=="cross" else "controls"].pop()
        mutations=[("source",outer_source),("native-status",status_bool),("cleanup",cleanup),("count-type",count_bool),("missing-control",missing_control)]
        if OPTIONS.kind in ("smoke","boundaries","capacity"):
            def missing_process(rows):
                control=next(r for r in rows["native/report.json"]["controls"] if "process" in r)
                del control["process"]
            mutations.append(("missing-required-process",missing_process))
            def predicate(rows):
                from hia.platform.mempool_node.suite_smoke import pool_result
                fixed=ci.native_contract.fixed_validations(OPTIONS.kind)
                control=next(r for r in rows["native/report.json"]["controls"] if r["name"] in fixed and fixed[r["name"]]["calls"] is not None)
                raw=bytearray.fromhex(control["raw_hex"])
                struct.pack_into("<Q",raw,64+40,struct.unpack_from("<Q",raw,64+40)[0]+1)
                spec=fixed[control["name"]];decoded=pool_result(bytes(raw),2,spec["outcome"],spec["error"])
                control.update(decoded)
            mutations.append(("self-consistent-fixed-calls",predicate))
        names=("report.json","native/report.json");saved={n:ci.read(shadow,n) for n in names}
        for label,change in mutations:
            rows={n:ci.safe.parse(raw) for n,raw in saved.items()};change(rows)
            inner=json.dumps(rows["native/report.json"],sort_keys=True,indent=2).encode()+b"\n"
            rows["report.json"]["native_report"]=ci.identity(inner)
            changed={"native/report.json":inner,"report.json":json.dumps(rows["report.json"],sort_keys=True,indent=2).encode()+b"\n"}
            overlay=WORK/"mutants"/("native-"+label)
            for name,raw in changed.items():
                path=overlay/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
                (shadow/name).write_bytes(raw)
            invoke("native-"+label,args_for(OPTIONS.kind,{OPTIONS.kind:shadow}),expected=1)
            for name,raw in saved.items():(shadow/name).write_bytes(raw)
        ok(ci.same(ci.object_inventory(shadow),baseline))
    def test07_original_actual_readback(self):
        result=ci.validate(OPTIONS.kind,ARTIFACTS,OPTIONS.original,capture=True)
        ok(result["kind"]==OPTIONS.kind and len(result["actual_original_tests"])==(6 if OPTIONS.kind=="original-m05" else 3))
        invoke("original-actual-positive",args_for(OPTIONS.kind,ARTIFACTS,OPTIONS.original))
    def test08_original_actual_bad_records(self):
        shadow=WORK/"original-shadow"
        shutil.copytree(OPTIONS.original,shadow,ignore=shutil.ignore_patterns("isolated-source"))
        self.__class__.original_shadow=shadow
        baseline=ci.object_inventory(shadow);save(WORK/"original-shadow-baseline.json",baseline)
        saved=ci.read(shadow,"report.json")
        def empty_sources(r):r["original_sources"]={}
        def omitted_stage(r):r["stages"].pop()
        def false_zero(r):r["failed"]=False
        def unclassified_scope(r):r["complete_node"]=True
        def missing_retained(r):r["original_retained"].pop()
        def tool_path(r):r["actual_tools"]["rustc"]["path"]+="-substitute"
        def missing_fence(r):r["fences"].pop()
        def serde_features(r):r["actual_serde_library"]["artifact"]["features"].append("arbitrary_precision")
        def binary_hash(r):r["actual_original_binary"]["sha256"]="0"*64
        changes=[("source-empty",empty_sources),("stage-omitted",omitted_stage),("bool-zero",false_zero),("scope",unclassified_scope),
                 ("retained-omitted",missing_retained),("compiler-path",tool_path),("fence-omitted",missing_fence),
                 ("serde-features",serde_features),("binary-identity",binary_hash)]
        for label,change in changes:
            report=ci.safe.parse(saved);change(report)
            raw=json.dumps(report,sort_keys=True,indent=2).encode()+b"\n"
            overlay=WORK/"mutants"/("original-"+label);overlay.mkdir(parents=True)
            (overlay/"report.json").write_bytes(raw);(shadow/"report.json").write_bytes(raw)
            invoke("original-"+label,args_for(OPTIONS.kind,ARTIFACTS,shadow),expected=1)
            (shadow/"report.json").write_bytes(saved)
        # The actual retained stdout, receipt and top-level stage identities agree
        # on an ignored test; the reader must still require its execution.
        report=ci.safe.parse(saved);stage=report["stages"][6]
        label=stage["stage"];old_raw=ci.read(shadow,label+"/stdout.raw");old_receipt=ci.read(shadow,label+"/receipt.json")
        raw=b"\nrunning 1 test\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out;\n"
        stage["stdout"]=ci.identity(raw)
        (shadow/label/"stdout.raw").write_bytes(raw);ci.safe.write_json(shadow/label/"receipt.json",stage);ci.safe.write_json(shadow/"report.json",report)
        overlay=WORK/"mutants/original-ignored-test";overlay.mkdir(parents=True)
        (overlay/"stdout.raw").write_bytes(raw);ci.safe.write_json(overlay/"receipt.json",stage);ci.safe.write_json(overlay/"report.json",report)
        invoke("original-ignored-test",args_for(OPTIONS.kind,ARTIFACTS,shadow),expected=1)
        (shadow/label/"stdout.raw").write_bytes(old_raw);(shadow/label/"receipt.json").write_bytes(old_receipt);(shadow/"report.json").write_bytes(saved)
        ok(ci.same(ci.object_inventory(shadow),baseline))
    def test09_cli_argument_scope(self):
        invoke("missing-kind",["validate"],expected=1)
        invoke("unrelated-native-argument",["validate","--kind","smoke","--smoke",str(WORK),"--node",str(WORK)],expected=1)
        invoke("missing-original",["validate","--kind","original-node","--node",str(WORK)],expected=1)
    @classmethod
    def tearDownClass(cls):
        now=ci.sources()
        ok(ci.same(now[0],cls.before[0]) and ci.same(now[1],cls.before[1]))

class RequiredResult(unittest.TextTestResult):
    def startTest(self,test):
        STARTED.append(test._testMethodName);super().startTest(test)
STARTED=[]
def main(argv=None):
    global OPTIONS,WORK,ARTIFACTS,TEST_REPORT
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scope",required=True,choices=("transport","original"))
    p.add_argument("--kind",required=True,choices=ci.KINDS)
    for name in ci.NATIVE:p.add_argument("--"+name,type=P)
    p.add_argument("--original",type=P);p.add_argument("--output",required=True,type=P)
    a=p.parse_args(argv);OPTIONS=a
    ARTIFACTS={n:getattr(a,n) for n in ci.NATIVE if getattr(a,n) is not None}
    if a.scope=="transport":
        ci.need(a.kind in ci.NATIVE and set(ARTIFACTS)=={a.kind} and a.original is None,"Transport scope requires one actual native partition")
        selected=("test01_strict_values_and_lineage","test02_actual_descriptor_special_controls","test03_complete_transport_special_metadata",
                  "test04_exact_archive_corruption_controls","test05_native_actual_readback","test06_native_actual_bad_records","test09_cli_argument_scope")
    else:
        group=a.kind.removeprefix("original-")
        required={"node"} if group=="node" else {"smoke","boundaries","capacity","cross"}
        ci.need(a.kind in ("original-node","original-m05") and set(ARTIFACTS)==required and a.original is not None,"Original scope requires complete actual native and original artifacts")
        selected=("test01_strict_values_and_lineage","test02_actual_descriptor_special_controls","test03_complete_transport_special_metadata",
                  "test04_exact_archive_corruption_controls","test07_original_actual_readback","test08_original_actual_bad_records","test09_cli_argument_scope")
    WORK=a.output.absolute();ci.need(not WORK.exists() and not WORK.is_symlink() and ci.REPOSITORY not in WORK.parents,"Fresh independent controls output");WORK.mkdir(mode=0o700)
    discovered=unittest.defaultTestLoader.getTestCaseNames(ReaderControls)
    all_names=[n for n in ReaderControls.__dict__ if n.startswith("test")]
    ci.need(discovered==sorted(all_names) and len(discovered)==9,"Whole control discovery")
    source_before=ci.sources();tool_before=ci.safe.file_identity(ci.__file__);test_before=ci.safe.file_identity(__file__)
    result=unittest.TextTestRunner(verbosity=2,resultclass=RequiredResult).run(unittest.TestSuite(ReaderControls(name) for name in selected))
    after_errors=[]
    try:
        current=ci.sources();ci.need(ci.same(current[0],source_before[0]) and ci.same(current[1],source_before[1]),"Source graph changed")
        ci.need(ci.same(ci.safe.file_identity(ci.__file__),tool_before) and ci.same(ci.safe.file_identity(__file__),test_before),"Control/reader source changed")
    except BaseException as e:after_errors.append(repr(e))
    passed=result.wasSuccessful() and not result.skipped and result.testsRun==len(selected) and STARTED==list(selected) and not after_errors
    report={"schema":"trnm.node-pool-ci-controls.v1","scope":a.scope,"kind":a.kind,"status":"PASS" if passed else "FAIL",
            "required_groups":len(selected),"executed_groups":result.testsRun,"started":STARTED,"controls":CONTROLS,"actual_cli":CLIS,
            "skipped":len(result.skipped),"failures":len(result.failures),"errors":len(result.errors),"source_after":{"status":"MATCH" if not after_errors else "FAIL","errors":after_errors},
            "reader":tool_before,"test":test_before,"source_inputs":source_before[0],"original_sources":source_before[1],
            "synthetic_archive_lineage_only":SYNTHETIC,"native_execution":False,"original_execution":False}
    save(WORK/"report.json",report)
    print(json.dumps({k:v for k,v in report.items() if k not in ("source_inputs","original_sources")},sort_keys=True))
    if not passed:raise SystemExit(1)
if __name__=="__main__":main()
