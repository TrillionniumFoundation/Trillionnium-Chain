"""Full original Rust comparison for the private HIA M01 governance owner."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from .governance_native import GovernanceNative, FAULT_SOURCE, SOURCE, FIXTURE
ROOT=Path(__file__).resolve().parents[2]
U64=(1<<64)-1

def command(op,handle=1,caller="",a="",b="",c="",d="",*,ident=0,eta=0,now=0,flags=0):
    fields=[v.encode("utf-8") if isinstance(v,str) else v for v in (caller,a,b,c,d)]
    return struct.pack("<12Q",op,handle,ident,eta,now,flags,*(len(s) for s in fields),0)+b"".join(fields)

def session(commands):
    return struct.pack("<8s3Q",b"GVS10001",len(commands),0,0)+b"".join(commands)

def replies(raw):
    if len(raw)<32 or raw[:8]!=b"GVR10001":raise AssertionError("Invalid complete governance response")
    count,total,reserved=struct.unpack_from("<3Q",raw,8)
    if total!=len(raw) or reserved:raise AssertionError("Governance response extent/reserved bytes differ")
    at=32;rows=[]
    for _ in range(count):
        op,handle,status,size=struct.unpack_from("<4Q",raw,at);at+=32
        data=raw[at:at+size];at+=size
        if len(data)!=size:raise AssertionError("Incomplete governance payload")
        rows.append((op,handle,status,data))
    if at!=len(raw):raise AssertionError("Trailing governance response")
    return rows

def observe(handle=1,ids=(1,2,3,4)):
    return [*(command(11,handle,ident=i) for i in ids),command(12,handle),command(13,handle),command(15,handle)]

def setup(delay=60):
    return [command(0,0,"admin","guardian",eta=delay),command(1,caller="admin",a="alice",flags=1),
        command(1,caller="admin",a="exec",flags=2),command(3,caller="admin",a="k",flags=1)]

def selected_rustc(stage,shim):
    """Ask the selected shim before resolving it; rustup uses argv[0]."""
    shim=str(Path(shim).absolute())
    driver=stage("rustc-driver-version",[shim,"-Vv"])
    selected=stage("rustc-driver-sysroot",[shim,"--print","sysroot"])
    lines=selected.stdout.decode("utf-8").splitlines()
    if len(lines)!=1 or not lines[0] or not Path(lines[0]).is_absolute():
        raise AssertionError("Rust compiler returned no exact absolute sysroot")
    sysroot=Path(lines[0]).resolve(strict=True)
    actual=(sysroot/"bin/rustc").resolve(strict=True)
    if not actual.is_file():raise AssertionError("Selected Rust compiler is not a file")
    version=stage("rustc-version",[str(actual),"-Vv"])
    if version.stdout!=driver.stdout or driver.stderr or selected.stderr or version.stderr:
        raise AssertionError("Selected compiler differs from the actual shim selection")
    return str(actual),{"selected_shim":shim,"sysroot":str(sysroot),"compiler":str(actual),
                       "compiler_sha256":hashlib.sha256(actual.read_bytes()).hexdigest(),
                       "version_sha256":hashlib.sha256(version.stdout).hexdigest()}


class PrivateGovernance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured=os.environ.get("TRNM_HIA_GOVERNANCE_OUTPUT")
        cls.temp=None
        if configured:
            cls.output=Path(configured).absolute()
            cls.output.mkdir(parents=True,exist_ok=False)
        else:
            cls.temp=tempfile.TemporaryDirectory(prefix="trnm-hia-governance-")
            cls.output=Path(cls.temp.name)
        cls.stages=[];cls.comparisons=[];cls.controls=[];cls.native=None
        cls.comparison_sequence=0
        cls.native_failure_sequence=0
        cls.expected_tests=[cls.__module__+"."+cls.__qualname__+"."+name
                            for name in unittest.defaultTestLoader.getTestCaseNames(cls)]
        cls.started_tests=[];cls.completed_tests=[];cls.finalized=False
        cls.source_after=None;cls.source_unchanged=None
        cls.source_before={};cls.original_tests=[]
        # Create an explicit incomplete record before reading source or selecting
        # a compiler. Failed setup must never leave an apparently absent run.
        cls.report()
        try:
            cls.setup_actual()
        except BaseException as error:
            streams={}
            for channel in ("stdout","stderr"):
                raw=getattr(error,channel,None)
                if raw is not None:
                    if isinstance(raw,str):raw=raw.encode()
                    (cls.output/("class-setup-failure."+channel+".raw")).write_bytes(raw)
                    streams[channel]=cls.identity(raw)
            cls.stages.append({"name":"class-setup-failure","stage_kind":"setup",
                "argv":getattr(error,"cmd",None),"returncode":None,
                "timeout":getattr(error,"timeout",None),"failure_kind":"setup",
                "expected_failure":None,"exception_type":type(error).__name__,
                "exception":repr(error),"stdout":streams.get("stdout"),
                "stderr":streams.get("stderr"),"input":None})
            cls.report()
            raise

    @classmethod
    def setup_actual(cls):
        cls.original_files=[ROOT/"trillionnium/crates/trnm-audit-events/src/lib.rs",
            ROOT/"trillionnium/crates/trnm-audit-events/Cargo.toml",
            ROOT/"trillionnium/crates/trnm-governance-guard/src/lib.rs",
            ROOT/"trillionnium/crates/trnm-governance-guard/Cargo.toml",
            ROOT/"hia/tests/rust_governance_reference.rs",
            ROOT/"hia/tests/rust_governance_wire.rs",ROOT/"hia/tests/rust_governance_boundary.rs"]
        cls.source_before={str(p.relative_to(ROOT)):cls.identity(p.read_bytes()) for p in cls.original_files}
        cls.source_before.update({str(p.relative_to(ROOT)):cls.identity(p.read_bytes()) for p in
            [SOURCE,FIXTURE,Path(__file__),ROOT/"hia/tests/governance_native.py",
             SOURCE.parent/"README.md",ROOT/"hia/components.json",ROOT/"config/hia-migration-v1.json",
             ROOT/"hia/tests/native_support.py",ROOT/"hia/tests/escrow_native.py",ROOT/"hia/src/escrow/vault.hepta",ROOT/"hia/tools/toolchain.py",
             ROOT/"hia/src/codec/json_primitives.hepta",ROOT/"hia/toolchain.lock.json",
             ROOT/"hia/qualification/compiler-binding.json"]})
        rustc=shutil.which("rustc")
        if not rustc:
            # Attempt the real requested process so the OS refusal, requested
            # argv and lack of child streams are retained by the same recorder.
            cls.stage("rustc-unavailable",["rustc","-Vv"])
            raise RuntimeError("Actual original Rust compiler is required, never skipped")
        cls.rustc,selection=selected_rustc(cls.stage,rustc)
        (cls.output/"rustc-selection.json").write_text(json.dumps(selection,sort_keys=True,indent=2)+"\n")
        audit=ROOT/"trillionnium/crates/trnm-audit-events/src/lib.rs"
        governance=ROOT/"trillionnium/crates/trnm-governance-guard/src/lib.rs"
        cls.auditlib=cls.output/"libtrnm_audit_events.rlib"
        cls.guardlib=cls.output/"libtrnm_governance_guard.rlib"
        cls.stage("audit-library",[cls.rustc,"--edition=2021","-O","--crate-type=rlib",
            "--crate-name=trnm_audit_events",str(audit),"-o",str(cls.auditlib)])
        cls.stage("guard-library",[cls.rustc,"--edition=2021","-O","--crate-type=rlib",
            "--crate-name=trnm_governance_guard",str(governance),"--extern",
            "trnm_audit_events="+str(cls.auditlib),"-o",str(cls.guardlib)])
        cls.original_tests=[]
        for name,source,args in [("audit",audit,[]),("guard",governance,
                ["--extern","trnm_audit_events="+str(cls.auditlib)])]:
            binary=cls.output/(name+"-original-tests")
            cls.stage(name+"-test-build",[cls.rustc,"--edition=2021","-O","--test",
                str(source),*args,"-o",str(binary)])
            run=cls.stage(name+"-retained-tests",[str(binary),"--nocapture"])
            count=3 if name=="audit" else 45
            if f"test result: ok. {count} passed; 0 failed; 0 ignored;".encode() not in run.stdout:
                raise AssertionError("Original retained tests did not complete")
            cls.original_tests.append({"name":name,"binary":cls.identity(binary.read_bytes()),
                                       "passed":count,"stdout":cls.identity(run.stdout)})
        cls.oracle=cls.output/"guard-original-reference"
        cls.stage("adapter-build",[cls.rustc,"--edition=2021","-O",
            str(ROOT/"hia/tests/rust_governance_reference.rs"),"--extern","trnm_audit_events="+str(cls.auditlib),
            "--extern","trnm_governance_guard="+str(cls.guardlib),"-L","dependency="+str(cls.output),
            "-o",str(cls.oracle)])
        cls.native=GovernanceNative()
        binding=json.loads((ROOT/"hia/qualification/compiler-binding.json").read_text())
        if (cls.native.receipt.get("compiler_sha256")!=binding["compiler_sha256"]
                or cls.native.receipt["chain_migration"]["backend"]!="selfhost"
                or cls.native.receipt["claims"]["fallback_used"] is not False):
            raise AssertionError("Governance did not use the original pinned native compiler")
        (cls.output/"guard-native.so").write_bytes(cls.native.library.read_bytes())
        (cls.output/"native-build.json").write_text(json.dumps(cls.native.receipt,sort_keys=True,indent=2)+"\n")
        cls.report()

    @classmethod
    def identity(cls,data):
        return {"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}

    @classmethod
    def stage(cls,name,argv,*,data=None,timeout=180,expected_failure=None):
        if expected_failure not in (None,"timeout","spawn","exit"):
            raise ValueError("Unknown qualification failure control")
        argv=[str(part) for part in argv]
        result=None;error=None;failure=None;returncode=None;stdout=b"";stderr=b""
        try:
            result=subprocess.run(argv,cwd=ROOT,input=data,capture_output=True,timeout=timeout,check=False)
            returncode=result.returncode;stdout=result.stdout;stderr=result.stderr
            if returncode:failure="exit"
        except subprocess.TimeoutExpired as captured:
            error=captured;failure="timeout"
            stdout=captured.stdout or b"";stderr=captured.stderr or b""
        except OSError as captured:
            error=captured;failure="spawn"
        # TimeoutExpired contains the actual bytes captured before the child was
        # killed/reaped. Do not replace those observations with a simulated log.
        (cls.output/(name+".stdout.raw")).write_bytes(stdout)
        (cls.output/(name+".stderr.raw")).write_bytes(stderr)
        if data is not None:(cls.output/(name+".input.raw")).write_bytes(data)
        cls.stages.append({"name":name,"stage_kind":"process","argv":argv,"returncode":returncode,
            "timeout":timeout,"failure_kind":failure,"expected_failure":expected_failure,
            "exception_type":None if error is None else type(error).__name__,
            "exception":None if error is None else repr(error),
            "errno":getattr(error,"errno",None),
            "stdout":cls.identity(stdout),"stderr":cls.identity(stderr),
            "input":None if data is None else cls.identity(data)})
        cls.report()
        if error is not None:raise error
        if returncode:
            raise AssertionError(("Actual process stage failed",name,returncode,stderr.decode(errors="replace")))
        if expected_failure is not None:
            raise AssertionError(("Expected process refusal did not occur",name,expected_failure))
        return result

    @classmethod
    def report(cls):
        files={p.relative_to(cls.output).as_posix():cls.identity(p.read_bytes())
               for p in sorted(cls.output.rglob("*"))
               if p.is_file() and p!=cls.output/"report.json"}
        actual=[row["test"] for row in cls.completed_tests]
        all_tests=(cls.started_tests==cls.expected_tests and actual==cls.expected_tests
                   and all(row["status"]=="PASS" for row in cls.completed_tests))
        failed=any(row["status"]!="PASS" for row in cls.completed_tests)
        failed=failed or any(
            (row.get("failure_kind")!=row["expected_failure"] if row.get("expected_failure") is not None
             else row["returncode"]!=0 or row.get("failure_kind") is not None)
            for row in cls.stages)
        failed=failed or any(not row["match"] for row in cls.comparisons)
        failed=failed or cls.source_unchanged is False
        status=("FAIL" if failed else "PASS" if cls.finalized and all_tests
                and cls.source_unchanged is True else "INCOMPLETE")
        data={"schema":"trnm.hia.governance-development.v1","status":status,
              "finalized":cls.finalized,"expected_tests":cls.expected_tests,
              "started_tests":cls.started_tests,"completed_tests":cls.completed_tests,
              "all_expected_tests_completed":all_tests,"source_inputs":cls.source_before,
              "source_after":cls.source_after,"source_unchanged":cls.source_unchanged,
              "stages":cls.stages,"original_tests":getattr(cls,"original_tests",[]),
              "comparisons":cls.comparisons,"native_controls":cls.controls,
              "native_operation_count":sum(r["operations"] for r in cls.comparisons),
              "public_operation_count":sum(r["operations"] for r in cls.comparisons if r["scope"]=="public-session"),
              "fixed_fixture_operation_count":sum(r["operations"] for r in cls.comparisons if r["scope"]=="fixed-private-fixture"),
              "all_recorded_comparisons_match":all(r["match"] for r in cls.comparisons),
              "files":files,"whole_chain_native":False,"live_node_integrated":False,
              "retirement_accepted":False}
        (cls.output/"report.json").write_text(json.dumps(data,sort_keys=True,indent=2)+"\n")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.source_after={name:cls.identity((ROOT/name).read_bytes()) for name in cls.source_before}
            cls.source_unchanged=cls.source_after==cls.source_before
            cls.finalized=True
            cls.report()
            if not cls.source_unchanged:raise AssertionError("Escrow source changed during qualification")
        finally:
            if cls.native:cls.native.close()
            if cls.temp:cls.temp.cleanup()

    def run(self,result=None):
        """Record the actual unittest lifecycle, including setup/assertion errors."""
        if result is None:result=self.defaultTestResult()
        cls=type(self)
        cls.started_tests.append(self.id())
        cls.report()
        try:
            returned=super().run(result)
        except BaseException as error:
            cls.completed_tests.append({"test":self.id(),"status":"ERROR","detail":repr(error)})
            cls.report()
            raise
        problems=[]
        for name,kind in [("errors","ERROR"),("failures","FAIL"),("skipped","SKIPPED"),
                          ("expectedFailures","EXPECTED_FAILURE")]:
            for test,detail in getattr(result,name,[]):
                if test is self or getattr(test,"test_case",None) is self:
                    problems.append({"kind":kind,"detail":detail})
        if self in getattr(result,"unexpectedSuccesses",[]):
            problems.append({"kind":"UNEXPECTED_SUCCESS","detail":"unexpected success"})
        cls.completed_tests.append({"test":self.id(),"status":"PASS" if not problems else problems[0]["kind"],
                                    "problems":problems})
        cls.report()
        return returned

    def compare(self,commands,label):
        raw=session(commands)
        # Reserve the identity before execution. A failed comparison cannot be
        # overwritten by the next method merely because it added no result row.
        index=type(self).comparison_sequence;type(self).comparison_sequence+=1
        (self.output/f"comparison-{index:04d}.input.bin").write_bytes(raw)
        result=self.stage(f"comparison-{index:04d}-oracle",[str(self.oracle)],data=raw,timeout=60)
        for suffix,data in [("input.bin",raw),("original.bin",result.stdout),("oracle.stderr.raw",result.stderr)]:
            (self.output/f"comparison-{index:04d}.{suffix}").write_bytes(data)
        (self.output/f"comparison-{index:04d}.oracle.execution.json").write_text(json.dumps({
            "argv":[str(self.oracle)],"returncode":result.returncode,"input":self.identity(raw),
            "stdout":self.identity(result.stdout),"stderr":self.identity(result.stderr)},sort_keys=True)+"\n")
        self.report()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stderr,b"")
        expected=result.stdout
        original=replies(expected)
        self.assertEqual(len(original),len(commands))
        observed=self.native_sessions(self.native,[(raw,len(expected)+19)])["cases"][0]
        actual=observed["output"][:-19]
        match=observed["value"]==0 and actual==expected and observed["output"][-19:]==b"\xa5"*19
        record={"index":index,"label":label,"scope":"public-session","operations":len(commands),"match":match,
                "input":self.identity(raw),"original":self.identity(expected),
                "native":self.identity(actual),"native_status":observed["value"]}
        for suffix,data in [("input",raw),("original",expected),("native",actual)]:
            (self.output/f"comparison-{index:04d}.{suffix}.bin").write_bytes(data)
        type(self).comparisons.append(record);self.report()
        self.assertTrue(match,(label,record))
        return original

    def native_sessions(self,native,cases,*,expected_failure=None,**options):
        """Retain delegated worker exceptions without changing its execution.

        Ordinary worker responses already have exact request/stdio capture in
        EscrowNative. On a timeout or OS exception it does not return a response;
        preserve the actual exception streams and supplied public arguments here.
        This wrapper supplies no state or governance outcome to the worker.
        """
        cases=list(cases)
        try:
            observed=native.sessions(cases,**options)
        except (subprocess.TimeoutExpired,OSError) as error:
            cls=type(self);index=cls.native_failure_sequence;cls.native_failure_sequence+=1
            name=f"native-delegate-failure-{index:04d}"
            kind="timeout" if isinstance(error,subprocess.TimeoutExpired) else "os-error"
            stdout=getattr(error,"stdout",None) or b"";stderr=getattr(error,"stderr",None) or b""
            if isinstance(stdout,str):stdout=stdout.encode()
            if isinstance(stderr,str):stderr=stderr.encode()
            (self.output/(name+".stdout.raw")).write_bytes(stdout)
            (self.output/(name+".stderr.raw")).write_bytes(stderr)
            invocation={"library_sha256":native.artifact_sha256,"source":str(native.source),
                "cases":[{"input_base64":base64.b64encode(case[0]).decode(),
                          "output_size":case[1],"fault_arguments":list(case[2:])} for case in cases],
                "options":{key:str(value) if isinstance(value,Path) else value for key,value in options.items()}}
            raw=json.dumps(invocation,sort_keys=True).encode()
            (self.output/(name+".public-invocation.json")).write_bytes(raw)
            cls.stages.append({"name":name,"stage_kind":"native-delegate-failure",
                "argv":getattr(error,"cmd",None),"returncode":None,
                "timeout":getattr(error,"timeout",options.get("timeout",120)),
                "failure_kind":kind,"expected_failure":expected_failure,
                "exception_type":type(error).__name__,"exception":repr(error),
                "errno":getattr(error,"errno",None),"stdout":self.identity(stdout),
                "stderr":self.identity(stderr),"input":None,"public_invocation":self.identity(raw)})
            self.report()
            raise
        if expected_failure is not None:
            raise AssertionError("Expected native worker refusal did not occur")
        return observed

    def test_all_public_methods_and_clone(self):
        commands=setup()+[
            command(4,caller="alice",a="k",b="",c="100",d="reason",eta=60),
            command(5,caller="alice",ident=1),command(5,caller="alice",ident=1),
            command(6,caller="exec",ident=1,now=59),*observe(),
            command(6,caller="exec",ident=1,now=60),*observe(),
            command(4,caller="alice",a="k",b="100",c="200",d="r2",eta=120,now=60),
            command(4,caller="alice",a="k",b="100",c="300",d="r3",eta=120,now=60),
            command(5,caller="alice",ident=2),command(5,caller="alice",ident=3),
            command(6,caller="exec",ident=2,now=120),command(6,caller="exec",ident=3,now=120),
            command(7,caller="guardian",ident=3),*observe(),
            command(8,caller="guardian",a="pause\x00理由"),command(8,caller="guardian",a="ignored"),
            command(4,caller="alice",a="k",b="200",c="400",eta=180,now=120),
            command(5,caller="alice",ident=4),command(6,caller="exec",ident=4,now=180),
            command(9,caller="guardian",a="restore",eta=240,now=180),
            command(10,caller="exec",ident=5,now=239),*observe(ids=(3,4,5)),
            command(16),command(2,2,"admin","guardian",flags=0),
            command(10,2,"exec",ident=5,now=240),command(10,caller="exec",ident=5,now=240),
            *observe(ids=(4,5)),*observe(2,ids=(4,5)),
            command(14),command(13),command(15),command(14),
            *observe(2,ids=(4,5)),command(17),command(12),command(16),
            command(17,2),command(12,2)]
        rows=self.compare(commands,"complete-public-lifecycle-and-deep-clone")
        self.assertIn(14,[r[2] for r in rows]);self.assertIn(6,[r[2] for r in rows])
        self.assertEqual(rows[-1][2],64)
        consumed=next(i for i,row in enumerate(rows) if row[0]==14)
        self.assertEqual(rows[consumed+1][3],struct.pack("<Q",0))
        self.assertEqual(rows[consumed+2][3],struct.pack("<Q",0))
        self.assertEqual(rows[consumed+3][3],struct.pack("<Q",1)+struct.pack("<18Q",7,*([0]*17)))
        self.assertEqual(self.original_tests[1]["name"],"guard")

    def test_fixed_private_boundaries(self):
        oracle=self.output/"guard-original-boundaries"
        self.stage("boundary-adapter-build",[self.rustc,"--edition=2021","-O",
            str(ROOT/"hia/tests/rust_governance_boundary.rs"),"--extern",
            "trnm_audit_events="+str(self.auditlib),"-L","dependency="+str(self.output),"-o",str(oracle)])
        original=self.stage("boundary-original-run",[str(oracle)]).stdout
        rows=replies(original)
        self.assertEqual(len(rows),193)
        self.assertEqual({row[2] for row in rows if row[2]}, {10,13,14,16})
        self.assertIn(struct.pack("<Q",U64),[row[3] for row in rows if row[0]==110])
        native=GovernanceNative(fixture=True)
        try:
            self.assertEqual(native.receipt["compiler_sha256"],self.native.receipt["compiler_sha256"])
            self.assertEqual(native.receipt["chain_migration"]["backend"],"selfhost")
            self.assertIs(native.receipt["claims"]["fallback_used"],False)
            (self.output/"boundary-native.so").write_bytes(native.library.read_bytes())
            (self.output/"boundary-native-build.json").write_text(json.dumps(native.receipt,sort_keys=True,indent=2)+"\n")
            observed=self.native_sessions(native,[(b"",len(original)+19)])["cases"][0]
            actual=observed["output"][:-19];match=observed["value"]==0 and actual==original and observed["output"][-19:]==b"\xa5"*19
            index=type(self).comparison_sequence;type(self).comparison_sequence+=1
            for suffix,data in [("input",b""),("original",original),("native",actual)]:
                (self.output/f"comparison-{index:04d}.{suffix}.bin").write_bytes(data)
            self.comparisons.append({"index":index,"label":"fixed-private-boundaries-no-state-input",
                "scope":"fixed-private-fixture","operations":len(rows),"match":match,
                "input":self.identity(b""),"original":self.identity(original),"native":self.identity(actual),
                "native_status":observed["value"]})
            self.report();self.assertTrue(match)
            for sent,expected in [((b"x",len(original)),1),((b"",len(original)-1),3)]:
                answer=self.native_sessions(native,[sent])["cases"][0]
                self.assertEqual(answer["value"],expected);self.assertEqual(answer["output"],b"\xa5"*sent[1])
                self.controls.append({"kind":"fixed-fixture-frame-or-capacity","status":expected,"output_unchanged":True})
        finally:
            native.close()

    def test_error_precedence_and_atomic_snapshots(self):
        base=setup()
        pending=base+[command(4,caller="alice",a="k",c="v",eta=60)]
        queued=pending+[command(5,caller="alice",ident=1)]
        paused=base+[command(8,caller="guardian",a="pause")]
        scheduled=paused+[command(9,caller="guardian",a="restore",eta=60)]
        cases=[
            (base,command(1,caller="intruder",a="alice",flags=3),1),
            (base,command(2,caller="intruder",a="guardian",flags=0),1),
            (base,command(3,caller="intruder",a="k",flags=0),1),
            (base,command(4,caller="admin",a="bad",eta=0,now=U64),1),
            (base,command(4,caller="alice",a="bad",eta=59),2),
            (base,command(4,caller="alice",a="bad",eta=U64,now=U64),2),
            (base,command(4,caller="alice",a="bad",eta=60),3),
            (base,command(5,caller="intruder",ident=999),1),
            (base,command(5,caller="alice",ident=999),4),
            (pending+[command(1,caller="admin",a="bob",flags=1)],command(5,caller="bob",ident=1),12),
            (pending+[command(1,caller="admin",a="alice",flags=0)],command(5,caller="alice",ident=1),1),
            (base,command(6,caller="intruder",ident=999),1),
            (base,command(6,caller="exec",ident=999),4),
            (pending,command(6,caller="exec",ident=1,now=U64),5),
            (queued,command(6,caller="exec",ident=1,now=59),6),
            (queued+[command(3,caller="admin",a="k",flags=0)],command(6,caller="exec",ident=1,now=60),3),
            (queued+[command(1,caller="admin",a="exec",flags=0)],command(6,caller="exec",ident=1,now=60),1),
            (queued+[command(6,caller="exec",ident=1,now=60)],command(6,caller="exec",ident=1,now=0),7),
            (queued+[command(7,caller="guardian",ident=1)],command(5,caller="alice",ident=1),7),
            (base,command(7,caller="intruder",ident=999),4),
            (pending,command(7,caller="intruder",ident=1),1),
            (pending+[command(1,caller="admin",a="alice",flags=0)],command(7,caller="alice",ident=1),1),
            (pending+[command(7,caller="guardian",ident=1)],command(7,caller="intruder",ident=1),7),
            (base,command(8,caller="admin",a=""),1),
            (base,command(9,caller="intruder",eta=0,now=U64),1),
            (base,command(9,caller="guardian",eta=0,now=U64),10),
            (paused,command(9,caller="guardian",eta=59),2),
            (paused,command(9,caller="guardian",eta=U64,now=U64),2),
            (scheduled,command(9,caller="guardian",eta=0),2),
            (scheduled,command(9,caller="guardian",eta=60),15),
            (scheduled,command(10,caller="intruder",ident=999),1),
            (scheduled+[command(1,caller="admin",a="guardian",flags=2)],command(10,caller="guardian",ident=999),11),
            (scheduled,command(10,caller="exec",ident=999),4),
            (queued,command(10,caller="exec",ident=1,now=0),8),
            (scheduled,command(6,caller="exec",ident=1,now=0),8),
            (scheduled,command(10,caller="exec",ident=1,now=59),6),
            (scheduled+[command(2,caller="admin",a="guardian",flags=0)],command(10,caller="exec",ident=1,now=60),1),
            (scheduled+[command(7,caller="guardian",ident=1)],command(10,caller="exec",ident=1,now=60),7),
            (scheduled+[command(10,caller="exec",ident=1,now=60)],command(10,caller="exec",ident=1,now=0),7),
            (scheduled+[command(1,caller="admin",a="guardian",flags=1)],command(5,caller="guardian",ident=1),8),
            (base+[command(4,caller="alice",a="k",b="wrong",c="v",eta=60),command(5,caller="alice",ident=1)],command(6,caller="exec",ident=1,now=60),13),
        ]
        for index,(prefix,operation,expected) in enumerate(cases):
            before=observe(ids=(1,2,999));rows=self.compare(prefix+before+[operation]+before,f"error-order-{index:02d}")
            at=len(prefix);self.assertEqual(rows[at+len(before)][2],expected)
            self.assertEqual(rows[at:at+len(before)],rows[at+len(before)+1:])

    def test_opaque_strings_option_presence_and_u64(self):
        strings=["","\x00","\t \u0085\u00a0\u2000\u2028\u3000","\u001c\u180e\u200b\ufeff",
                 "🔐é中"," a ","a","a\x00b","emergency_pause"]
        for index,text in enumerate(strings):
            cmds=[command(0,0,text,text,eta=0),command(1,caller=text,a=text,flags=3),
                command(3,caller=text,a=text,flags=1),command(4,caller=text,a=text,b="",c=text,d=text,eta=U64,now=U64),
                command(5,caller=text,ident=1),command(6,caller=text,ident=1,now=U64),*observe(),
                command(8,caller=text,a=text),command(9,caller=text,a=text,eta=U64,now=U64),
                command(1,caller=text,a="other",flags=2),command(10,caller="other",ident=2,now=U64),
                *observe(),command(14),command(15),command(14)]
            rows=self.compare(cmds,f"opaque-option-{index}")
            self.assertTrue(all(r[2]==0 for r in rows))
        for delay,now,eta,expected in [(U64,0,U64,0),(U64,1,U64,2),(60,U64-60,U64,0),(60,U64-59,U64,2),(1,U64-1,U64,0)]:
            rows=self.compare(setup(delay)+[command(4,caller="alice",a="k",eta=eta,now=now),*observe()],f"u64-delay-{delay}-{now}")
            self.assertEqual(rows[4][2],expected)

    def test_growth_sorted_maps_and_clone_ownership(self):
        cmds=setup(0);keys=["", "é", "a\x00", "a", "中", "emergency_pause"]+[f"key-{i:03d}" for i in range(96)]
        random.Random(4261).shuffle(keys)
        for ident,key in enumerate(keys,1):
            cmds.extend([command(3,caller="admin",a=key,flags=1),command(4,caller="alice",a=key,c=key+"\x00value",eta=ident,now=ident),command(5,caller="alice",ident=ident),command(6,caller="exec",ident=ident,now=ident)])
        cmds.extend(observe(ids=(1,len(keys),U64)))
        for handle in range(1,7):
            cmds.extend([command(16,handle),command(14,handle),command(8,handle,"guardian",f"pause-{handle}"),
                         command(2,handle,"admin","guardian",flags=0),*observe(handle,ids=(1,len(keys))),
                         *observe(handle+1,ids=(1,len(keys))),command(17,handle),command(12,handle)])
        self.compare(cmds,"native-arena-growth-clone-drop-independent-history")

    def test_permission_restoration_and_guardian_replacement(self):
        for seed in range(12):
            rng=random.Random(79000+seed);delay=rng.choice([0,1,60]);eta=rng.choice([delay,120,U64]);key=rng.choice(["k","", "授权\x00"])
            cmds=setup(delay)+[command(3,caller="admin",a=key,flags=1),
                command(4,caller="alice",a=key,c="100",d="first",eta=eta),
                command(5,caller="alice",ident=1),command(1,caller="admin",a="exec",flags=0),
                command(6,caller="exec",ident=1,now=eta),*observe(),
                command(1,caller="admin",a="exec",flags=2),command(3,caller="admin",a=key,flags=0),
                command(6,caller="exec",ident=1,now=eta),*observe(),
                command(3,caller="admin",a=key,flags=1),command(6,caller="exec",ident=1,now=eta),
                command(4,caller="alice",a=key,b="100",c="200",eta=eta),
                command(1,caller="admin",a="alice",flags=0),command(7,caller="alice",ident=2),
                command(1,caller="admin",a="alice",flags=1),command(7,caller="alice",ident=2),
                command(8,caller="guardian",a="pause-A"),command(2,caller="admin",a="g2",flags=1),
                command(9,caller="g2",a="restore-A",eta=eta),
                command(2,caller="admin",a="g2",flags=0),command(10,caller="exec",ident=3,now=eta),
                command(7,caller="g2",ident=3),*observe(),
                command(7,caller="guardian",ident=3),command(9,caller="guardian",a="restore-B",eta=eta),
                command(2,caller="admin",a="exec",flags=1),command(10,caller="exec",ident=4,now=eta),
                command(2,caller="admin",a="exec",flags=0),command(10,caller="exec",ident=4,now=eta),
                command(9,caller="guardian",a="inactive",eta=eta),*observe(),
                command(8,caller="guardian",a="pause-C"),command(9,caller="guardian",a="restore-C",eta=eta),
                command(1,caller="admin",a="guardian",flags=2),command(2,caller="admin",a="guardian",flags=0),
                command(10,caller="guardian",ident=5,now=eta),
                command(2,caller="admin",a="g2",flags=1),command(7,caller="g2",ident=5),
                command(9,caller="g2",a="restore-D",eta=eta),command(10,caller="exec",ident=6,now=eta),
                *observe(ids=(1,2,3,4,5,6)),command(14),command(15)]
            rows=self.compare(cmds,f"restored-permissions-guardian-replacement-{seed:02d}")
            self.assertTrue({1,3,10,11}.issubset({r[2] for r in rows}))
            self.assertEqual(rows[-2][2],0);self.assertEqual(rows[-1][3],struct.pack("<Q",0))

    def test_randomized_public_sequences(self):
        names=["admin","guardian","alice","exec","bob","", " a ","🔐\x00"]
        keys=["k","","a","a\x00","é","emergency_pause"]
        for seed in range(24):
            rng=random.Random(52000+seed);cmds=setup(rng.choice([0,1,60,U64]));handles=1
            for i in range(85):
                op=rng.randrange(18);h=rng.randrange(1,handles+2);caller=rng.choice(names)
                if op==0:cmd=command(0,0,caller,rng.choice(names),eta=rng.choice([0,1,60,U64]));handles+=1
                elif op==1:cmd=command(op,h,caller,rng.choice(names),flags=rng.randrange(4))
                elif op in [2,3]:cmd=command(op,h,caller,rng.choice(names if op==2 else keys),flags=rng.randrange(2))
                elif op==4:cmd=command(op,h,caller,rng.choice(keys),rng.choice(["","v","\x00"]),rng.choice(["","v","new"]),rng.choice(names),eta=rng.choice([0,60,120,U64]),now=rng.choice([0,60,U64]))
                elif op in [5,7,11]:cmd=command(op,h,caller if op!=11 else "",ident=rng.randrange(1,10))
                elif op in [6,10]:cmd=command(op,h,caller,ident=rng.randrange(1,10),now=rng.choice([0,60,120,U64]))
                elif op==8:cmd=command(op,h,caller,rng.choice(names))
                elif op==9:cmd=command(op,h,caller,rng.choice(names),eta=rng.choice([0,60,120,U64]),now=rng.choice([0,60,U64]))
                else:cmd=command(op,h)
                cmds.append(cmd)
                if op==16:handles+=1  # A possibly unused selector remains harmless.
                if i%9==0:cmds.extend(observe(h,ids=(1,2,3)))
            self.compare(cmds,f"random-public-transcript-{seed:02d}")

    def test_malformed_utf8_capacity_atomicity(self):
        valid=session(setup()+[command(4,caller="alice",a="k",c="v",eta=60),command(5,caller="alice",ident=1),command(6,caller="exec",ident=1,now=60),*observe()])
        original=self.stage("capacity-original-run",[str(self.oracle)],data=valid).stdout
        invalid=[]
        for n in [0,1,7,8,16,24,31,32,40,127,len(valid)-1]:invalid.append((valid[:n],1,"truncated-"+str(n)))
        for offset,value in [(0,0),(16,1),(24,1),(32,18),(40,1),(32+88,1),(32+16,1),(32+32,1),(32+40,1),(32+48,U64)]:
            raw=bytearray(valid);struct.pack_into("<Q",raw,offset,value);invalid.append((bytes(raw),1,"header-word-"+str(offset)))
        invalid.append((valid+b"\x00",1,"trailing-byte"))
        for raw in [b"\xff",b"\xc0\x80",b"\xed\xa0\x80",b"\xf4\x90\x80\x80",b"\xe2\x82",b"\x80"]:
            invalid.append((session([command(0,0,raw)]),2,"invalid-utf8-"+raw.hex()))
        cases=[(raw,len(original)+100) for raw,_,_ in invalid]+[(valid,n) for n in [0,1,31,32,39,63,len(original)-1]]
        observed=self.native_sessions(self.native,cases)["cases"]
        for index,row in enumerate(observed):
            expected=invalid[index][1] if index<len(invalid) else 3
            self.assertEqual(row["value"],expected);self.assertEqual(row["output"],b"\xa5"*cases[index][1])
            self.controls.append({"kind":"frame-or-capacity","label":invalid[index][2] if index<len(invalid) else "capacity", "status":row["value"],"input":self.identity(cases[index][0]),"output_size":cases[index][1],"output_unchanged":True})
        exact=self.native_sessions(self.native,[(valid,len(original))])["cases"][0]
        self.assertEqual(exact["value"],0);self.assertEqual(exact["output"],original)

    def test_process_failure_evidence_retains_actual_streams(self):
        data=b"actual timeout input\n"
        command_line=[sys.executable,"-I","-S","-c",
            "import sys,time; data=sys.stdin.buffer.read(); "
            "sys.stdout.buffer.write(b'partial stdout\\n'+data); sys.stdout.buffer.flush(); "
            "sys.stderr.buffer.write(b'partial stderr\\n'); sys.stderr.buffer.flush(); time.sleep(5)"]
        with self.assertRaises(subprocess.TimeoutExpired):
            self.stage("failure-control-timeout",command_line,data=data,timeout=0.5,expected_failure="timeout")
        row=self.stages[-1]
        self.assertEqual((row["failure_kind"],row["returncode"],row["timeout"]),("timeout",None,0.5))
        self.assertEqual((self.output/"failure-control-timeout.stdout.raw").read_bytes(),b"partial stdout\n"+data)
        self.assertEqual((self.output/"failure-control-timeout.stderr.raw").read_bytes(),b"partial stderr\n")
        self.assertEqual((self.output/"failure-control-timeout.input.raw").read_bytes(),data)
        missing=self.output/"intentionally-absent-executable"
        self.assertFalse(missing.exists())
        with self.assertRaises(FileNotFoundError):
            self.stage("failure-control-missing",[str(missing)],data=b"unspawned input",expected_failure="spawn")
        row=self.stages[-1]
        self.assertEqual((row["failure_kind"],row["returncode"],row["errno"]),("spawn",None,2))
        self.assertEqual((self.output/"failure-control-missing.stdout.raw").read_bytes(),b"")
        self.assertEqual((self.output/"failure-control-missing.stderr.raw").read_bytes(),b"")
        # Exercise the real class-setup path in a distinct process with no Rust
        # executable on PATH. This is not a mocked subprocess or exception.
        child=self.output/"setup-failure-control"
        script=("import os,unittest; "
                "os.environ['PATH']=''; "
                f"os.environ['TRNM_HIA_GOVERNANCE_OUTPUT']={str(child)!r}; "
                "suite=unittest.defaultTestLoader.loadTestsFromName("
                "'hia.tests.test_governance.PrivateGovernance.test_all_public_methods_and_clone'); "
                "result=unittest.TextTestRunner().run(suite); "
                "raise SystemExit(0 if result.wasSuccessful() else 1)")
        with self.assertRaises(AssertionError):
            self.stage("failure-control-class-setup",[sys.executable,"-c",script],
                       timeout=20,expected_failure="exit")
        self.assertEqual(self.stages[-1]["returncode"],1)
        child_report=json.loads((child/"report.json").read_text())
        self.assertEqual(child_report["status"],"FAIL")
        self.assertFalse(child_report["finalized"])
        self.assertEqual(child_report["started_tests"],[])
        self.assertTrue(any(item.get("failure_kind")=="spawn" and item.get("errno")==2
                            for item in child_report["stages"]))
        self.assertTrue(any(item.get("stage_kind")=="setup" for item in child_report["stages"]))
        # Start the actual isolated native worker with an intentionally tiny
        # deadline. Its real timeout must retain the delegated exception data.
        with self.assertRaises(subprocess.TimeoutExpired):
            self.native_sessions(self.native,[(session([]),32)],timeout=0.000001,expected_failure="timeout")
        native_failure=self.stages[-1]
        self.assertEqual(native_failure["stage_kind"],"native-delegate-failure")
        self.assertEqual(native_failure["failure_kind"],"timeout")
        self.assertIsNone(native_failure["returncode"])
        self.assertTrue(native_failure["argv"])
        self.assertEqual(native_failure["public_invocation"],self.identity(
            (self.output/(native_failure["name"]+".public-invocation.json")).read_bytes()))
        self.controls.append({"kind":"actual-process-failure-retention","timeout_partial_streams":True,
            "missing_executable_os_refusal":True,"class_setup_fail_closed":True,
            "actual_native_worker_timeout_retained":True,
            "child_report":self.identity((child/"report.json").read_bytes())})

    def test_real_allocator_refusal_and_cleanup(self):
        compiler=shutil.which("cc")
        self.assertIsNotNone(compiler,"Actual allocator interposer compiler is required")
        source=self.output/"allocator-interposer.c";source.write_text(FAULT_SOURCE)
        library=self.output/"allocator-interposer.so"
        self.stage("allocator-build",[compiler,"-shared","-fPIC","-O2",str(source),"-o",str(library)])
        cmds=setup(0)
        for i in range(1,180):
            key=f"k{i}";cmds.extend([command(3,caller="admin",a=key,flags=1),command(4,caller="alice",a=key,c="v",eta=i,now=i),command(5,caller="alice",ident=i),command(6,caller="exec",ident=i,now=i)])
        cmds.extend([command(16),command(14),command(17),*observe(2),command(17,2)])
        data=session(cmds);expected=self.stage("allocator-original-run",[str(self.oracle)],data=data).stdout
        baseline=self.native_sessions(self.native,[(data,len(expected)+7)],fault_library=library)["cases"][0]
        self.assertEqual(baseline["value"],0);self.assertEqual(baseline["output"],expected+b"\xa5"*7)
        stats=baseline["allocator"];self.assertGreater(stats["calls"],5);self.assertEqual(stats["alive"],0);self.assertEqual(stats["invalid"],0)
        self.controls.append({"kind":"allocator-baseline",**stats})
        cases=[(data,len(expected)+7,i) for i in range(1,stats["calls"]+1)]
        for index,row in enumerate(self.native_sessions(self.native,cases,fault_library=library)["cases"],1):
            self.assertEqual(row["value"],4);self.assertEqual(row["output"],b"\xa5"*(len(expected)+7))
            self.assertEqual(row["allocator"]["denied"],1);self.assertEqual(row["allocator"]["alive"],0);self.assertEqual(row["allocator"]["invalid"],0)
            self.controls.append({"kind":"allocator-refusal","index":index,"status":row["value"],"output_unchanged":True,**row["allocator"]})
