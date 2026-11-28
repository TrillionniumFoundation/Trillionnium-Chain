"""Complete public M12 vault methods against the executed original Rust crate.

The native path has no Python model: private HIA allocations retain every
balance, lock, owner, event and clone. An independent unchanged Rust crate
produces each complete comparison byte stream.
"""
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
import tempfile
import unittest

from .escrow_native import EscrowNative, FAULT_SOURCE, SOURCE

ROOT = Path(__file__).resolve().parents[2]
U128 = (1 << 128) - 1
U64 = (1 << 64) - 1
WHITESPACE = [*range(9, 14), 0x20, 0x85, 0xA0, 0x1680, *range(0x2000,0x200B),
              0x2028,0x2029,0x202F,0x205F,0x3000]
NONSPACE = [0,0x1C,0x1D,0x1E,0x1F,0x180E,0x200B,0xFEFF,0x10FFFF]


def command(op, handle=1, caller="", a="", b="", value=0):
    assert 0 <= value <= U128
    fields = [s.encode("utf-8") if isinstance(s,str) else s for s in (caller,a,b)]
    return struct.pack("<8Q", op, handle, value & U64, value >> 64,
                       *(len(s) for s in fields),0) + b"".join(fields)


def session(commands):
    return struct.pack("<8s3Q",b"VES10001",len(commands),0,0) + b"".join(commands)


def replies(raw):
    if len(raw)<32 or raw[:8]!=b"VER10001":
        raise AssertionError("Invalid complete vault response")
    count,total,reserved=struct.unpack_from("<3Q",raw,8)
    if total!=len(raw) or reserved:
        raise AssertionError("Vault response extent/reserved bytes differ")
    at=32;rows=[]
    for _ in range(count):
        op,handle,status,size=struct.unpack_from("<4Q",raw,at);at+=32
        data=raw[at:at+size];at+=size
        if len(data)!=size:raise AssertionError("Incomplete vault payload")
        rows.append((op,handle,status,data))
    if at!=len(raw):raise AssertionError("Trailing vault response")
    return rows


def observe(handle=1, accounts=("alice","bob","treasury"), requests=("r","s")):
    return [command(8,handle),command(9,handle),
            *(command(10,handle,a=a) for a in accounts),
            *(command(11,handle,a=r) for r in requests),command(12,handle),command(14,handle)]


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


class PrivateVault(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured=os.environ.get("TRNM_HIA_ESCROW_OUTPUT")
        cls.temp=None
        if configured:
            cls.output=Path(configured).absolute()
            cls.output.mkdir(parents=True,exist_ok=False)
        else:
            cls.temp=tempfile.TemporaryDirectory(prefix="trnm-hia-escrow-")
            cls.output=Path(cls.temp.name)
        cls.stages=[];cls.comparisons=[];cls.controls=[];cls.native=None
        cls.expected_tests=[cls.__module__+"."+cls.__qualname__+"."+name
                            for name in unittest.defaultTestLoader.getTestCaseNames(cls)]
        cls.started_tests=[];cls.completed_tests=[];cls.finalized=False
        cls.source_after=None;cls.source_unchanged=None
        cls.original_files=[ROOT/"trillionnium/crates/trnm-audit-events/src/lib.rs",
            ROOT/"trillionnium/crates/trnm-audit-events/Cargo.toml",
            ROOT/"trillionnium/crates/trnm-escrow-vault/src/lib.rs",
            ROOT/"trillionnium/crates/trnm-escrow-vault/Cargo.toml",
            ROOT/"hia/tests/rust_escrow_reference.rs"]
        cls.source_before={str(p.relative_to(ROOT)):cls.identity(p.read_bytes()) for p in cls.original_files}
        cls.source_before.update({str(p.relative_to(ROOT)):cls.identity(p.read_bytes()) for p in
            [SOURCE,Path(__file__),ROOT/"hia/tests/escrow_native.py",
             SOURCE.parent/"README.md",ROOT/"hia/components.json",
             ROOT/"hia/tests/native_support.py",ROOT/"hia/tools/toolchain.py",
             ROOT/"hia/src/codec/json_primitives.hepta",ROOT/"hia/toolchain.lock.json",
             ROOT/"hia/qualification/compiler-binding.json"]})
        rustc=shutil.which("rustc")
        if not rustc:
            raise RuntimeError("Actual original Rust compiler is required, never skipped")
        cls.rustc,selection=selected_rustc(cls.stage,rustc)
        (cls.output/"rustc-selection.json").write_text(json.dumps(selection,sort_keys=True,indent=2)+"\n")
        audit=ROOT/"trillionnium/crates/trnm-audit-events/src/lib.rs"
        escrow=ROOT/"trillionnium/crates/trnm-escrow-vault/src/lib.rs"
        cls.auditlib=cls.output/"libtrnm_audit_events.rlib"
        cls.vaultlib=cls.output/"libtrnm_escrow_vault.rlib"
        cls.stage("audit-library",[cls.rustc,"--edition=2021","-O","--crate-type=rlib",
            "--crate-name=trnm_audit_events",str(audit),"-o",str(cls.auditlib)])
        cls.stage("vault-library",[cls.rustc,"--edition=2021","-O","--crate-type=rlib",
            "--crate-name=trnm_escrow_vault",str(escrow),"--extern",
            "trnm_audit_events="+str(cls.auditlib),"-o",str(cls.vaultlib)])
        cls.original_tests=[]
        for name,source,args in [("audit",audit,[]),("vault",escrow,
                ["--extern","trnm_audit_events="+str(cls.auditlib)])]:
            binary=cls.output/(name+"-original-tests")
            cls.stage(name+"-test-build",[cls.rustc,"--edition=2021","-O","--test",
                str(source),*args,"-o",str(binary)])
            run=cls.stage(name+"-retained-tests",[str(binary),"--nocapture"])
            if b"test result: ok." not in run.stdout or b"0 failed" not in run.stdout:
                raise AssertionError("Original retained tests did not complete")
            cls.original_tests.append({"name":name,"binary":cls.identity(binary.read_bytes()),
                                       "stdout":cls.identity(run.stdout)})
        cls.oracle=cls.output/"vault-original-reference"
        cls.stage("adapter-build",[cls.rustc,"--edition=2021","-O",
            str(ROOT/"hia/tests/rust_escrow_reference.rs"),"--extern","trnm_audit_events="+str(cls.auditlib),
            "--extern","trnm_escrow_vault="+str(cls.vaultlib),"-L","dependency="+str(cls.output),
            "-o",str(cls.oracle)])
        cls.native=EscrowNative()
        binding=json.loads((ROOT/"hia/qualification/compiler-binding.json").read_text())
        if (cls.native.receipt.get("compiler_sha256")!=binding["compiler_sha256"]
                or cls.native.receipt["chain_migration"]["backend"]!="selfhost"
                or cls.native.receipt["claims"]["fallback_used"] is not False):
            raise AssertionError("Escrow did not use the original pinned native compiler")
        (cls.output/"vault-native.so").write_bytes(cls.native.library.read_bytes())
        (cls.output/"native-build.json").write_text(json.dumps(cls.native.receipt,sort_keys=True,indent=2)+"\n")
        cls.report()

    @classmethod
    def identity(cls,data):
        return {"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}

    @classmethod
    def stage(cls,name,argv):
        result=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=180,check=False)
        (cls.output/(name+".stdout.raw")).write_bytes(result.stdout)
        (cls.output/(name+".stderr.raw")).write_bytes(result.stderr)
        cls.stages.append({"name":name,"argv":argv,"returncode":result.returncode,
            "stdout":cls.identity(result.stdout),"stderr":cls.identity(result.stderr)})
        cls.report()
        if result.returncode:
            raise AssertionError(("Actual original Rust stage failed",name,result.stderr.decode(errors="replace")))
        return result

    @classmethod
    def report(cls):
        files={p.name:cls.identity(p.read_bytes()) for p in sorted(cls.output.iterdir())
               if p.is_file() and p.name!="report.json"}
        actual=[row["test"] for row in cls.completed_tests]
        all_tests=(cls.started_tests==cls.expected_tests and actual==cls.expected_tests
                   and all(row["status"]=="PASS" for row in cls.completed_tests))
        failed=any(row["status"]!="PASS" for row in cls.completed_tests)
        failed=failed or any(row["returncode"]!=0 for row in cls.stages)
        failed=failed or any(not row["match"] for row in cls.comparisons)
        failed=failed or cls.source_unchanged is False
        status=("FAIL" if failed else "PASS" if cls.finalized and all_tests
                and cls.source_unchanged is True else "INCOMPLETE")
        data={"schema":"trnm.hia.escrow-development.v1","status":status,
              "finalized":cls.finalized,"expected_tests":cls.expected_tests,
              "started_tests":cls.started_tests,"completed_tests":cls.completed_tests,
              "all_expected_tests_completed":all_tests,"source_inputs":cls.source_before,
              "source_after":cls.source_after,"source_unchanged":cls.source_unchanged,
              "stages":cls.stages,"comparisons":cls.comparisons,"native_controls":cls.controls,
              "native_operation_count":sum(r["operations"] for r in cls.comparisons),
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
        result=subprocess.run([str(self.oracle)],input=raw,capture_output=True,timeout=60,check=False)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stderr,b"")
        expected=result.stdout
        original=replies(expected)
        self.assertEqual(len(original),len(commands))
        observed=self.native.sessions([(raw,len(expected)+19)])["cases"][0]
        actual=observed["output"][:-19]
        match=observed["value"]==0 and actual==expected and observed["output"][-19:]==b"\xa5"*19
        index=len(type(self).comparisons)
        record={"index":index,"label":label,"operations":len(commands),"match":match,
                "input":self.identity(raw),"original":self.identity(expected),
                "native":self.identity(actual),"native_status":observed["value"]}
        for suffix,data in [("input",raw),("original",expected),("native",actual)]:
            (self.output/f"comparison-{index:04d}.{suffix}.bin").write_bytes(data)
        type(self).comparisons.append(record);self.report()
        self.assertTrue(match,(label,record))
        return original

    def test_all_methods_full_width_and_clone_isolation(self):
        # Real argv[0]-sensitive symlink execution reproduces the rustup driver
        # boundary without substituting this fixture for any original build.
        with tempfile.TemporaryDirectory(prefix="vault-rustup-selection-") as directory:
            root=Path(directory);binpath=root/"selected/bin";binpath.mkdir(parents=True)
            driver=root/"rustup-dispatch-fixture"
            script=("#!/bin/sh\ncase \"${0##*/}\" in rustc) ;; *) exit 71;; esac\n"
                    "if [ \"$1\" = '-Vv' ]; then printf '%s\\n' 'rustc selector regression fixture'; "
                    "elif [ \"$1\" = '--print' ] && [ \"$2\" = 'sysroot' ]; then printf '%s\\n' '"+
                    str(root/"selected")+"'; else exit 72; fi\n")
            driver.write_text(script);driver.chmod(0o700)
            actual=binpath/"rustc";actual.write_text(script);actual.chmod(0o700)
            shimbin=root/"shim";shimbin.mkdir();shim=shimbin/"rustc";shim.symlink_to(driver)
            stages=[]
            def execute(name,argv):
                run=subprocess.run(argv,capture_output=True,timeout=5,check=False)
                stages.append({"name":name,"argv":argv,"returncode":run.returncode,
                               "stdout":run.stdout.decode(),"stderr":run.stderr.decode()})
                self.assertEqual(run.returncode,0)
                return run
            selected,identity=selected_rustc(execute,shim)
            self.assertEqual(selected,str(actual))
            self.assertEqual(stages[0]["argv"][0],str(shim))
            broken=subprocess.run([str(shim.resolve()),"-Vv"],capture_output=True,timeout=5,check=False)
            self.assertEqual(broken.returncode,71)
            self.controls.append({"name":"rustup-argv0-selection-regression","stages":stages,
                                  "resolved_shim_refusal":broken.returncode,"complete":True})
        ops=[command(0,0,caller="owner"),command(7,caller="owner"),
             command(1,caller="owner",a="alice",value=U128),
             command(1,caller="owner",a="bob",value=U128),
             command(5,caller="owner",a="alice",b="alice",value=U128),
             command(2,caller="owner",a="r",b="alice",value=(1<<127)+1),
             command(2,caller="owner",a="s",b="bob",value=(1<<64)+1),
             command(15),*observe(1),*observe(2),
             command(3,caller="owner",a="r"),command(4,caller="owner",a="s",b="treasury"),
             command(6,caller="owner"),command(6,caller="owner"),command(7,caller="owner"),
             command(13),*observe(1),*observe(2),command(3,2,caller="owner",a="s"),
             command(4,2,caller="owner",a="r",b="treasury"),*observe(1),*observe(2),
             command(16),command(15),command(10,a="alice"),command(16),*observe(2),
             command(0,0,caller="other"),command(1,3,caller="owner",a="alice",value=99),
             command(1,3,caller="other",a="alice",value=99),command(2,3,caller="other",a="r",b="alice",value=99),
             *observe(2),*observe(3),command(16,2),command(10,2,a="alice"),*observe(3)]
        rows=self.compare(ops,"complete-methods-u128-clone")
        self.assertEqual(rows[1][2],4)
        self.assertEqual(rows[3][2],0)  # aggregate account total may exceed u128
        self.assertEqual(rows[4][2],0)  # self transfer remains a recorded success

    def test_error_precedence_and_atomic_overflow(self):
        ops=[command(0,0,caller="owner"),command(1,caller="owner",a="alice",value=10),
             command(1,caller="owner",a="bob",value=U128),command(2,caller="owner",a="r",b="alice",value=10),
             command(1,caller="owner",a="alice",value=U128)]
        for c in [command(3,caller="owner",a="r"),command(4,caller="owner",a="r",b="bob"),
                  command(5,caller="owner",a="alice",b="bob",value=1),
                  command(1,caller="owner",a="alice",value=1)]:
            ops.extend([*observe(),c,*observe()])
        # Drain the credit target and retry the very same lock; a failed release
        # must not have changed Locked into Released.
        ops += [command(5,caller="owner",a="alice",b="treasury",value=U128),
                command(3,caller="owner",a="r"),command(2,caller="owner",a="r",b="alice",value=0),
                command(2,caller="owner",a="r",b="alice",value=1),command(3,caller="owner",a="r"),
                command(4,caller="owner",a="r",b=""),*observe()]
        for paused in [False,True]:
            if paused:ops.append(command(6,caller="owner"))
            for op in range(1,8):
                for caller in ["intruder","owner"]:
                    kw={"caller":caller}
                    if op in [1,2,3,4,5]:kw["a"]=" "
                    if op in [2,4,5]:kw["b"]=""
                    if op in [1,2,5]:kw["value"]=0
                    ops.append(command(op,**kw))
            ops.extend(observe())
        self.compare(ops,"error-order-overflow-atomicity")

    def test_unicode_exact_trim_opaque_names_and_embedded_nul(self):
        for cp in WHITESPACE+NONSPACE:
            char=chr(cp)
            ops=[command(0,0,caller=""),command(1,caller="",a="alice",value=100),
                 command(1,caller="",a=char,value=3),command(1,caller="",a=char+"alice"+char,value=5),
                 command(2,caller="",a=char,b="alice",value=1),
                 command(2,caller="",a=char+"r",b="alice",value=1),
                 command(2,caller="",a="r"+char,b="alice",value=1),
                 command(2,caller="",a="r"+char+"s",b="alice",value=1),
                 command(4,caller="",a="r"+char+"s",b=char),
                 *observe(accounts=("alice",char,char+"alice"+char),requests=(char,char+"r","r"+char,"r"+char+"s"))]
            rows=self.compare(ops,"unicode-"+hex(cp))
            self.assertEqual(rows[2][2],6 if cp in WHITESPACE else 0)
            self.assertEqual(rows[3][2],0)
            self.assertEqual(rows[4][2],7 if cp in WHITESPACE else 0)
        for owner in [" ","\u2003","\0","负责👩🏽‍💻\0", "x"*8193]:
            self.compare([command(0,0,caller=owner),command(8),command(1,caller=owner,a="\0",value=1),
                command(2,caller=owner,a="r\0x",b="\0",value=1),command(4,caller=owner,a="r\0x",b="\0x"),
                command(14),command(12)],"opaque-owner-"+str(len(owner)))

    def test_each_u128_bit_and_all_lock_terminal_replays(self):
        for bit in range(128):
            amount=1<<bit
            ops=[command(0,0,caller="o"),command(1,caller="o",a="a",value=amount),
                 command(2,caller="o",a="r",b="a",value=amount),
                 command(3 if bit%2 else 4,caller="o",a="r",b="b" if not bit%2 else ""),
                 command(2,caller="o",a="r",b="a",value=amount),
                 command(3,caller="o",a="r"),command(4,caller="o",a="r",b="a"),
                 *observe(accounts=("a","b"),requests=("r",))]
            rows=self.compare(ops,"amount-bit-"+str(bit))
            self.assertEqual([r[2] for r in rows[4:7]],[9,11,11])

    def test_deterministic_mixed_histories_and_growth(self):
        rng=random.Random(0x4D120018)
        accounts=["a","b","c"," a ","é","e\u0301","\0","\x1c","\u2003","", "財"]
        requests=["r"+str(i) for i in range(32)]+["", " r", "r\u2003", "r\0s"]
        for run in range(24):
            ops=[command(0,0,caller="owner")]
            for i in range(160):
                op=rng.randrange(1,8);kw={"caller":"owner" if rng.randrange(7) else "intruder"}
                if op in [1,2,3,4,5]:kw["a"]=rng.choice(requests if op in [2,3,4] else accounts)
                if op in [2,4,5]:kw["b"]=rng.choice(accounts)
                if op in [1,2,5]:kw["value"]=rng.choice([0,1,2,17,(1<<64)-1,1<<64,1<<127,U128])
                ops.append(command(op,**kw))
                if i%19==0:ops.extend(observe(accounts=accounts,requests=requests))
                if i%37==0:ops.extend([command(13),command(12),command(14)])
            ops.extend(observe(accounts=accounts,requests=requests));self.compare(ops,"mixed-"+str(run))
        ops=[command(0,0,caller="o")]
        for i in range(320):
            ops.extend([command(1,caller="o",a="a"+str(i),value=U128-i),
                        command(2,caller="o",a="r"+str(i),b="a"+str(i),value=1)])
        ops += [command(15),command(13),command(12),command(14,2),command(16),command(12,2)]
        self.compare(ops,"private-arena-real-growth-large-clone")

    def test_malformed_frames_utf8_and_output_capacity_do_not_publish(self):
        raw=session([command(0,0,caller="o"),command(1,caller="o",a="a",value=1),command(14)])
        valid=self.native.sessions([(raw,4096)])["cases"][0]
        self.assertEqual(valid["value"],0)
        needed=struct.unpack_from("<Q",valid["output"],16)[0]
        cases=[(raw,n) for n in [0,1,31,32,39,needed-1,needed]]
        expected=[3]*6+[0]
        bad=[raw[:i] for i in range(32)]
        bad += [raw+b"x",raw[:-1]]
        for offset in [0,8,16,24,32,64,72,80,88]:
            v=bytearray(raw);v[offset:offset+8]=struct.pack("<Q",U64);bad.append(bytes(v))
        cases += [(value,512) for value in bad];expected += [1]*len(bad)
        malformed=[b"\xff",b"\xc0\x80",b"\xed\xa0\x80",b"\xf4\x90\x80\x80",b"\xe0\x80\x80",b"\xc2"]
        cases += [(session([command(0,0,caller=value)]),512) for value in malformed];expected += [2]*len(malformed)
        observed=self.native.sessions(cases)["cases"]
        for index,(case,wanted,row) in enumerate(zip(cases,expected,observed)):
            self.assertEqual(row["value"],wanted,(index,row["value"],wanted))
            if wanted:self.assertEqual(row["output"],b"\xa5"*case[1])
        self.controls.append({"name":"malformed-capacity-utf8","cases":len(cases),"complete":True})
        self.report()

    def test_actual_allocation_failures_release_all_private_owners(self):
        compiler=shutil.which("cc")
        if not compiler:raise RuntimeError("Actual allocation fault interposer compiler is required")
        source=self.output/"allocator-fault.c";source.write_text(FAULT_SOURCE)
        library=self.output/"allocator-fault.so"
        self.stage("allocation-fault-build",[compiler,"-shared","-fPIC","-O2",str(source),"-o",str(library)])
        ops=[command(0,0,caller="o")]
        for i in range(110):ops += [command(1,caller="o",a="a"+str(i),value=i+1),command(15)]
        ops += [command(14),command(13),command(14),command(16)]
        raw=session(ops)
        baseline=self.native.sessions([(raw,3000000,0)],fault_library=library)["cases"][0]
        self.assertEqual(baseline["value"],0)
        self.assertEqual(baseline["allocator"]["alive"],0)
        self.assertEqual(baseline["allocator"]["invalid"],0)
        count=baseline["allocator"]["calls"]
        self.assertGreater(count,4)  # string/result/initial arena plus real growth
        observations=self.native.sessions([(raw,3000000,i) for i in range(1,count+1)],
                                          fault_library=library,timeout=240)["cases"]
        for index,row in enumerate(observations,1):
            self.assertEqual(row["value"],4,(index,row["allocator"]))
            self.assertEqual(row["output"],b"\xa5"*3000000)
            self.assertEqual(row["allocator"]["denied"],1)
            self.assertEqual(row["allocator"]["alive"],0)
            self.assertEqual(row["allocator"]["invalid"],0)
        self.controls.append({"name":"actual-allocation-failure","cases":count,
            "baseline":baseline["allocator"],"observations":[r["allocator"] for r in observations]})
        self.report()


if __name__=="__main__":
    unittest.main()
