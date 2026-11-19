"""Source/corpus/evidence admission controls, separate from native/Rust execution."""
from __future__ import annotations
import argparse,copy,hashlib,json,lzma,os,shutil,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
from . import rust_oracle as gate
from .build import source_manifest
from .native_io import parse_result,frame,magic
COUNTS={"controls":0,"actual_cli":0}
BUNDLE=None
def control():
    COUNTS["controls"]+=1
class Integrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix="hia-prepare-admission-")
        cls.base=Path(cls.temporary.name);cls.original=gate.complete_source_manifest(gate.REPOSITORY)
        cls.fixture=cls.base/"source";cls.fixture.mkdir()
        copy_names=set(cls.original)
        components=json.loads((gate.REPOSITORY/"hia/components.json").read_bytes())
        copy_names.update("hia/"+name for name in components["includes"])
        for name in sorted(copy_names):
            path=cls.fixture/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes((gate.REPOSITORY/name).read_bytes())
    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()
    def rejected(self,call):
        with self.assertRaises((ValueError,FileNotFoundError,KeyError,TypeError,UnicodeError,lzma.LZMAError)):
            call()
        control()
    def test_complete_actual_source_sets(self):
        self.assertEqual(source_manifest(gate.REPOSITORY),self.original);control()
        self.assertEqual(gate.complete_source_manifest(self.fixture),self.original);control()
        original=gate.original_manifest(gate.REPOSITORY)
        self.assertIn(gate.STORE,original);self.assertIn("trillionnium/Cargo.lock",original);control()
    def test_source_admission_negatives(self):
        own=self.fixture/gate.OWNED
        mutations=(
          (own/"cases.py",b"\n# actual byte mutation\n"),
          (self.fixture/"hia/src/protocol/pnx1.hepta",b"\n# actual dependency mutation\n"),
        )
        comparison={"schema":gate.COMP_SCHEMA,"status":"PASS","build":{"schema":gate.BUILD_SCHEMA,"status":"PASS",
         "source_inputs":self.original,"source_set_sha256":gate.digest(gate.canonical_json(self.original)),
         "source_inputs_stable":True,"runtime_host_proxy":False,"rust_or_interpreter_fallback":False,
         "complete_node":False,"successor_block_admission":False}}
        self.assertEqual(gate.validate_source_bindings(self.fixture,comparison),self.original);control()
        for path,extra in mutations:
            before=path.read_bytes()
            try:
                path.write_bytes(before+extra)
                self.rejected(lambda:gate.validate_source_bindings(self.fixture,comparison))
            finally:path.write_bytes(before)
        for name in ("cases.py","owner_policy.hepta"):
            path=own/name;raw=path.read_bytes()
            path.unlink()
            try:self.rejected(lambda:gate.complete_source_manifest(self.fixture))
            finally:path.write_bytes(raw)
        cache=own/"__pycache__";cache.mkdir()
        try:self.rejected(lambda:gate.complete_source_manifest(self.fixture))
        finally:cache.rmdir()
        nested=own/"nested";nested.mkdir();(nested/"unbound.py").write_text("pass\n")
        try:self.rejected(lambda:gate.complete_source_manifest(self.fixture))
        finally:shutil.rmtree(nested)
        path=own/"README.md";raw=path.read_bytes();path.unlink();path.symlink_to(own/"cases.py")
        try:self.rejected(lambda:gate.complete_source_manifest(self.fixture))
        finally:path.unlink();path.write_bytes(raw)
        for mode in ("missing","extra","wrong-digest","bool-claim"):
            altered=copy.deepcopy(comparison)
            if mode=="missing":altered["build"]["source_inputs"].pop(next(iter(self.original)))
            if mode=="extra":altered["build"]["source_inputs"]["trillionnium/Cargo.toml"]={"bytes":0,"sha256":"0"*64}
            if mode=="wrong-digest":altered["build"]["source_set_sha256"]="0"*64
            if mode=="bool-claim":altered["build"]["source_inputs_stable"]=1
            self.rejected(lambda:gate.validate_source_bindings(gate.REPOSITORY,altered))
    def test_component_and_configuration_closure(self):
        component=self.fixture/"hia/components.json";raw=component.read_bytes();parsed=json.loads(raw)
        target=gate.CANONICAL_ROOTS[1]
        for value in (
          {"schema":"trnm.hia.component-includes.v1","includes":{target:[{"source":target,"functions":["f0"]}]}},
          {"schema":"trnm.hia.component-includes.v1","includes":{target:[{"source":"src/crypto/sha256.hepta","functions":["not_present"]}]}},
          {"schema":"trnm.hia.component-includes.v1","includes":{target:[{"source":"src/crypto/sha256.hepta","functions":[]}]}},
        ):
            try:component.write_text(json.dumps(value));self.rejected(lambda:gate.complete_source_manifest(self.fixture))
            finally:component.write_bytes(raw)
        try:
            component.write_text('{"schema":"x","schema":"y","includes":{}}')
            self.rejected(lambda:gate.complete_source_manifest(self.fixture))
        finally:component.write_bytes(raw)
        path=self.fixture/gate.OWNED/"source-inputs.json";raw=path.read_bytes()
        for files in ([],["config/pon/devnet-v1.json"]*4,["config/pon/../other.json"]):
            try:
                path.write_text(json.dumps({"schema":"trnm.hia.legacy-preparation-default-inputs.v1","files":files}))
                self.rejected(lambda:gate.complete_source_manifest(self.fixture))
            finally:path.write_bytes(raw)
    def test_bounded_archive_and_json(self):
        path=self.base/"corpus.xz";wanted=b"abc\n"*300
        for raw,valid in ((lzma.compress(wanted),True),(lzma.compress(wanted)+b"x",False),
                          (lzma.compress(wanted)*2,False),(lzma.compress(wanted)[:-1],False),
                          (lzma.compress(wanted+b"x"),False),(lzma.compress(wanted[:-1]),False)):
            path.write_bytes(raw)
            if valid:self.assertEqual(gate.bounded_xz(path,wanted),wanted);control()
            else:self.rejected(lambda:gate.bounded_xz(path,wanted))
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}',b'{"x":-Infinity}'):
            self.rejected(lambda:gate.load_json(raw))
        for value in ({"bytes":True,"sha256":"0"*64},{"bytes":0,"sha256":"A"*64},{"bytes":-1,"sha256":"0"*64}):
            self.assertFalse(gate.valid_identity(value));control()
    def test_result_parser_attempt_and_generation_boundary(self):
        good=struct.pack("<12Q",magic(b"MPRESULT"),1,0,1,199,10,0,0,1,40,199,0)
        self.assertEqual(parse_result(good)["generation"],1);control()
        for word,value in ((0,0),(2,10),(3,0),(6,1),(7,1),(8,0),(9,41),(10,200),(11,1)):
            words=list(struct.unpack("<12Q",good));words[word]=value
            self.rejected(lambda:parse_result(struct.pack("<12Q",*words)))
        for code,codec,strict,attempts in ((1,0,0,0),(9,0,0,1),(7,0,0,1),(1,1,0,1)):
            raw=struct.pack("<12Q",magic(b"MPRESULT"),1,code,attempts,199,10,codec,strict,0,0,0,0)
            self.rejected(lambda:parse_result(raw))
    def test_actual_cli_admission_precedes_tools(self):
        bundle=self.base/"invalid-bundle";bundle.mkdir(exist_ok=True)
        fake=self.base/"tools";fake.mkdir(exist_ok=True)
        marker=self.base/"cargo-was-started"
        cargo=fake/"cargo";cargo.write_text("#!/bin/sh\nprintf invoked > '"+str(marker)+"'\nexit 99\n");cargo.chmod(0o700)
        for optimized in (False,True):
            output=self.base/("must-not-exist-"+str(optimized))
            command=[sys.executable]
            if optimized:command.append("-O")
            command+=["-B","-m","hia.platform.execution_prepare.rust_oracle","--bundle",str(bundle),"--output",str(output)]
            env=dict(os.environ,PATH=str(fake),PYTHONDONTWRITEBYTECODE="1")
            p=subprocess.run(command,cwd=gate.REPOSITORY,env=env,capture_output=True,timeout=30)
            self.assertNotEqual(p.returncode,0);self.assertFalse(output.exists());self.assertFalse(marker.exists())
            (self.base/("cli-"+str(optimized)+".stdout")).write_bytes(p.stdout)
            (self.base/("cli-"+str(optimized)+".stderr")).write_bytes(p.stderr)
            control();COUNTS["actual_cli"]+=1

    def test_actual_local_crate_compile_time_fixture_inventory(self):
        inventory=gate.original_include_dependencies(gate.REPOSITORY)
        self.assertEqual(set(inventory['local_packages']),{
            'trillionnium/crates/trnm-mvcc-fee','trillionnium/crates/trnm-protocol',
            'trillionnium/crates/trnm-crypto-primitives','trillionnium/crates/trnm-verification-profiles'})
        original=gate.original_manifest(gate.REPOSITORY)
        for name in ('tests/vectors/pon/native-growth-reference-v2.json','tests/fixtures/cpq1-content-v1/vectors.json'):
            self.assertIn(name,inventory['data_includes'])
            self.assertEqual(original[name],gate.file_identity(gate.REPOSITORY/name));control()
    def test_dynamic_original_data_include_and_local_package_controls(self):
        with tempfile.TemporaryDirectory(prefix='svp-original-include-') as temporary:
            root=Path(temporary)
            for name in ('config','formal','trillionnium/crates/trnm-mvcc-fee/src','trillionnium/crates/trnm-protocol/src','tests/vectors'):
                (root/name).mkdir(parents=True,exist_ok=True)
            (root/'trillionnium/Cargo.toml').write_text('[workspace]\nmembers=[]\n')
            (root/'trillionnium/Cargo.lock').write_text('SOURCE_ONLY_FIXTURE_NOT_A_CARGO_BUILD\n')
            (root/gate.STORE).write_text('// source-only original inventory fixture\n')
            main=root/'trillionnium/crates/trnm-mvcc-fee/Cargo.toml'
            main.write_text('[package]\nname="trnm-mvcc-fee"\nversion="0.1.0"\n[dependencies]\ntrnm-protocol={path="../trnm-protocol"}\n')
            (root/'trillionnium/crates/trnm-protocol/Cargo.toml').write_text('[package]\nname="trnm-protocol"\nversion="0.1.0"\n')
            source=root/'trillionnium/crates/trnm-protocol/src/data.rs'
            source.write_text('const DATA: &str=include_str!("../../../../tests/vectors/example.json");\n')
            fixture=root/'tests/vectors/example.json';fixture.write_bytes(b'{"n":1}\n')
            before=gate.original_manifest(root)
            self.assertEqual(before['tests/vectors/example.json'],gate.file_identity(fixture));control()
            fixture.unlink()
            with self.assertRaises((ValueError,OSError)):gate.original_manifest(root)
            control();fixture.write_bytes(b'{"n":2}\n')
            self.assertNotEqual(gate.original_manifest(root),before);control()
            raw=source.read_bytes()
            for changed in (
                b'include_bytes!("../../../../../../escape.bin")',
                b'include_str!("/absolute/fixture")',
                b'include_str!(concat!("a","b"))',
                b'include!("generated.rs")',
            ):
                source.write_bytes(changed)
                with self.assertRaises((ValueError,OSError)):gate.original_manifest(root)
                control()
            source.write_bytes(raw);fixture.unlink();fixture.symlink_to(root/'trillionnium/Cargo.lock')
            with self.assertRaises((ValueError,OSError)):gate.original_manifest(root)
            control();fixture.unlink();fixture.write_bytes(b'{"n":1}\n')
            added=root/'trillionnium/crates/trnm-protocol/src/another.rs'
            added.write_text('const NEXT: &[u8]=include_bytes!("../../../../tests/vectors/next.bin");\n')
            with self.assertRaises((ValueError,OSError)):gate.original_manifest(root)
            control();(root/'tests/vectors/next.bin').write_bytes(b'exact additional bytes')
            self.assertIn('tests/vectors/next.bin',gate.original_manifest(root));control()
            old=main.read_bytes();main.write_bytes(old+b'missing={path="../missing-package"}\n')
            with self.assertRaises((ValueError,OSError)):gate.original_manifest(root)
            control()

    def test_original_environment_requires_explicit_compiler_binding(self):
        values=(*gate.FORBIDDEN_ORIGINAL_OVERRIDES,
          "CARGO_PROFILE_TEST_OVERFLOW_CHECKS","CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
          "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTDOCFLAGS",
          "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER","CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER")
        for key in values:
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError,"Unbound original compilation/runtime override: "+key):
                    gate.original_environment({"PATH":"unchanged",key:"unbound-negative"})
                control()
        original={"PATH":"unchanged","RUSTC":"","RUSTC_WRAPPER":""}
        result=gate.original_environment(original)
        self.assertEqual(original,{"PATH":"unchanged","RUSTC":"","RUSTC_WRAPPER":""})
        self.assertEqual(result["PATH"],"unchanged")
        self.assertEqual(result["PYTHONDONTWRITEBYTECODE"],"1");control()

    def test_public_cli_override_refusal_precedes_bundle_tools_and_copy(self):
        with tempfile.TemporaryDirectory(prefix="hia-prepare-compiler-refusals-") as temporary:
            root=Path(temporary);empty=root/"empty-bundle";empty.mkdir()
            bundle=BUNDLE if BUNDLE is not None else empty
            fake=root/"tools";fake.mkdir();marker=root/"tool-invoked"
            for name in ("cargo","rustc"):
                script=fake/name
                script.write_text("#!/bin/sh\nprintf invoked > '"+str(marker)+"'\nexit 99\n")
                script.chmod(0o700)
            values=(*gate.FORBIDDEN_ORIGINAL_OVERRIDES,
              "CARGO_PROFILE_TEST_OVERFLOW_CHECKS","CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
              "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTDOCFLAGS",
              "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER","CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER")
            for index,key in enumerate(values):
                output=root/("refused-"+str(index))
                env={"PATH":str(fake),"PYTHONPATH":str(gate.REPOSITORY),"PYTHONDONTWRITEBYTECODE":"1",
                     key:"unbound-private-negative"}
                process=subprocess.run([sys.executable,"-B","-m","hia.platform.execution_prepare.rust_oracle",
                  "--bundle",str(bundle),"--output",str(output)],cwd=gate.REPOSITORY,
                  env=env,capture_output=True,timeout=30)
                self.assertNotEqual(process.returncode,0)
                self.assertIn("Unbound original compilation/runtime override: "+key,
                              (process.stdout+process.stderr).decode())
                self.assertFalse(output.exists());self.assertFalse(marker.exists())
                control();COUNTS["actual_cli"]+=1

    def test_cargo_target_rejects_input_aliases_before_copy(self):
        with tempfile.TemporaryDirectory(prefix="hia-prepare-target-refusals-") as temporary:
            root=Path(temporary);bundle=root/"bundle";bundle.mkdir();output=root/"output"
            isolated=output/"isolated";alias=root/"alias";alias.symlink_to(gate.REPOSITORY,target_is_directory=True)
            targets=(gate.REPOSITORY,gate.REPOSITORY/"target",gate.REPOSITORY.parent,
                     bundle,bundle/"target",root,isolated,isolated/"target",output,alias/"target")
            for target in targets:
                with self.subTest(target=str(target)):
                    with self.assertRaisesRegex(ValueError,"Cargo target"):
                        gate.safe_target(target,output,gate.REPOSITORY,bundle,isolated)
                    control()
            self.assertEqual(gate.safe_target(None,output,gate.REPOSITORY,bundle,isolated),output/"cargo-target");control()
            for index,target in enumerate((gate.REPOSITORY,gate.REPOSITORY.parent,isolated,alias/"target")):
                env={"PATH":"","PYTHONPATH":str(gate.REPOSITORY),"PYTHONDONTWRITEBYTECODE":"1"}
                process=subprocess.run([sys.executable,"-B","-m","hia.platform.execution_prepare.rust_oracle",
                  "--bundle",str(bundle),"--output",str(output),"--cargo-target",str(target)],
                  cwd=gate.REPOSITORY,env=env,capture_output=True,timeout=30)
                self.assertNotEqual(process.returncode,0)
                self.assertIn("Cargo target",(process.stdout+process.stderr).decode())
                self.assertFalse(output.exists());control();COUNTS["actual_cli"]+=1

    def test_actual_cargo_library_selector_keeps_custom_build_separate(self):
        with tempfile.TemporaryDirectory(prefix="hia-prepare-artifact-refusals-") as temporary:
            root=Path(temporary);crate=root/"crate";(crate/"src").mkdir(parents=True)
            source=crate/"src/lib.rs";source.write_text("// qualification-only source fixture\n")
            target=root/"target";target.mkdir()
            library=target/"libserde_json-fixture.rlib";library.write_bytes(b"qualification-only-library-bytes")
            metadata=target/"libserde_json-fixture.rmeta";metadata.write_bytes(b"qualification-only-metadata-bytes")
            binding={"package":{"id":"registry+fixture#serde_json@1.0.149"},"crate_directory":str(crate),
                     "crate_sources":{"src/lib.rs":gate.file_identity(source)}}
            artifact={"reason":"compiler-artifact","package_id":binding["package"]["id"],
              "target":{"name":"serde_json","kind":["lib"],"src_path":str(source)},
              "features":["default","std"],"filenames":[str(library),str(metadata)]}
            custom=copy.deepcopy(artifact);custom["target"]["kind"]=["custom-build"]
            def stream(rows):return b"".join(gate.canonical_json(row)+b"\n" for row in rows)
            output=root/"positive";output.mkdir()
            observed,fence=gate.capture_serde_library(stream([custom,artifact]),binding,target,output)
            self.assertEqual(observed["compiler_artifact"],artifact);self.assertTrue(fence());control()
            negatives=[]
            negatives.append(("only-custom-build",[custom]))
            negatives.append(("duplicate-library",[artifact,artifact]))
            for name,change in (
                ("wrong-package",lambda row:row.update(package_id="unbound-package")),
                ("missing-feature",lambda row:row.update(features=["std"])),
                ("extra-feature",lambda row:row.update(features=["default","std","arbitrary_precision"])),
                ("duplicate-feature",lambda row:row.update(features=["default","std","std"])),
                ("wrong-source",lambda row:row["target"].update(src_path=str(crate/"other.rs"))),
                ("empty-artifacts",lambda row:row.update(filenames=[])),
                ("duplicate-artifacts",lambda row:row.update(filenames=[str(library),str(library)])),
                ("outside-target",lambda row:row.update(filenames=[str(source)])),
                ("wrong-kind",lambda row:row["target"].update(kind=["rlib"])),
            ):
                row=copy.deepcopy(artifact);change(row);negatives.append((name,[row]))
            for name,rows in negatives:
                destination=root/name;destination.mkdir()
                with self.subTest(name=name),self.assertRaises((ValueError,OSError)):
                    gate.capture_serde_library(stream(rows),binding,target,destination)
                control()
            linked=target/"linked.rlib";linked.symlink_to(library)
            row=copy.deepcopy(artifact);row["filenames"]=[str(linked)]
            destination=root/"symbolic-artifact";destination.mkdir()
            with self.assertRaises((ValueError,OSError)):
                gate.capture_serde_library(stream([row]),binding,target,destination)
            control()
            before=library.read_bytes();library.write_bytes(before+b"changed")
            with self.assertRaises(ValueError):fence()
            control();library.write_bytes(before)
            copy_path=output/"serde-library"/library.name
            before=copy_path.read_bytes();copy_path.write_bytes(before+b"changed")
            with self.assertRaises(ValueError):fence()
            control();copy_path.write_bytes(before)
            before=source.read_bytes();source.write_bytes(before+b"changed")
            with self.assertRaises(ValueError):fence()
            control();source.write_bytes(before)
            self.assertTrue(fence());control()


    def test_optional_real_native_bundle_mutations(self):
        if BUNDLE is None:return
        gate.validate_bundle(gate.REPOSITORY,BUNDLE);control()
        fixture=self.base/"actual-bundle";shutil.copytree(BUNDLE,fixture)
        for relative in ("native.elf","raw/stdout.raw","raw/stdin.raw","corpus.jsonl.xz","native-report.json"):
            path=fixture/relative;before=path.read_bytes()
            try:
                path.write_bytes(before+b"x")
                self.rejected(lambda:gate.validate_bundle(gate.REPOSITORY,fixture))
            finally:path.write_bytes(before)
        path=fixture/"raw/stdout.raw";before=path.read_bytes();path.unlink()
        path.symlink_to(BUNDLE/"raw/stdout.raw")
        try:self.rejected(lambda:gate.validate_bundle(gate.REPOSITORY,fixture))
        finally:path.unlink();path.write_bytes(before)
        report_path=fixture/"native-report.json";before=report_path.read_bytes()
        for change in ("count","source","cleanup","primary"):
            report=json.loads(before)
            if change=="count":report["native_cases"]=True
            if change=="source":report["verification"]["source_after"]["source_set_sha256"]="0"*64
            if change=="cleanup":report["verification"]["cleanup_errors"]=["real cleanup failure"]
            if change=="primary":report["verification"]["primary_error"]={"type":"Failure"}
            try:
                report_path.write_text(json.dumps(report))
                self.rejected(lambda:gate.validate_bundle(gate.REPOSITORY,fixture))
            finally:report_path.write_bytes(before)
def main():
    global BUNDLE
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):raise RuntimeError("Optimized integrity tests refused")
    parser=argparse.ArgumentParser();parser.add_argument("--report",type=Path,required=True)
    parser.add_argument("--bundle",type=Path);args=parser.parse_args()
    BUNDLE=args.bundle.absolute() if args.bundle else None
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Integrity)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    report={"schema":"trnm.hia.prepare-source-integrity-controls.v1","status":"PASS" if result.wasSuccessful() else "FAIL",
      "test_groups":result.testsRun,**COUNTS,"actual_native_runs":0,"actual_rust_runs":0,
      "real_bundle_rechecked":BUNDLE is not None,"errors":[(str(t),e) for t,e in result.errors],
      "failures":[(str(t),e) for t,e in result.failures]}
    args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps(report,sort_keys=True))
    if not result.wasSuccessful():raise SystemExit(1)
if __name__=="__main__":main()
