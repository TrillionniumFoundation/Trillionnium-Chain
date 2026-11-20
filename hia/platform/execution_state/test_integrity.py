"""Negative source/bundle admission controls, requiring neither Rust nor HIA tools.

The source-only fixture below deliberately cannot pass validate_bundle. It
contains no alleged native build, process, differential or semantic result.
"""
from __future__ import annotations
import copy,json,lzma,os,shutil,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
from . import rust_oracle as oracle

CONTROL_COUNT=0

def counted():
    global CONTROL_COUNT
    CONTROL_COUNT+=1


class Integrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repository=oracle.REPOSITORY
        cls.manifest=oracle.complete_source_manifest(cls.repository)
        cls.pin=oracle.load_json((cls.repository/'hia/qualification/compiler-binding.json').read_bytes())
        cls.lock=oracle.load_json((cls.repository/'hia/toolchain.lock.json').read_bytes())
    def source_fixture(self):
        return {'schema':oracle.COMP_SCHEMA,'status':'PASS','build':{'schema':oracle.BUILD_SCHEMA,'status':'PASS','source_inputs':copy.deepcopy(self.manifest),'source_set_sha256':oracle.digest(oracle.canonical_json(self.manifest)),'source_after':{'status':'PASS','errors':[]},'failure':None,'runtime_host_proxy':False,'original_rust_executed':False,'compiler_qualification_binding':self.pin,'compiler_sha256':self.pin['compiler_sha256'],'toolchain':self.lock}}
    def reject_source(self,value):
        with self.assertRaises((ValueError,OSError,TypeError,KeyError)):
            oracle.validate_source_bindings(self.repository,value)
        counted()
    def fixture_repository(self,root):
        for name in self.manifest:
            destination=root/name;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes((self.repository/name).read_bytes())
        components=oracle.load_json((root/'hia/components.json').read_bytes())
        for name in components['includes']:
            destination=root/'hia'/name
            if not destination.exists():destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(b'UNUSED_PATH_METADATA_ONLY\n')
        return root
    def test_complete_current_source_only_closure(self):
        self.assertEqual(oracle.validate_source_bindings(self.repository,self.source_fixture()),self.manifest);counted()
        self.assertTrue(oracle.OWNED_REQUIRED<={Path(name).name for name in self.manifest if name.startswith(oracle.OWNED+'/')})
    def test_each_dependency_omission_and_false_identity(self):
        for name in self.manifest:
            with self.subTest(name=name):
                value=self.source_fixture();del value['build']['source_inputs'][name];self.reject_source(value)
        for mutation in ('bytes','sha','digest','extra','top-map','runtime','source-fence','compiler','original-claim'):
            value=self.source_fixture();build=value['build'];name=next(iter(self.manifest))
            if mutation=='bytes':build['source_inputs'][name]['bytes']+=1
            if mutation=='sha':build['source_inputs'][name]['sha256']='0'*64
            if mutation=='digest':build['source_set_sha256']='0'*64
            if mutation=='extra':build['source_inputs']['trillionnium/Cargo.toml']=oracle.file_identity(self.repository/'trillionnium/Cargo.toml')
            if mutation=='top-map':value['source_inputs']={}
            if mutation=='runtime':build['runtime_host_proxy']=True
            if mutation=='source-fence':build['source_after']['status']='FAIL'
            if mutation=='compiler':build['compiler_sha256']='0'*64
            if mutation=='original-claim':build['original_rust_executed']=True
            self.reject_source(value)
    def test_dynamic_owned_and_explicit_recursive_declarations(self):
        with tempfile.TemporaryDirectory(prefix='svp-source-integrity-') as temporary:
            root=self.fixture_repository(Path(temporary)/'repo');before=oracle.complete_source_manifest(root)
            added=root/oracle.OWNED/'new_helper.py';added.write_text('VALUE=17\n');after=oracle.complete_source_manifest(root)
            self.assertEqual(set(after)-set(before),{oracle.OWNED+'/new_helper.py'});counted();added.unlink()
            includes=root/oracle.OWNED/'includes.json';raw=includes.read_bytes();value=oracle.load_json(raw)
            value['includes']['platform/execution_state/owner.hepta'].append({'source':'platform/execution_state/owner.hepta','functions':['f0']});includes.write_text(json.dumps(value))
            with self.assertRaises(ValueError):oracle.complete_source_manifest(root)
            counted();includes.write_bytes(raw)
            value=oracle.load_json(raw);value['includes']['platform/execution_state/owner.hepta'][0]['functions'].remove('ev_r');includes.write_text(json.dumps(value))
            with self.assertRaises(ValueError):oracle.complete_source_manifest(root)
            counted();includes.write_bytes(raw)
            cache=root/oracle.OWNED/'__pycache__';cache.mkdir()
            with self.assertRaises(ValueError):oracle.complete_source_manifest(root)
            counted();cache.rmdir()
            extra=root/oracle.OWNED/'unexpected.bin';extra.write_bytes(b'x')
            with self.assertRaises(ValueError):oracle.complete_source_manifest(root)
            counted();extra.unlink()
            builder=root/oracle.OWNED/'build.py';old=builder.read_bytes();builder.write_bytes(old.replace(b"ROOT_SOURCE='src/protocol/state_root_compact.hepta'",b"ROOT_SOURCE='src/protocol/state_root.hepta'"))
            with self.assertRaises(ValueError):oracle.complete_source_manifest(root)
            counted();builder.write_bytes(old)
    def test_paths_json_and_symbolic_ancestors(self):
        for name in ('../escape','/absolute','hia//bad','hia/./bad','hia\\bad','.',True):
            with self.assertRaises((ValueError,TypeError)):oracle.canonical_path(self.repository,name)
            counted()
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":Infinity}'):
            with self.assertRaises(ValueError):oracle.load_json(raw)
            counted()
        with tempfile.TemporaryDirectory(prefix='svp-symbolic-') as temporary:
            root=Path(temporary);(root/'real').mkdir();(root/'real/file').write_bytes(b'x');(root/'link').symlink_to(root/'real',target_is_directory=True)
            with self.assertRaises(ValueError):oracle.canonical_path(root,'link/file')
            counted()
    def test_source_corpus_and_bounded_archive(self):
        raw,rows=oracle.bound_corpus(self.repository);self.assertTrue(rows and raw.endswith(b'\n'));counted()
        with tempfile.TemporaryDirectory(prefix='svp-xz-') as temporary:
            path=Path(temporary)/'corpus.xz';expected=b'one\n';encoded=lzma.compress(expected);path.write_bytes(encoded)
            self.assertEqual(oracle.bounded_xz(path,expected),expected);counted()
            for raw in (encoded[:-1],encoded+b'x',encoded+encoded,lzma.compress(expected+b'x'),b'not-xz'):
                path.write_bytes(raw)
                with self.assertRaises((ValueError,lzma.LZMAError,EOFError)):oracle.bounded_xz(path,expected)
                counted()
    def test_native_pipe_extent_and_close_controls(self):
        frame=b'SVPR0001'+struct.pack('<7Q',26,1,0,0,0,0,0);raw=struct.pack('<Q',len(frame))+frame
        self.assertEqual(oracle.native_frames(raw)[0]['op'],26);counted()
        mutations=[raw[:-1],raw+b'x',struct.pack('<Q',63)+frame[:63],struct.pack('<Q',len(frame))+b'BADMAGIC'+frame[8:],struct.pack('<Q',len(frame))+frame[:40]+struct.pack('<Q',1)+frame[48:],struct.pack('<Q',len(frame))+frame[:56]+struct.pack('<Q',1)]
        for item in mutations:
            with self.assertRaises(ValueError):oracle.native_frames(item)
            counted()
    def test_public_cli_refuses_before_tool_discovery_or_source_copy(self):
        script=self.repository/oracle.OWNED/'rust_oracle.py'
        with tempfile.TemporaryDirectory(prefix='svp-cli-integrity-') as temporary:
            root=Path(temporary);bundle=root/'bundle';bundle.mkdir();(bundle/'native-comparison.json').write_text('{}\n');tools=root/'tools';tools.mkdir();marker=root/'cargo-called'
            for name in ('cargo','rustc'):
                path=tools/name;path.write_text('#!/bin/sh\nprintf called > "'+str(marker)+'"\nexit 99\n');path.chmod(0o700)
            for index,options in enumerate(([],['-O'])):
                output=root/('output-'+str(index));env={**os.environ,'PATH':str(tools),'PYTHONDONTWRITEBYTECODE':'1'};env.pop('PYTHONOPTIMIZE',None)
                result=subprocess.run([sys.executable,'-B',*options,str(script),'--repository',str(self.repository),'--bundle',str(bundle),'--output',str(output)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
                self.assertNotEqual(result.returncode,0);self.assertFalse(marker.exists());self.assertFalse((output/'isolated-source').exists());counted()
    def test_source_only_fixture_is_never_complete_native_evidence(self):
        with tempfile.TemporaryDirectory(prefix='svp-incomplete-bundle-') as temporary:
            bundle=Path(temporary);(bundle/'native-comparison.json').write_text(json.dumps(self.source_fixture()))
            with self.assertRaises(ValueError):oracle.validate_bundle(self.repository,bundle)
            counted()

    def test_actual_local_crate_compile_time_fixture_inventory(self):
        inventory=oracle.original_include_dependencies(self.repository)
        self.assertEqual(set(inventory['local_packages']),{
            'trillionnium/crates/trnm-mvcc-fee','trillionnium/crates/trnm-protocol',
            'trillionnium/crates/trnm-crypto-primitives','trillionnium/crates/trnm-verification-profiles'})
        original=oracle.original_manifest(self.repository)
        for name in ('tests/vectors/pon/native-growth-reference-v2.json','tests/fixtures/cpq1-content-v1/vectors.json'):
            self.assertIn(name,inventory['data_includes'])
            self.assertEqual(original[name],oracle.file_identity(self.repository/name));counted()

    def test_dynamic_original_data_include_and_local_package_controls(self):
        with tempfile.TemporaryDirectory(prefix='svp-original-include-') as temporary:
            root=Path(temporary)
            for name in ('config','formal','trillionnium/crates/trnm-mvcc-fee/src','trillionnium/crates/trnm-protocol/src','tests/vectors'):
                (root/name).mkdir(parents=True,exist_ok=True)
            (root/'trillionnium/Cargo.toml').write_text('[workspace]\nmembers=[]\n')
            (root/'trillionnium/Cargo.lock').write_text('SOURCE_ONLY_FIXTURE_NOT_A_CARGO_BUILD\n')
            (root/oracle.STORE).write_text('// source-only original inventory fixture\n')
            main=root/'trillionnium/crates/trnm-mvcc-fee/Cargo.toml'
            main.write_text('[package]\nname="trnm-mvcc-fee"\nversion="0.1.0"\n[dependencies]\ntrnm-protocol={path="../trnm-protocol"}\n')
            (root/'trillionnium/crates/trnm-protocol/Cargo.toml').write_text('[package]\nname="trnm-protocol"\nversion="0.1.0"\n')
            source=root/'trillionnium/crates/trnm-protocol/src/data.rs'
            source.write_text('const DATA: &str=include_str!("../../../../tests/vectors/example.json");\n')
            fixture=root/'tests/vectors/example.json';fixture.write_bytes(b'{"n":1}\n')
            before=oracle.original_manifest(root)
            self.assertEqual(before['tests/vectors/example.json'],oracle.file_identity(fixture));counted()
            fixture.unlink()
            with self.assertRaises((ValueError,OSError)):oracle.original_manifest(root)
            counted();fixture.write_bytes(b'{"n":2}\n')
            self.assertNotEqual(oracle.original_manifest(root),before);counted()
            raw=source.read_bytes()
            for changed in (
                b'include_bytes!("../../../../../../escape.bin")',
                b'include_str!("/absolute/fixture")',
                b'include_str!(concat!("a","b"))',
                b'include!("generated.rs")',
            ):
                source.write_bytes(changed)
                with self.assertRaises((ValueError,OSError)):oracle.original_manifest(root)
                counted()
            source.write_bytes(raw);fixture.unlink();fixture.symlink_to(root/'trillionnium/Cargo.lock')
            with self.assertRaises((ValueError,OSError)):oracle.original_manifest(root)
            counted();fixture.unlink();fixture.write_bytes(b'{"n":1}\n')
            added=root/'trillionnium/crates/trnm-protocol/src/another.rs'
            added.write_text('const NEXT: &[u8]=include_bytes!("../../../../tests/vectors/next.bin");\n')
            with self.assertRaises((ValueError,OSError)):oracle.original_manifest(root)
            counted();(root/'tests/vectors/next.bin').write_bytes(b'exact additional bytes')
            self.assertIn('tests/vectors/next.bin',oracle.original_manifest(root));counted()
            old=main.read_bytes();main.write_bytes(old+b'missing={path="../missing-package"}\n')
            with self.assertRaises((ValueError,OSError)):oracle.original_manifest(root)
            counted()

    def test_original_environment_and_target_overrides(self):
        names=(*oracle.FORBIDDEN_OVERRIDES,'CARGO_PROFILE_DEV_OVERFLOW_CHECKS',
            'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS','CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTDOCFLAGS',
            'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER','CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER')
        for name in names:
            with mock.patch.dict(os.environ,{name:'controlled-override'},clear=True):
                with self.assertRaises(ValueError):oracle.clean_build_environment()
                counted()
        with mock.patch.dict(os.environ,{'RUSTC':'','CARGO_PROFILE_DEV_OPT_LEVEL':''},clear=True):
            self.assertEqual(oracle.clean_build_environment()['PYTHONDONTWRITEBYTECODE'],'1');counted()
        with tempfile.TemporaryDirectory(prefix='svp-original-target-') as temporary:
            root=Path(temporary);repository=root/'repo';bundle=root/'bundle';repository.mkdir();bundle.mkdir()
            output=root/'output';isolated=output/'isolated-source';ordinary=root/'not-a-directory';ordinary.write_bytes(b'x');alias=root/'alias';alias.symlink_to(repository,target_is_directory=True)
            for value in (repository,repository/'target',root,bundle,bundle/'target',output,output/'other',ordinary,alias/'target'):
                with self.assertRaises(ValueError):oracle.safe_target(value,output,repository,bundle,isolated)
                counted()
            self.assertEqual(oracle.safe_target(None,output,repository,bundle,isolated),output/'cargo-target');counted()
            self.assertEqual(oracle.safe_target(root/'shared-cache',output,repository,bundle,isolated),root/'shared-cache');counted()

    def test_actual_library_artifact_kind_selection(self):
        # Real Cargo emitted custom-build/build-script-build plus lib/serde_json.
        script={'target':{'name':'build-script-build','kind':['custom-build']}}
        library={'target':{'name':'serde_json','kind':['lib']}}
        binary={'target':{'name':'trnm_mvcc_fee','kind':['lib']},'executable':'actual-test','profile':{'test':True}}
        self.assertEqual(oracle.original_artifacts([script,library,binary]),([library],[binary]));counted()
        for name in ('serde_json','trnm_mvcc_fee'):
            forged={'target':{'name':name,'kind':['custom-build']},'executable':'not-a-test','profile':{'test':True}}
            self.assertEqual(oracle.original_artifacts([forged]),([],[]));counted()

    def test_public_cli_override_refusal_precedes_copy_and_tool_discovery(self):
        script=self.repository/oracle.OWNED/'rust_oracle.py'
        with tempfile.TemporaryDirectory(prefix='svp-public-original-overrides-') as temporary:
            root=Path(temporary);bundle=root/'bundle';bundle.mkdir();(bundle/'native-comparison.json').write_text('{}\n');tools=root/'tools';tools.mkdir();marker=root/'tool-called'
            for name in ('cargo','rustc'):
                path=tools/name;path.write_text('#!/bin/sh\nprintf called > "'+str(marker)+'"\nexit 99\n');path.chmod(0o700)
            rows=[({'RUSTC':'unadmitted'},None,'RUSTC'),({'RUSTDOC':'unadmitted'},None,'RUSTDOC'),
                ({'CARGO_BUILD_RUSTC':'unadmitted'},None,'CARGO_BUILD_RUSTC'),
                ({'CARGO_PROFILE_DEV_OVERFLOW_CHECKS':'false'},None,'CARGO_PROFILE_DEV_OVERFLOW_CHECKS'),
                ({'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER':'unadmitted'},None,'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER'),
                ({'CARGO_BUILD_TARGET':'unadmitted'},None,'CARGO_BUILD_TARGET'),
                ({},self.repository,'Cargo target overlaps'),({},root,'Cargo target overlaps')]
            for index,(overrides,target,error_text) in enumerate(rows):
                output=root/('refusal-'+str(index));env={k:v for k,v in os.environ.items() if not oracle.forbidden_override(k)};env.update(PATH=str(tools),PYTHONDONTWRITEBYTECODE='1');env.pop('PYTHONOPTIMIZE',None);env.update(overrides)
                args=[sys.executable,'-B',str(script),'--repository',str(self.repository),'--bundle',str(bundle),'--output',str(output)]
                if target is not None:args.extend(('--target-dir',str(target)))
                result=subprocess.run(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
                self.assertNotEqual(result.returncode,0);self.assertFalse(marker.exists());self.assertFalse((output/'isolated-source').exists())
                report=json.loads((output/'report.json').read_bytes());self.assertIn(error_text,report['primary_error']);self.assertEqual(report['stages'],[]);counted()


if __name__=='__main__':
    program=unittest.main(exit=False)
    print(json.dumps({'status':'PASS' if program.result.wasSuccessful() else 'FAIL','test_groups':program.result.testsRun,'controls':CONTROL_COUNT,'requires_rust':False,'requires_hia_toolchain':False,'synthetic_source_only_checks_are_native_evidence':False},sort_keys=True))
    raise SystemExit(not program.result.wasSuccessful())
