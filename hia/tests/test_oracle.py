"""Complete Oracle public methods and concrete serde_json surface against Rust.

The complete unchanged crate is compiled in four configurations. HIA receives original typed or
JSON bytes and performs all validation, hashing, arithmetic and formatting.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import traceback
import types
import unittest
from unittest.mock import patch

from hia.tests.oracle_native import Evidence, OracleNative, ROOT, digest
from hia.tests.oracle_cases import (I128_MIN,I128_MAX,U32_MAX,U64_MAX,U128_MAX,WHITESPACE,
    word,string,frame,json_frame,json_decode,snapshot,policy,validate,report,replace_word,
    json_values,json_roundtrip_cases)

VERSIONS={'sha2':'0.10.9','serde':'1.0.229','serde_json':'1.0.149',
          'hex':'0.4.3','thiserror':'1.0.69'}


def completed_result(case,result):
    def belongs(item):
        return item is case or getattr(item,'test_case',None) is case
    issues=[]
    for label,items in [('failure',result.failures),('error',result.errors),
                        ('skipped',result.skipped),('expected_failure',result.expectedFailures)]:
        issues.extend({'kind':label,'detail':str(detail)} for item,detail in items if belongs(item))
    issues.extend({'kind':'unexpected_success','detail':''} for item in result.unexpectedSuccesses
                  if belongs(item))
    return {'passed':not issues,'issues':issues}


def dependencies(workspace=False):
    prefix="HIA_ORACLE_WORKSPACE_" if workspace else "HIA_ORACLE_"
    configured=os.environ.get(prefix+"DEPENDENCIES_JSON")
    if configured:
        chosen={name:Path(path) for name,path in json.loads(Path(configured).read_text()).items()}
        if set(chosen)!=set(VERSIONS):
            raise AssertionError('Require exact five original dependency artifact names')
    else:
        directory=Path(os.environ[prefix+'DEPS'])
        chosen={}
        for name,version in VERSIONS.items():
            candidates=[]
            for path in directory.glob('lib'+name+'-*.rlib'):
                dep=path.with_name(path.name[3:-5]+'.d')
                if dep.is_file() and '/'+name+'-'+version+'/' in dep.read_text():
                    candidates.append(path)
            if len(candidates)!=1:
                raise AssertionError('Original dependency artifact is not unique: '+name)
            chosen[name]=candidates[0]
    records=[]
    for name,path in chosen.items():
        if not path.is_file():
            raise AssertionError('Missing actual original dependency: '+str(path))
        dep=path.with_name(path.name[3:-5]+'.d')
        if not dep.is_file() or '/'+name+'-'+VERSIONS[name]+'/' not in dep.read_text():
            raise AssertionError('Dependency .d source version differs from original Cargo.lock: '+name)
        fingerprint=path.parent.parent/'.fingerprint'/path.name[3:-5]/('lib-'+name+'.json')
        if not fingerprint.is_file():
            raise AssertionError('Missing actual Cargo build fingerprint: '+name)
        metadata=json.loads(fingerprint.read_text())
        expected_features=['arbitrary_precision','default','std'] if workspace else ['default','std']
        if name=='serde_json' and json.loads(metadata['features'])!=expected_features:
            raise AssertionError('Oracle JSON profile feature artifact differs: '+str(expected_features))
        records.append({'serde_profile':'workspace' if workspace else 'default',
                        'name':name,'version':VERSIONS[name],'path':str(path),
                        'sha256':digest(path),'size':path.stat().st_size,
                        'dep_info_sha256':digest(dep),'fingerprint':metadata})
    return chosen,records


class OracleNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='trnm-oracle-')
        cls.addClassCleanup(cls.temporary.cleanup)
        destination=os.environ.get('HIA_ORACLE_OUTPUT')
        cls.e=Evidence(Path(destination) if destination else Path(cls.temporary.name)/'evidence',
                       unittest.defaultTestLoader.getTestCaseNames(cls))
        cls.addClassCleanup(cls.e.finish)
        cls.modules={}
        try:
            if os.environ.get('HIA_ORACLE_SETUP_PROBE')=='missing-executable':
                cls.e.run([str(cls.e.directory/'missing-rustc')],stage='setup-before-source-missing',
                          capture_output=True,timeout=1,check=True)
            cls.e.run(['bash','scripts/project-preflight.sh'],stage='project-preflight',cwd=ROOT,
                      capture_output=True,timeout=20,check=True)
            from hia.tools import toolchain
            source_paths={ROOT/'hia/tests/test_oracle.py',ROOT/'hia/tests/oracle_native.py',
                ROOT/'hia/tests/oracle_cases.py',ROOT/'hia/tests/oracle_original.rs',
                ROOT/'hia/tests/native_support.py',ROOT/'hia/tools/toolchain.py',
                ROOT/'hia/toolchain.lock.json',ROOT/'hia/qualification/compiler-binding.json',
                ROOT/'hia/src/oracle/README.md',ROOT/'trillionnium/Cargo.toml',
                ROOT/'trillionnium/Cargo.lock',ROOT/'trillionnium/crates/trnm-oracle/Cargo.toml',
                ROOT/'trillionnium/crates/trnm-data-availability/Cargo.toml',ROOT/'scripts/ci/ci_job.sh',
                ROOT/'trillionnium/crates/trnm-oracle/src/lib.rs'}
            facade=types.SimpleNamespace(run=cls.e.run)
            with patch.object(toolchain,'subprocess',facade):
                for name in ('values','serde_json'):
                    checked=toolchain.checked_source(ROOT/('hia/src/oracle/'+name+'.hepta'))
                    source_paths.update(path for path,_ in checked[4])
            cls.e.snapshot(source_paths)
            default,first=dependencies(False)
            workspace,second=dependencies(True)
            cls.dependency_records=first+second
            cls.e.dependency_inputs=cls.dependency_records
            cls.dependency_paths={'default':default,'workspace':workspace}
            for profile in cls.dependency_paths:(cls.e.directory/'dependencies'/profile).mkdir(parents=True)
            for row in cls.dependency_records:
                selected=Path(row['path']);dest=cls.e.directory/'dependencies'/row['serde_profile']/selected.name
                shutil.copy2(selected,dest);cls.e.artifact(dest,'original-dependency-'+row['serde_profile']+'-'+row['name'])
            (cls.e.directory/'dependency-identities.json').write_text(json.dumps(cls.dependency_records,indent=2))
            compiler=Path(os.environ['HIA_NATIVE_COMPILER'])
            shutil.copy2(compiler,cls.e.directory/'hia-native-compiler')
            cls.e.artifact(cls.e.directory/'hia-native-compiler','selected-HIA-compiler')
            with patch.object(toolchain,'subprocess',facade):
                for name in ('values','serde_json'):
                    source=ROOT/('hia/src/oracle/'+name+'.hepta')
                    receipt,_=toolchain.build_native(source,cls.e.directory/(name+'.so'),
                        byte_exports=('f0',),backend='selfhost',compiler=str(compiler),
                        compiler_sha256=os.environ['HIA_NATIVE_COMPILER_SHA256'])
                    (cls.e.directory/(name+'-build.json')).write_text(json.dumps(receipt,indent=2))
                    (cls.e.directory/(name+'-composed.hepta')).write_bytes(toolchain.checked_source(source)[1])
                    cls.e.artifact(cls.e.directory/(name+'.so'),'actual-native-'+name)
                    cls.modules[name]=OracleNative(cls.e.directory/(name+'.so'),cls.e,name)
            cls.rustc=os.environ.get('HIA_ORACLE_RUSTC','rustc')
            cls.e.run([cls.rustc,'--version','--verbose'],stage='rustc-identity',
                      capture_output=True,timeout=15,check=True)
            for feature,chosen in cls.dependency_paths.items():
                externs=[]
                for name,path in chosen.items():externs+=['--extern',name+'='+str(path)]
                dirs=sorted({str(path.parent) for path in chosen.values()})
                search=[arg for path in dirs for arg in ['-L','dependency='+path]]
                for arithmetic,checked in [('release',False),('checked',True)]:
                    name=arithmetic+'-'+feature
                    options=['--edition=2021','-C','opt-level='+('0' if checked else '3'),'-C','overflow-checks='+('on' if checked else 'off'),
                             '-C','debug-assertions='+('on' if checked else 'off'),*search,*externs]
                    library=cls.e.directory/('libtrnm_oracle_'+name+'.rlib')
                    cls.e.run([cls.rustc,'--crate-name','trnm_oracle','--crate-type','rlib',
                        str(ROOT/'trillionnium/crates/trnm-oracle/src/lib.rs'),'-o',str(library),*options],
                        stage=name+'-original-build',capture_output=True,timeout=60,check=True)
                    cls.e.artifact(library,'complete-original-crate-'+name)
                    retained=cls.e.directory/(name+'-retained')
                    cls.e.run([cls.rustc,'--crate-name','trnm_oracle','--test',
                        str(ROOT/'trillionnium/crates/trnm-oracle/src/lib.rs'),'-o',str(retained),*options],
                        stage=name+'-retained-build',capture_output=True,timeout=60,check=True)
                    cls.e.artifact(retained,'complete-original-retained-tests-'+name)
                    listing=cls.e.run([str(retained),'--list'],stage=name+'-retained-roster',
                        capture_output=True,timeout=30,check=True)
                    if len([x for x in listing.stdout.splitlines() if x.endswith(b': test')])!=118:
                        raise AssertionError('Actual full retained roster differs from 118')
                    tests=cls.e.run([str(retained),'--test-threads=1'],stage=name+'-retained-run',
                        capture_output=True,timeout=60,check=True)
                    if b'118 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out' not in tests.stdout:
                        raise AssertionError('Full original retained execution did not complete')
                    original=cls.e.directory/(name+'-original')
                    cls.e.run([cls.rustc,str(ROOT/'hia/tests/oracle_original.rs'),'-o',str(original),
                        *options,'--extern','trnm_oracle='+str(library),
                        *(['--cfg','oracle_checked'] if checked else []),
                        *(['--cfg','oracle_json_arbitrary_precision'] if feature=='workspace' else [])],stage=name+'-adapter-build',
                        capture_output=True,timeout=60,check=True)
                    cls.e.artifact(original,'actual-original-public-API-adapter-'+name)
            cls.e.write()
        except BaseException:
            cls.e.setup_error=traceback.format_exc();cls.e.write();raise

    def setUp(self):
        self.e.current_test=self._testMethodName
        self.e.started.append(self._testMethodName)
        self.e.write()

    def run(self,result=None):
        result=self.defaultTestResult() if result is None else result
        returned=super().run(result)
        if hasattr(type(self),'e'):
            self.e.completed.append({'method':self._testMethodName,**completed_result(self,result)})
            self.e.write()
        return returned

    @classmethod
    def tearDownClass(cls):
        try:
            for row in cls.dependency_records:
                if digest(row['path'])!=row['sha256']:
                    raise AssertionError('Actual original dependency changed during execution')
            for row in cls.e.artifacts:
                if digest(cls.e.directory/row['path'])!=row['sha256']:
                    raise AssertionError('Tested artifact changed during execution')
            cls.e.teardown_checks_passed=True
        except BaseException:
            cls.e.teardown_checks_passed=False
            cls.e.finalization_error=traceback.format_exc()
            cls.e.write()
            raise

    def reference(self,rows):
        rows=list(rows);answers=[None]*len(rows)
        for profile in (0,1,2,3):
            selected=[(i,x) for i,x in enumerate(rows)
                      if struct.unpack_from('<Q',x,24 if x[:8]==b'ORJS0001' else 16)[0]==profile]
            if not selected:continue
            arithmetic='checked' if profile&1 else 'release'
            name=arithmetic+('-workspace' if profile&2 else '-default')
            raw=''.join(x.hex()+'\n' for _,x in selected).encode()
            proc=self.e.run([str(self.e.directory/(name+'-original')),arithmetic],stage='original-'+name,
                           input=raw,capture_output=True,timeout=60,check=False)
            self.assertEqual(proc.returncode,0,proc.stderr)
            lines=proc.stdout.splitlines();self.assertEqual(len(lines),len(selected))
            for (index,_),line in zip(selected,lines):
                status,data=line.split(b' ',1)
                answers[index]=(int(status),b'' if data==b'-' else bytes.fromhex(data.decode()),
                                len(self.e.processes)-1)
        return answers

    def check(self,rows, *, both=False):
        rows=list(rows)
        if both:
            rows += [replace_word(x,24 if x[:8]==b'ORJS0001' else 16,
                         int.from_bytes(x[24:32] if x[:8]==b'ORJS0001' else x[16:24],'little')|1) for x in rows]
        rows += [replace_word(x,24,int.from_bytes(x[24:32],'little')|2)
                 for x in rows if x[:8]==b'ORJS0001' and int.from_bytes(x[24:32],'little')<2]
        expected=self.reference(rows)
        pending=[];answers=[]
        def execute(batch):
            if not batch:return
            name='serde_json' if batch[0][1][:8]==b'ORJS0001' else 'values'
            calls=[]
            for _,raw,_,_,_ in batch:
                count=16 if name=='serde_json' else 10
                calls.append((raw,b'\xa5'*(8192+len(raw)*6),b'\x6d'*(32768+count*len(raw)+13)))
            native_start=len(self.e.native)
            got=self.modules[name].call_many(calls,expected_failure=batch[0][2]==250)
            for offset,((index,raw,status,target,process),actual) in enumerate(zip(batch,got)):
                row={'test':self._testMethodName,'module':name,'input':self.e.blob(raw),
                     'oracle_process':process,'oracle_status':status,'oracle_output':self.e.blob(target),
                     'native_observation':native_start+offset,'native_status':actual.status,
                     'native_value':actual.value,'expected_original_panic':status==250,
                     'passed':False}
                self.e.comparisons.append(row)
                if status==250:
                    self.assertEqual(actual.status,'trapped',row)
                    self.assertIn(actual.returncode,(-4,-6),row)
                    self.assertIsNone(actual.arguments)
                else:
                    actual.require_returned();self.assertEqual(actual.value,status,row)
                    if status==0:
                        self.assertGreaterEqual(len(target),16)
                        self.assertEqual(int.from_bytes(target[8:16],'little'),len(target)-16)
                        self.assertEqual(actual.arguments[1],target+b'\xa5'*(len(calls[offset][1])-len(target)),row)
                    else:
                        self.assertEqual(actual.arguments[1],calls[offset][1],row)
                    self.assertEqual(actual.arguments[2][-13:],b'\x6d'*13,row)
                row['passed']=True
        for index,(raw,(status,target,process)) in enumerate(zip(rows,expected)):
            item=(index,raw,status,target,process)
            if status==250:
                execute(pending);pending=[];execute([item])
            else:
                if pending and (len(pending)>=20 or pending[0][1][:8]!=raw[:8]):
                    execute(pending);pending=[]
                pending.append(item)
        execute(pending)
        return [(status,target) for status,target,_ in expected]

    def test_01_original_source_graph_and_retained_roster(self):
        source=(ROOT/'trillionnium/crates/trnm-oracle/src/lib.rs').read_text()
        self.assertEqual(len(re.findall(r'#\[test\]',source)),118)
        self.assertNotRegex(source,r'(?m)^mod (snapshot|validation);')
        self.assertNotIn('f64',source[:source.index('#[cfg(test)]')])
        self.assertEqual(set(self.dependency_paths),{'default','workspace'})
        for chosen in self.dependency_paths.values():self.assertEqual(set(chosen),set(VERSIONS))
        for profile in ('release-default','checked-default','release-workspace','checked-workspace'):
            self.assertEqual(len([x for x in self.e.processes if x['stage']==profile+'-retained-run'
                                  and x['returncode']==0]),1)

    def test_02_source_ids_full_unicode_trim_control_and_as_str(self):
        strings=['','a','A',' a ','chain-link','É','é','Ａ','中','🧬','\u200b','\ufeff','\ue000',
                 'x\0y','a'*4097, ''.join(chr(i) for i in range(128))]
        for value in WHITESPACE:
            c=chr(value);strings.extend([c,c+'a', 'a'+c,'a'+c+'b',c+'A'+c])
        for value in list(range(32))+list(range(127,160)):
            strings.append('a'+chr(value)+'b')
        rng=random.Random(0x0A11CE)
        for _ in range(100):
            values=[rng.randrange(0x110000) for _ in range(6)]
            strings.append(''.join(chr(c) for c in values if not 0xD800<=c<=0xDFFF))
        self.check([frame(op,string(s)) for s in strings for op in (0,10)],both=True)

    def test_03_constructor_sorting_original_order_duplicate_and_error_precedence(self):
        rows=[]
        sequences=[[],['a'],['b','a'],['z','a','b'],['a','a'],['b','a','b'],
                   ['b','a','A'],['a','a','A'],['A','a','a'],['é','É','中'],['a',' a'],['','a']]
        for sources in sequences:
            for count in (0,1,2,3,U32_MAX):
                rows.append(frame(1,snapshot(sources=sources,sample_count=count,snapshot_hash='')))
        for feed in ('',' A ','x\0y','usd'):
            for start,end,ts in [(2,1,0),(1,2,1),(1,1,1),(0,U64_MAX,U64_MAX)]:
                rows.append(frame(1,snapshot(feed_id=feed,window_start_ms=start,window_end_ms=end,
                                            snapshot_ts_ms=ts,sources=['A','a','a'],snapshot_hash='')))
        for count in (0,1,17,100,257):
            sources=[f'source-{i:06}' for i in range(count)][::-1]
            rows.append(frame(1,snapshot(sources=sources,sample_count=max(1,count),snapshot_hash='')))
        self.check(rows,both=True)

    def test_04_original_hash_framing_options_order_and_error_values(self):
        rows=[]
        for value in (I128_MIN,I128_MIN+1,-1,0,1,I128_MAX):
            for median in (None,I128_MIN,0,I128_MAX):
                for mad in (None,0,U128_MAX):
                    rows.append(frame(2,snapshot(value=value,median=median,mad=mad)))
        for sources in (['a','b'],['b','a'],['a','a'],['\0','a\xff'],[]):
            for op in (2,3):rows.append(frame(op,snapshot(sources=sources)))
        for hashed in ('',' ','\u3000','A'*64,'0'*64,'f'*64,'g'*64,'a'*63,'a'*65,
                       'a'*64+' ', '\u200ba'+'0'*62,'a\0'+'0'*62):
            for op in (3,5,6):
                raw=snapshot(snapshot_hash=hashed)
                rows.append(frame(op,raw) if op==3 else validate(op,raw))
        self.check(rows,both=True)

    def test_05_policy_all_checks_temporal_u64_and_first_error_order(self):
        rows=[]
        limits=[policy(),policy(0,0,10001,0),policy(2,0,10001,0),policy(2,1,10001,0),
                policy(2,1,10000,0),policy(2,1,10000,1),policy(1,U64_MAX,0,U32_MAX)]
        bads=[snapshot(),snapshot(feed_id=''),snapshot(window_start_ms=3,window_end_ms=2),
              snapshot(sources=['a','a']),snapshot(sources=['b','a']),snapshot(snapshot_hash=''),
              snapshot(sample_count=0),snapshot(sources=['a']),snapshot(sample_count=61)]
        for rules in limits:
            rows.append(frame(4,rules))
            for raw in bads:
                for op in (5,6):rows.append(validate(op,raw,limits=rules))
        for ts in (0,1,200,U64_MAX-1,U64_MAX):
            for now in (0,1,200,5199,5200,5201,U64_MAX):
                for op in (5,6):rows.append(validate(op,snapshot(window_start_ms=0,
                    window_end_ms=ts,snapshot_ts_ms=ts),now=now))
        self.check(rows,both=True)

    def test_06_full_signed128_saturating_unsigned128_deviation(self):
        rows=[]
        values=[I128_MIN,I128_MIN+1,-10001,-1,0,1,94999,95000,95001,100000,I128_MAX]
        for value in values:
            for median in (I128_MIN,-100000,-1,0,1,100000,I128_MAX,None):
                for limit in (0,1,500,10000):
                    rows.append(validate(5,snapshot(value=value,median=median),
                                         limits=policy(max_deviation_bps=limit)))
        rng=random.Random(0x0128)
        for _ in range(250):
            raw=snapshot(value=rng.randrange(I128_MIN,I128_MAX+1),
                         median=rng.randrange(I128_MIN,I128_MAX+1),mad=rng.getrandbits(128))
            rows.append(validate(6,raw,limits=policy(max_deviation_bps=rng.randrange(10001))))
        self.check(rows,both=True)

    def test_07_observed_labels_cardinality_and_all_report_methods(self):
        rows=[]
        for sources in ([],['a'],['a','a'],['A',' a ','a','\tA\n',''],
                        ['\u3000','\t','\x85'],['É','é','É'],['a b','a\tb','a b']):
            for raw in (snapshot(sources=sources),snapshot(sources=sources,feed_id=''),
                        snapshot(sources=sources,snapshot_hash='0'*64),
                        snapshot(sources=sources,snapshot_ts_ms=U64_MAX)):
                rows += [validate(6,raw),validate(6,raw,limits=policy(min_sources=0))]
        results=self.check(rows,both=True)
        helpers=[]
        for status,response in results:
            self.assertEqual(status,0);self.assertEqual(response[:8],bytes(8))
            for method in range(8):helpers.append(frame(9,word(method)+response[16:]))
        self.check(helpers)

    def test_08_counter_wrapping_and_actual_checked_overflow_traps(self):
        rows=[]
        for counters in [(0,0,0,0),(1,2,3,4),(U32_MAX,0,0,0),(U32_MAX,1,0,0),
                         (U32_MAX,0,1,0),(0,U32_MAX,1,0),(1,0,0,U32_MAX),
                         (U32_MAX,U32_MAX,U32_MAX,U32_MAX)]:
            for method in range(3):
                rows.append(frame(7,word(method,U32_MAX,*counters)))
                rows.append(frame(8,word(method,*counters[:3],U32_MAX,counters[3],U32_MAX)))
            for method in range(8):
                rows.append(frame(9,word(method)+report(ok=True,observation=counters,
                    metrics=(*counters[:3],0,counters[3],0),error=None)))
        results=self.check(rows,both=True)
        self.assertTrue(any(status==250 for status,_ in results))
        self.assertTrue(any(status==0 for status,_ in results))

    def test_09_report_consistency_short_circuit_and_classified_conservation(self):
        rows=[]
        counters=[(0,0,0,0),(0,0,0,1),(1,0,0,0),(0,1,0,0),(1,2,3,4)]
        labels=[None,'',' ','stale','quorum','drift','rate','invalid policy: x',
                'snapshot hash mismatch:','snapshot hash mismatch','\u3000rate\u3000',
                'stale\0',' STALE ', 'snapshot hash mismatch:x']
        for ok in (False,True):
            for label in labels:
                for sample in (0,1,10,U32_MAX):
                    for count in counters:
                        rows.append(frame(9,word(7)+report(ok=ok,observation=count,
                            metrics=(*count[:3],0,count[3],sample),error=label)))
        # Metrics conservation short-circuits the observation sum; the eager
        # local calculation still runs before final non-empty-sample checks.
        for metrics in [(0,0,0,0,0,1),(0,0,0,0,0,0),(U32_MAX,1,0,0,0,0)]:
            rows.append(frame(9,word(7)+report(observation=(U32_MAX,1,0,0),metrics=metrics,error='')))
        # Publicly supplied reports preserve the original release u32 rollover.
        rows.append(frame(9,word(7)+report(observation=(U32_MAX,2,0,0),
                    metrics=(U32_MAX,2,0,0,0,1),error='quorum')))
        self.check(rows,both=True)

    def test_10_typed_transport_invalid_utf8_truncation_ranges_and_trailing(self):
        valid=[frame(0,string('a')),frame(1,snapshot(snapshot_hash='')),frame(4,policy()),
               validate(6),frame(7,word(2,1,0,0,0,1)),frame(8,word(2,0,0,0,1,1,1)),
               frame(9,word(7)+report())]
        rows=[]
        for raw in valid:
            rows.extend(raw[:n] for n in range(24,len(raw)))
            rows.append(raw+b'\0')
        rows += [frame(0,string(b'\xff')),frame(0,string(b'\xed\xa0\x80')),
                 frame(0,string(b'\xc0\x80')),frame(0,string(b'\xf4\x90\x80\x80')),
                 frame(4,word(1<<32,1,1,1)),frame(7,word(3,1,0,0,0,0)),
                 frame(7,word(0,1<<32,0,0,0,0)),frame(8,word(0,U64_MAX,0,0,1,0,1))]
        for off,value in [(24,2),(48,2),(16,1<<32),(96,U64_MAX),(104,U64_MAX),(112,U64_MAX)]:
            rows.append(frame(2,replace_word(snapshot(),off,value)))
        results=self.check(rows)
        self.assertTrue(all(status==100 for status,_ in results))

    def test_11_exact_capacities_and_atomic_output_refusal(self):
        frames=[frame(0,string(' A ')),frame(1,snapshot(snapshot_hash='')),validate(6),
                json_decode(1,json.dumps(json_values()[1]))]
        refs=self.reference(frames)
        for raw,(status,target,_) in zip(frames,refs):
            self.assertEqual(status,0)
            name='serde_json' if raw[:8]==b'ORJS0001' else 'values'
            size=32768+(16 if name=='serde_json' else 10)*len(raw)
            cases=[(raw,b'\xa5'*len(target),b'\x6d'*size),
                   (raw,b'\xa5'*(len(target)-1),b'\x6d'*size),
                   (raw,b'\xa5'*len(target),b'\x6d'*(size-1))]
            got=self.modules[name].call_many(cases)
            for item,answer,code in zip(cases,got,(0,102,101)):
                answer.require_returned();self.assertEqual(answer.value,code)
                self.assertEqual(answer.arguments[1],target if code==0 else item[1])
            self.e.write()

    def test_12_serde_all_six_public_types_roundtrip_order_defaults_and_duplicates(self):
        rows=json_roundtrip_cases();answers=self.check(rows)
        encoded=[]
        for raw,(status,response) in zip(rows,answers):
            if status==0 and response[:8]==bytes(8):
                encoded.append(json_frame(int.from_bytes(raw[8:16],'little'),1,response[16:]))
        self.assertGreater(len(encoded),40)
        self.check(encoded,both=True)

    def test_13_serde_ignored_any_unknown_fields_unicode_and_unbounded_skip_stack(self):
        rows=[]
        good=[b'null',b'1e99999',b'"\\ud800"',b'"\xff"',b'[1,{"a":true}]',
              b'{"\xff":"\\udfff"}',b'['*1500+b'0'+b']'*1500,
              b'{"a":'*700+b'0'+b'}'*700]
        bad=[b'[1,]',b'{"a":}',b'1e+',b'01',b'"\\uQQQQ"',b'"\x01"',b'"\\x00"']
        for kind,value in enumerate(json_values()):
            if not isinstance(value,dict):continue
            prefix=json.dumps(value).encode()[:-1]
            for raw in good+bad:rows.append(json_decode(kind,prefix+b',"unknown":'+raw+b'}'))
            rows.append(json_decode(kind,prefix+b',"unknown":0,"unknown":1}'))
        for raw in [b'',b'null',b'true',b'false',b'0',b'[]',b'{}',b'""',b'"\xff"',
                    b'"\\ud800"',b'"\\ud800\\udc00"',b'"\\u0000"',b'"\\/"',
                    b'"\\u0041"',b'"\\u00FF"',b'"\\uDC00"',b'"a" ',b' "a"',
                    b'"a" 0',b'"a"\xc2\xa0']:
            for kind in range(6):rows.append(json_decode(kind,raw))
        for count in (0,1,63,64,4095,50000):rows.append(json_decode(0,'"'+'x'*count+'"'))
        self.check(rows)

    def test_14_serde_full_numeric_domain_decimal_exponent_and_negative_zero(self):
        rows=[];baseline=json_values()[1]
        values=['-0','0','0.0','1e0','-1',str(U32_MAX),str(U32_MAX+1),str(U64_MAX),
                str(U64_MAX+1),str(U128_MAX),str(U128_MAX+1),str(I128_MAX),str(I128_MAX+1),
                str(I128_MIN),str(I128_MIN-1),'+0','01','1e999','-1e999','NaN','Infinity']
        for name in ('value','median','mad','sample_count','window_start_ms'):
            for raw in values:
                value=baseline.copy();value.pop(name)
                rows.append(json_decode(1,json.dumps(value)[:-1]+','+json.dumps(name)+':'+raw+'}'))
        rng=random.Random(0x5E2DE)
        for _ in range(200):
            value=baseline.copy();value['value']=rng.randrange(I128_MIN,I128_MAX+1)
            value['median']=rng.randrange(I128_MIN,I128_MAX+1);value['mad']=rng.getrandbits(128)
            value['window_end_ms']=rng.getrandbits(64)
            rows.append(json_decode(1,json.dumps(value)))
        results=self.check(rows)
        self.check([json_frame(1,1,data[16:]) for status,data in results[:len(rows)] if status==0 and data[:8]==bytes(8)])

    def test_15_serde_seeded_mutations_and_typed_representation_refusals(self):
        rng=random.Random(0xF022);rows=[]
        originals=[json.dumps(value,ensure_ascii=False).encode() for value in json_values()]
        for _ in range(650):
            kind=rng.randrange(6);raw=bytearray(originals[kind]);at=rng.randrange(len(raw)+1)
            action=rng.randrange(3)
            if action==0:raw[at:at]=bytes([rng.randrange(256)])
            elif action==1 and at<len(raw):raw[at]=rng.randrange(256)
            else:raw=raw[:at]
            rows.append(json_decode(kind,bytes(raw)))
        rows += [json_frame(3,1,word(U64_MAX,0,0,0)),json_frame(4,1,word(0,0,0,0,0,1<<32)),
                 json_frame(0,1,string(b'\xff')),json_frame(5,1,replace_word(report(),0,2))]
        self.check(rows)

    def test_16_real_timeout_missing_executable_and_setup_failure_records(self):
        start=len(self.e.processes)
        with self.assertRaises(subprocess.TimeoutExpired):
            self.e.run([sys.executable,'-c',
                'import sys,time;print("oracle-timeout-out",flush=True);print("oracle-timeout-err",file=sys.stderr,flush=True);time.sleep(10)'],
                stage='negative-real-timeout',expected_failure=True,capture_output=True,timeout=0.5)
        with self.assertRaises(FileNotFoundError):
            self.e.run([str(self.e.directory/'does-not-exist')],stage='negative-missing-executable',
                       expected_failure=True,capture_output=True,timeout=1)
        first,second=self.e.processes[start:start+2]
        self.assertEqual((self.e.directory/first['stdout']['path']).read_bytes(),b'oracle-timeout-out\n')
        self.assertEqual((self.e.directory/first['stderr']['path']).read_bytes(),b'oracle-timeout-err\n')
        self.assertEqual(first['failure_kind'],'timeout');self.assertEqual(second['failure_kind'],'os-error')
        child=self.e.directory/'setup-failure-control'
        env=dict(os.environ,HIA_ORACLE_OUTPUT=str(child),HIA_ORACLE_SETUP_PROBE='missing-executable')
        proc=self.e.run([sys.executable,'-m','unittest',__name__+'.OracleNativeTests.test_01_original_source_graph_and_retained_roster'],
            stage='negative-real-class-setup-failure',expected_failure=True,cwd=ROOT,env=env,
            capture_output=True,timeout=15,check=False)
        self.assertNotEqual(proc.returncode,0)
        observed=json.loads((child/'observations.json').read_text())
        self.assertEqual(observed['result'],'FAIL');self.assertFalse(observed['finalized'])
        self.assertEqual(observed['started_test_methods'],[])
        self.assertEqual(observed['processes'][0]['failure_kind'],'os-error')

    def test_17_changed_actual_artifact_rejected_before_native_call(self):
        original=self.e.directory/'values.so';changed=self.e.directory/'negative-changed-native.so'
        raw=bytearray(original.read_bytes());raw[-1]^=1;changed.write_bytes(raw)
        self.e.artifact(changed,'negative-deliberately-changed-native')
        module=OracleNative(changed,self.e,'negative-stale-artifact')
        module.artifact_sha256=digest(original)
        request=frame(0,string('a'))
        answer=module.call_many([(request,bytes(128),bytes(32768+10*len(request)))],
                                expected_failure=True)[0]
        self.assertEqual(answer.status,'faulted')
        self.assertIn('Changed native artifact',answer.stderr)
        self.assertIsNone(answer.arguments)


    def test_18_real_class_teardown_artifact_failure_cannot_report_pass(self):
        child=self.e.directory/'teardown-failure-control'
        script="""import pathlib,shutil,sys,unittest
from hia.tests.test_oracle import OracleNativeTests
from hia.tests.oracle_native import Evidence,ROOT
class Probe(OracleNativeTests):
 @classmethod
 def setUpClass(cls):
  cls.e=Evidence(pathlib.Path(sys.argv[1]),['test_observed'])
  cls.dependency_records=[]
  cls.addClassCleanup(cls.e.finish)
  cls.e.snapshot([ROOT/'hia/tests/test_oracle.py'])
  artifact=cls.e.directory/'observed-native.so'
  shutil.copy2(sys.argv[2],artifact)
  cls.e.artifact(artifact,'negative-class-finalization-artifact')
 def test_observed(self):
  artifact=self.e.directory/'observed-native.so'
  raw=bytearray(artifact.read_bytes());raw[-1]^=1;artifact.write_bytes(raw)
result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([Probe('test_observed')]))
sys.exit(0 if result.wasSuccessful() else 1)
"""
        proc=self.e.run([sys.executable,'-c',script,str(child),str(self.e.directory/'values.so')],
            stage='negative-real-class-teardown-failure',expected_failure=True,cwd=ROOT,
            capture_output=True,timeout=15,check=False)
        self.assertNotEqual(proc.returncode,0)
        result=json.loads((child/'observations.json').read_text())
        self.assertEqual(result['result'],'FAIL');self.assertFalse(result['finalized'])
        self.assertFalse(result['teardown_checks_passed'])
        self.assertEqual(result['started_test_methods'],['test_observed'])
        self.assertTrue(result['completed_test_methods'][0]['passed'])
        self.assertIn('Artifact changed',result['finalization_error'])

    def test_19_large_source_sorting_duplicate_first_error_and_cardinality(self):
        rows=[]
        expected_codes=[]
        for count in (512,2048,4096):
            ordered=[f's{i:05}' for i in range(count)]
            reversed_sources=ordered[::-1]
            for sources,code in ((reversed_sources,0),(['same']*count,7)):
                rows.append(frame(1,snapshot(sources=sources,sample_count=count,snapshot_hash='')))
                expected_codes.append(code)
            for sources,code in ((ordered,0),(reversed_sources,8),(['same']*count,7)):
                rows.append(validate(5,snapshot(sources=sources,sample_count=count),
                                     limits=policy(max_update_rate_per_window=count)))
                expected_codes.append(code)
            rows.append(validate(6,snapshot(sources=ordered,sample_count=count),
                                 limits=policy(max_update_rate_per_window=count)))
            expected_codes.append(0)
        for sources in ([f' S{i:05} ' for i in range(4095,-1,-1)],
                        [' SAME ']*4096,
                        (['   ','\t',' SAME ','same','\u3000Same\u3000']*820)[:4096]):
            rows.append(validate(6,snapshot(sources=sources,sample_count=len(sources)),
                                 limits=policy(min_sources=0)))
            expected_codes.append(0)
        prefix=[f's{i:05}' for i in range(4096)]
        for suffix,code in (([prefix[1],'A'],7),(['A',prefix[1]],2)):
            sources=prefix+suffix
            rows.append(validate(5,snapshot(sources=sources,sample_count=len(sources))))
            expected_codes.append(code)
            rows.append(frame(1,snapshot(sources=sources,sample_count=len(sources),snapshot_hash='')))
            expected_codes.append(2)
        answers=self.check(rows,both=True)
        for (status,payload),code in zip(answers,expected_codes*2):
            self.assertEqual(status,0)
            self.assertEqual(int.from_bytes(payload[:8],'little'),code)
        report_counts=[(i,count) for i,count in ((5,512),(11,2048),(17,4096),(18,4096),(19,1),(20,1))]
        for offset in (0,len(rows)):
            for index,count in report_counts:
                payload=answers[offset+index][1]
                self.assertEqual(int.from_bytes(payload[88:96],'little'),count)


if __name__=='__main__':
    unittest.main()
