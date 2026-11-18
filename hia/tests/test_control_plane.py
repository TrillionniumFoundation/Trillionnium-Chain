"""Execute native HIA control-plane values against the unchanged Rust crate.

The comparison adapter only constructs original public values and calls their
public methods. Python prepares cases; the selected HIA compiler emits all
native hashing, validation and ordering operations. There is no host fallback.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'hia/src/control_plane/core.hepta'
ORIGINAL = ROOT / 'trillionnium/crates/trnm-control-plane/src/lib.rs'
ADAPTER = ROOT / 'hia/tests/control_plane_original.rs'
MAGIC = b'NCPL0001'
MASK = (1 << 64) - 1
MIN128, MAX128 = -(1 << 127), (1 << 127) - 1


def u64(*values):
    return struct.pack('<' + 'Q' * len(values), *values)


def request(op, payload):
    return MAGIC + u64(op) + payload


def digest(byte):
    return bytes([byte]) * 32


def domain_hash(domain, *parts):
    return hashlib.sha256(len(domain).to_bytes(8, 'big') + domain + b''.join(
        len(part).to_bytes(8, 'big') + part for part in parts)).digest()


def descriptor(module=4, generation=1, capabilities=None, fields=None, claimed=None):
    capabilities = [digest(5)] if capabilities is None else capabilities
    fields = [digest(i) for i in (1, 2, 3, 4, 6)] if fields is None else fields
    calculated = hashlib.sha256(b'trnm.control.module-descriptor.v0'
        + module.to_bytes(2, 'big') + generation.to_bytes(8, 'big') + b''.join(fields[:4])
        + len(capabilities).to_bytes(8, 'big') + b''.join(sorted(capabilities)) + fields[4]).digest()
    return u64(module, generation, len(capabilities)) + b''.join(fields) + (
        calculated if claimed is None else claimed) + b''.join(capabilities)


def measurement(fields=None, values=None):
    fields = [digest(1), digest(2), digest(3)] if fields is None else fields
    values = [100, 10, 20, 30, 250, 200, 300, 400, 1000, 0, 0, 50] if values is None else values
    return b''.join(fields) + u64(*values)


def action(module=4, parameter=b'ingress_queue_items', value=1024, cls=0):
    return u64(0, module, cls) + value.to_bytes(16, 'little', signed=True) + u64(len(parameter)) + parameter


def placement(module=4, profile=None, place=None):
    return u64(1, module) + (digest(20) if profile is None else profile) + (digest(21) if place is None else place)


def forbidden(kind=2):
    return u64(2, kind)


def action_digest(raw):
    kind = struct.unpack_from('<Q', raw)[0]
    if kind == 0:
        _, module, cls = struct.unpack_from('<3Q', raw)
        return domain_hash(b'trnm.control.action.set-bounded-integer.v0', module.to_bytes(2, 'big'),
                           raw[48:], raw[24:40][::-1], bytes([cls]))
    if kind == 1:
        module = struct.unpack_from('<Q', raw, 8)[0]
        return domain_hash(b'trnm.control.action.place-worker.v0', module.to_bytes(2, 'big'), raw[16:48], raw[48:80])
    return domain_hash(b'trnm.control.action.forbidden.v0', bytes([struct.unpack_from('<Q', raw, 8)[0]]))


def plan(actions=None, fields=None, generation=8, before=100, expires=200, signer=None, signature=None, claimed=None):
    actions = [action()] if actions is None else actions
    fields = [digest(i) for i in range(1, 7)] if fields is None else fields
    signer = digest(7) if signer is None else signer
    signature = digest(8) if signature is None else signature
    calculated = hashlib.sha256(b'trnm.control.optimization-plan.v1' + b''.join(fields)
        + struct.pack('>4Q', generation, before, expires, len(actions))
        + b''.join(action_digest(row) for row in actions) + signer).digest()
    return (b''.join(fields) + u64(generation, before, expires) + signer + signature
            + (calculated if claimed is None else claimed) + u64(len(actions))
            + b''.join(u64(len(row)) + row for row in actions))


def bound(module=4, parameter=b'ingress_queue_items', minimum=32, maximum=4096, cls=0):
    return (u64(module, cls) + minimum.to_bytes(16, 'little', signed=True)
            + maximum.to_bytes(16, 'little', signed=True) + u64(len(parameter)) + parameter)


def receipt(results=None, accepted=1, generation=8, fields=None, claimed=None):
    results = [(digest(12), 0, 0)] if results is None else results
    fields = [digest(i) for i in (1, 2, 3, 4)] if fields is None else fields
    calculated = hashlib.sha256(b'trnm.control.action-receipt.v1' + fields[0]
        + generation.to_bytes(8, 'big') + b''.join(fields[1:]) + bytes([accepted])
        + len(results).to_bytes(8, 'big') + b''.join(key + bytes([decision]) +
            (error.to_bytes(2, 'big') if decision else b'') for key, decision, error in results)).digest()
    raw = (fields[0] + u64(generation) + b''.join(fields[1:]) + u64(accepted, len(results))
           + (calculated if claimed is None else claimed)
           + b''.join(key + u64(decision, error) for key, decision, error in results))
    return raw, calculated


def cases():
    """Substantive protocol boundaries and independent randomized valid values."""
    rows = []
    def add(op, raw, status=0, output=None):
        if output is None:
            output = (raw[184:216] if op in (0, 1) else action_digest(raw) if op == 3
                      else raw[280:312] if op in (4, 5) else b'')
        rows.append((request(op, raw), status, output if status == 0 else b''))
    for caps in ([], [digest(5)], [digest(9), digest(1), digest(3)],
                 [digest(3), digest(9), digest(1)], [digest(0)], [digest(1)] * 2):
        raw = descriptor(capabilities=caps)
        add(0, raw)
        add(1, raw, 2 if len(set(caps)) != len(caps) else 0)
    for module, generation in itertools.product((0, 63, 64, 65535), (0, 1, MASK)):
        raw = descriptor(module=module, generation=generation)
        add(0, raw)
        add(1, raw, 1 if module >= 64 or generation == 0 else 0)
    for i in range(5):
        fields = [digest(k) for k in (1, 2, 3, 4, 6)]
        fields[i] = bytes(32)
        raw = descriptor(fields=fields)
        add(0, raw)
        add(1, raw, 1)
    for count in (255, 256, 257):
        caps = [i.to_bytes(32, 'big') for i in range(count)]
        raw = descriptor(capabilities=list(reversed(caps)))
        add(0, raw)
        add(1, raw, 1 if count > 256 else 0)
    add(1, descriptor(claimed=bytes(32)), 1)
    add(1, descriptor(capabilities=[digest(1)] * 2, claimed=bytes(32)), 1)
    add(2, measurement())
    for i in range(3):
        fields = [digest(1), digest(2), digest(3)]
        fields[i] = bytes(32)
        add(2, measurement(fields=fields), 5)
    for values, status in (([MASK]*8+[1000,MASK,MASK,MASK], 0),
                           ([0]*12, 0), ([1,30,20,30,0,0,0,0,0,0,0,0], 5),
                           ([1,10,30,20,0,0,0,0,0,0,0,0,0], 100),
                           ([1,10,30,20,0,0,0,0,0,0,0,0], 5),
                           ([0]*8+[1001,0,0,0], 5),
                           ([0]*8+[0xffffffff,0,0,0], 5),
                           ([0]*8+[0x100000000,0,0,0], 100)):
        add(2, measurement(values=values), status)
    for value in (MIN128, MIN128+1, -(1<<64), -1, 0, 1, (1<<64)-1, 1<<64, MAX128):
        for parameter in (b'', b'x', b'\x00\xff\x80', b'p'*128, b'p'*129):
            raw = action(value=value, parameter=parameter)
            add(3, raw)
            add(5, plan([raw]), 9 if len(parameter) == 0 or len(parameter) > 128 else 0)
    for module, cls in itertools.product((0, 63, 64, 65535), range(3)):
        raw = action(module=module, cls=cls)
        add(3, raw)
        add(5, plan([raw]), 9 if module >= 64 else 25 if cls else 0)
    for module in (0, 65535):
        raw = placement(module)
        add(3, raw)
        add(5, plan([raw]), 25)
    for kind in range(10):
        raw = forbidden(kind)
        add(3, raw)
        add(5, plan([raw]), 17)
    for actions, status in (([], 8), ([action(), action()], 24),
                            ([action(value=0), action(value=1)], 24),
                            ([action(parameter=b'x'), action(parameter=b'xx')], 0),
                            ([action(parameter=b'x'), action(module=5, parameter=b'x')], 0),
                            ([action(cls=1), action(cls=1)], 25),
                            ([placement(), placement()], 25),
                            ([forbidden(), forbidden()], 17)):
        raw = plan(actions)
        add(4, raw)
        add(5, raw, status)
    for count in (127, 128, 129):
        raw = plan([action(parameter=b'p'+i.to_bytes(2,'big')) for i in range(count)])
        add(4, raw)
        add(5, raw, 8 if count > 128 else 0)
    for i in range(6):
        fields = [digest(i) for i in range(1,7)]
        fields[i] = bytes(32)
        add(5, plan(fields=fields), 8)
    for kwargs in ({'generation':0}, {'before':0}, {'expires':99}, {'signer':bytes(32)},
                   {'signature':bytes(32)}, {'claimed':bytes(32)}):
        add(5, plan(**kwargs), 8)
    add(5, plan([forbidden()], claimed=bytes(32)), 8)
    add(5, plan([action()], generation=MASK, before=MASK, expires=MASK))
    for minimum, maximum in itertools.product((MIN128, -(1<<64), -1, 0, 1, 1<<64, MAX128), repeat=2):
        add(6, bound(minimum=minimum, maximum=maximum), 10 if minimum > maximum else 0)
    for parameter, cls, module in ((b'',0,4),(b'\x00\xff\x80',0,4),(b'x'*128,0,63),(b'x'*129,0,4),
                                  (b'x',1,4),(b'x',2,4),(b'x',0,64),(b'x',0,65535)):
        add(6,bound(parameter=parameter,cls=cls,module=module),10 if not 0<len(parameter)<=128 or cls or module>=64 else 0)
    for error in range(1,27):
        raw, hashed = receipt([(digest(12),1,error)], accepted=0, generation=MASK)
        add(7, raw, output=hashed)
    for count in (0, 1, 128, 129, 1024):
        raw, hashed = receipt([(i.to_bytes(32,'big'),i%2,(i%26)+1 if i%2 else 0) for i in range(count)])
        add(7,raw,output=hashed)
    rng = random.Random(0xC091A6)
    for _ in range(64):
        fields=[rng.randbytes(32) for _ in range(5)]
        raw=descriptor(module=rng.randrange(64), generation=rng.randrange(1,1<<64),fields=fields,
                       capabilities=[rng.randbytes(32) for _ in range(rng.randrange(12))])
        add(1,raw)
        raw=action(module=rng.randrange(64), parameter=rng.randbytes(rng.randrange(1,129)),
                   value=rng.randrange(MIN128,MAX128+1))
        add(3,raw)
        add(5,plan([raw]))
    return rows


def registry_request(commands):
    return b'NCPR0001'+u64(len(commands))+b''.join(u64(op,len(body))+body for op,body in commands)


def registry_decode(raw):
    size,count=struct.unpack_from('<2Q',raw)
    if size!=len(raw):
        raise AssertionError('registry output extent')
    position=16;rows=[]
    for _ in range(count):
        status,extent=struct.unpack_from('<2Q',raw,position);position+=16
        rows.append((status,raw[position:position+extent]));position+=extent
    if position!=len(raw):
        raise AssertionError('registry output trailing data')
    return rows


def build_original(directory):
    """Build the entire original source and its retained tests, never a copy model."""
    directory = Path(directory)
    before = hashlib.sha256(ORIGINAL.read_bytes()).hexdigest()
    rlib, original, tests = [directory / name for name in ('libtrnm_control_plane.rlib', 'original', 'original-tests')]
    dependency = os.environ.get('HIA_CONTROL_PLANE_SHA2')
    if dependency:
        dependency = Path(dependency).resolve(strict=True)
        deps = dependency.parent
        commands = [
            ['rustc','--edition=2021','--crate-type=rlib','--crate-name','trnm_control_plane','-O',str(ORIGINAL),
             '-L','dependency='+str(deps),'--extern','sha2='+str(dependency),'-o',str(rlib)],
            ['rustc','--edition=2021','--test',str(ORIGINAL),'-L','dependency='+str(deps),
             '--extern','sha2='+str(dependency),'-o',str(tests)],
        ]
    else:
        project = directory / 'original-crate'
        project.mkdir()
        manifest = '[package]\nname="trnm-control-plane"\nversion="0.1.0"\nedition="2021"\n[workspace]\n[lib]\npath='+json.dumps(str(ORIGINAL))+'\n[dependencies]\nsha2="=0.10.9"\n'
        (project/'Cargo.toml').write_text(manifest)
        commands = [['cargo','build','--manifest-path',str(project/'Cargo.toml')],
                    ['cargo','test','--manifest-path',str(project/'Cargo.toml'),'--','--test-threads=1']]
        deps = project/'target/debug/deps'
    logs = []
    for command in commands:
        result = subprocess.run(command,capture_output=True,text=True,timeout=180,check=False)
        logs.append({'command':command,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        if result.returncode:
            (directory/'build-log.json').write_text(json.dumps(logs,indent=2))
            raise AssertionError(result.stdout+result.stderr)
    if not dependency:
        rlib = next(deps.glob('libtrnm_control_plane-*.rlib'))
    for command in ([['rustc','--edition=2021','-O',str(ADAPTER),'-L','dependency='+str(deps),
                      '--extern','trnm_control_plane='+str(rlib),'-o',str(original)]]
                    + ([[str(tests),'--test-threads=1']] if dependency else [])):
        result = subprocess.run(command,capture_output=True,text=True,timeout=180,check=False)
        logs.append({'command':command,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        if result.returncode:
            (directory/'build-log.json').write_text(json.dumps(logs,indent=2))
            raise AssertionError(result.stdout+result.stderr)
    if hashlib.sha256(ORIGINAL.read_bytes()).hexdigest()!=before:
        raise AssertionError('Original source changed during its build')
    record={'original_sha256':before,'adapter_sha256':hashlib.sha256(ADAPTER.read_bytes()).hexdigest(),
            'executable_sha256':hashlib.sha256(original.read_bytes()).hexdigest(),'commands':logs}
    (directory/'build-log.json').write_text(json.dumps(record,indent=2))
    return original


def completed_test_result(case, result):
    """Inspect the finalized unittest result, including attached failed subtests."""
    categories=('failures','errors','skipped','expectedFailures','unexpectedSuccesses')
    counts={}
    for name in categories:
        items=getattr(result,name,None)
        if items is None:
            return {'passed':False,'result_contract_missing':name}
        count=0
        for item in items:
            candidate=item[0] if isinstance(item,tuple) else item
            if candidate is case or getattr(candidate,'test_case',None) is case:
                count+=1
        counts[name]=count
    return {'passed':all(value==0 for value in counts.values()),'unittest_outcomes':counts}


class ControlPlaneNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='trnm-control-plane-original-')
        destination = os.environ.get('HIA_CONTROL_PLANE_OUTPUT')
        cls.directory = Path(destination) if destination else Path(cls.temporary.name)/'evidence'
        cls.directory.mkdir(parents=True,exist_ok=False)
        (cls.directory/'blobs').mkdir()
        cls.expected_roster=unittest.defaultTestLoader.getTestCaseNames(cls)
        cls.started=[];cls.completed=[];cls.evidence=[];cls.native_observations=[];cls.oracle_observations=[]
        cls.call_count=0;cls.case_count=0;cls.current_test='setUpClass'
        cls.source_paths=['hia/src/control_plane/core.hepta','hia/src/control_plane/registry.hepta',
            'hia/src/crypto/sha256_stream.hepta','hia/components.json','hia/toolchain.lock.json',
            'hia/tools/toolchain.py','hia/tests/native_support.py','hia/tests/test_control_plane.py',
            'hia/tests/control_plane_original.rs','hia/tests/control_plane_alloc.c',
            'trillionnium/crates/trnm-control-plane/src/lib.rs']
        cls.source_before={path:hashlib.sha256((ROOT/path).read_bytes()).hexdigest() for path in cls.source_paths}
        (cls.directory/'run-start.json').write_text(json.dumps({'schema':'trnm.hia.control-plane.run-start.v1',
            'expected_test_methods':cls.expected_roster,'source_before':cls.source_before,'finalized':False},indent=2))
        cls.native = NativeModule(SOURCE, byte_exports=('f0',))
        cls.registry = NativeModule(ROOT/'hia/src/control_plane/registry.hepta', byte_exports=('f0',))
        for name,module in [('core',cls.native),('registry',cls.registry)]:
            original_call_many=module.call_many
            def captured(cases, *, timeout=30, selected=original_call_many, label=name):
                cases=list(cases)
                observed=selected(cases,timeout=timeout)
                for (function,arguments),value in zip(cases,observed):
                    row={'module':label,'test':cls.current_test,'function':function,'timeout':timeout,
                         'arguments':cls.capture_arguments(arguments),'status':value.status,
                         'returncode':value.returncode,'abi_status':value.abi_status,'value':value.value,
                         'observed_arguments':cls.capture_arguments(value.arguments),
                         'stderr':cls.capture_blob(value.stderr.encode())}
                    cls.native_observations.append(row);cls.call_count+=1
                return observed
            module.call_many=captured
        cls.original = build_original(cls.temporary.name)


    @classmethod
    def capture_blob(cls, raw):
        key=hashlib.sha256(raw).hexdigest()
        path=cls.directory/'blobs'/key
        if not path.exists():
            with path.open('xb') as stream:stream.write(raw)
        elif path.read_bytes()!=raw:
            raise AssertionError('Blob identity collision')
        return {'path':'blobs/'+key,'size':len(raw),'sha256':key}

    @classmethod
    def capture_arguments(cls, arguments):
        if arguments is None:return None
        return [cls.capture_blob(bytes(arg)) if isinstance(arg,(bytes,bytearray)) else arg for arg in arguments]

    def setUp(self):
        type(self).current_test=self._testMethodName
        type(self).started.append(self._testMethodName)

    def run(self, result=None):
        result=self.defaultTestResult() if result is None else result
        returned=super().run(result)
        type(self).completed.append({'method':self._testMethodName,**completed_test_result(self,result)})
        return returned

    @classmethod
    def tearDownClass(cls):
        directory=cls.directory
        shutil.copy2(cls.native.library,directory/'native.so')
        shutil.copy2(cls.registry.library,directory/'registry.so')
        shutil.copy2(cls.original,directory/'original')
        tests=Path(cls.temporary.name)/'original-tests'
        if tests.is_file():shutil.copy2(tests,directory/'original-tests')
        else:
            executable=[p for p in (Path(cls.temporary.name)/'original-crate/target/debug/deps').glob('trnm_control_plane-*')
                        if p.is_file() and p.suffix=='' and os.access(p,os.X_OK)]
            if len(executable)!=1:raise AssertionError('Original retained test executable is not unique')
            shutil.copy2(executable[0],directory/'original-tests')
        shutil.copy2(Path(cls.temporary.name)/'build-log.json',directory/'original-build.json')
        (directory/'native-build.json').write_text(json.dumps(cls.native.receipt,indent=2))
        (directory/'registry-build.json').write_text(json.dumps(cls.registry.receipt,indent=2))
        from hia.tools.toolchain import checked_source
        for name,module in [('core',cls.native),('registry',cls.registry)]:
            (directory/(name+'-composed.hepta')).write_bytes(checked_source(module.source)[1])
        paths=cls.source_paths
        sources=[]
        for path in paths:
            raw=(ROOT/path).read_bytes();sources.append({'path':path,**cls.capture_blob(raw)})
            sources[-1]['source_path']=path
            sources[-1]['before_sha256']=cls.source_before[path]
            if sources[-1]['sha256']!=cls.source_before[path]:
                raise AssertionError('Source changed during native/original execution: '+path)
        finalized=(cls.started==cls.expected_roster and len(cls.completed)==len(cls.expected_roster)
                   and [x['method'] for x in cls.completed]==cls.expected_roster)
        report={'schema':'trnm.hia.control-plane.development.v1','expected_test_methods':cls.expected_roster,
                'started_test_methods':cls.started,'completed_test_methods':cls.completed,'finalized':finalized,
                'result':'PASS' if finalized and all(x['passed'] for x in cls.completed) else 'FAIL',
                'native_calls':cls.call_count,'original_comparisons':cls.case_count,'cases':cls.evidence,
                'native_observations':cls.native_observations,'oracle_processes':cls.oracle_observations,
                'source_inputs':sources,'whole_package_retired':False,'signature_provider_implemented':False,
                'node_integration_complete':False}
        (directory/'observations.json').write_text(json.dumps(report,indent=2))
        cls.native.close();cls.registry.close();cls.temporary.cleanup()

    def original_results(self, rows):
        wire=''.join(raw.hex()+'\n' for raw,_,_ in rows)
        result=subprocess.run([str(self.original)],input=wire,text=True,capture_output=True,timeout=60,check=False)
        type(self).oracle_observations.append({'test':self._testMethodName,'stdin':self.capture_blob(wire.encode()),
            'stdout':self.capture_blob(result.stdout.encode()),'stderr':self.capture_blob(result.stderr.encode()),
            'returncode':result.returncode,'executable_sha256':hashlib.sha256(self.original.read_bytes()).hexdigest()})
        self.assertEqual(result.returncode,0,result.stderr)
        out=[]
        for line in result.stdout.splitlines():
            status,data=line.split(' ',1)
            out.append((int(status),b'' if data=='-' else bytes.fromhex(data)))
        self.assertEqual(len(out),len(rows))
        return out

    def check(self, rows, *, compare_original=True):
        rows=list(rows)
        if compare_original:
            original=self.original_results(rows)
            self.assertEqual(original,[(status,out) for _,status,out in rows])
        for start in range(0,len(rows),12):
            batch=rows[start:start+12]
            inputs=[('f0',[raw,b'\xa5'*45,b'\x6d'*(65536+len(raw)*3+13)]) for raw,_,_ in batch]
            observed=self.native.call_many(inputs)
            for (raw,status,expected),got in zip(batch,observed):
                got.require_returned()
                self.assertEqual(got.value,status,raw.hex()[:400])
                self.assertEqual(got.arguments[0],raw)
                self.assertEqual(got.arguments[1],expected+b'\xa5'*(45-len(expected)) if status==0 else b'\xa5'*45)
                self.assertEqual(got.arguments[2][-13:],b'\x6d'*13)
                type(self).case_count+=int(compare_original)
                type(self).evidence.append({'input':raw.hex(),'status':status,'output':expected.hex(),
                                           'original_compared':compare_original,'module':'core','native_status':got.value,
                                           'native_output':got.arguments[1][:len(expected)].hex()})

    def test_complete_public_value_semantics_against_original(self):
        self.check(cases())

    def test_all_descriptor_and_plan_digest_bits_are_binding(self):
        rows=[]
        for op,raw,offset,error in ((1,descriptor(),184,1),(5,plan(),280,8)):
            for bit in range(256):
                changed=bytearray(raw)
                changed[offset+bit//8]^=1<<(bit%8)
                rows.append((request(op,changed),error,b''))
        self.check(rows)

    def test_malformed_typed_frames_never_publish(self):
        raws=[request(1,descriptor()),request(2,measurement()),request(3,action()),request(3,placement()),
              request(3,forbidden()),request(5,plan()),request(6,bound()),request(7,receipt()[0])]
        rows=[]
        for raw in raws:
            for size in range(len(raw)):
                rows.append((raw[:size],100,b''))
            rows.append((raw+b'\0',100,b''))
            changed=bytearray(raw);changed[0]^=128;rows.append((bytes(changed),100,b''))
        self.check(rows)

    def test_typed_scalar_and_extent_overflow_refusals(self):
        rows=[]
        specs=[(0,descriptor(),[0,16]),(3,action(),[0,8,16,40]),(3,placement(),[0,8]),
               (3,forbidden(),[0,8]),(4,plan(),[312,320]),(6,bound(),[0,8,48]),
               (7,receipt()[0],[136,144,184+32,184+40])]
        for op,payload,offsets in specs:
            for offset in offsets:
                for value in (MASK,1<<63):
                    changed=bytearray(payload);struct.pack_into('<Q',changed,offset,value)
                    rows.append((request(op,changed),100,b''))
        self.check(rows)

    def test_output_and_workspace_capacity_are_explicit(self):
        raw=request(1,descriptor())
        for output,workspace,error in ((31,65536+len(raw)*3,101),(32,65536+len(raw)*3-1,102)):
            before=[raw,b'\xa5'*output,b'\x6d'*workspace]
            got=self.native.call('f0',before).require_returned()
            self.assertEqual(got.value,error)
            self.assertEqual(got.arguments,before)

    def test_canonical_methods_keep_original_unvalidated_vector_domains(self):
        # The original digest methods hash values beyond validate() limits.
        caps=[i.to_bytes(32,'big') for i in range(5000)]
        desc=descriptor(capabilities=caps)
        actions=[forbidden(i%10) for i in range(180)]
        raw=plan(actions)
        rec,hashed=receipt([(digest(i%255),1,1+i%26) for i in range(5000)])
        self.check([(request(0,desc),0,desc[184:216]),(request(1,desc),1,b''),
                    (request(4,raw),0,raw[280:312]),(request(5,raw),8,b''),
                    (request(7,rec),0,hashed)])

    def test_signature_digest_is_not_part_of_original_plan_canonical_digest(self):
        one=plan(signature=digest(8));two=plan(signature=digest(9))
        self.assertEqual(one[280:312],two[280:312])
        self.check([(request(op,raw),0,raw[280:312]) for op in (4,5) for raw in (one,two)])

    def test_descriptor_canonical_sort_preserves_original_input_order(self):
        caps=[digest(9),digest(1),digest(3)]
        one=descriptor(capabilities=caps);two=descriptor(capabilities=list(reversed(caps)))
        self.assertEqual(one[184:216],two[184:216])
        self.assertNotEqual(one,two)
        self.check([(request(op,raw),0,raw[184:216]) for op in (0,1) for raw in (one,two)])

    def check_registry(self, raws):
        rows=[(raw,0,b'') for raw in raws]
        original=self.original_results(rows)
        results=[]
        for raw,(status,expected) in zip(raws,original):
            capacity=max(45,len(expected)+13)
            got=self.registry.call('f0',[raw,b'\xa5'*capacity,b'\x6d'*(65536+len(raw)*3+13)]).require_returned()
            self.assertEqual(got.value,status)
            self.assertEqual(got.arguments[0],raw)
            self.assertEqual(got.arguments[1],expected+b'\xa5'*(capacity-len(expected)) if status==0 else b'\xa5'*capacity)
            self.assertEqual(got.arguments[2][-13:],b'\x6d'*13)
            type(self).case_count+=1
            type(self).evidence.append({'module':'registry','input':raw.hex(),'status':status,'output':expected.hex(),
                'original_compared':True,'native_status':got.value,'native_output':got.arguments[1][:len(expected)].hex()})
            results.append((status,expected))
        return results

    def test_generic_hash_frames_all_domain_and_part_boundaries(self):
        rows=[]
        for domain,parts in ((b'',[]),(b'',[b'']),(b'a',[b'bc']),(b'ab',[b'c']),
                             (b'\0\xff',[b'a',b'',b'\0\xff']),
                             (bytes(range(256)),[bytes(range(256))*1024,b'x'])):
            payload=u64(len(domain),len(parts))+domain+b''.join(u64(len(p))+p for p in parts)
            rows.append((request(8,payload),0,domain_hash(domain,*parts)))
        self.check(rows)
        raw=rows[-1][0]
        self.check([(raw[:-1],100,b''),(raw+b'x',100,b''),
                    (request(8,u64(MASK,0)),100,b''),(request(8,u64(0,MASK)),100,b'')])

    def test_registry_generation_equality_and_retained_measurements(self):
        first=descriptor(generation=2,capabilities=[digest(9),digest(1)])
        reordered=descriptor(generation=2,capabilities=[digest(1),digest(9)])
        later=descriptor(generation=3,capabilities=[digest(1),digest(9)])
        measure=measurement();changed=bytearray(measure);changed[-1]^=1
        invalid=measurement(fields=[bytes(32),digest(2),digest(3)])
        commands=[(2,u64(4)),(1,u64(4)+invalid),(0,first),(1,u64(4)+measure),(0,first),
                  (0,reordered),(2,u64(4)),(0,descriptor(generation=1)),(0,later),
                  (1,u64(4)+measure),(1,u64(4)+changed),(1,u64(4)+invalid),
                  (2,u64(4)),(0,descriptor(generation=MASK)),(0,later),(2,u64(4))]
        status,out=self.check_registry([registry_request(commands)])[0]
        self.assertEqual(status,0)
        decoded=registry_decode(out)
        self.assertEqual([s for s,_ in decoded],[0,6,0,0,0,4,0,3,0,0,7,5,0,0,3,0])
        self.assertEqual(decoded[6][1],first)
        self.assertEqual(decoded[12][1],later)
        self.assertEqual(decoded[15][1],descriptor(generation=MASK))

    def test_registry_all_modules_and_rejection_atomicity(self):
        commands=[]
        for module in range(64):
            commands.extend([(0,descriptor(module=module)),(1,u64(module)+measurement()),
                             (0,descriptor(module=module,claimed=bytes(32))),
                             (2,u64(module)),(1,u64(module)+measurement())])
        commands.extend([(2,u64(64)),(2,u64(65535)),(1,u64(65535)+measurement())])
        _,out=self.check_registry([registry_request(commands)])[0]
        rows=registry_decode(out)
        for module in range(64):
            self.assertEqual([x[0] for x in rows[module*5:module*5+5]],[0,0,1,0,0])
            self.assertEqual(rows[module*5+3][1],descriptor(module=module))
        self.assertEqual(rows[-3:],[(0,b''),(0,b''),(6,b'')])

    def test_registry_deterministic_mixed_histories_match_original(self):
        rng=random.Random(0xC091C)
        raws=[]
        for _ in range(12):
            commands=[]
            for index in range(100):
                module=rng.randrange(8);op=rng.randrange(3)
                if op==0:
                    payload=descriptor(module=module,generation=rng.randrange(1,6),
                                       capabilities=[digest(rng.randrange(5)) for _ in range(rng.randrange(5))])
                elif op==1:
                    values=[index,10,20,30,0,0,0,0,0,0,0,0]
                    payload=u64(module)+measurement(fields=[digest(rng.randrange(4)),digest(2),digest(3)],values=values)
                else:payload=u64(module)
                commands.append((op,payload))
            raws.append(registry_request(commands))
        self.check_registry(raws)

    def test_registry_transport_and_output_failures_publish_nothing(self):
        good=registry_request([(0,descriptor()),(2,u64(4)),(1,u64(4)+measurement())])
        malformed=[good[:-1],good+b'x',registry_request([(0,descriptor()),(7,b'')]),
                   registry_request([(0,descriptor()),(2,u64(MASK))]),
                   b'NCPR0001'+u64(MASK),b'NCPR0001'+u64(0)+b'x']
        self.check_registry(malformed)
        expected=self.original_results([(good,0,b'')])[0][1]
        for capacity in (0,15,16,len(expected)-1):
            output=b'\xa5'*capacity
            got=self.registry.call('f0',[good,output,bytes(65536+len(good)*3)]).require_returned()
            self.assertEqual(got.value,101)
            self.assertEqual(got.arguments[1],output)
        self.check_registry([good,registry_request([])])

    def test_reporter_refuses_actual_failure_error_skip_and_subtest(self):
        class Probe(unittest.TestCase):
            def test_pass(self):pass
            def test_fail(self):self.fail('intentional reporter negative control')
            def test_error(self):raise RuntimeError('intentional reporter negative control')
            def test_skip(self):self.skipTest('intentional reporter negative control')
            @unittest.expectedFailure
            def test_expected_failure(self):self.fail('intentional reporter negative control')
            @unittest.expectedFailure
            def test_unexpected_success(self):pass
            def test_subtest(self):
                with self.subTest('intentional reporter negative control'):
                    self.fail('actual failed subtest')
        observations=[]
        for name in unittest.defaultTestLoader.getTestCaseNames(Probe):
            case=Probe(name);result=unittest.TestResult();case.run(result)
            observed=completed_test_result(case,result)
            observations.append({'method':name,**observed})
            self.assertEqual(observed['passed'],name=='test_pass')
        type(self).evidence.append({'reporter_controls':observations})

    def test_registry_private_allocations_cleanup_on_every_oom(self):
        directory=self.directory/'allocator-observer'
        directory.mkdir(exist_ok=False)
        observer=directory/'alloc-observer'
        source=directory/'control_plane_alloc.c'
        source.write_bytes((ROOT/'hia/tests/control_plane_alloc.c').read_bytes())
        command=['cc','-O2','-Wall','-Wextra','-Werror','-Wl,--export-dynamic',
                 str(source),'-ldl','-o',str(observer)]
        result=subprocess.run(command,capture_output=True,text=True,timeout=30,check=False)
        (directory/'build.stdout').write_text(result.stdout)
        (directory/'build.stderr').write_text(result.stderr)
        (directory/'build.json').write_text(json.dumps({'command':command,'returncode':result.returncode,
            'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
            'executable_sha256':hashlib.sha256(observer.read_bytes()).hexdigest() if observer.is_file() else None},indent=2))
        self.assertEqual(result.returncode,0,result.stderr)
        raw=registry_request([(0,descriptor()),(2,u64(4)),(1,u64(4)+measurement())])
        expected=self.original_results([(raw,0,b'')])[0][1]
        cases=[(raw,len(expected)+13,fail,103 if fail in (1,2,3) else 0) for fail in range(5)]
        cases.extend([(raw,len(expected)-1,0,101),(raw+b'x',100,0,100)])
        for index,(data,capacity,fail,status) in enumerate(cases):
            source=directory/('alloc-input-'+str(index));source.write_bytes(data)
            command=[str(observer),str(self.registry.library),str(source),str(capacity),str(fail)]
            result=subprocess.run(command,capture_output=True,timeout=30,check=False)
            (directory/('case-'+str(index)+'.stdout')).write_bytes(result.stdout)
            (directory/('case-'+str(index)+'.stderr')).write_bytes(result.stderr)
            (directory/('case-'+str(index)+'.json')).write_text(json.dumps({'command':command,
                'returncode':result.returncode,'executable_sha256':hashlib.sha256(observer.read_bytes()).hexdigest(),
                'native_artifact_sha256':self.registry.artifact_sha256,
                'input_sha256':hashlib.sha256(data).hexdigest()},indent=2))
            type(self).native_observations.append({'module':'registry','test':self._testMethodName,'allocation_observer':True,
                'input':self.capture_blob(data),'output_capacity':capacity,'fail_at':fail,
                'observer_executable':self.capture_blob(observer.read_bytes()),
                'returncode':result.returncode,'stdout':self.capture_blob(result.stdout),'stderr':self.capture_blob(result.stderr)})
            type(self).call_count+=1
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(len(result.stdout),32+capacity)
            actual,calls,denied,live=struct.unpack('<4Q',result.stdout[:32])
            self.assertEqual(actual,status)
            self.assertEqual(calls,0 if status==100 else fail if status==103 else 3)
            self.assertEqual(denied,int(status==103));self.assertEqual(live,0)
            wanted=expected+b'\xa5'*13 if status==0 else b'\xa5'*capacity
            self.assertEqual(result.stdout[32:],wanted)
            type(self).evidence.append({'module':'registry','allocation_control':True,
                'input':data.hex(),'output_capacity':capacity,'fail_at':fail,'native_status':actual,
                'allocation_calls':calls,'denied':denied,'live':live,'stdout':result.stdout.hex()})


if __name__=='__main__':
    unittest.main()
