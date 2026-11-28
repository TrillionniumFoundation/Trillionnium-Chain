"""Observe real SQLite and filesystem calls from HIA and original Rust."""
from pathlib import Path
import ctypes
import hashlib
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[4]
BUILD,ORIGINAL,WORK=Path(sys.argv[1]).absolute(),Path(sys.argv[2]).absolute(),Path(sys.argv[3]).absolute()
assert __debug__ and not WORK.exists() and ROOT not in WORK.parents
WORK.mkdir(mode=0o700);CASES=WORK/'cases';CASES.mkdir();(WORK/'blobs').mkdir()
def identity(p):
    raw=Path(p).read_bytes();return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def blob(raw):
    digest=hashlib.sha256(raw).hexdigest();p=WORK/'blobs'/digest
    if not p.exists():p.write_bytes(raw)
    assert p.read_bytes()==raw
    return {'bytes':len(raw),'sha256':digest,'path':'blobs/'+digest}
report={'schema':'trnm.hia.task-kernel.store-io-qualification.v1','status':'FAIL','finalized':False,
        'scope':'Actual original open_ro_raw/open_rw_raw, require_existing_regular_store and reject_sidecars; not full store audit',
        'native_calls':0,'original_calls':0,'fixture_preparations':0,'stages':[]}
def save():(WORK/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def frame(method,path):return b'TKIO0001'+struct.pack('<QQ',method,len(path))+path
def original(label,raw):
    data=raw.hex().encode()+b'\n';(WORK/(label+'.stdin.raw')).write_bytes(data)
    start=time.monotonic_ns();p=subprocess.run([str(ORIGINAL)],input=data,capture_output=True,cwd=CASES,timeout=30)
    (WORK/(label+'.stdout.raw')).write_bytes(p.stdout);(WORK/(label+'.stderr.raw')).write_bytes(p.stderr)
    report['stages'].append({'name':label,'argv':[str(ORIGINAL)],'cwd':str(CASES),'timeout_seconds':30,'elapsed_ns':time.monotonic_ns()-start,'exit_code':p.returncode});save()
    assert p.returncode==0 and not p.stderr
    code,out=p.stdout.strip().split(b'|',1);return int(code),bytes.fromhex(out.decode())
def inventory():
    rows=[]
    for directory,dirs,files in os.walk(os.fsencode(CASES),followlinks=False):
        for name in sorted(dirs+files):
            p=directory+b'/'+name;st=os.lstat(p)
            row={'path_hex':os.path.relpath(p,os.fsencode(CASES)).hex(),'kind':stat.S_IFMT(st.st_mode),'mode':stat.S_IMODE(st.st_mode)}
            if stat.S_ISREG(st.st_mode):
                with open(p,'rb') as stream:row['content']=blob(stream.read())
            elif stat.S_ISLNK(st.st_mode):row['target_hex']=os.readlink(p).hex()
            rows.append(row)
    return sorted(rows,key=lambda r:r['path_hex'])

try:
    build=json.loads((BUILD/'build.json').read_text());assert build['status']=='PASS' and build['finalized'] and build['source_before']==build['source_after']
    inputs=dict(build['source_before'])
    for name,expected in build['artifacts'].items():assert identity(BUILD/name)==expected;inputs[str(BUILD/name)]=expected
    for p in [Path(__file__),BUILD/'build.json',ORIGINAL]:inputs[str(p)]=identity(p)
    assert {p:identity(p) for p in inputs}==inputs
    report['source_before']=inputs;save()
    good_path=os.fsencode(CASES/'fixture-good.db')
    status,prepared=original('prepare-original-database',frame(2,good_path))
    assert status==0 and struct.unpack_from('<Q',prepared)[0]==0
    with open(good_path,'rb') as stream:good=stream.read()
    (WORK/'fixture-good-db.raw').write_bytes(good);report['fixture_preparations']=1
    os.unlink(good_path)
    library=ctypes.CDLL(str(BUILD/'store-io-native.so'))
    new=library.trnm_task_owner_new;new.argtypes=[];new.restype=ctypes.c_void_p
    invoke=library.trnm_task_owner_invoke;invoke.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint64,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(ctypes.c_uint64)];invoke.restype=ctypes.c_uint64
    free=library.trnm_task_owner_free;free.argtypes=[ctypes.c_void_p]
    release=library.trnm_task_owner_result_free;release.argtypes=[ctypes.c_void_p]
    owner=new();assert owner
    def native(raw):
        source=ctypes.create_string_buffer(raw);result=ctypes.c_void_p();size=ctypes.c_uint64()
        code=invoke(owner,source,len(raw),ctypes.byref(result),ctypes.byref(size))
        assert source.raw[:len(raw)]==raw
        data=ctypes.string_at(result,size.value) if result else b''
        if result:release(result)
        return code,data
    # Every filesystem case is reconstructed before each implementation. Both
    # implementations see the same exact path bytes and initial file contents.
    def setup(shape):
        directory=CASES/'current'
        if directory.exists():shutil.rmtree(directory)
        directory.mkdir()
        base=os.fsencode(directory);path=base+b'/data.db'
        if shape=='unicode':path=base+'/正文 😀 ?%#.db'.encode()
        if shape=='non-utf8':path=base+b'/\xff\xc0\x80.db'
        if shape in ['valid','unicode','non-utf8','symlink','dangling','wal','shm','journal','multi-sidecars','sidecar-dangling']:
            with open(path,'wb') as stream:stream.write(good)
        if shape=='corrupt':
            with open(path,'wb') as stream:stream.write(b'not a SQLite database\x00'+bytes(range(256)))
        if shape=='directory':os.mkdir(path)
        if shape=='fifo':os.mkfifo(path)
        if shape in ['symlink','dangling']:
            target=base+b'/target.db'
            if shape=='symlink':
                with open(target,'wb') as stream:stream.write(good)
            os.unlink(path);os.symlink(target,path)
        if shape=='missing-parent':path=base+b'/absent/data.db'
        if shape=='long-component':path=base+b'/'+b'x'*256
        if shape=='nul':path=base+b'/x\x00y.db'
        if shape=='memory':path=b':memory:'
        if shape=='empty':path=b''
        if shape=='relative':
            path=b'current/relative.db'
            with open(os.fsencode(CASES)+b'/'+path,'wb') as stream:stream.write(good)
        for suffix in ['wal','shm','journal']:
            if shape==suffix or shape=='multi-sidecars':
                with open(path+b'-'+suffix.encode(),'wb') as stream:stream.write(b'pending')
        if shape=='sidecar-dangling':os.symlink(base+b'/absent-sidecar',path+b'-shm')
        return path
    cases=[]
    for method in [0,1,2]:
        for shape in ['valid','missing','missing-parent','directory','corrupt','symlink','dangling','unicode','non-utf8','long-component','relative','memory','empty']:
            cases.append((f'open-{method}-{shape}',method,shape))
    for shape in ['valid','missing','missing-parent','directory','corrupt','fifo','symlink','dangling','unicode','non-utf8','long-component','nul']:
        cases.append(('regular-'+shape,3,shape))
    for shape in ['valid','missing','missing-parent','wal','shm','journal','multi-sidecars','sidecar-dangling','unicode','non-utf8','long-component','nul']:
        cases.append(('sidecars-'+shape,4,shape))
    os.chdir(CASES)
    with (WORK/'observations.jsonl').open('x') as stream:
        for index,(label,method,shape) in enumerate(cases):
            path=setup(shape);raw=frame(method,path);before=inventory()
            expected_code,expected=original(f'original-{index:03d}',raw);original_after=inventory()
            assert setup(shape)==path and inventory()==before
            row={'index':index,'name':label,'input':blob(raw),'before':before,'expected_code':expected_code,'expected_output':blob(expected),'original_after':original_after}
            (WORK/'current-call.json').write_text(json.dumps(row,indent=2)+'\n')
            start=time.monotonic_ns();code,data=native(raw);after=inventory()
            row.update(return_code=code,actual_output=blob(data),native_after=after,elapsed_ns=time.monotonic_ns()-start,equal=code==expected_code and data==expected and after==original_after)
            stream.write(json.dumps(row)+'\n');stream.flush();report['native_calls']+=1;report['original_calls']+=1;save()
            assert row['equal'],label
        for index,raw in enumerate([b'',b'TKIO0001'+struct.pack('<QQ',5,0),b'TKIO0001'+struct.pack('<QQ',0,1)]):
            expected_code,expected=original(f'original-frame-{index}',raw);code,data=native(raw)
            row={'name':f'frame-{index}','input':blob(raw),'expected_code':expected_code,'expected_output':blob(expected),'return_code':code,'actual_output':blob(data),'equal':code==expected_code and data==expected}
            stream.write(json.dumps(row)+'\n');stream.flush();report['native_calls']+=1;report['original_calls']+=1;save();assert row['equal']
        path=setup('valid');raw=frame(1,path);expected_code,expected=original('original-retry-after-frame',raw);code,data=native(raw)
        row={'name':'retry-after-frame','input':blob(raw),'expected_code':expected_code,'expected_output':blob(expected),'return_code':code,'actual_output':blob(data),'equal':code==expected_code and data==expected}
        stream.write(json.dumps(row)+'\n');stream.flush();report['native_calls']+=1;report['original_calls']+=1;assert row['equal']
    free(owner);owner=None
    report['source_after']={p:identity(p) for p in inputs};assert report['source_after']==inputs
    report.update(status='PASS',finalized=True,sqlite_provider_shared=True,full_task_kernel_owner_qualified=False,
                  source_graph_binding='The exact source and native executable identities recorded here only.')
    save()
except BaseException as error:
    report.update(status='FAIL',finalized=False,failure=repr(error));save();raise
finally:
    if 'owner' in globals() and owner:free(owner)
print(json.dumps({k:v for k,v in report.items() if k not in ['source_before','source_after','stages']}))
