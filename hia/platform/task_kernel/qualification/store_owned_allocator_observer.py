"""Exercise real HIA-owned allocations, every observed calloc failure, and drops."""
from pathlib import Path
import ctypes,hashlib,json,os,stat,struct,sys,time
from store_public_native import Native

BUILD,RECORDS,WORK=map(lambda x:Path(x).absolute(),sys.argv[1:])
ROOT=Path(__file__).resolve().parents[4]
assert __debug__ and not WORK.exists() and ROOT not in WORK.parents
WORK.mkdir(mode=0o700);(WORK/'blobs').mkdir();CASES=WORK/'cases';CASES.mkdir();DB=CASES/'lifecycle.sqlite'
report={'schema':'trnm.hia.task-kernel.allocator-owner-qualification.v1','status':'FAIL','finalized':False,'scope':'actual identical HIA objects relinked with qualification-only real-libc calloc/free observer; provider unchanged','controls':[],'full_task_kernel_owner_qualified':False}
def ident(p):
    raw=Path(p).read_bytes();return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def blob(raw):
    h=hashlib.sha256(raw).hexdigest();p=WORK/'blobs'/h
    if not p.exists():p.write_bytes(raw)
    assert p.read_bytes()==raw
    return {'bytes':len(raw),'sha256':h,'path':'blobs/'+h}
def save():(WORK/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def inventory():
    rows={}
    for path in sorted(CASES.iterdir()):
        s=path.lstat();assert stat.S_ISREG(s.st_mode)
        rows[path.name]={'mode':stat.S_IMODE(s.st_mode),'data':blob(path.read_bytes())}
    return rows
def record(name,**row):report['controls'].append({'name':name,**row});save()
try:
    built=json.loads((BUILD/'build.json').read_text());assert built['status']=='PASS' and built['finalized']
    inputs=dict(built['source_before']);assert inputs==built['source_after']
    for name,expected in built['artifacts'].items():assert ident(BUILD/name)==expected;inputs[str(BUILD/name)]=expected
    for p in [Path(__file__),Path(__file__).with_name('store_public_native.py'),BUILD/'build.json',RECORDS/'report.json',RECORDS/'observations.jsonl']:inputs[str(p)]=ident(p)
    old=json.loads((RECORDS/'report.json').read_text());assert old['status']=='PASS'
    def old_blob(row):
        p=RECORDS/row['path'];assert ident(p)=={k:row[k] for k in ['bytes','sha256']};inputs[str(p)]=ident(p);return p.read_bytes()
    bundle=old_blob(old['trust_bundle']);observations={r['name']:r for r in map(json.loads,(RECORDS/'observations.jsonl').read_text().splitlines())}
    commands=[]
    for name in ['requester-capability','requester-session','provider-capability','provider-session','task-create','bid','lease-accept','provider-accept']:
        raw=old_blob(observations['execute-full-'+name]['input']);sizes=struct.unpack_from('<5Q',raw,40);at=160;pieces=[]
        for n in sizes:pieces.append(raw[at:at+n]);at+=n
        commands.append(pieces[3])
    report['source_before']=inputs;save()
    native=Native(BUILD/'task-store-allocator-observed.so');lib=native.lib
    def counter(name):
        f=getattr(lib,'trnm_task_test_alloc_'+name);f.argtypes=[];f.restype=ctypes.c_uint64;return f()
    fail=lib.trnm_task_test_alloc_fail_after;fail.argtypes=[ctypes.c_uint64];fail.restype=None
    def stats():return {k:counter(k) for k in ['calls','frees','live','bytes','failures','bad_frees']}
    assert stats()==dict.fromkeys(['calls','frees','live','bytes','failures','bad_frees'],0)
    path=os.fsencode(DB);config=struct.pack('<2Q',len(path),len(bundle))+bytes([9])*32+path+bundle
    assert native.run(['open','store',config.hex()])=='V|1|'
    raw=native.run(['fresh','parent','store']);parent=bytes.fromhex(raw.split('|',2)[2]);height=struct.unpack_from('<Q',parent,len(parent)-178+42)[0]
    sidecar=Path(str(DB)+'-wal');sidecar.write_bytes(b'');error=native.run(['fresh','error','store']);assert error.startswith('V|255|');sidecar.unlink()
    values={slot:native.pack(p) for slot,p in native.objects.items()}
    initial=stats();assert initial['live']==3
    void=ctypes.c_void_p;u64=ctypes.c_uint64;out_type=ctypes.POINTER(void)
    config_buffer=ctypes.create_string_buffer(config);block=ctypes.create_string_buffer(bytes([222])*32)
    commands_raw=struct.pack('<Q',len(commands))+b''.join(commands);command_buffer=ctypes.create_string_buffer(commands_raw)
    descriptors=[
        ('clone',native.fn('store_clone',[void,out_type]),[native.objects['store']],1),
        ('fresh',native.fn('store_fresh_readback',[void,out_type]),[native.objects['store']],2),
        ('open-existing',native.fn('store_open_existing',[void,u64,out_type]),[config_buffer,len(config)],1),
        ('preview-complete-eight-steps',native.fn('store_preview',[void,void,u64,void,void,u64,out_type]),[native.objects['store'],native.objects['parent'],height+1,block,command_buffer,len(commands_raw)],4),
        ('error-clone',native.fn('error_clone',[void,out_type]),[native.objects['error']],255),
    ]
    for label,function,args,kind in descriptors:
        before=stats();files=inventory();out=void(0xdeadbeef);start=time.monotonic_ns();code=function(*args,ctypes.byref(out));assert code==0 and native.kind(out.value)==kind
        allocations=counter('calls')-before['calls'];observed=native.pack(out.value);native.drop(out.value)
        assert counter('live')==before['live'] and counter('bytes')==before['bytes'] and inventory()==files
        record(label+'-normal',allocations=allocations,output=blob(observed.encode()),elapsed_ns=time.monotonic_ns()-start,stats=stats())
        for ordinal in range(1,allocations+1):
            before=stats();fail(ordinal);out=void(0xdeadbeef);start=time.monotonic_ns();code=function(*args,ctypes.byref(out));fail(0)
            row={'ordinal':ordinal,'code':code,'out_null':out.value is None,'elapsed_ns':time.monotonic_ns()-start,'before':before,'after':stats(),'files':inventory()}
            record(label+'-allocation-failure',**row)
            assert code==103 and out.value is None,row
            assert row['after']['failures']==before['failures']+1 and row['after']['live']==before['live'] and row['after']['bytes']==before['bytes'] and row['after']['bad_frees']==0,row
            assert row['files']==files
            assert {slot:native.pack(p) for slot,p in native.objects.items()}==values
            retry=void();assert function(*args,ctypes.byref(retry))==0 and native.pack(retry.value)==observed
            native.drop(retry.value);assert counter('live')==before['live'] and counter('bytes')==before['bytes'] and inventory()==files
    # Wrong public types/null borrows reject before I/O, with no minted value.
    for label,function,args in [
        ('null-store-clone',native.fn('store_clone',[void,out_type]),[None]),
        ('readback-is-not-store',native.fn('store_fresh_readback',[void,out_type]),[native.objects['parent']]),
        ('error-is-not-store',native.fn('store_clone',[void,out_type]),[native.objects['error']]),
        ('store-is-not-readback',native.fn('store_preview',[void,void,u64,void,void,u64,out_type]),[native.objects['store'],native.objects['store'],height+1,block,command_buffer,len(commands_raw)]),
        ('store-is-not-error',native.fn('error_clone',[void,out_type]),[native.objects['store']]),
    ]:
        before=stats();files=inventory();out=void(0xdeadbeef);code=function(*args,ctypes.byref(out));record(label,code=code,out_null=out.value is None,before=before,after=stats());assert code==104 and out.value is None and stats()==before and inventory()==files
    for i,config_raw in enumerate([b'',bytes(47),struct.pack('<2Q',1,0)+bytes(32),struct.pack('<2Q',(1<<64)-1,0)+bytes(32),struct.pack('<2Q',0,(1<<64)-1)+bytes(32)]):
        p=ctypes.create_string_buffer(config_raw);out=void(0xdeadbeef);before=stats();code=native.fn('store_open',[void,u64,out_type])(p,len(config_raw),ctypes.byref(out));record('config-framing-'+str(i),code=code,out_null=out.value is None);assert code==104 and out.value is None and stats()==before
    before=stats();rows=native.run(['parallel','store','8','4']).split('|',1)[1].split(';');assert all(r==values['parent'] for r in rows)
    assert counter('live')==before['live'] and counter('bytes')==before['bytes'];record('concurrent-same-store-real-allocations',threads=8,calls=32,before=before,after=stats())
    native.drop(native.objects.pop('store'))
    assert native.pack(native.objects['parent'])==values['parent'] and native.pack(native.objects['error'])==values['error']
    native.close();final=stats();assert final['live']==0 and final['bytes']==0 and final['bad_frees']==0 and final['calls']==final['frees']+final['failures']
    report['source_after']={p:ident(p) for p in inputs};assert report['source_after']==inputs
    report.update(status='PASS',finalized=True,final_allocator=final,controls_count=len(report['controls']),provider_operations_unchanged=29)
    save()
except BaseException as error:
    report.update(status='FAIL',failure=repr(error));save();raise
finally:
    if 'fail' in globals():fail(0)
    if 'native' in globals():native.close()
print(json.dumps({k:v for k,v in report.items() if k not in ['source_before','source_after','controls']}))
