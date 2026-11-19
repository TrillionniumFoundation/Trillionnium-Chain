"""Actual public opaque-owner API versus unchanged Rust public methods/getters."""
from pathlib import Path
import concurrent.futures,ctypes,hashlib,json,os,select,sqlite3,stat,struct,subprocess,sys,threading,time

ROOT=Path(__file__).resolve().parents[4]
BUILD,ORIGINAL,RECORDS,WORK=map(lambda s:Path(s).absolute(),sys.argv[1:])
assert __debug__ and not WORK.exists() and ROOT not in WORK.parents
WORK.mkdir(mode=0o700);(WORK/'blobs').mkdir();CASES=WORK/'cases';CASES.mkdir();DB=CASES/'public.sqlite'
report={'schema':'trnm.hia.task-kernel.public-owner-qualification.v1','status':'FAIL','finalized':False,'native_method_calls':0,'original_method_calls':0,'native_getter_calls':0,'full_task_kernel_owner_qualified':False,'scope':'public TaskStore/config copy/Clone, opaque observations, full execute/preview/empty/confirm/state methods and public getters; separate allocator and complete retained test gates still required'}
def identity(path):
    b=Path(path).read_bytes();return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def blob(raw):
    sha=hashlib.sha256(raw).hexdigest();p=WORK/'blobs'/sha
    if not p.exists():p.write_bytes(raw)
    assert p.read_bytes()==raw
    return {'bytes':len(raw),'sha256':sha,'path':'blobs/'+sha}
def save():(WORK/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def inventory():
    result={}
    def walk(parent):
        for path in sorted(parent.iterdir()):
            st=path.lstat();row={'mode':stat.S_IMODE(st.st_mode)}
            if stat.S_ISLNK(st.st_mode):row.update(kind='symlink',target=os.readlink(path))
            elif stat.S_ISREG(st.st_mode):row.update(kind='file',content=blob(path.read_bytes()))
            elif stat.S_ISDIR(st.st_mode):row.update(kind='directory')
            else:raise AssertionError('Unexpected filesystem object')
            result[path.relative_to(CASES).as_posix()]=row
            if row['kind']=='directory':walk(path)
    walk(CASES);return result
def restore(rows):
    def remove(parent):
        for path in parent.iterdir():
            if path.is_dir() and not path.is_symlink():remove(path);path.rmdir()
            else:path.unlink()
    remove(CASES)
    for name,row in rows.items():
        p=CASES/name
        if row['kind']=='directory':p.mkdir();p.chmod(row['mode'])
        elif row['kind']=='symlink':p.symlink_to(row['target'])
        else:p.write_bytes((WORK/row['content']['path']).read_bytes());p.chmod(row['mode'])

from store_public_native import Native,STATE_NAMES

try:
    build=json.loads((BUILD/'build.json').read_text());assert build['status']=='PASS' and build['finalized']
    inputs=dict(build['source_before']);assert inputs==build['source_after']
    for path,expected in build['artifacts'].items():assert identity(BUILD/path)==expected;inputs[str(BUILD/path)]=expected
    for p in [Path(__file__),BUILD/'build.json',ORIGINAL,RECORDS/'report.json',RECORDS/'observations.jsonl']:inputs[str(p)]=identity(p)
    old=json.loads((RECORDS/'report.json').read_text());assert old['status']=='PASS' and old['finalized']
    report['fixture_provenance']={'report':identity(RECORDS/'report.json'),'observations':identity(RECORDS/'observations.jsonl'),'native_calls':old['native_calls'],'original_calls':old['original_calls'],'qualification_is_not_reused':True}
    def old_blob(row):
        p=RECORDS/row['path'];assert identity(p)=={k:row[k] for k in ['bytes','sha256']};inputs[str(p)]=identity(p);return p.read_bytes()
    bundle=old_blob(old['trust_bundle']);baseline=old_blob(old['baseline_database'])
    observations={row['name']:row for row in map(json.loads,(RECORDS/'observations.jsonl').read_text().splitlines())}
    def old_frame(name):
        raw=old_blob(observations[name]['input']);sizes=struct.unpack_from('<5Q',raw,40);at=160;values=[]
        for n in sizes:values.append(raw[at:at+n]);at+=n
        assert at==len(raw);return raw,values
    labels=['requester-capability','requester-session','provider-capability','provider-session','task-create','bid','lease-accept','provider-accept']
    flow=[old_frame('execute-full-'+name)[1] for name in labels];execution=flow[0][2];commands=[x[3] for x in flow]
    successor=old_frame('empty-after-full-direct-successor')[1][2]
    report['source_before']=inputs;save()
    native=Native(BUILD/'task-store-native.so')
    original_input=(WORK/'original.stdin.raw').open('xb');original_output=(WORK/'original.stdout.raw').open('xb');original_error=(WORK/'original.stderr.raw').open('xb')
    original_process=subprocess.Popen([str(ORIGINAL)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=original_error,cwd=CASES)
    def original(parts):
        data=('|'.join(parts)+'\n').encode();original_input.write(data);original_input.flush();original_process.stdin.write(data);original_process.stdin.flush()
        assert select.select([original_process.stdout],[],[],30)[0],'Original method timed out'
        raw=original_process.stdout.readline();original_output.write(raw);original_output.flush();assert raw.endswith(b'\n'),raw
        return raw.decode().strip()
    log=(WORK/'observations.jsonl').open('x');serial=0
    def call(*parts):
        global serial
        parts=list(map(str,parts));before=inventory();expected=original(parts);expected_after=inventory();restore(before)
        row={'index':serial,'action':parts[0],'input':blob(('|'.join(parts)+'\n').encode()),'expected':blob(expected.encode()),'before':before,'expected_after':expected_after}
        (WORK/'current-call.json').write_text(json.dumps(row,indent=2)+'\n');started=time.monotonic_ns();actual=native.run(parts);after=inventory()
        row.update(actual=blob(actual.encode()),native_after=after,elapsed_ns=time.monotonic_ns()-started,equal=actual==expected and after==expected_after)
        log.write(json.dumps(row)+'\n');log.flush();serial+=1;report.update(native_method_calls=serial,original_method_calls=serial,native_getter_calls=native.getters);save()
        assert row['equal'],(parts[0:3],actual,expected)
        return actual
    def cfg(path=DB,trust=bundle,store_id=bytes([9])*32):
        path=os.fsencode(path);return (struct.pack('<2Q',len(path),len(trust))+store_id+path+trust).hex()
    def vec(values):return (struct.pack('<Q',len(values))+b''.join(values)).hex()
    def data(value):return bytes.fromhex(value.split('|',2)[2])
    call('open','s0',cfg());assert DB.read_bytes()==baseline
    call('clone','s1','s0');call('fresh','r0','s0');call('existing','s2',cfg());call('fresh','r1','s2');assert call('equal','r0','r1')=='S|1'
    parent=data(call('observe','r0'));context=len(parent)-178;height=struct.unpack_from('<Q',parent,context+42)[0]
    block=bytes([222])*32
    call('preview','cross-store-empty','s1','r1',height+1,block.hex(),vec([]))
    call('parallel','s1',8,3)
    call('drop','s0');call('observe','r0');call('fresh','r2','s1');assert call('equal','r0','r2')=='S|1'
    # Clone is an immutable config copy, with no filesystem access or trust revalidation.
    sidecar=Path(str(DB)+'-wal');sidecar.write_bytes(b'')
    call('clone','cloned-with-sidecar','s1');call('fresh','sidecar-error','cloned-with-sidecar');sidecar.unlink()
    call('error_clone','sidecar-error-copy','sidecar-error');call('drop','sidecar-error');call('observe','sidecar-error-copy')
    call('drop','cloned-with-sidecar')
    receipts=[]
    for i,(label,command) in enumerate(zip(labels,commands)):
        call('fresh','parent'+str(i),'s2')
        call('preview','suffix'+str(i),'s1','parent'+str(i),height+1,block.hex(),vec(commands[i:]))
        call('preview','duplicate'+str(i),'s1','parent'+str(i),height+1,block.hex(),vec([command,command]))
        bad=command[:-1]+bytes([command[-1]^1])
        call('preview','bad-signature'+str(i),'s1','parent'+str(i),height+1,block.hex(),vec([command,bad]))
        applied=call('execute','outcome'+str(i),'s1',execution.hex(),command.hex());assert applied.startswith('V|3|00')
        receipt=data(applied)[1:];receipts.append(receipt)
        call('confirm','confirmed'+str(i),'s2',receipt.hex())
        replay=call('execute','replay'+str(i),'s2',execution.hex(),command.hex());assert replay.startswith('V|3|01')
        call('fresh','after'+str(i),'s1');assert call('equal','parent'+str(i),'after'+str(i))=='S|0'
        call('preview','stale-parent'+str(i),'s1','parent'+str(i),height+1,block.hex(),vec([]))
    call('parallel','s1',8,4)
    connection=sqlite3.connect(DB);ids=connection.execute('SELECT object_kind,object_id FROM agent_market_objects_v1 ORDER BY object_kind,object_id').fetchall();connection.close()
    for i,(kind,ident) in enumerate(ids):call('state','state'+str(i),'s1',kind,ident.hex())
    for kind in STATE_NAMES:call('state','absent'+str(kind),'s1',kind,(bytes([251])*32).hex())
    call('empty','empty1','s1',successor.hex());call('empty','empty2','s2',successor.hex());assert call('equal','empty1','empty2')=='S|1'
    call('fresh','after-empty','s1');assert call('equal','empty1','after-empty')=='S|1'
    for i,receipt in enumerate(receipts):call('confirm','old-confirm'+str(i),'s1',receipt.hex())
    for i,command in enumerate(commands):call('execute','old-replay'+str(i),'s1',execution.hex(),command.hex())
    # Errors remain owned and observe exact original code/message/Display.
    for i,raw in enumerate([b'',execution[:-1],execution+b'x']):call('empty','decode-empty'+str(i),'s1',raw.hex())
    for i,raw in enumerate([b'',commands[0][:-1],b'\xff']):call('execute','decode-command'+str(i),'s1',execution.hex(),raw.hex())
    for i,raw in enumerate([struct.pack('<Q',1),struct.pack('<Q',(1<<64)-1),struct.pack('<Q',1)+b'\xff',bytes(8)+b'x']):
        call('preview','decode-preview'+str(i),'s1','after-empty',height+2,bytes([223]*32).hex(),raw.hex())
    call('existing','bad-store-id',cfg(store_id=bytes([19])*32));call('open','bad-bundle',cfg(trust=b''))
    call('existing','missing',cfg(path=CASES/'absent.sqlite'))
    directory=CASES/'directory';directory.mkdir();call('existing','directory-error',cfg(path=directory))
    link=CASES/'link';link.symlink_to(DB);call('existing','link-error',cfg(path=link))
    call('open','nested',cfg(path=CASES/'nested'/'database'));call('fresh','other-store-parent','nested')
    call('equal','after-empty','other-store-parent');call('preview','other-parent-error','s1','other-store-parent',height+2,bytes([224]*32).hex(),vec([]))
    call('drop','nested');call('observe','other-store-parent')
    # All private results, including borrowed views, remain usable after every Store is gone.
    retained=list(native.objects)
    for slot in ['s1','s2']:call('drop',slot)
    for slot in retained:
        if slot in native.objects:call('observe',slot)
    for slot in list(native.objects):call('drop',slot)
    assert not native.objects
    original_process.stdin.close();original_input.close();original_process.wait(timeout=30)
    original_output.close();original_error.close();assert original_process.returncode==0 and not (WORK/'original.stderr.raw').read_bytes()
    log.close();report['source_after']={p:identity(p) for p in inputs};assert report['source_after']==inputs
    report.update(status='PASS',finalized=True,native_getter_calls=native.getters,native_method_drop_compare_calls=native.calls,native_total_abi_calls=native.calls+native.getters,
                  counter_definition='Every actual public method/drop/equality invocation plus each actual kind/scalar/view getter; observe and parallel protocol containers do not add synthetic calls.',
                  live_values_after=0,original_exit_code=0,public_exports=len(native.exports),provider_operations_unchanged=29)
    save()
except BaseException as error:
    report.update(status='FAIL',failure=repr(error));save();raise
finally:
    if 'native' in globals():native.close()
    if 'original_process' in globals() and original_process.poll() is None:
        original_process.stdin.close()
        try:original_process.wait(timeout=5)
        except subprocess.TimeoutExpired:original_process.kill();original_process.wait()
print(json.dumps({k:v for k,v in report.items() if k not in ['source_before','source_after']}))
