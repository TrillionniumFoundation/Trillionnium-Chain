"""Actual native/Rust transaction differential, including exact durable SQLite bytes."""
from pathlib import Path
import ctypes,hashlib,json,os,sqlite3,stat,struct,subprocess,sys,time
from borsh_fixture import Fixtures
ROOT=Path(__file__).resolve().parents[4]
BUILD,ORIGINAL,AUDITOR,POLICY,WORK=map(lambda s:Path(s).absolute(),sys.argv[1:])
assert __debug__ and not WORK.exists() and ROOT not in WORK.parents
WORK.mkdir(mode=0o700);(WORK/'blobs').mkdir();CASES=WORK/'cases';CASES.mkdir();DB=CASES/'records.sqlite'
report={'schema':'trnm.hia.task-kernel.store-records-qualification.v1','status':'FAIL','finalized':False,'scope':'private persistence, verified reopening/readback, all six apply_command branches, budget, authorize snapshots, operation-scope resolution, same-transaction authorization consumption, full execute/replay/commit faults, empty committed advancement and private-value preview lifecycle; not public opaque owner lifecycle','native_calls':0,'original_calls':0,'fixture_preparations':0,'stages':[]}
def identity(path):
    raw=Path(path).read_bytes();return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def blob(raw):
    sha=hashlib.sha256(raw).hexdigest();p=WORK/'blobs'/sha
    if not p.exists():p.write_bytes(raw)
    assert p.read_bytes()==raw
    return {'bytes':len(raw),'sha256':sha,'path':'blobs/'+sha}
def save():(WORK/'report.json').write_text(json.dumps(report,separators=(',',':'))+'\n')
def stage(label,executable,data):
    (WORK/(label+'.stdin.raw')).write_bytes(data);start=time.monotonic_ns()
    completed=subprocess.run([str(executable)],input=data,capture_output=True,cwd=CASES,timeout=30)
    (WORK/(label+'.stdout.raw')).write_bytes(completed.stdout);(WORK/(label+'.stderr.raw')).write_bytes(completed.stderr)
    report['stages'].append({'name':label,'argv':[str(executable)],'cwd':str(CASES),'timeout_seconds':30,'elapsed_ns':time.monotonic_ns()-start,'exit_code':completed.returncode});save()
    assert completed.returncode==0 and not completed.stderr
    return completed.stdout
def original(label,raw):
    out=stage(label,ORIGINAL,raw.hex().encode()+b'\n').strip();code,out=out.split(b'|',1);return int(code),bytes.fromhex(out.decode())
def frame(method,kind=45,expected=0,successor=1,body=b'',state=b'',command=b'',object_id=bytes([233])*32,bundle_override=None,path_override=None):
    trust=bundle if bundle_override is None else bundle_override;path=os.fsencode(DB if path_override is None else path_override)
    return b'TKSR0001'+struct.pack('<9Q',method,kind,expected,successor,len(path),len(trust),len(body),len(state),len(command))+bytes([9])*32+object_id+bytes(16)+path+trust+body+state+command
def inventory():
    result={}
    def walk(parent):
        for path in sorted(parent.iterdir()):
            st=path.lstat();row={'mode':stat.S_IMODE(st.st_mode)}
            if stat.S_ISLNK(st.st_mode):row.update(kind='symlink',target=os.readlink(path))
            elif stat.S_ISREG(st.st_mode):row.update(kind='file',content=blob(path.read_bytes()))
            elif stat.S_ISDIR(st.st_mode):row.update(kind='directory')
            else:raise AssertionError('Unexpected fixture filesystem object')
            result[path.relative_to(CASES).as_posix()]=row
            if row['kind']=='directory':walk(path)
    walk(CASES)
    return result
def restore(rows):
    def remove(parent):
        for path in parent.iterdir():
            if path.is_dir() and not path.is_symlink():remove(path);path.rmdir()
            else:path.unlink()
    remove(CASES)
    for name,row in rows.items():
        path=CASES/name
        if row['kind']=='directory':path.mkdir();path.chmod(row['mode'])
        elif row['kind']=='symlink':path.symlink_to(row['target'])
        else:path.write_bytes((WORK/row['content']['path']).read_bytes());path.chmod(row['mode'])
def successful(code,raw):return code==0 and len(raw)>=32 and struct.unpack_from('<Q',raw)[0]==0

try:
    build=json.loads((BUILD/'build.json').read_text());assert build['status']=='PASS' and build['finalized'] and build['source_before']==build['source_after']
    inputs=dict(build['source_before'])
    for name,expected in build['artifacts'].items():assert identity(BUILD/name)==expected;inputs[str(BUILD/name)]=expected
    for p in [Path(__file__),Path(__file__).with_name('borsh_fixture.py'),Path(__file__).with_name('type_layout.json'),BUILD/'build.json',ORIGINAL,AUDITOR,AUDITOR.parent/'original-store.rs',AUDITOR.parent/'store-audit-original.rs',AUDITOR.parent/'receipt.json',POLICY]:inputs[str(p)]=identity(p)
    assert {p:identity(p) for p in inputs}==inputs
    report['source_before']=inputs;report['fixture_sqlite_version']=sqlite3.sqlite_version;save()
    fixture=Fixtures(91937);raw=fixture.value(27,0)
    bundle=bytes.fromhex(stage('fixture-original-trust',POLICY,b'trust:'+raw.hex().encode()+b'\n').strip().decode());report['fixture_preparations']+=1
    path=os.fsencode(DB);create=b'TKSA0001'+struct.pack('<4Q',0,(1<<64)-1,len(path),len(bundle))+bytes([9])*32+path+bundle
    response=stage('fixture-original-create',AUDITOR,b'create:'+create.hex().encode()+b'\n').strip().split(b'|');assert successful(int(response[0]),bytes.fromhex(response[1].decode()));report['fixture_preparations']+=1
    baseline=DB.read_bytes();report['baseline_database']=blob(baseline);report['trust_bundle']=blob(bundle)
    library=ctypes.CDLL(str(BUILD/'store-records-native.so'))
    new=library.trnm_task_owner_new;new.argtypes=[];new.restype=ctypes.c_void_p
    invoke=library.trnm_task_owner_invoke;invoke.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint64,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(ctypes.c_uint64)];invoke.restype=ctypes.c_uint64
    free=library.trnm_task_owner_free;free.argtypes=[ctypes.c_void_p]
    release=library.trnm_task_owner_result_free;release.argtypes=[ctypes.c_void_p]
    owner=new();assert owner
    def native(raw):
        source=ctypes.create_string_buffer(raw);result=ctypes.c_void_p();size=ctypes.c_uint64();code=invoke(owner,source,len(raw),ctypes.byref(result),ctypes.byref(size));assert source.raw[:len(raw)]==raw
        out=ctypes.string_at(result,size.value) if result else b''
        if result:release(result)
        return code,out
    cases=[]
    def add(name,raw,sql=(),unconstrained=False,database='baseline',filesystem=()):cases.append((name,raw,list(sql),unconstrained,database,list(filesystem)))
    insert='INSERT INTO agent_market_objects_v1 VALUES (?,?,?,?,?,?)'
    kinds={2:(33,36),3:(37,38),4:(48,50),5:(54,55),6:(56,57),7:(51,53),44:(39,40),45:(43,44),47:(45,46)}
    for kind,(body_type,state_type) in kinds.items():
        object_id=bytes([120+kind])*32
        for mode,version in enumerate([0,255,(1<<64)-1]):
            body=fixture.value(body_type,mode);state=fixture.value(state_type,mode)
            args=dict(kind=kind,expected=version,body=body,state=state,object_id=object_id)
            record=(kind,object_id,struct.pack('<Q',version),body,state,bytes(32))
            add(f'insert-{kind}-{mode}',frame(1,**args))
            add(f'insert-duplicate-{kind}-{mode}',frame(1,**args),[(insert,record)])
            add(f'load-{kind}-{mode}',frame(0,kind=kind,object_id=object_id),[(insert,record)])
        body=fixture.value(body_type,0);state=fixture.value(state_type,0)
        add(f'load-absent-{kind}',frame(0,kind=kind,object_id=object_id))
        for expected,successor in [(0,1),(255,256),((1<<64)-2,(1<<64)-1),((1<<64)-1,0),(0,0),(0,2)]:
            record=(kind,object_id,struct.pack('<Q',expected),body,state,bytes(32))
            args=dict(kind=kind,expected=expected,successor=successor,body=fixture.value(body_type,1),state=fixture.value(state_type,1),object_id=object_id)
            add(f'update-{kind}-{expected}-{successor}',frame(2,**args),[(insert,record)])
        for method in [1,2]:
            add(f'decode-body-first-{kind}-{method}',frame(method,kind=kind,body=b'',state=b'',object_id=object_id),database='absent')
            add(f'decode-state-{kind}-{method}',frame(method,kind=kind,body=body,state=state[:-1],object_id=object_id))
        record=(kind,object_id,bytes(8),body,state,bytes(32))
        add(f'load-body-before-state-{kind}',frame(0,kind=kind,object_id=object_id),[(insert,record),('UPDATE agent_market_objects_v1 SET immutable_body=?,mutable_state=? WHERE object_id=?',(b'',b'',object_id))])
        add(f'load-state-{kind}',frame(0,kind=kind,object_id=object_id),[(insert,record),('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_id=?',(state[:-1],object_id))])
        add(f'load-ignores-row-checksum-{kind}',frame(0,kind=kind,object_id=object_id),[(insert,record),('UPDATE agent_market_objects_v1 SET object_version=?,row_checksum=? WHERE object_id=?',(b'',b'',object_id))],True)
    kind=45;object_id=bytes([233])*32;body=fixture.value(43,0);state=fixture.value(44,0);record=(kind,object_id,bytes(8),body,state,bytes(32))
    args=dict(body=body,state=state)
    add('update-missing',frame(2,**args))
    add('update-stale',frame(2,expected=1,successor=2,**args),[(insert,record)])
    add('update-multiple-matches',frame(2,**args),[(insert,record),(insert,record)],True)
    add('insert-ignored-is-success',frame(1,**args),[('CREATE TRIGGER fixture_ignore BEFORE INSERT ON agent_market_objects_v1 BEGIN SELECT RAISE(IGNORE); END',())])
    add('update-ignored-is-stale',frame(2,**args),[(insert,record),('CREATE TRIGGER fixture_ignore BEFORE UPDATE ON agent_market_objects_v1 BEGIN SELECT RAISE(IGNORE); END',())])
    add('insert-trigger-failure-maps-conflict',frame(1,**args),[("CREATE TRIGGER fixture_abort BEFORE INSERT ON agent_market_objects_v1 BEGIN SELECT RAISE(ABORT,'fixture rejected'); END",())])
    for method in [0,1,2]:
        add('objects-missing-table-'+str(method),frame(method,**args),[('DROP TABLE agent_market_objects_v1',())])
        add('objects-empty-database-'+str(method),frame(method,**args),database='empty')
        add('objects-missing-database-'+str(method),frame(method,**args),database='absent')
    add('update-overflow-before-missing-table',frame(2,expected=(1<<64)-1,successor=0,**args),[('DROP TABLE agent_market_objects_v1',())])
    add('update-bad-successor-before-missing-table',frame(2,expected=0,successor=2,**args),[('DROP TABLE agent_market_objects_v1',())])
    for column in ['immutable_body','mutable_state']:
        for label,value in [('null',None),('text','wrong'),('integer',-1)]:add('load-type-'+column+'-'+label,frame(0),[(insert,record),('UPDATE agent_market_objects_v1 SET '+column+'=? WHERE object_id=?',(value,object_id))],True)
    add('load-typed-receipt-before-body-borsh',frame(0),[(insert,record),('UPDATE agent_market_objects_v1 SET immutable_body=?,mutable_state=? WHERE object_id=?',(b'',None,object_id))],True)
    for variant in range(6):
        command=bytes([variant])+fixture.value(68+variant,0);receipt=fixture.value(61,variant%3)
        receipt=fixture.replace_field(61,receipt,3,object_id)
        args=dict(body=command,state=receipt,command=b'raw command bytes\x00'+bytes([variant]))
        add('operation-insert-kind-'+str(variant),frame(3,**args))
        op=(object_id,bytes(8),variant+2,args['command'],receipt,bytes(32))
        add('operation-insert-duplicate-'+str(variant),frame(3,**args),[('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',op)])
        add('operation-load-'+str(variant),frame(4,command=args['command']),[('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',op)])
    command=bytes([0])+fixture.value(68,0);receipt=fixture.value(61,0);receipt=fixture.replace_field(61,receipt,3,object_id)
    op=(object_id,bytes(8),2,b'opaque',receipt,bytes(32));opsql=[('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',op)]
    add('operation-load-absent',frame(4,command=b'opaque'))
    add('operation-command-collision',frame(4,command=b'different'),opsql)
    add('operation-collision-before-receipt-decode',frame(4,command=b'different'),opsql+[('UPDATE agent_market_operations_v1 SET receipt=?',(b'',))])
    add('operation-receipt-decode',frame(4,command=b'opaque'),opsql+[('UPDATE agent_market_operations_v1 SET receipt=?',(b'',))])
    add('operation-ignores-row-binding',frame(4,command=b'opaque'),opsql+[('UPDATE agent_market_operations_v1 SET sequence=?,operation_kind=?,row_checksum=?',(b'',65535,b''))],True)
    add('operation-typed-receipt-before-collision',frame(4,command=b'different'),opsql+[('UPDATE agent_market_operations_v1 SET receipt=?',('wrong',))],True)
    add('operation-insert-ignored-success',frame(3,body=command,state=receipt,command=b'opaque'),[('CREATE TRIGGER fixture_ignore BEFORE INSERT ON agent_market_operations_v1 BEGIN SELECT RAISE(IGNORE); END',())])
    for column in ['command','receipt']:
        for label,value in [('null',None),('text','wrong'),('integer',-1)]:add('operation-load-type-'+column+'-'+label,frame(4,command=b'opaque'),opsql+[('UPDATE agent_market_operations_v1 SET '+column+'=?',(value,))],True)
    for method in [3,4]:
        add('operations-missing-table-'+str(method),frame(method,body=command,state=receipt,command=b'opaque'),[('DROP TABLE agent_market_operations_v1',())])
    for version in [255,256,(1<<63),(1<<64)-1]:
        r=fixture.replace_field(61,receipt,2,struct.pack('<Q',version));add('operation-full-u64-sequence-'+str(version),frame(3,body=command,state=r,command=b''))
    context=fixture.value(25,0);chain=b'Q'*((1<<21)+257);context=fixture.replace_field(25,context,1,struct.pack('<I',len(chain))+chain)
    large_body=fixture.replace_field(43,body,1,context)
    add('object-insert-larger-than-2mib',frame(1,body=large_body,state=state))
    add('object-load-larger-than-2mib',frame(0),[(insert,(45,object_id,bytes(8),large_body,state,bytes(32)))])
    add('operation-insert-larger-than-2mib',frame(3,body=command,state=receipt,command=chain))
    add('operation-load-larger-than-2mib',frame(4,command=chain),[('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',(object_id,bytes(8),2,chain,receipt,bytes(32)))])
    marker_columns='marker_sequence,order_height,order_block_id,parent_order_height,parent_order_block_id,source_operation_sequence,target_operation_sequence,source_state_root,target_state_root,source_operation_root,target_operation_root,previous_marker_checksum,row_checksum'
    con=sqlite3.connect(DB);marker=list(con.execute('SELECT '+marker_columns+' FROM agent_market_committed_blocks_v1').fetchone());con.close()
    def changed_marker(changes):
        values=list(marker)
        for index,value in changes.items():values[index]=value
        raw=b''.join(values);assert len(raw)==296;return raw
    initial_height=struct.unpack('<Q',marker[1])[0];initial_block=marker[2];state_root=marker[8];operation_root=marker[10]
    for sequence in [0,1,255,256,(1<<63),(1<<64)-1]:
        for fenced in [0,1]:add(f'metadata-progress-{sequence}-{fenced}',frame(5,expected=sequence,successor=sequence,body=state_root+operation_root,state=bytes([fenced])))
    add('metadata-progress-insert',frame(5,body=bytes(64),state=b'\0'),[('DELETE FROM agent_market_metadata_v1',())])
    add('metadata-progress-ignore-success',frame(5,body=bytes(64),state=b'\0'),[('CREATE TRIGGER fixture_ignore BEFORE UPDATE ON agent_market_metadata_v1 BEGIN SELECT RAISE(IGNORE); END',())])
    add('metadata-progress-missing-table',frame(5,body=bytes(64),state=b'\0'),[('DROP TABLE agent_market_metadata_v1',())])
    large_bundle=fixture.replace_field(27,bundle,1,context)
    add('metadata-progress-large-config',frame(5,body=state_root+operation_root,state=b'\1',bundle_override=large_bundle))
    for sequence in [0,1,255,256,(1<<63),(1<<64)-1]:
        raw=changed_marker({0:struct.pack('<Q',sequence),1:struct.pack('<Q',(1<<64)-1),2:bytes([220])*32,12:bytes([251])*32})
        add('marker-insert-'+str(sequence),frame(6,body=raw),[('DELETE FROM agent_market_committed_blocks_v1',())])
    add('marker-insert-duplicate-sequence',frame(6,body=changed_marker({2:bytes([220])*32})))
    add('marker-insert-duplicate-block',frame(6,body=changed_marker({0:struct.pack('<Q',1)})))
    add('marker-insert-ignored-fails',frame(6,body=changed_marker({0:struct.pack('<Q',1),2:bytes([220])*32})),[('CREATE TRIGGER fixture_ignore BEFORE INSERT ON agent_market_committed_blocks_v1 BEGIN SELECT RAISE(IGNORE); END',())])
    add('marker-anchor-insert',frame(8,body=state_root+operation_root),[('DELETE FROM agent_market_committed_blocks_v1',())])
    add('marker-anchor-duplicate',frame(8,body=state_root+operation_root))
    execution=fixture.value(28,0)
    for index,value in [(2,marker[1]),(3,initial_block),(4,marker[1]),(5,initial_block)]:execution=fixture.replace_field(28,execution,index,value)
    roots=state_root+state_root+operation_root+operation_root
    add('marker-extend-same-block',frame(7,expected=0,successor=0,body=execution,state=roots))
    add('marker-extend-new-target-data',frame(7,expected=0,successor=(1<<64)-1,body=execution,state=state_root+bytes([240])*32+operation_root+bytes([241])*32))
    successor=fixture.replace_field(28,execution,4,struct.pack('<Q',initial_height+1));successor=fixture.replace_field(28,successor,5,bytes([222])*32)
    add('marker-direct-successor',frame(7,expected=0,successor=0,body=successor,state=roots))
    add('marker-direct-successor-with-operations',frame(7,expected=0,successor=15,body=successor,state=state_root+bytes([240])*32+operation_root+bytes([241])*32))
    for label,ex in [('same',execution),('successor',successor)]:
        add('marker-source-sequence-'+label,frame(7,expected=1,successor=0,body=ex,state=roots))
        add('marker-source-state-'+label,frame(7,expected=0,successor=0,body=ex,state=bytes(32)+roots[32:]))
        add('marker-source-operation-'+label,frame(7,expected=0,successor=0,body=ex,state=roots[:64]+bytes(32)+roots[96:]))
        for field,value in [(2,struct.pack('<Q',255)),(3,bytes(32))]:
            changed=fixture.replace_field(28,ex,field,value);add('marker-expect-'+label+'-'+str(field),frame(7,expected=0,successor=0,body=changed,state=roots))
    for field,value in [(4,struct.pack('<Q',initial_height+2)),(4,struct.pack('<Q',(1<<64)-1)),(5,initial_block)]:
        ex=fixture.replace_field(28,successor,field,value);add('marker-bad-successor-'+str(field)+'-'+value.hex(),frame(7,expected=0,successor=0,body=ex,state=roots))
    add('marker-extend-ignore-is-stale',frame(7,expected=0,successor=0,body=execution,state=roots),[('CREATE TRIGGER fixture_ignore BEFORE UPDATE ON agent_market_committed_blocks_v1 BEGIN SELECT RAISE(IGNORE); END',())])
    add('marker-extend-multiple-matches-is-stale',frame(7,expected=0,successor=0,body=execution,state=roots),[('INSERT INTO agent_market_committed_blocks_v1 VALUES ('+','.join('?' for _ in marker)+')',tuple(marker))],True)
    for sql,label in [([('DELETE FROM agent_market_committed_blocks_v1',())],'empty'),([('UPDATE agent_market_committed_blocks_v1 SET row_checksum=?',(bytes(32),))],'checksum'),([('UPDATE agent_market_committed_blocks_v1 SET marker_sequence=?',(b'',))],'width')]:
        add('marker-load-error-before-source-'+label,frame(7,expected=9,successor=0,body=execution,state=roots),sql,True)
    def prepared_marker_database(label,raw):
        DB.write_bytes(baseline);con=sqlite3.connect(DB);con.execute('DELETE FROM agent_market_committed_blocks_v1');con.commit();con.close()
        code,out=original('fixture-original-marker-'+label,frame(6,body=raw));assert successful(code,out);report['fixture_preparations']+=1
        data=DB.read_bytes();report.setdefault('marker_fixture_databases',{})[label]=blob(data);DB.write_bytes(baseline);return data
    sequence_max=prepared_marker_database('sequence-max',changed_marker({0:struct.pack('<Q',(1<<64)-1)}))
    add('marker-sequence-overflow',frame(7,expected=0,successor=0,body=successor,state=roots),database=sequence_max)
    add('marker-same-block-at-sequence-max',frame(7,expected=0,successor=0,body=execution,state=roots),database=sequence_max)
    height_max=prepared_marker_database('height-max',changed_marker({1:struct.pack('<Q',(1<<64)-1)}))
    ex=fixture.replace_field(28,successor,2,struct.pack('<Q',(1<<64)-1));ex=fixture.replace_field(28,ex,4,struct.pack('<Q',0))
    add('marker-height-overflow-is-context',frame(7,expected=0,successor=0,body=ex,state=roots),database=height_max)
    source_one=prepared_marker_database('source-one',changed_marker({6:struct.pack('<Q',1)}))
    add('marker-target-regression',frame(7,expected=1,successor=0,body=execution,state=roots),database=source_one)
    for method in [5,6,7,8]:
        body_value={5:bytes(64),6:b''.join(marker),7:successor,8:bytes(64)}[method];state_value={5:b'\0',6:b'',7:roots,8:b''}[method]
        add('progress-missing-table-'+str(method),frame(method,body=body_value,state=state_value),[('DROP TABLE '+('agent_market_metadata_v1' if method==5 else 'agent_market_committed_blocks_v1'),())])
    for database in ['empty','absent','baseline']:
        add('create-schema-'+database,frame(9),database=database)
    add('create-schema-not-a-database',frame(9),database=b'not a database')
    add('create-schema-extra-table-post-commit-failure',frame(9),[('CREATE TABLE extra(x BLOB)',())],database='empty')
    requester_start,requester_end=fixture.fields(27,bundle)[4]
    duplicate_agent=fixture.replace_field(27,bundle,5,bundle[requester_start:requester_end])
    add('create-schema-duplicate-lane-rolls-back',frame(9,bundle_override=duplicate_agent),database='empty')
    for field,value,label in [(0,b'\0\0','private-trust-schema-not-revalidated'),(2,struct.pack('<Q',(1<<64)-1),'maximum-height'),(3,bytes(32),'zero-block-post-commit'),(7,bytes(32),'account-id-post-commit'),(10,bytes(32),'bond-id-post-commit'),(8,bytes(16),'zero-account-funding'),(11,bytes(16),'zero-bond-funding')]:
        custom=fixture.replace_field(27,bundle,field,value);add('create-schema-'+label,frame(9,bundle_override=custom),database='empty')
    custom=fixture.replace_field(27,bundle,8,bytes([255])*16);custom=fixture.replace_field(27,custom,11,bytes([255])*16)
    add('create-schema-full-u128-funding',frame(9,bundle_override=custom),database='empty')
    add('create-schema-large-context',frame(9,bundle_override=large_bundle),database='empty')
    for mode in range(3):add('nonce-insert-'+str(mode),frame(10,body=fixture.value(39,mode)))
    nonce=fixture.value(39,0)
    large_nonce=fixture.replace_field(39,nonce,1,context)
    add('nonce-insert-large-context',frame(10,body=large_nonce))
    add('nonce-insert-missing-table',frame(10,body=nonce),[('DROP TABLE agent_market_objects_v1',())])
    add('nonce-decode-before-missing-path',frame(10,body=nonce[:-1]),database='absent')
    DB.write_bytes(baseline)
    code,out=original('fixture-original-nonce-insert',frame(10,body=nonce));assert successful(code,out);report['fixture_preparations']+=1
    nonce_database=DB.read_bytes();report['nonce_fixture_database']=blob(nonce_database);DB.write_bytes(baseline)
    add('nonce-insert-duplicate',frame(10,body=nonce),database=nonce_database)
    # Build authenticated fixture heads with the unchanged original checksum/root
    # routines. Python changes fixture rows only; no host code is the oracle.
    def audit_fixture(label,method=0,prefix=b'',maximum=(1<<64)-1,trust=None):
        trust=bundle if trust is None else trust;path=os.fsencode(DB)
        request=b'TKSA0001'+struct.pack('<4Q',method,maximum,len(path),len(trust))+bytes([9])*32+path+trust
        value=stage('fixture-verified-'+label,AUDITOR,prefix+request.hex().encode()+b'\n').strip().split(b'|')
        code,out=int(value[0]),bytes.fromhex(value[1].decode());assert successful(code,out),label
        report['fixture_preparations']+=1
        return out[32:]
    def normalized_object(label,kind,body,state):
        request=f'object:{kind}:{body.hex()}:{state.hex()}:500:1\n'.encode()
        raw=bytes.fromhex(stage('fixture-verified-object-'+label,AUDITOR,request).strip().decode());report['fixture_preparations']+=1
        bn,sn=struct.unpack_from('<QQ',raw,42);assert len(raw)==90+bn+sn and struct.unpack_from('<H',raw)[0]==kind
        return (kind,raw[2:34],raw[34:42],raw[58:58+bn],raw[58+bn:58+bn+sn],raw[-32:])
    def records_fixture(label,raw):
        code,out=original('fixture-verified-records-'+label,raw);assert successful(code,out),label
        report['fixture_preparations']+=1
        return out[32:]
    normalized=[]
    for kind,(bt,st) in kinds.items():normalized.append(normalized_object(str(kind),kind,fixture.value(bt,0),fixture.value(st,0)))
    DB.write_bytes(baseline);con=sqlite3.connect(DB);con.executemany(insert,normalized);con.commit();con.close()
    all_root=audit_fixture('all-object-root')
    con=sqlite3.connect(DB);con.execute('DELETE FROM agent_market_committed_blocks_v1');con.commit();con.close()
    records_fixture('all-object-anchor',frame(8,body=all_root+operation_root))
    records_fixture('all-object-meta',frame(5,expected=0,successor=initial_height,object_id=initial_block,body=all_root+operation_root,state=b'\0'))
    audit_fixture('all-object-audit',14)
    all_objects=DB.read_bytes();report['verified_all_objects_database']=blob(all_objects)
    for record in normalized:add('verified-state-kind-'+str(record[0]),frame(15,kind=record[0],object_id=record[1]),database=all_objects)
    for kind in kinds:add('verified-state-absent-'+str(kind),frame(15,kind=kind))
    for method in [11,12,13,14,16,18]:
        add('verified-baseline-'+str(method),frame(method))
        add('verified-all-objects-'+str(method),frame(method),database=all_objects)
    DB.write_bytes(baseline);audit_fixture('three-empty-blocks',prefix=b'empty-blocks:',maximum=3)
    empty_chain=DB.read_bytes();report['verified_empty_chain_database']=blob(empty_chain)
    for method in [11,12,13,14,16,18]:add('verified-three-empty-blocks-'+str(method),frame(method),database=empty_chain)
    DB.write_bytes(baseline)
    complete_ops=[]
    for variant in range(6):
        command=bytes([variant])+fixture.value(68+variant,0)
        auth=fixture.fields(68+variant,command,1)[-1][0]
        command=fixture.replace_field(59,command,11,struct.pack('<Q',variant),auth)
        request=f'operation:{command.hex()}:{variant+1}:{initial_height}:{initial_block.hex()}:{state_root.hex()}\n'.encode()
        raw=bytes.fromhex(stage('fixture-verified-operation-'+str(variant),AUDITOR,request).strip().decode());report['fixture_preparations']+=1
        bn,sn=struct.unpack_from('<QQ',raw,42);assert len(raw)==90+bn+sn
        complete_ops.append((raw[2:34],raw[34:42],struct.unpack_from('<H',raw)[0],raw[58:58+bn],raw[58+bn:58+bn+sn],raw[-32:]))
    con=sqlite3.connect(DB);con.executemany('INSERT INTO agent_market_operations_v1 VALUES (?,?,?,?,?,?)',complete_ops);con.commit();con.close()
    op_root=audit_fixture('six-operation-root',1)
    con=sqlite3.connect(DB);con.execute('DELETE FROM agent_market_committed_blocks_v1');con.commit();con.close()
    records_fixture('six-operation-markers',frame(6,body=changed_marker({6:struct.pack('<Q',6),10:op_root})))
    records_fixture('six-operation-meta',frame(5,expected=6,successor=initial_height,object_id=initial_block,body=state_root+op_root,state=b'\0'))
    audit_fixture('six-operation-audit',14)
    all_operations=DB.read_bytes();report['verified_six_operations_database']=blob(all_operations)
    for method in [11,12,13,14,16,18]:add('verified-six-operations-'+str(method),frame(method),database=all_operations)
    for i,record in enumerate(complete_ops):add('confirm-exact-'+str(i),frame(17,body=record[4]),database=all_operations)
    valid_receipt=complete_ops[0][4]
    for field,value in [(0,b'\0\0'),(1,bytes(32)),(2,bytes(8)),(3,bytes(32)),(4,b'\0\0'),(5,bytes(32)),(6,struct.pack('<Q',(1<<64)-1)),(7,bytes(32)),(8,bytes(32))]:
        changed=fixture.replace_field(61,valid_receipt,field,value)
        add('confirm-different-field-'+str(field),frame(17,body=changed),database=all_operations)
    add('confirm-absent',frame(17,body=valid_receipt))
    add('confirm-decode-before-missing-path',frame(17,body=valid_receipt[:-1]),database='absent')
    wrong_store=fixture.replace_field(61,valid_receipt,1,bytes(32))
    add('confirm-store-before-missing-path',frame(17,body=wrong_store),database='absent')
    add('confirm-store-before-sidecar',frame(17,body=wrong_store),filesystem=[('file','records.sqlite-wal',b'x')])
    # An original-created fenced store and authentic checksum failures exercise
    # the complete verified gate, before any getter/confirmation can return.
    DB.write_bytes(baseline);records_fixture('fenced',frame(5,expected=0,successor=initial_height,object_id=initial_block,body=state_root+operation_root,state=b'\1'));fenced_database=DB.read_bytes()
    bad_bundle=fixture.replace_field(27,bundle,0,b'\0\0')
    for method in [11,12,13,14,15,16,17,18]:
        args={'body':valid_receipt} if method==17 else {}
        add('verified-missing-path-'+str(method),frame(method,**args),database='absent')
        add('verified-empty-file-'+str(method),frame(method,**args),database='empty')
        add('verified-fenced-'+str(method),frame(method,**args),database=fenced_database)
        add('verified-bad-checksum-'+str(method),frame(method,**args),[('UPDATE agent_market_objects_v1 SET row_checksum=? WHERE object_kind=45',(bytes(32),))])
        add('verified-schema-before-metadata-'+str(method),frame(method,**args),[('CREATE TABLE extra(x BLOB)',()),('UPDATE agent_market_metadata_v1 SET row_checksum=?',(bytes(32),))])
        add('verified-bad-trust-before-sidecar-'+str(method),frame(method,bundle_override=bad_bundle,**args),filesystem=[('file','records.sqlite-wal',b'x')])
    for method in [11,12,13,14]:
        add('verified-bad-trust-missing-'+str(method),frame(method,bundle_override=bad_bundle),database='absent')
        add('verified-bad-config-'+str(method),frame(method,bundle_override=fixture.replace_field(27,bundle,8,(2000).to_bytes(16,'little'))))
        for suffix in ['-wal','-shm','-journal']:
            add('verified-sidecar-'+str(method)+suffix,frame(method),filesystem=[('file','records.sqlite'+suffix,b'')])
        for path_kind in ['directory','symlink']:
            setup=[('directory','records.sqlite',None)] if path_kind=='directory' else [('file','target.sqlite',baseline),('symlink','records.sqlite','target.sqlite')]
            add('verified-'+path_kind+'-'+str(method),frame(method),database='absent',filesystem=setup)
        add('verified-nested-missing-'+str(method),frame(method,path_override=CASES/'new-parent'/'nested'/'store.sqlite'),database='absent')
        add('verified-parent-file-'+str(method),frame(method,path_override=CASES/'not-directory'/'store.sqlite'),database='absent',filesystem=[('file','not-directory',b'parent')])
    # Actual original apply_capability_grant/apply_session_grant, inside the
    # original transaction. Envelope verification belongs to the later owner
    # entry point, so this private branch qualifier does not invent signatures.
    bs=fixture.fields(27,bundle);protocol_context=bundle[bs[1][0]:bs[1][1]]
    agent=bundle[bs[4][0]:bs[4][1]];agent_id=agent[:32];session_key=agent[96:128]
    def flatten_context(kind,body):
        body=fixture.replace_field(kind,body,0,b'\1\0')
        for field,(a,b) in enumerate(fixture.fields(25,protocol_context),1):body=fixture.replace_field(kind,body,field,protocol_context[a:b])
        return body
    def vector_u16(values):return struct.pack('<I',len(values))+b''.join(struct.pack('<H',v) for v in values)
    def vector(values):return struct.pack('<I',len(values))+b''.join(values)
    auth=fixture.value(60,0);auth=fixture.replace_field(59,auth,4,agent_id)
    op_scope=fixture.replace_field(30,fixture.value(30,0),0,struct.pack('<H',4))
    resource=fixture.value(31,0)
    for field,value in [(0,b'\1\0'),(1,b'\0'),(2,vector([bytes([7])*32])),(3,b'\0')]:resource=fixture.replace_field(31,resource,field,value)
    cap=flatten_context(33,fixture.value(33,0))
    for field,value in [(5,agent_id),(6,bytes(32)),(7,agent_id),(8,b'\1'+session_key),(9,b'\0'),(11,vector([op_scope])),(12,vector([resource])),(13,vector([bytes([8])*32+bytes([255])*16,bytes([9])*32+(1000).to_bytes(16,'little')])),(14,bytes([255])*16),(15,bytes([255])*8),(16,bytes([255])*8),(17,bytes([255])*8),(18,vector_u16([1,255,256,65535])),(19,bytes(8)),(20,bytes([255])*8),(21,struct.pack('<Q',5)),(22,struct.pack('<Q',32)),(23,struct.pack('<Q',100)),(25,struct.pack('<Q',42))]:cap=fixture.replace_field(33,cap,field,value)
    def grant_command(body,authorization=auth,session=False):return bytes([1 if session else 0])+body+authorization
    for height in [0,17,(1<<64)-1]:add('capability-grant-height-'+str(height),frame(19,expected=height,body=grant_command(cap)))
    DB.write_bytes(baseline);records_fixture('capability-grant',frame(19,expected=17,body=grant_command(cap)));cap_database=DB.read_bytes();report['capability_database']=blob(cap_database)
    con=sqlite3.connect(DB);cap_id,cap_state=con.execute('SELECT object_id,mutable_state FROM agent_market_objects_v1 WHERE object_kind=2').fetchone();con.close()
    add('capability-grant-duplicate',frame(19,expected=17,body=grant_command(cap)),database=cap_database)
    for field,value,label in [(0,bytes(2),'schema'),(1,bytes([99])*32,'genesis'),(2,struct.pack('<I',1)+b'x','chain'),(3,struct.pack('<I',2),'protocol'),(4,bytes([99])*32,'profile'),(5,bytes(32),'issuer-agent'),(6,bytes([1])*32,'issuer-key'),(7,bytes(32),'delegate-agent'),(8,b'\0','delegate-none'),(8,b'\1'+bytes(32),'delegate-key'),(9,b'\1'+bytes(32),'parent'),(11,bytes(4),'empty-operations'),(12,bytes(4),'empty-resources'),(18,bytes(4),'empty-lanes'),(18,vector_u16([0,1]),'zero-lane'),(19,struct.pack('<Q',18),'future'),(20,struct.pack('<Q',16),'expired'),(21,bytes(8),'rate-window'),(22,bytes(8),'rate-max'),(23,bytes(8),'operation-max')]:
        add('capability-invalid-'+label,frame(19,expected=17,body=grant_command(fixture.replace_field(33,cap,field,value))))
    unknown_auth=fixture.replace_field(59,auth,4,bytes([99])*32)
    add('capability-unknown-bootstrap',frame(19,expected=17,body=grant_command(cap,unknown_auth)))
    add('capability-context-before-agent',frame(19,expected=17,body=grant_command(fixture.replace_field(33,cap,0,bytes(2)),unknown_auth)))
    op_high=fixture.replace_field(30,op_scope,0,struct.pack('<H',256));op_low=fixture.replace_field(30,op_scope,0,struct.pack('<H',255))
    op_same_key=fixture.replace_field(30,op_scope,1,b'\1'+bytes([5])*32)
    res_second=fixture.replace_field(31,resource,2,vector([bytes([8])*32]))
    for field,value,label in [(11,vector([op_scope,op_scope]),'operation-duplicate'),(11,vector([op_high,op_low]),'operation-unsorted'),(11,vector([op_low,op_high]),'operation-u16-order'),(11,vector([op_scope,op_same_key]),'operation-key-duplicate'),(12,vector([resource,resource]),'resource-duplicate'),(12,vector([res_second,resource]),'resource-unsorted'),(12,vector([resource,res_second]),'resource-key-duplicate'),(13,vector([bytes([8])*32+(1).to_bytes(16,'little'),bytes([8])*32+(2).to_bytes(16,'little')]),'asset-key-duplicate'),(13,vector([bytes([9])*48,bytes([8])*48]),'asset-unsorted'),(18,vector_u16([256,255]),'lane-unsorted'),(18,vector_u16([1,1]),'lane-duplicate')]:
        add('capability-order-'+label,frame(19,expected=17,body=grant_command(fixture.replace_field(33,cap,field,value))))
    bad_ops=fixture.replace_field(33,cap,11,vector([op_scope,op_scope]));bad_ops=fixture.replace_field(33,bad_ops,12,vector([resource,resource]))
    add('capability-order-operations-before-resources',frame(19,expected=17,body=grant_command(bad_ops)))
    add('capability-bounds-before-order',frame(19,expected=17,body=grant_command(fixture.replace_field(33,bad_ops,5,bytes(32)))))
    for field,value,label in [(0,b'\2\0','kind'),(1,b'\1','mode'),(2,bytes(4),'empty-allowlist'),(3,b'\1'+bytes(32),'commitment'),(2,vector([bytes([7])*32,bytes([7])*32]),'duplicate-allowlist'),(2,vector([bytes([8])*32,bytes([7])*32]),'unsorted-allowlist')]:
        changed=fixture.replace_field(31,resource,field,value);body=fixture.replace_field(33,cap,12,vector([changed]))
        add('capability-resource-'+label,frame(19,expected=17,body=grant_command(body)))
    session=flatten_context(37,fixture.value(37,0))
    for field,value in [(5,agent_id),(6,session_key),(7,cap_id),(8,vector_u16([1,256])),(9,bytes(8)),(10,bytes([255])*8),(11,struct.pack('<Q',50)),(12,struct.pack('<Q',1))]:session=fixture.replace_field(37,session,field,value)
    for height in [0,17,(1<<64)-1]:add('session-grant-height-'+str(height),frame(19,expected=height,body=grant_command(session,session=True)),database=cap_database)
    add('session-future-validity-private-branch',frame(19,expected=17,body=grant_command(fixture.replace_field(37,session,9,struct.pack('<Q',100)),session=True)),database=cap_database)
    DB.write_bytes(cap_database);records_fixture('session-grant',frame(19,expected=17,body=grant_command(session,session=True)));session_database=DB.read_bytes();report['session_database']=blob(session_database)
    add('session-grant-duplicate',frame(19,expected=17,body=grant_command(session,session=True)),database=session_database)
    other_session=fixture.replace_field(37,session,13,bytes([99])*32)
    add('session-nonce-conflict-rolls-back-insert',frame(19,expected=17,body=grant_command(other_session,session=True)),database=session_database)
    for field,value,label in [(0,bytes(2),'schema'),(1,bytes([99])*32,'genesis'),(5,bytes(32),'agent'),(6,bytes(32),'key'),(7,bytes(32),'capability-absent'),(8,bytes(4),'empty-lanes'),(8,vector_u16([0]),'zero-lane'),(8,vector_u16([2]),'outside-lane'),(8,vector_u16([256,1]),'unsorted-lanes'),(8,vector_u16([1,1]),'duplicate-lanes'),(9,bytes([255])*8,'start-at-max-valid'),(11,bytes(8),'zero-operations'),(11,struct.pack('<Q',101),'excess-operations'),(12,bytes(8),'generation-zero'),(12,bytes([255])*8,'generation-max')]:
        add('session-invalid-or-boundary-'+label,frame(19,expected=17,body=grant_command(fixture.replace_field(37,session,field,value),session=True)),database=cap_database)
    add('session-unknown-agent-before-capability',frame(19,expected=17,body=grant_command(fixture.replace_field(37,session,7,bytes(32)),unknown_auth,True)),database=cap_database)
    add('session-capability-before-bounds',frame(19,expected=17,body=grant_command(fixture.replace_field(37,session,5,bytes(32)),session=True)))
    changed_state=fixture.replace_field(36,cap_state,4,b'\1')
    add('session-inactive-capability',frame(19,expected=17,body=grant_command(session,session=True)),[('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_kind=2',(changed_state,))],database=cap_database)
    add('session-malformed-capability-state-before-bounds',frame(19,expected=17,body=grant_command(fixture.replace_field(37,session,5,bytes(32)),session=True)),[('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_kind=2',(b'',))],database=cap_database)
    for body,label in [(grant_command(cap),'capability'),(grant_command(session,session=True),'session')]:
        add(label+'-missing-path',frame(19,expected=17,body=body),database='absent')
        add(label+'-decode-before-missing-path',frame(19,expected=17,body=body[:-1]),database='absent')
        add(label+'-missing-table',frame(19,expected=17,body=body),[('DROP TABLE agent_market_objects_v1',())])
    charge=fixture.value(42,0)
    for field,value in [(0,vector([bytes([8])*32+(1).to_bytes(16,'little')])),(1,(1).to_bytes(16,'little')),*[(i,struct.pack('<Q',1)) for i in range(2,6)]]:charge=fixture.replace_field(42,charge,field,value)
    def budget_state(changes,state=cap_state):
        a,b=fixture.fields(36,state)[9];part=state[a:b]
        for field,value in changes:part=fixture.replace_field(35,part,field,value)
        return fixture.replace_field(36,state,9,part)
    def asset_counter(changes,state=cap_state,index=0):
        a,b=fixture.fields(36,state)[9];part=state[a:b];a,b=fixture.fields(35,part)[5];counters=part[a:b]
        item=counters[4+index*80:4+(index+1)*80]
        for field,value in changes:item=fixture.replace_field(34,item,field,value)
        counters=counters[:4+index*80]+item+counters[4+(index+1)*80:]
        return budget_state([(5,counters)],state)
    def budget_case(label,body=cap,state=cap_state,requested=charge,height=17):add('budget-'+label,frame(20,expected=height,body=body,state=state,command=requested),database='absent')
    for height in [0,17,21,22,(1<<64)-1]:budget_case('height-'+str(height),height=height)
    for operations in [0,2,(1<<64)-1]:budget_case('operations-'+str(operations),requested=fixture.replace_field(42,charge,5,struct.pack('<Q',operations)))
    empty_assets=fixture.replace_field(42,charge,0,bytes(4));budget_case('empty-assets',requested=empty_assets)
    for label,values in [('two',[bytes([8])*32+(1).to_bytes(16,'little'),bytes([9])*32+(1).to_bytes(16,'little')]),('duplicate',[bytes([8])*32+(1).to_bytes(16,'little')]*2),('same-key',[bytes([8])*32+(1).to_bytes(16,'little'),bytes([8])*32+(2).to_bytes(16,'little')]),('unsorted',[bytes([9])*32+(1).to_bytes(16,'little'),bytes([8])*32+(1).to_bytes(16,'little')]),('outside',[bytes([7])*32+(1).to_bytes(16,'little')]),('second-exceeded',[bytes([8])*32+(1).to_bytes(16,'little'),bytes([9])*32+(1001).to_bytes(16,'little')])]:budget_case('asset-'+label,requested=fixture.replace_field(42,charge,0,vector(values)))
    for amount in [0,(1<<64)-1,1<<64,1<<127,(1<<128)-1]:budget_case('asset-amount-'+str(amount),requested=fixture.replace_field(42,charge,0,vector([bytes([8])*32+amount.to_bytes(16,'little')])))
    for spent,reserved,amount,label in [((1<<64)-1,0,1,'carry'),((1<<128)-1,1,0,'reserved-overflow'),((1<<128)-1,0,1,'requested-overflow'),(1000,0,0,'at-limit'),(1000,0,1,'exceeded')]:
        changed=asset_counter([(1,((1<<128)-1 if label!='exceeded' and label!='at-limit' else 1000).to_bytes(16,'little')),(2,spent.to_bytes(16,'little')),(3,reserved.to_bytes(16,'little'))])
        budget_case('asset-'+label,state=changed,requested=fixture.replace_field(42,charge,0,vector([bytes([8])*32+amount.to_bytes(16,'little')])))
    counter_a=bytes([8])*32+bytes(48);counter_b=bytes([8])*32+bytes([255])*16+bytes(32)
    budget_case('counter-first-match',state=budget_state([(5,vector([counter_a,counter_b]))]))
    budget_case('counter-unordered-not-rejected',state=budget_state([(5,vector([bytes([9])*32+bytes(48),counter_b]))]))
    for spent,reserved,amount,limit,label in [((1<<64)-1,0,1,(1<<128)-1,'carry'),((1<<128)-1,1,0,(1<<128)-1,'reserved-overflow'),((1<<128)-1,0,1,(1<<128)-1,'requested-overflow'),(1000,0,0,1000,'at-limit'),(1000,0,1,1000,'exceeded'),(0,0,(1<<128)-1,(1<<128)-1,'full-u128')]:
        changed=budget_state([(6,limit.to_bytes(16,'little')),(7,spent.to_bytes(16,'little')),(8,reserved.to_bytes(16,'little'))])
        budget_case('fee-'+label,state=changed,requested=fixture.replace_field(42,charge,1,amount.to_bytes(16,'little')))
    for i,label in enumerate(['gas','da','retention','operations']):
        for spent,reserved,amount,limit,suffix in [((1<<64)-1,1,0,(1<<64)-1,'reserved-overflow'),((1<<64)-1,0,1,(1<<64)-1,'requested-overflow'),(99,0,1,100,'at-limit'),(100,0,1,100,'exceeded')]:
            if i==3:amount=1
            changed=budget_state([(9+3*i,struct.pack('<Q',limit)),(10+3*i,struct.pack('<Q',spent)),(11+3*i,struct.pack('<Q',reserved))])
            requested=fixture.replace_field(42,charge,2+i,struct.pack('<Q',amount));budget_case(label+'-'+suffix,state=changed,requested=requested)
    for start,counter,height,label in [((1<<64)-1,0,(1<<64)-1,'window-overflow'),(17,(1<<64)-1,17,'counter-overflow'),(17,(1<<64)-1,22,'reset-counter'),(17,32,17,'rate-exceeded'),(17,31,17,'rate-at-limit')]:
        budget_case(label,state=budget_state([(21,struct.pack('<Q',start)),(22,struct.pack('<Q',counter))]),height=height)
    budget_case('zero-window-private-body',body=fixture.replace_field(33,cap,21,bytes(8)),state=budget_state([(22,bytes([255])*8)]))
    budget_case('budget-version-overflow',state=budget_state([(3,bytes([255])*8)]))
    budget_case('capability-version-overflow',state=fixture.replace_field(36,cap_state,3,bytes([255])*8))
    budget_case('budget-version-before-capability',state=budget_state([(3,bytes([255])*8)],fixture.replace_field(36,cap_state,3,bytes([255])*8)))
    bad_assets=fixture.replace_field(42,charge,0,vector([bytes([8])*32+(1).to_bytes(16,'little')]*2))
    budget_case('operation-before-sort',requested=fixture.replace_field(42,bad_assets,5,bytes(8)))
    budget_case('asset-before-fee',state=budget_state([(6,bytes(16))]),requested=fixture.replace_field(42,charge,0,vector([bytes([7])*32+bytes(16)])))
    budget_case('fee-before-gas',state=budget_state([(6,bytes(16)),(9,bytes(8))]))
    budget_case('gas-before-da',state=budget_state([(9,bytes(8)),(12,bytes(8))]))
    budget_case('da-before-retention',state=budget_state([(12,bytes(8)),(15,bytes(8))]))
    budget_case('retention-before-operations',state=budget_state([(15,bytes(8)),(18,bytes(8))]))
    budget_case('rate-before-version',state=budget_state([(3,bytes([255])*8),(22,struct.pack('<Q',32))]))
    # This is a real >2 MiB typed counter vector, not a synthetic length claim.
    counters=vector([i.to_bytes(32,'little')+(1000).to_bytes(16,'little')+bytes(32) for i in range(32769)])
    requested=fixture.replace_field(42,charge,0,vector([(32768).to_bytes(32,'little')+(1).to_bytes(16,'little')]))
    budget_case('large-counter-vector',state=budget_state([(5,counters)]),requested=requested)
    for part in ['body','state','command']:
        args={'body':cap,'state':cap_state,'command':charge};args[part]=args[part][:-1];add('budget-truncated-'+part,frame(20,**args),database='absent')
    DB.write_bytes(baseline);con=sqlite3.connect(DB)
    funding_id,funding_body,funding_state=con.execute('SELECT object_id,immutable_body,mutable_state FROM agent_market_objects_v1 WHERE object_kind=45').fetchone();con.close()
    a,b=fixture.fields(43,funding_body)[3];asset_id=funding_body[a:b]
    terms=fixture.value(47,0)
    for field,value in [(0,b'\1\0'),(1,asset_id),(2,(100).to_bytes(16,'little')),(3,(80).to_bytes(16,'little')),(4,(5).to_bytes(16,'little')),(5,(5).to_bytes(16,'little')),(6,(5).to_bytes(16,'little')),(7,(3).to_bytes(16,'little')),(8,(2).to_bytes(16,'little')),(9,agent_id)]:terms=fixture.replace_field(47,terms,field,value)
    offer=flatten_context(48,fixture.value(48,0))
    for field,value in [(5,agent_id),(6,bytes(32)),(7,b'\0'),(8,bytes(8)),(9,bytes(2)),(10,bytes(8)),(11,struct.pack('<I',7)+b'compute'),(27,struct.pack('<Q',50)),(28,struct.pack('<Q',100)),(29,struct.pack('<Q',200)),(30,struct.pack('<Q',300))]:offer=fixture.replace_field(48,offer,field,value)
    def task_command(offer=offer,terms=terms,account=funding_id,version=0,authorization=auth,bind=True):
        if bind:
            digest=bytes.fromhex(stage('fixture-task-terms-'+str(report['fixture_preparations']),ORIGINAL,b'terms:'+terms.hex().encode()+b'\n').strip().decode());assert len(digest)==32;report['fixture_preparations']+=1
            offer=fixture.replace_field(48,offer,23,digest)
        body=offer+terms+account+struct.pack('<Q',version)+bytes([99])*32
        return b'\2'+body+charge+authorization
    task_command_valid=task_command()
    for height in [0,17,50,51,(1<<64)-1]:add('task-create-height-'+str(height),frame(19,expected=height,body=task_command_valid))
    records_fixture('task-create',frame(19,expected=17,body=task_command_valid));task_database=DB.read_bytes();report['task_database']=blob(task_database)
    con=sqlite3.connect(DB);task_record=con.execute('SELECT * FROM agent_market_objects_v1 WHERE object_kind=4').fetchone();escrow_record=con.execute('SELECT * FROM agent_market_objects_v1 WHERE object_kind=7').fetchone();con.close()
    add('task-duplicate-rolls-back-account',frame(19,expected=17,body=task_command(version=1)),database=task_database)
    add('escrow-duplicate-rolls-back-account-and-task',frame(19,expected=17,body=task_command_valid),[(insert,escrow_record)])
    for kind in [4,7]:
        add('task-insert-trigger-'+str(kind),frame(19,expected=17,body=task_command_valid),[(f"CREATE TRIGGER fixture_task_abort BEFORE INSERT ON agent_market_objects_v1 WHEN NEW.object_kind={kind} BEGIN SELECT RAISE(ABORT,'task fixture rejected'); END",())])
    add('task-ignored-insert-private-branch',frame(19,expected=17,body=task_command_valid),[("CREATE TRIGGER fixture_task_ignore BEFORE INSERT ON agent_market_objects_v1 WHEN NEW.object_kind=4 BEGIN SELECT RAISE(IGNORE); END",())])
    for field,value,label in [(0,bytes(2),'schema'),(1,bytes([99])*32,'genesis'),(2,struct.pack('<I',1)+b'x','chain'),(5,bytes(32),'requester'),(6,bytes([99])*32,'key'),(7,b'\1'+bytes(32),'capability'),(8,struct.pack('<Q',1),'generation'),(9,b'\1\0','lane'),(10,struct.pack('<Q',1),'nonce'),(11,bytes(4),'empty-kind'),(27,struct.pack('<Q',16),'expired'),(28,struct.pack('<Q',49),'start-order'),(29,struct.pack('<Q',99),'result-order'),(30,struct.pack('<Q',199),'settlement-order')]:
        add('task-offer-'+label,frame(19,expected=17,body=task_command(offer=fixture.replace_field(48,offer,field,value))))
    add('task-wrong-escrow-hash',frame(19,expected=17,body=task_command(bind=False)))
    for field,value,label in [(0,bytes(2),'schema'),(9,bytes(32),'refund'),(2,(99).to_bytes(16,'little'),'allocation-exceeds'),(3,bytes([255])*16,'allocation-overflow')]:add('task-terms-'+label,frame(19,expected=17,body=task_command(terms=fixture.replace_field(47,terms,field,value))))
    wrong_offer=fixture.replace_field(48,offer,5,bytes(32))
    add('task-binding-before-missing-account',frame(19,expected=17,body=task_command(offer=wrong_offer,account=bytes(32))))
    overallocated=fixture.replace_field(47,terms,2,(1).to_bytes(16,'little'))
    add('task-allocation-before-missing-account',frame(19,expected=17,body=task_command(terms=overallocated,account=bytes(32))))
    add('task-account-absent',frame(19,expected=17,body=task_command(account=bytes(32))))
    add('task-account-version-stale',frame(19,expected=17,body=task_command(version=1)))
    for field,value,label in [(3,struct.pack('<Q',1),'version'),(4,(99).to_bytes(16,'little'),'underfunded'),(7,b'\1','closed'),(5,bytes([255])*16,'total-reserved-overflow'),(6,bytes([255])*16,'total-spent-overflow')]:
        changed=fixture.replace_field(44,funding_state,field,value)
        add('task-account-'+label,frame(19,expected=17,body=task_command_valid),[('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_kind=45',(changed,))])
    for field,label in [(2,'owner'),(3,'asset')]:
        changed=fixture.replace_field(43,funding_body,field,bytes([99])*32)
        add('task-account-wrong-'+label,frame(19,expected=17,body=task_command_valid),[('UPDATE agent_market_objects_v1 SET immutable_body=? WHERE object_kind=45',(changed,))])
    changed=fixture.replace_field(44,funding_state,3,bytes([255])*8)
    add('task-account-version-overflow',frame(19,expected=17,body=task_command(version=(1<<64)-1)),[('UPDATE agent_market_objects_v1 SET object_version=?,mutable_state=? WHERE object_kind=45',(bytes([255])*8,changed))])
    changed=fixture.replace_field(44,funding_state,4,(1<<64).to_bytes(16,'little'))
    add('task-u128-subtraction-borrow',frame(19,expected=17,body=task_command_valid),[('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_kind=45',(changed,))])
    maximal_terms=terms
    for field in range(2,9):maximal_terms=fixture.replace_field(47,maximal_terms,field,bytes([255])*16 if field in [2,3] else bytes(16))
    changed=fixture.replace_field(44,funding_state,4,bytes([255])*16)
    add('task-full-u128-funding',frame(19,expected=17,body=task_command(terms=maximal_terms)),[('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_kind=45',(changed,))])
    zero_terms=terms
    for field in range(2,9):zero_terms=fixture.replace_field(47,zero_terms,field,bytes(16))
    add('task-zero-funded-private-branch',frame(19,expected=17,body=task_command(terms=zero_terms)))
    max_offer=offer
    for field in range(27,31):max_offer=fixture.replace_field(48,max_offer,field,bytes([255])*8)
    add('task-full-u64-deadlines',frame(19,expected=(1<<64)-1,body=task_command(offer=max_offer)))
    large_kind=b't'*((1<<21)+257);large_offer=fixture.replace_field(48,offer,11,struct.pack('<I',len(large_kind))+large_kind)
    add('task-kind-larger-than-2mib',frame(19,expected=17,body=task_command(offer=large_offer)))
    add('task-missing-table',frame(19,expected=17,body=task_command_valid),[('DROP TABLE agent_market_objects_v1',())])
    add('task-malformed-account-before-funding',frame(19,expected=17,body=task_command_valid),[('UPDATE agent_market_objects_v1 SET immutable_body=?,mutable_state=? WHERE object_kind=45',(b'',b''))])
    add('task-missing-path',frame(19,expected=17,body=task_command_valid),database='absent')
    add('task-decode-before-missing-path',frame(19,expected=17,body=task_command_valid[:-1]),database='absent')
    provider_agent=bundle[bs[5][0]:bs[5][1]][:32];bond_id=bundle[bs[10][0]:bs[10][1]]
    provider_auth=fixture.replace_field(59,auth,4,provider_agent)
    bid=flatten_context(54,fixture.value(54,0))
    for field,value in [(5,task_record[1]),(6,bytes(8)),(7,provider_agent),(8,bytes(32)),(9,b'\0'),(10,bytes(8)),(11,bytes(2)),(12,bytes(8)),(13,asset_id),(14,(50).to_bytes(16,'little')),(18,bond_id),(21,struct.pack('<Q',60))]:bid=fixture.replace_field(54,bid,field,value)
    def bid_command(body=bid,authorization=provider_auth):return b'\3'+body+charge+authorization
    for height in [0,17,50,51,60,61,(1<<64)-1]:add('bid-height-'+str(height),frame(19,expected=height,body=bid_command()),database=task_database)
    DB.write_bytes(task_database);records_fixture('bid',frame(19,expected=17,body=bid_command()));bid_database=DB.read_bytes();report['bid_database']=blob(bid_database)
    con=sqlite3.connect(DB);bid_record=con.execute('SELECT * FROM agent_market_objects_v1 WHERE object_kind=5').fetchone();bond_record=con.execute('SELECT * FROM agent_market_objects_v1 WHERE object_kind=47').fetchone();con.close()
    add('bid-duplicate',frame(19,expected=17,body=bid_command()),database=bid_database)
    for field,value,label in [(0,bytes(2),'schema'),(1,bytes([99])*32,'genesis'),(5,bytes(32),'task-absent'),(6,struct.pack('<Q',1),'revision'),(7,bytes(32),'provider'),(8,bytes([99])*32,'key'),(9,b'\1'+bytes(32),'capability'),(10,struct.pack('<Q',1),'generation'),(11,b'\1\0','lane'),(12,struct.pack('<Q',1),'nonce'),(13,bytes([99])*32,'price-asset'),(14,bytes(16),'zero-price'),(14,(80).to_bytes(16,'little'),'price-at-cap'),(14,(81).to_bytes(16,'little'),'price-above-cap'),(18,bytes(32),'bond-absent'),(21,struct.pack('<Q',16),'expired')]:
        add('bid-body-'+label,frame(19,expected=17,body=bid_command(fixture.replace_field(54,bid,field,value))),database=task_database)
    bad_bid=fixture.replace_field(54,bid,7,bytes(32))
    for kind,label in [(4,'task'),(7,'escrow'),(47,'bond')]:
        add('bid-missing-'+label+'-before-binding',frame(19,expected=17,body=bid_command(bad_bid)),[('DELETE FROM agent_market_objects_v1 WHERE object_kind=?',(kind,))],database=task_database)
        for column in ['immutable_body','mutable_state']:
            add('bid-'+label+'-malformed-'+column,frame(19,expected=17,body=bid_command(bad_bid)),[('UPDATE agent_market_objects_v1 SET '+column+'=? WHERE object_kind=?',(b'',kind))],database=task_database)
    add('bid-context-before-missing-task',frame(19,expected=17,body=bid_command(fixture.replace_field(54,bad_bid,0,bytes(2)))),[('DELETE FROM agent_market_objects_v1 WHERE object_kind=4',())],database=task_database)
    for field,value,label in [(3,struct.pack('<Q',1),'revision'),(5,b'\1','status'),(4,bytes([255])*4,'ignored-attempt')]:
        changed=fixture.replace_field(50,task_record[4],field,value)
        add('bid-task-state-'+label,frame(19,expected=17,body=bid_command()),[('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_kind=4',(changed,))],database=task_database)
    changed=fixture.replace_field(48,task_record[3],27,struct.pack('<Q',16))
    add('bid-task-offer-expired',frame(19,expected=17,body=bid_command()),[('UPDATE agent_market_objects_v1 SET immutable_body=? WHERE object_kind=4',(changed,))],database=task_database)
    for field,value,label in [(4,(99).to_bytes(16,'little'),'underfunded'),(4,(100).to_bytes(16,'little'),'at-hold'),(8,b'\1','closed')]:
        changed=fixture.replace_field(46,bond_record[4],field,value)
        add('bid-bond-'+label,frame(19,expected=17,body=bid_command()),[('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_kind=47',(changed,))],database=task_database)
    changed=fixture.replace_field(45,bond_record[3],2,bytes([99])*32)
    add('bid-bond-wrong-owner',frame(19,expected=17,body=bid_command()),[('UPDATE agent_market_objects_v1 SET immutable_body=? WHERE object_kind=47',(changed,))],database=task_database)
    changed=fixture.replace_field(53,escrow_record[4],12,b'\1')
    add('bid-private-branch-ignores-escrow-closed',frame(19,expected=17,body=bid_command()),[('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_kind=7',(changed,))],database=task_database)
    changed=fixture.replace_field(51,escrow_record[3],9,bytes([255])*16)
    add('bid-full-u128-price',frame(19,expected=17,body=bid_command(fixture.replace_field(54,bid,14,bytes([255])*16))),[('UPDATE agent_market_objects_v1 SET immutable_body=? WHERE object_kind=7',(changed,))],database=task_database)
    changed=fixture.replace_field(48,task_record[3],27,bytes([255])*8)
    add('bid-full-u64-height',frame(19,expected=(1<<64)-1,body=bid_command(fixture.replace_field(54,bid,21,bytes([255])*8))),[('UPDATE agent_market_objects_v1 SET immutable_body=? WHERE object_kind=4',(changed,))],database=task_database)
    add('bid-insert-ignored-private-branch',frame(19,expected=17,body=bid_command()),[("CREATE TRIGGER fixture_bid_ignore BEFORE INSERT ON agent_market_objects_v1 WHEN NEW.object_kind=5 BEGIN SELECT RAISE(IGNORE); END",())],database=task_database)
    add('bid-missing-path',frame(19,expected=17,body=bid_command()),database='absent')
    add('bid-decode-before-missing-path',frame(19,expected=17,body=bid_command()[:-1]),database='absent')
    def field_bytes(kind,raw,index):
        start,end=fixture.fields(kind,raw)[index];return raw[start:end]
    lease=flatten_context(56,fixture.value(56,0))
    for field,value in [(5,task_record[1]),(6,bytes(8)),(7,bytes(4)),(8,bid_record[1]),(9,agent_id),(10,provider_agent),(11,escrow_record[1]),(12,bond_id),(14,field_bytes(54,bid,17)),(15,field_bytes(48,task_record[3],16)),(16,field_bytes(48,task_record[3],17)),(17,field_bytes(48,task_record[3],18)),(18,field_bytes(54,bid,15)),(19,field_bytes(54,bid,19)),(20,field_bytes(54,bid,20)),(21,struct.pack('<Q',100)),(22,struct.pack('<Q',150)),(23,struct.pack('<Q',200))]:lease=fixture.replace_field(56,lease,field,value)
    def lease_command(body=lease,versions=(0,0,0),authorization=auth):return b'\4'+body+struct.pack('<3Q',*versions)+charge+authorization
    for height in [0,17,60,61,(1<<64)-1]:add('lease-height-'+str(height),frame(19,expected=height,body=lease_command()),database=bid_database)
    DB.write_bytes(bid_database);records_fixture('lease',frame(19,expected=17,body=lease_command()));lease_database=DB.read_bytes();report['lease_database']=blob(lease_database)
    con=sqlite3.connect(DB);lease_record=con.execute('SELECT * FROM agent_market_objects_v1 WHERE object_kind=6').fetchone();leased_task_record=con.execute('SELECT * FROM agent_market_objects_v1 WHERE object_kind=4').fetchone();con.close()
    add('lease-duplicate-rolls-back-four-updates',frame(19,expected=17,body=lease_command()),[(insert,lease_record)],database=bid_database)
    bad_lease=fixture.replace_field(56,lease,9,bytes(32))
    for kind,label in [(4,'task'),(5,'bid'),(7,'escrow'),(47,'bond')]:
        add('lease-missing-'+label+'-before-binding',frame(19,expected=17,body=lease_command(bad_lease)),[('DELETE FROM agent_market_objects_v1 WHERE object_kind=?',(kind,))],database=bid_database)
        for column in ['immutable_body','mutable_state']:
            add('lease-'+label+'-malformed-'+column,frame(19,expected=17,body=lease_command(bad_lease)),[('UPDATE agent_market_objects_v1 SET '+column+'=? WHERE object_kind=?',(b'',kind))],database=bid_database)
    add('lease-context-before-missing-task',frame(19,expected=17,body=lease_command(fixture.replace_field(56,bad_lease,0,bytes(2)))),[('DELETE FROM agent_market_objects_v1 WHERE object_kind=4',())],database=bid_database)
    for field,value,label in [(0,bytes(2),'schema'),(1,bytes(32),'genesis'),(5,bytes(32),'task-absent'),(6,struct.pack('<Q',1),'revision'),(7,struct.pack('<I',1),'attempt'),(8,bytes(32),'bid-absent'),(9,bytes(32),'requester'),(10,bytes(32),'provider'),(11,bytes(32),'escrow-absent'),(12,bytes(32),'bond-absent'),(14,bytes(32),'environment'),(16,bytes([255])*4,'profile-version'),(17,bytes(32),'profile-hash'),(18,bytes(32),'pricing'),(19,bytes(32),'checkpoint-terms'),(20,bytes(32),'availability'),(21,struct.pack('<Q',101),'start'),(22,struct.pack('<Q',99),'checkpoint-before'),(22,struct.pack('<Q',201),'checkpoint-after'),(22,struct.pack('<Q',100),'checkpoint-at-start'),(22,struct.pack('<Q',200),'checkpoint-at-end'),(23,struct.pack('<Q',201),'result')]:
        add('lease-body-'+label,frame(19,expected=17,body=lease_command(fixture.replace_field(56,lease,field,value))),database=bid_database)
    for versions,label in [((1,0,0),'bid'),((0,1,0),'escrow'),((0,0,1),'bond')]:add('lease-stale-'+label,frame(19,expected=17,body=lease_command(versions=versions)),database=bid_database)
    def lease_mutation(label,kind,type_id,original,changes,versions=(0,0,0),height=17,extra=()):
        value=original
        for field,new in changes:value=fixture.replace_field(type_id,value,field,new)
        column='immutable_body' if type_id in [48,54,51,45] else 'mutable_state'
        sql=[('UPDATE agent_market_objects_v1 SET '+column+'=? WHERE object_kind=?',(value,kind)),*extra]
        add('lease-'+label,frame(19,expected=height,body=lease_command(versions=versions)),sql,database=bid_database)
    for field,value,label in [(3,struct.pack('<Q',1),'task-revision'),(4,struct.pack('<I',1),'task-attempt'),(5,b'\1','task-status'),(6,b'\1'+bytes(32),'task-active'),(9,bytes(32),'task-escrow')]:lease_mutation(label,4,50,task_record[4],[(field,value)])
    lease_mutation('task-requester',4,48,task_record[3],[(5,bytes(32))])
    for field,value,label in [(6,struct.pack('<Q',1),'bid-revision'),(7,bytes(32),'bid-provider'),(14,(81).to_bytes(16,'little'),'bid-above-cap'),(18,bytes(32),'bid-bond'),(21,struct.pack('<Q',16),'bid-expired')]:lease_mutation(label,5,54,bid_record[3],[(field,value)])
    for field,value,label in [(2,bytes(32),'bid-state-id'),(4,b'\1','bid-status')]:lease_mutation(label,5,55,bid_record[4],[(field,value)])
    for field,value,label in [(4,(49).to_bytes(16,'little'),'escrow-underfunded'),(12,b'\1','escrow-closed'),(5,bytes([255])*16,'escrow-reserve-overflow'),(6,bytes([255])*16,'escrow-total-overflow'),(5,(1).to_bytes(16,'little'),'escrow-conservation'),(9,vector([fixture.value(52,0)]),'escrow-reservation-conflict')]:lease_mutation(label,7,53,escrow_record[4],[(field,value)])
    for field,value,label in [(4,(99).to_bytes(16,'little'),'bond-underfunded'),(8,b'\1','bond-closed'),(5,bytes([255])*16,'bond-hold-overflow'),(6,bytes([255])*16,'bond-total-overflow'),(4,(499).to_bytes(16,'little'),'bond-conservation')]:lease_mutation(label,47,46,bond_record[4],[(field,value)])
    lease_mutation('bond-owner',47,45,bond_record[3],[(2,bytes(32))])
    for kind,type_id,record,versions,label in [(5,55,bid_record,((1<<64)-1,0,0),'bid'),(7,53,escrow_record,(0,(1<<64)-1,0),'escrow'),(47,46,bond_record,(0,0,(1<<64)-1),'bond')]:
        lease_mutation(label+'-version-overflow',kind,type_id,record[4],[(3,bytes([255])*8)],versions=versions,extra=[('UPDATE agent_market_objects_v1 SET object_version=? WHERE object_kind=?',(bytes([255])*8,kind))])
    lease_mutation('task-other-options-retained',4,50,task_record[4],[(7,b'\1'+bytes([91])*32),(8,b'\1'+bytes([92])*32)])
    lease_mutation('bid-options-replaced-terminal-retained',5,55,bid_record[4],[(5,b'\1'+bytes([93])*32),(6,b'\1'+bytes([255])*8),(7,b'\1'+struct.pack('<Q',99))])
    lease_mutation('escrow-old-root-replaced-last-retained',7,53,escrow_record[4],[(10,bytes(32)),(11,b'\1'+bytes([94])*32)])
    lease_mutation('full-u64-height',5,54,bid_record[3],[(21,bytes([255])*8)],height=(1<<64)-1)
    full_escrow=fixture.replace_field(51,fixture.replace_field(51,escrow_record[3],8,bytes([255])*16),9,bytes([255])*16)
    full_state=fixture.replace_field(53,escrow_record[4],4,bytes([255])*16)
    full_bid=fixture.replace_field(54,bid_record[3],14,bytes([255])*16)
    add('lease-full-u128-price',frame(19,expected=17,body=lease_command()),[('UPDATE agent_market_objects_v1 SET immutable_body=?,mutable_state=? WHERE object_kind=7',(full_escrow,full_state)),('UPDATE agent_market_objects_v1 SET immutable_body=? WHERE object_kind=5',(full_bid,))],database=bid_database)
    for kind in [4,5,7,47]:
        for behavior in ["IGNORE","ABORT,'lease fixture rejected'"]:
            add('lease-update-'+str(kind)+'-'+behavior,frame(19,expected=17,body=lease_command()),[(f'CREATE TRIGGER fixture_lease_update BEFORE UPDATE ON agent_market_objects_v1 WHEN NEW.object_kind={kind} BEGIN SELECT RAISE({behavior}); END',())],database=bid_database)
        add('lease-row-version-cas-'+str(kind),frame(19,expected=17,body=lease_command()),[('UPDATE agent_market_objects_v1 SET object_version=? WHERE object_kind=?',(struct.pack('<Q',1),kind))],database=bid_database)
    for behavior in ["IGNORE","ABORT,'lease fixture rejected'"]:
        add('lease-insert-'+behavior,frame(19,expected=17,body=lease_command()),[(f'CREATE TRIGGER fixture_lease_insert BEFORE INSERT ON agent_market_objects_v1 WHEN NEW.object_kind=6 BEGIN SELECT RAISE({behavior}); END',())],database=bid_database)
    add('lease-missing-path',frame(19,expected=17,body=lease_command()),database='absent')
    add('lease-decode-before-missing-path',frame(19,expected=17,body=lease_command()[:-1]),database='absent')
    acceptance=fixture.value(58,0)
    for field,value in [(0,b'\1\0'),(1,protocol_context),(2,lease_record[1]),(3,provider_agent),(4,struct.pack('<Q',1))]:acceptance=fixture.replace_field(58,acceptance,field,value)
    def provider_command(body=acceptance,version=0,authorization=provider_auth):return b'\5'+body+struct.pack('<Q',version)+charge+authorization
    for height in [0,17,100,200,(1<<64)-1]:add('provider-height-'+str(height),frame(19,expected=height,body=provider_command()),database=lease_database)
    DB.write_bytes(lease_database);records_fixture('provider-accept',frame(19,expected=17,body=provider_command()));provider_database=DB.read_bytes();report['provider_database']=blob(provider_database)
    add('provider-already-accepted',frame(19,expected=17,body=provider_command(version=1)),database=provider_database)
    bad_acceptance=fixture.replace_field(58,acceptance,3,bytes(32))
    for kind,label in [(6,'lease'),(4,'task')]:
        add('provider-missing-'+label+'-before-binding',frame(19,expected=17,body=provider_command(bad_acceptance)),[('DELETE FROM agent_market_objects_v1 WHERE object_kind=?',(kind,))],database=lease_database)
        for column in ['immutable_body','mutable_state']:
            add('provider-'+label+'-malformed-'+column,frame(19,expected=17,body=provider_command(bad_acceptance)),[('UPDATE agent_market_objects_v1 SET '+column+'=? WHERE object_kind=?',(b'',kind))],database=lease_database)
    for field,value,label in [(0,bytes(2),'schema'),(1,fixture.replace_field(25,protocol_context,0,bytes(32)),'context'),(2,bytes(32),'lease-absent'),(3,bytes(32),'provider'),(4,bytes(8),'task-revision')]:add('provider-body-'+label,frame(19,expected=17,body=provider_command(fixture.replace_field(58,acceptance,field,value))),database=lease_database)
    add('provider-context-before-missing-lease',frame(19,expected=17,body=provider_command(fixture.replace_field(58,bad_acceptance,0,bytes(2)))),[('DELETE FROM agent_market_objects_v1 WHERE object_kind=6',())],database=lease_database)
    add('provider-auth-sender',frame(19,expected=17,body=provider_command(authorization=auth)),database=lease_database)
    add('provider-stale-lease',frame(19,expected=17,body=provider_command(version=1)),database=lease_database)
    def provider_mutation(label,kind,type_id,original,changes,version=0,extra=()):
        value=original
        for field,new in changes:value=fixture.replace_field(type_id,value,field,new)
        column='immutable_body' if type_id in [48,56] else 'mutable_state'
        sql=[('UPDATE agent_market_objects_v1 SET '+column+'=? WHERE object_kind=?',(value,kind)),*extra]
        add('provider-'+label,frame(19,expected=17,body=provider_command(version=version)),sql,database=lease_database)
    for field,value,label in [(3,struct.pack('<Q',2),'task-revision'),(5,b'\0','task-status'),(6,b'\0','task-no-lease'),(6,b'\1'+bytes(32),'task-different-lease')]:provider_mutation(label,4,50,leased_task_record[4],[(field,value)])
    for field,value,label in [(4,struct.pack('<I',1),'lease-attempt'),(5,b'\1','lease-status')]:provider_mutation(label,6,57,lease_record[4],[(field,value)])
    for field,value,label in [(5,bytes(32),'lease-task-absent'),(7,struct.pack('<I',1),'lease-body-attempt'),(10,bytes(32),'lease-provider')]:provider_mutation(label,6,56,lease_record[3],[(field,value)])
    provider_mutation('lease-version-overflow',6,57,lease_record[4],[(3,bytes([255])*8)],version=(1<<64)-1,extra=[('UPDATE agent_market_objects_v1 SET object_version=? WHERE object_kind=6',(bytes([255])*8,))])
    provider_mutation('accepted-option-replaced-other-options-retained',6,57,lease_record[4],[(6,b'\1'+bytes([255])*8),(7,b'\1'+struct.pack('<Q',81)),(8,b'\1'+struct.pack('<Q',82)),(9,b'\1'+bytes([83])*32)])
    provider_mutation('private-branch-does-not-add-state-id-check',6,57,lease_record[4],[(2,bytes([84])*32)])
    provider_mutation('private-branch-does-not-add-state-schema-check',6,57,lease_record[4],[(0,bytes(2))])
    max_attempt=fixture.replace_field(56,lease_record[3],7,bytes([255])*4)
    provider_mutation('full-u32-attempt',6,57,lease_record[4],[(4,bytes([255])*4)],extra=[('UPDATE agent_market_objects_v1 SET immutable_body=? WHERE object_kind=6',(max_attempt,))])
    add('provider-row-version-cas',frame(19,expected=17,body=provider_command()),[('UPDATE agent_market_objects_v1 SET object_version=? WHERE object_kind=6',(struct.pack('<Q',1),))],database=lease_database)
    for behavior in ["IGNORE","ABORT,'provider fixture rejected'"]:
        add('provider-update-'+behavior,frame(19,expected=17,body=provider_command()),[(f'CREATE TRIGGER fixture_provider_update BEFORE UPDATE ON agent_market_objects_v1 WHEN NEW.object_kind=6 BEGIN SELECT RAISE({behavior}); END',())],database=lease_database)
    add('provider-missing-path',frame(19,expected=17,body=provider_command()),database='absent')
    add('provider-decode-before-missing-path',frame(19,expected=17,body=provider_command()[:-1]),database='absent')
    # The frozen v13 ELF confused statement fields 7 and 9. These are separate
    # live-capability and session generations, including their full u64 domains.
    def generation_command(raw,live,session,body_generation=None):
        variant=raw[0]
        if body_generation is not None:
            assert variant in [2,3]
            raw=fixture.replace_field(48 if variant==2 else 54,raw,8 if variant==2 else 10,struct.pack('<Q',body_generation),p=1)
        auth_index=[1,1,2,2,5,3][variant];start=fixture.fields(68+variant,raw,1)[auth_index][0]
        raw=fixture.replace_field(59,raw,7,struct.pack('<Q',live),p=start)
        return fixture.replace_field(59,raw,9,struct.pack('<Q',session),p=start)
    for name,command,database in [('task',task_command_valid,'baseline'),('bid',bid_command(),task_database)]:
        for body_generation in [0,1,(1<<64)-1]:
            for live in [0,1,(1<<64)-1]:
                for session_generation in [0,1,(1<<64)-1]:
                    add(name+'-generation-'+str((body_generation,live,session_generation)),frame(19,expected=17,body=generation_command(command,live,session_generation,body_generation)),database=database)
    for name,command,database in [('lease',lease_command(),bid_database),('provider',provider_command(),lease_database)]:
        for live in [0,1,(1<<64)-1]:
            for session_generation in [0,1,(1<<64)-1]:
                add(name+'-generation-'+str((live,session_generation)),frame(19,expected=17,body=generation_command(command,live,session_generation)),database=database)
    def value_id(kind,value):
        raw=stage('fixture-value-id-'+str(report['fixture_preparations']),ORIGINAL,b'value-id:'+str(kind).encode()+b':'+value.hex().encode()+b'\n');report['fixture_preparations']+=1
        result=bytes.fromhex(raw.strip().decode());assert len(result)==32;return result
    task_resource=field_bytes(48,task_record[3],21)
    scopes=[fixture.replace_field(30,fixture.value(30,0),0,struct.pack('<H',kind)) for kind in [4,5,6,7]]
    scope_resource=fixture.replace_field(31,resource,2,vector([task_resource]))
    scope_cap=fixture.replace_field(33,fixture.replace_field(33,cap,11,vector(scopes)),12,vector([scope_resource]))
    scope_commands=[('task',task_command_valid,'baseline'),('bid',bid_command(),task_database),('lease',lease_command(),bid_database),('provider',provider_command(),lease_database)]
    def scope_case(label,command,capability=scope_cap,database='baseline',sql=()):add('scope-'+label,frame(22,body=capability,command=command),sql,database=database)
    for name,command,database in scope_commands:
        scope_case(name,command,database=database)
        scope_case(name+'-absent-kind',command,fixture.replace_field(33,scope_cap,11,bytes(4)),database)
        scope_case(name+'-no-resource',command,fixture.replace_field(33,scope_cap,12,bytes(4)),database)
        variant=command[0];selected=scopes[variant-2]
        for field,value,label in [(1,b'\1'+bytes([91])*32,'task-id'),(2,b'\1'+bytes(32),'market'),(3,b'\1'+bytes([92])*32,'model'),(4,b'\1'+bytes([93])*32,'tool'),(5,b'\1'+bytes(32),'endpoint'),(7,b'\1'+bytes([byte^255 for byte in field_bytes(48,task_record[3],19)]),'privacy'),(8,b'\1'+(49).to_bytes(16,'little'),'price-below'),(8,b'\1'+(50).to_bytes(16,'little'),'price-at'),(8,b'\1'+bytes([255])*16,'price-max')]:
            changed=fixture.replace_field(33,scope_cap,11,vector([fixture.replace_field(30,selected,field,value)]));scope_case(name+'-'+label,command,changed,database)
        profile=b''.join(field_bytes(48,task_record[3],n) for n in [16,17,18])
        for new_profile,label in [(profile,'profile-exact'),(fixture.replace_field(29,profile,1,bytes([255])*4),'profile-version')]:
            changed=fixture.replace_field(33,scope_cap,11,vector([fixture.replace_field(30,selected,6,b'\1'+new_profile)]));scope_case(name+'-'+label,command,changed,database)
        wrong=fixture.replace_field(30,selected,1,b'\1'+bytes(32))
        scope_case(name+'-first-matching-bad',command,fixture.replace_field(33,scope_cap,11,vector([wrong,selected])),database)
        scope_case(name+'-first-matching-good',command,fixture.replace_field(33,scope_cap,11,vector([selected,wrong])),database)
        for kind,label in ([(4,'task')] if variant==3 else [(4,'task'),(5,'bid')] if variant==4 else [(6,'lease'),(4,'task'),(5,'bid')] if variant==5 else []):
            scope_case(name+'-missing-'+label+'-before-scope-binding',command,fixture.replace_field(33,scope_cap,11,vector([wrong])),database,[('DELETE FROM agent_market_objects_v1 WHERE object_kind=?',(kind,))])
            for column in ['immutable_body','mutable_state']:scope_case(name+'-decode-'+label+'-'+column,command,scope_cap,database,[('UPDATE agent_market_objects_v1 SET '+column+'=? WHERE object_kind=?',(b'',kind))])
    for field,value,label in [(1,b'\1','mode'),(2,bytes(4),'empty-ids'),(2,vector([bytes([97])*32]),'wrong-id'),(3,b'\1'+bytes(32),'ignored-allowlist-commitment')]:scope_case('resource-'+label,task_command_valid,fixture.replace_field(33,scope_cap,12,vector([fixture.replace_field(31,scope_resource,field,value)])))
    wrong_resource=fixture.replace_field(31,scope_resource,2,bytes(4))
    scope_case('first-resource-bad',task_command_valid,fixture.replace_field(33,scope_cap,12,vector([wrong_resource,scope_resource])))
    scope_case('first-resource-good',task_command_valid,fixture.replace_field(33,scope_cap,12,vector([scope_resource,wrong_resource])))
    for variant,command in [(0,grant_command(cap)),(1,grant_command(session,session=True))]:
        selected=fixture.replace_field(30,fixture.value(30,0),0,struct.pack('<H',variant+2));scope_case('controller-'+str(variant),command,fixture.replace_field(33,scope_cap,11,vector([selected])))
    scope_case('large-task-hash',fixture.replace_field(48,task_command_valid,11,struct.pack('<I',len(large_kind))+large_kind,p=1))
    large_ids=vector([i.to_bytes(32,'little') for i in range(65537)]+[task_resource])
    scope_case('large-resource-list',task_command_valid,fixture.replace_field(33,scope_cap,12,vector([fixture.replace_field(31,scope_resource,2,large_ids)])))
    scope_case('task-no-table-needed',task_command_valid,sql=[('DROP TABLE agent_market_objects_v1',())])
    for variant,command,database in scope_commands:
        add('authorize-controller-namespace-'+variant,frame(21,expected=17,body=command),database=database)
    for command,label in [(grant_command(cap),'capability'),(grant_command(session,session=True),'session')]:
        add('authorize-controller-'+label,frame(21,expected=17,body=command))
        for field,value,suffix in [(5,bytes([1])*32,'key'),(6,b'\1'+cap_id,'capability'),(7,struct.pack('<Q',42),'live-generation'),(8,b'\1'+bytes(32),'session'),(9,struct.pack('<Q',1),'session-generation'),(10,b'\1\0','lane')]:
            changed=fixture.replace_field(59,auth,field,value);bad=grant_command(cap if label=='capability' else session,changed,session=label=='session')
            add('authorize-controller-'+label+'-'+suffix,frame(21,expected=17,body=bad),[('DROP TABLE agent_market_objects_v1',())])
    DB.write_bytes(baseline);con=sqlite3.connect(DB);lane_rows=con.execute('SELECT * FROM agent_market_objects_v1 WHERE object_kind=44').fetchall();con.close()
    controller_lane=next(r for r in lane_rows if field_bytes(39,r[3],2)==agent_id)
    for field,value,label in [(2,bytes(32),'id'),(3,struct.pack('<Q',1),'version'),(9,struct.pack('<Q',1),'replay'),(11,b'\1','status'),(4,bytes([91])*32,'ignored-copied-agent')]:
        changed=fixture.replace_field(40,controller_lane[4],field,value);add('authorize-lane-'+label,frame(21,expected=17,body=grant_command(cap)),[('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_id=?',(changed,controller_lane[1]))])
    for field,value,label in [(11,struct.pack('<Q',1),'gap'),(12,struct.pack('<Q',1),'expected-version'),(4,bytes(32),'sender-absent')]:add('authorize-statement-'+label,frame(21,expected=17,body=grant_command(cap,fixture.replace_field(59,auth,field,value))))
    changed=fixture.replace_field(40,controller_lane[4],9,bytes([255])*8);max_auth=fixture.replace_field(59,auth,11,bytes([255])*8)
    add('authorize-nonce-max-without-consume-overflow',frame(21,expected=17,body=grant_command(cap,max_auth)),[('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_id=?',(changed,controller_lane[1]))])
    changed=fixture.replace_field(39,controller_lane[3],0,bytes(2));add('authorize-lane-body-exact',frame(21,expected=17,body=grant_command(cap)),[('UPDATE agent_market_objects_v1 SET immutable_body=? WHERE object_id=?',(changed,controller_lane[1]))])
    DB.write_bytes(session_database);con=sqlite3.connect(DB);session_record=con.execute('SELECT * FROM agent_market_objects_v1 WHERE object_kind=3').fetchone();session_lanes=con.execute('SELECT * FROM agent_market_objects_v1 WHERE object_kind=44').fetchall();con.close()
    delegated_lane=next(r for r in session_lanes if field_bytes(39,r[3],6)==b'\1\0')
    session_authorization=auth
    for field,value in [(5,session_key),(6,b'\1'+cap_id),(7,struct.pack('<Q',42)),(8,b'\1'+session_record[1]),(9,struct.pack('<Q',1)),(10,b'\1\0')]:session_authorization=fixture.replace_field(59,session_authorization,field,value)
    authorized_task=fixture.replace_field(70,task_command_valid,2,session_authorization,p=1)
    for field,value in [(6,session_key),(7,b'\1'+cap_id),(8,struct.pack('<Q',1)),(9,b'\1\0'),(21,bytes([7])*32)]:authorized_task=fixture.replace_field(48,authorized_task,field,value,p=1)
    def authorize_case(label,command=authorized_task,sql=(),height=17,database=session_database):add('authorize-'+label,frame(21,expected=height,body=command),sql,database=database)
    for height in [0,17,(1<<64)-1]:authorize_case('delegated-height-'+str(height),height=height)
    for field,value,label in [(5,bytes(32),'sentinel'),(6,b'\0','missing-cap'),(8,b'\0','missing-session'),(9,bytes(8),'zero-generation'),(10,bytes(2),'zero-lane')]:
        changed=fixture.replace_field(59,session_authorization,field,value);authorize_case('namespace-'+label,fixture.replace_field(70,authorized_task,2,changed,p=1),[('DROP TABLE agent_market_objects_v1',())])
    for field,value,label in [(7,bytes(8),'cap-generation'),(9,struct.pack('<Q',2),'session-generation'),(10,b'\2\0','lane-absent'),(11,struct.pack('<Q',1),'nonce-gap')]:
        changed=fixture.replace_field(59,session_authorization,field,value);authorize_case('statement-'+label,fixture.replace_field(70,authorized_task,2,changed,p=1))
    for kind,label in [(44,'lane'),(2,'capability'),(3,'session')]:
        authorize_case('missing-'+label,sql=[('DELETE FROM agent_market_objects_v1 WHERE object_kind=?',(kind,))])
        for column in ['immutable_body','mutable_state']:authorize_case('decode-'+label+'-'+column,sql=[('UPDATE agent_market_objects_v1 SET '+column+'=? WHERE object_kind=?',(b'',kind))])
    bad_cap=fixture.replace_field(36,cap_state,4,b'\1')
    authorize_case('session-load-before-capability-reject',sql=[('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_kind=2',(bad_cap,)),('DELETE FROM agent_market_objects_v1 WHERE object_kind=3',())])
    for kind,type_id,value,column,changes,label in [(2,36,cap_state,'mutable_state',[(4,b'\1')],'cap-status'),(2,36,cap_state,'mutable_state',[(5,struct.pack('<Q',41))],'cap-generation'),(2,33,cap,'immutable_body',[(25,struct.pack('<Q',41))],'cap-body-generation'),(2,33,cap,'immutable_body',[(7,bytes(32))],'cap-delegate'),(2,33,cap,'immutable_body',[(19,struct.pack('<Q',18))],'cap-future'),(2,33,cap,'immutable_body',[(20,struct.pack('<Q',16))],'cap-expired'),(3,38,session_record[4],'mutable_state',[(4,b'\1')],'session-status'),(3,38,session_record[4],'mutable_state',[(5,struct.pack('<Q',2))],'session-generation'),(3,38,session_record[4],'mutable_state',[(6,struct.pack('<Q',41))],'session-bound-generation'),(3,38,session_record[4],'mutable_state',[(7,struct.pack('<Q',50))],'session-exhausted'),(3,37,session_record[3],'immutable_body',[(13,bytes([99])*32)],'session-id'),(3,37,session_record[3],'immutable_body',[(5,bytes(32))],'session-agent'),(3,37,session_record[3],'immutable_body',[(6,bytes(32))],'session-key'),(3,37,session_record[3],'immutable_body',[(7,bytes(32))],'session-capability')]:
        for field,new in changes:value=fixture.replace_field(type_id,value,field,new)
        authorize_case(label,sql=[('UPDATE agent_market_objects_v1 SET '+column+'=? WHERE object_kind=?',(value,kind))])
    for field,value,label in [(11,bytes(4),'scope-before-resource'),(12,bytes(4),'resource')]:authorize_case(label,sql=[('UPDATE agent_market_objects_v1 SET immutable_body=? WHERE object_kind=2',(fixture.replace_field(33,cap,field,value),))])
    def consume_case(label,command=grant_command(cap),sql=(),height=17,database='baseline'):add('consume-'+label,frame(23,expected=height,body=command),sql,database=database)
    consume_case('controller')
    DB.write_bytes(baseline);records_fixture('consume-controller',frame(23,expected=17,body=grant_command(cap)));controller_consumed=DB.read_bytes();report['controller_consumed_database']=blob(controller_consumed)
    consume_case('controller-replay',database=controller_consumed)
    next_auth=fixture.replace_field(59,fixture.replace_field(59,auth,11,struct.pack('<Q',1)),12,struct.pack('<Q',1))
    consume_case('controller-next',grant_command(cap,next_auth),database=controller_consumed)
    for field,value,label in [(10,b'\1'+bytes([99])*32,'replace-last-digest'),(3,bytes([255])*8,'lane-version-overflow'),(9,bytes([255])*8,'nonce-overflow')]:
        changed=fixture.replace_field(40,controller_lane[4],field,value);authorization=auth;sql=[('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_id=?',(changed,controller_lane[1]))]
        if field==3:
            authorization=fixture.replace_field(59,authorization,12,bytes([255])*8);sql.append(('UPDATE agent_market_objects_v1 SET object_version=? WHERE object_id=?',(bytes([255])*8,controller_lane[1])))
        if field==9:authorization=fixture.replace_field(59,authorization,11,bytes([255])*8)
        consume_case(label,grant_command(cap,authorization),sql)
    both=fixture.replace_field(40,fixture.replace_field(40,controller_lane[4],3,bytes([255])*8),9,bytes([255])*8)
    both_auth=fixture.replace_field(59,fixture.replace_field(59,auth,12,bytes([255])*8),11,bytes([255])*8)
    consume_case('lane-version-before-nonce-overflow',grant_command(cap,both_auth),[('UPDATE agent_market_objects_v1 SET object_version=?,mutable_state=? WHERE object_id=?',(bytes([255])*8,both,controller_lane[1]))])
    consume_case('lane-row-cas',sql=[('UPDATE agent_market_objects_v1 SET object_version=? WHERE object_id=?',(struct.pack('<Q',1),controller_lane[1]))])
    for behavior in ["IGNORE","ABORT,'consume lane fixture'"]:
        consume_case('lane-update-'+behavior,sql=[(f'CREATE TRIGGER fixture_consume_lane BEFORE UPDATE ON agent_market_objects_v1 WHEN NEW.object_kind=44 BEGIN SELECT RAISE({behavior}); END',())])
    exact_charge=fixture.replace_field(42,charge,0,vector([asset_id+(100).to_bytes(16,'little')]))
    consume_task=fixture.replace_field(70,authorized_task,1,exact_charge,p=1)
    counters=field_bytes(35,field_bytes(36,cap_state,9),5)
    funded_counters=vector([asset_id+(1000).to_bytes(16,'little')+bytes(32)])+counters[4:]
    funded_counters=struct.pack('<I',1+struct.unpack_from('<I',counters)[0])+funded_counters[4:]
    funded_cap_state=budget_state([(5,funded_counters)])
    funding_sql=[('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_kind=2',(funded_cap_state,))]
    consume_case('delegated-task',consume_task,funding_sql,database=session_database)
    consume_case('delegated-full-height',consume_task,funding_sql,height=(1<<64)-1,database=session_database)
    for assets,label in [(bytes(4),'none'),(vector([asset_id+(99).to_bytes(16,'little')]),'wrong-amount'),(vector([bytes([99])*32+(100).to_bytes(16,'little')]),'wrong-asset'),(vector([asset_id+(100).to_bytes(16,'little')]*2),'two')]:
        bad=fixture.replace_field(42,exact_charge,0,assets);consume_case('exact-task-charge-'+label,fixture.replace_field(70,consume_task,1,bad,p=1),funding_sql,database=session_database)
    bad_charge=fixture.replace_field(42,fixture.replace_field(42,exact_charge,0,bytes(4)),5,bytes(8))
    consume_case('exact-task-charge-before-operation-count',fixture.replace_field(70,consume_task,1,bad_charge,p=1),funding_sql,database=session_database)
    consume_case('lane-cas-before-task-charge',authorized_task,[*funding_sql,('UPDATE agent_market_objects_v1 SET object_version=? WHERE object_id=?',(struct.pack('<Q',1),delegated_lane[1]))],database=session_database)
    for field,value,label in [(3,bytes([255])*8,'budget-version-overflow'),(6,bytes(16),'fee-exceeded'),(9,bytes(8),'gas-exceeded'),(12,bytes(8),'da-exceeded'),(18,bytes(8),'operations-exceeded'),(22,struct.pack('<Q',32),'rate-exceeded')]:
        changed=budget_state([(field,value)],funded_cap_state);consume_case(label,consume_task,[('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_kind=2',(changed,))],database=session_database)
    for kind,type_id,state,field,value,label in [(2,36,funded_cap_state,3,bytes([255])*8,'capability-version-overflow'),(3,38,session_record[4],3,bytes([255])*8,'session-version-overflow'),(3,38,session_record[4],7,struct.pack('<Q',49),'session-at-limit'),(3,38,session_record[4],7,struct.pack('<Q',50),'session-exhausted-before-consume'),(2,36,funded_cap_state,2,bytes(32),'capability-state-id'),(3,38,session_record[4],2,bytes(32),'session-state-id')]:
        changed=fixture.replace_field(type_id,state,field,value);consume_case(label,consume_task,[*funding_sql,('UPDATE agent_market_objects_v1 SET mutable_state=? WHERE object_kind=?',(changed,kind))],database=session_database)
    for kind in [2,3]:
        consume_case('row-cas-'+str(kind),consume_task,[*funding_sql,('UPDATE agent_market_objects_v1 SET object_version=? WHERE object_kind=?',(struct.pack('<Q',1),kind))],database=session_database)
        for behavior in ["IGNORE","ABORT,'consume delegated fixture'"]:
            consume_case('update-'+str(kind)+'-'+behavior,consume_task,[*funding_sql,(f'CREATE TRIGGER fixture_consume_delegated BEFORE UPDATE ON agent_market_objects_v1 WHEN NEW.object_kind={kind} BEGIN SELECT RAISE({behavior}); END',())],database=session_database)
    # Genuine signed full-method lifecycle, using the original implementation to
    # create every authenticated predecessor and to produce every ID/signature.
    # The native execution performs all authorization, hashes and SQL itself.
    flow_execution=b'\1\0'+protocol_context+struct.pack('<Q',initial_height)+initial_block+struct.pack('<Q',initial_height)+initial_block
    flow_successor=fixture.replace_field(28,flow_execution,4,struct.pack('<Q',initial_height+1));flow_successor=fixture.replace_field(28,flow_successor,5,bytes([222])*32)
    flow_databases=[];flow_commands=[];flow_receipts=[]
    def sign_flow(raw,provider=False):
        signed=stage('fixture-sign-flow-'+str(report['fixture_preparations']),POLICY,b'command:'+bundle.hex().encode()+b':'+raw.hex().encode()+b':'+(b'1' if provider else b'0')+b'\n');report['fixture_preparations']+=1
        return bytes.fromhex(signed.strip().decode())
    def full_auth(nonce,provider=False,capability=None,session_id=None):
        value=auth
        values=[(5,bytes(32)),(6,b'\0'),(7,bytes(8)),(8,b'\0'),(9,bytes(8)),(10,bytes(2)),(11,struct.pack('<Q',nonce)),(12,struct.pack('<Q',nonce))]
        if capability is not None:
            key=bundle[bs[5 if provider else 4][0]+96:bs[5 if provider else 4][0]+128]
            values[:6]=[(5,key),(6,b'\1'+capability),(7,struct.pack('<Q',42)),(8,b'\1'+session_id),(9,struct.pack('<Q',1)),(10,b'\1\0')]
        for index,value_bytes in values:value=fixture.replace_field(59,value,index,value_bytes)
        return value
    def full_step(label,raw,provider=False):
        signed=sign_flow(raw,provider);before=DB.read_bytes()
        add('execute-full-'+label,frame(24,kind=0,body=flow_execution,state=signed),database=before)
        for fault in [1,2,3]:add('execute-fault-'+str(fault)+'-'+label,frame(24,kind=fault,body=flow_execution,state=signed),database=before)
        output=records_fixture('full-execute-'+label,frame(24,kind=0,body=flow_execution,state=signed))
        assert len(output)==181 and output[0]==0,label
        after=DB.read_bytes();receipt=output[1:]
        add('execute-replay-'+label,frame(24,kind=0,body=flow_execution,state=signed),database=after)
        add('execute-replay-precedes-fault-'+label,frame(24,kind=3,body=flow_execution,state=signed),database=after)
        flow_databases.append(before);flow_commands.append(signed);flow_receipts.append(receipt)
        report.setdefault('full_execution_lifecycle',[]).append({'label':label,'before':blob(before),'after':blob(after),'command':blob(signed),'receipt':blob(receipt)})
        return signed
    DB.write_bytes(baseline)
    flow_cap=fixture.replace_field(33,cap,11,vector(scopes))
    flow_cap=fixture.replace_field(33,flow_cap,14,(1000).to_bytes(16,'little'))
    flow_cap=fixture.replace_field(33,flow_cap,13,vector([key+(1000).to_bytes(16,'little') for key in sorted({asset_id,bytes([8])*32,bytes([9])*32})]))
    full_step('requester-capability',grant_command(flow_cap,full_auth(0)))
    flow_cap_id=value_id(33,flow_cap)
    flow_session=fixture.replace_field(37,session,7,flow_cap_id)
    full_step('requester-session',grant_command(flow_session,full_auth(1),session=True))
    flow_session_id=value_id(37,flow_session)
    provider_key=bundle[bs[5][0]+96:bs[5][0]+128]
    flow_provider_cap=flow_cap
    for index,value in [(5,provider_agent),(7,provider_agent),(8,b'\1'+provider_key)]:flow_provider_cap=fixture.replace_field(33,flow_provider_cap,index,value)
    full_step('provider-capability',grant_command(flow_provider_cap,full_auth(0,True)),True)
    flow_provider_cap_id=value_id(33,flow_provider_cap)
    flow_provider_session=flow_session
    for index,value in [(5,provider_agent),(6,provider_key),(7,flow_provider_cap_id)]:flow_provider_session=fixture.replace_field(37,flow_provider_session,index,value)
    full_step('provider-session',grant_command(flow_provider_session,full_auth(1,True),session=True),True)
    flow_provider_session_id=value_id(37,flow_provider_session)
    flow_charge=fixture.value(42,0);flow_charge=fixture.replace_field(42,flow_charge,5,struct.pack('<Q',1))
    flow_task_charge=fixture.replace_field(42,flow_charge,0,vector([asset_id+(100).to_bytes(16,'little')]))
    flow_task=fixture.replace_field(70,consume_task,1,flow_task_charge,p=1)
    flow_task=fixture.replace_field(48,flow_task,7,b'\1'+flow_cap_id,p=1)
    flow_task=fixture.replace_field(70,flow_task,2,full_auth(0,False,flow_cap_id,flow_session_id),p=1)
    full_step('task-create',flow_task)
    con=sqlite3.connect(DB);flow_task_id=con.execute('SELECT object_id FROM agent_market_objects_v1 WHERE object_kind=4').fetchone()[0];flow_escrow_id=con.execute('SELECT object_id FROM agent_market_objects_v1 WHERE object_kind=7').fetchone()[0];con.close()
    flow_bid=bid
    for index,value in [(5,flow_task_id),(8,provider_key),(9,b'\1'+flow_provider_cap_id),(10,struct.pack('<Q',1)),(11,b'\1\0'),(12,bytes(8))]:flow_bid=fixture.replace_field(54,flow_bid,index,value)
    full_step('bid',b'\3'+flow_bid+flow_charge+full_auth(0,True,flow_provider_cap_id,flow_provider_session_id),True)
    flow_bid_id=value_id(54,flow_bid)
    flow_lease=lease
    for index,value in [(5,flow_task_id),(8,flow_bid_id),(11,flow_escrow_id)]:flow_lease=fixture.replace_field(56,flow_lease,index,value)
    full_step('lease-accept',b'\4'+flow_lease+bytes(24)+flow_charge+full_auth(1,False,flow_cap_id,flow_session_id))
    flow_lease_id=value_id(56,flow_lease)
    flow_acceptance=fixture.replace_field(58,acceptance,2,flow_lease_id)
    full_step('provider-accept',b'\5'+flow_acceptance+bytes(8)+flow_charge+full_auth(1,True,flow_provider_cap_id,flow_provider_session_id),True)
    flow_final=DB.read_bytes();report['full_execution_final_database']=blob(flow_final)
    for index,(raw,db) in enumerate(zip(flow_commands,flow_databases)):
        stale=fixture.replace_field(28,flow_execution,3,bytes([99])*32)
        add('execute-stale-cas-'+str(index),frame(24,kind=0,body=stale,state=raw),database=db)
        add('execute-replay-after-later-same-block-'+str(index),frame(24,kind=0,body=flow_execution,state=raw),database=flow_final)
        add('execute-wrong-replay-target-'+str(index),frame(24,kind=0,body=flow_successor,state=raw),database=flow_final)
    for field,value,label in [(0,bytes(2),'schema'),(1,fixture.replace_field(25,protocol_context,0,bytes(32)),'context'),(2,bytes([255])*8,'regression'),(3,bytes(32),'zero-parent'),(5,bytes(32),'zero-target')]:
        changed=fixture.replace_field(28,flow_execution,field,value)
        add('execute-static-'+label,frame(24,kind=0,body=changed,state=flow_commands[0]),database='absent')
        add('execute-sidecar-before-static-'+label,frame(24,kind=0,body=changed,state=flow_commands[0]),filesystem=[('file','records.sqlite-wal',b'')])
    for field,value,label in [(0,bytes(2),'schema'),(2,b'\7\0','operation-kind'),(3,bytes(32),'digest'),(13,struct.pack('<Q',1),'future'),(14,bytes(8),'expires')]:
        signed=flow_commands[0];auth_offset=fixture.fields(68,signed,1)[1][0];changed=fixture.replace_field(59,signed,field,value,p=auth_offset)
        add('execute-envelope-'+label,frame(24,kind=0,body=flow_execution,state=changed),database='absent')
    wrong_signature=flow_commands[0][:-1]+bytes([flow_commands[0][-1]^1])
    add('execute-signature-before-open',frame(24,kind=0,body=flow_execution,state=wrong_signature),database='absent')
    add('execute-open-missing-after-envelope',frame(24,kind=0,body=flow_execution,state=flow_commands[0]),database='absent')
    for index in [4,5,6,7]:
        raw=flow_commands[index];variant=raw[0];charge_index={2:1,3:1,4:4,5:2}[variant]
        current=fixture.fields(68+variant,raw,1)[charge_index];requested=raw[current[0]:current[1]]
        for field,value,label in [(5,bytes(8),'zero-operations'),(1,bytes([255])*16,'fee-limit')]:
            changed=fixture.replace_field(42,requested,field,value);bad=fixture.replace_field(68+variant,raw,charge_index,changed,p=1);bad=sign_flow(bad,index in [5,7])
            add('execute-apply-then-consume-rollback-'+str(index)+'-'+label,frame(24,kind=0,body=flow_execution,state=bad),database=flow_databases[index])
    bad=fixture.replace_field(42,flow_task_charge,0,bytes(4));bad=fixture.replace_field(70,flow_commands[4],1,bad,p=1);bad=sign_flow(bad)
    add('execute-task-insert-then-charge-rollback',frame(24,kind=0,body=flow_execution,state=bad),database=flow_databases[4])
    for raw,label in [(flow_execution,'same-height'),(flow_successor,'direct-successor')]:
        add('empty-'+label,frame(25,body=raw))
        add('empty-after-full-'+label,frame(25,body=raw),database=flow_final)
    DB.write_bytes(flow_final);records_fixture('full-empty-successor',frame(25,body=flow_successor));flow_empty=DB.read_bytes();report['full_empty_database']=blob(flow_empty)
    add('empty-idempotent-target',frame(25,body=flow_successor),database=flow_empty)
    for raw,label in [(fixture.replace_field(28,flow_successor,2,struct.pack('<Q',1)),'non-direct'),(fixture.replace_field(28,flow_successor,3,bytes([99])*32),'stale-parent'),(fixture.replace_field(28,flow_successor,4,struct.pack('<Q',2)),'skip-height')]:
        add('empty-'+label,frame(25,body=raw),database=flow_final)
    maximum=fixture.replace_field(28,flow_execution,2,bytes([255])*8);maximum=fixture.replace_field(28,maximum,4,bytes([255])*8)
    add('empty-height-overflow',frame(25,body=maximum),database='absent')
    for index,raw in enumerate(flow_commands):add('execute-replay-stale-after-empty-'+str(index),frame(24,kind=0,body=flow_execution,state=raw),database=flow_empty)
    # The qualifier passes canonical field values to a private test hook. The
    # eventual public SDK must retain the genuine opaque fresh-readback owner;
    # this fixture does not claim that arbitrary callers may mint that owner.
    candidate_block=bytes([222])*32;flow_parents=[]
    def preview_case(label,parent,commands,database='baseline',height=initial_height+1,block=candidate_block,trust=None,filesystem=()):
        add('preview-'+label,frame(26,expected=height,body=parent,state=vector(commands),command=block,bundle_override=trust),database=database,filesystem=filesystem)
    for index,database in enumerate(flow_databases):
        DB.write_bytes(database);parent=records_fixture('preview-parent-'+str(index),frame(16));flow_parents.append(parent)
        preview_case('empty-'+str(index),parent,[],database)
        preview_case('one-'+str(index),parent,[flow_commands[index]],database)
        preview_case('complete-suffix-'+str(index),parent,flow_commands[index:],database)
        preview_case('duplicate-'+str(index),parent,[flow_commands[index]]*2,database)
        corrupted=flow_commands[index][:-1]+bytes([flow_commands[index][-1]^1])
        preview_case('signature-before-duplicate-'+str(index),parent,[flow_commands[index],corrupted],database)
    parent=flow_parents[0];context_size=len(parent)-178
    for offset,size,label in [(0,2,'schema'),(2,32,'store'),(34,8,'sequence'),(42,8,'height'),(50,32,'block'),(82,32,'state-root'),(114,32,'journal-root'),(146,32,'block-root')]:
        changed=bytearray(parent);changed[context_size+offset]^=1
        preview_case('parent-'+label,bytes(changed),flow_commands)
    changed=bytearray(parent);changed[0]^=1;preview_case('parent-context',bytes(changed),flow_commands)
    for height,label in [(initial_height,'same-height'),(initial_height+2,'skipped-height'),((1<<64)-1,'height-max')]:preview_case(label,parent,[],height=height)
    preview_case('block-zero',parent,[],block=bytes(32));preview_case('block-same',parent,[],block=initial_block)
    preview_case('sidecar-before-parent',bytes(changed),[],filesystem=[('file','records.sqlite-wal',b'')])
    preview_case('missing-before-parent',bytes(changed),[],database='absent')
    DB.write_bytes(flow_final);final_parent=records_fixture('preview-final-parent',frame(16))
    for index,raw in enumerate(flow_commands):preview_case('already-committed-'+str(index),final_parent,[raw],flow_final)
    bad_task=fixture.replace_field(42,flow_task_charge,0,bytes(4));bad_task=sign_flow(fixture.replace_field(70,flow_commands[4],1,bad_task,p=1))
    preview_case('whole-prefix-rollback-after-task-charge',parent,flow_commands[:4]+[bad_task])
    corrupted=flow_commands[7][:-1]+bytes([flow_commands[7][-1]^1]);preview_case('whole-prefix-rollback-after-signature',parent,flow_commands[:7]+[corrupted])
    many=[]
    for i in range(32):
        changed_cap=fixture.replace_field(33,flow_cap,10,i.to_bytes(32,'little'))
        many.append(sign_flow(grant_command(changed_cap,full_auth(i))))
    preview_case('32-distinct-controller-operations',parent,many)
    preview_case('32-operation-duplicate-near-end',parent,many+many[:1])
    maximum_bundle=fixture.replace_field(27,bundle,2,bytes([255])*8)
    DB.write_bytes(b'');records_fixture('preview-height-max-create',frame(9,bundle_override=maximum_bundle));maximum_db=DB.read_bytes()
    maximum_parent=records_fixture('preview-height-max-readback',frame(16,bundle_override=maximum_bundle))
    preview_case('height-overflow-before-zero-block',maximum_parent,[],maximum_db,height=(1<<64)-1,block=bytes(32),trust=maximum_bundle)
    changed=bytearray(maximum_parent);changed[-1]^=1
    preview_case('parent-mismatch-before-height-overflow',bytes(changed),[],maximum_db,height=(1<<64)-1,block=bytes(32),trust=maximum_bundle)
    for value,label in [(b'','empty-vector-framing'),(struct.pack('<I',1),'missing-command'),(struct.pack('<I',1)+b'\xff','unknown-command'),(vector(flow_commands)+b'x','trailing-command-bytes')]:
        add('preview-decode-'+label,frame(26,expected=1,body=parent,state=value,command=candidate_block),database='absent')
    for index in [0,4,7]:
        raw=flow_commands[index]
        for cut in sorted({0,1,2,31,len(raw)-65,len(raw)-1}):
            for prefix in [[],flow_commands[:1]]:
                values=vector(prefix+[raw[:cut]])
                add('preview-decode-truncated-'+str((index,cut,len(prefix))),frame(26,expected=1,body=parent,state=values,command=candidate_block),database='absent')
    add('preview-decode-empty-vector-trailing',frame(26,expected=1,body=parent,state=bytes(4)+b'x',command=candidate_block),database='absent')
    for method in [19,21,23]:
        for tag in [6,255]:add('unknown-command-'+str((method,tag)),frame(method,body=bytes([tag])),database='absent')
    for tag in [6,255]:add('unknown-scope-command-'+str(tag),frame(22,body=cap,command=bytes([tag])),database='absent')
    for i,raw in enumerate([b'',b'TKSR0001'+bytes(151),b'TKSR0001'+struct.pack('<Q',24)+bytes(144),frame(0,kind=65535),frame(1,body=b'',state=b'',bundle_override=b''),frame(5,body=bytes(64),state=b'\2'),frame(6,body=bytes(295)),frame(7,state=bytes(127)),frame(7,body=b'',state=bytes(128)),frame(8,body=bytes(63)),frame(15,kind=65535),frame(17,body=b''),frame(19,body=b''),frame(19,body=b'\4'),frame(20),frame(21),frame(22,body=cap),frame(23)]):add('frame-'+str(i),raw)
    with (WORK/'observations.jsonl').open('x') as stream:
        for index,(name,raw,sql,unconstrained,database,filesystem) in enumerate(cases):
            restore({})
            if database!='absent':DB.write_bytes(database if isinstance(database,bytes) else (baseline if database=='baseline' else b''))
            for kind,name_part,value in filesystem:
                target=CASES/name_part
                if kind=='file':target.write_bytes(value)
                elif kind=='directory':target.mkdir()
                elif kind=='symlink':target.symlink_to(value)
                else:raise AssertionError(kind)
            if sql:
                con=sqlite3.connect(DB);con.execute('PRAGMA ignore_check_constraints=ON')
                if unconstrained:
                    for table,columns in [('agent_market_objects_v1','object_kind,object_id,object_version,immutable_body,mutable_state,row_checksum'),('agent_market_operations_v1','operation_id,sequence,operation_kind,command,receipt,row_checksum'),('agent_market_committed_blocks_v1',marker_columns)]:
                        rows=con.execute('SELECT '+columns+' FROM '+table).fetchall();con.execute('DROP TABLE '+table);con.execute('CREATE TABLE '+table+' ('+columns+')');con.executemany('INSERT INTO '+table+' VALUES ('+','.join('?' for _ in columns.split(','))+')',rows)
                for query,parameters in sql:con.execute(query,parameters)
                con.commit();con.close()
            before=inventory();expected_code,expected=original(f'original-{index:03d}',raw);expected_after=inventory();restore(before)
            row={'index':index,'name':name,'input':blob(raw),'before':before,'expected_code':expected_code,'expected_output':blob(expected),'expected_after':expected_after}
            (WORK/'current-call.json').write_text(json.dumps(row,indent=2)+'\n');start=time.monotonic_ns();code,out=native(raw);after=inventory()
            row.update(return_code=code,actual_output=blob(out),native_after=after,elapsed_ns=time.monotonic_ns()-start,equal=code==expected_code and out==expected and after==expected_after)
            stream.write(json.dumps(row)+'\n');stream.flush();report['native_calls']+=1;report['original_calls']+=1;save();assert row['equal'],name
    free(owner);owner=None
    report['source_after']={p:identity(p) for p in inputs};assert report['source_after']==inputs
    report.update(status='PASS',finalized=True,sqlite_provider_shared=True,exact_database_bytes_compared=True,full_task_kernel_owner_qualified=False);save()
except BaseException as error:
    report.update(status='FAIL',failure=repr(error));save();raise
finally:
    if 'owner' in globals() and owner:free(owner)
print(json.dumps({k:v for k,v in report.items() if k not in ['source_before','source_after','stages']}))
