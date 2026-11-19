"""Actual HIA/unchanged-Rust durable store qualification with complete evidence."""
from __future__ import annotations
import argparse, hashlib, json, os, random, re, shutil, signal, stat, struct, sys, time, types, unittest, tempfile
from pathlib import Path
from .build import Build, ROOT, identity, need, source_capture
from .native_io import Child, word, MAX
from .original_build import Original

CTX = None

def wire_scope(local=1, remote=2, direction=1, epoch=7, peer=4):
    return bytes([local])*32+bytes([remote])*32+bytes([direction])+word(epoch)+bytes([peer])*32

def request(op, now, *, scope=None, session=None, generation=1, expiry=0, ttl=1000, digest=bytes(32)):
    return word(op)+word(now)+(wire_scope() if scope is None else scope)+(bytes([3])*32 if session is None else session)+word(generation)+word(expiry)+word(ttl)+digest

def token_request(op,now,token,*,ttl=0):
    return request(op,now,scope=token[:105],session=token[105:137],generation=struct.unpack_from('<Q',token,137)[0],
                   expiry=struct.unpack_from('<Q',token,145)[0],ttl=ttl,digest=token[153:185])

def checked_head(count,digest):
    body=b'TPLH\x01\0\0\0'+word(count)+digest
    return body+hashlib.sha256(b'TPLH'+word(len(body))+body).digest()

def reseal(records):
    previous=bytes(32);result=bytearray()
    for raw in records:
        row=bytearray(raw);row[10:42]=previous
        row[204:236]=hashlib.sha256(row[:204]).digest();previous=bytes(row[204:236]);result.extend(row)
    return bytes(result)

def file_identity(path):
    h=hashlib.sha256();n=0
    with path.open('rb') as stream:
        while block:=stream.read(1<<20):h.update(block);n+=len(block)
    return {'bytes':n,'sha256':h.hexdigest()}

def sparse_copy(source,destination):
    source=Path(source);destination=Path(destination)
    # Preserve full actual bytes without materializing sparse cap-control holes.
    with source.open('rb') as src, destination.open('xb') as dst:
        size=os.fstat(src.fileno()).st_size;dst.truncate(size);position=0
        while position<size:
            try:start=os.lseek(src.fileno(),position,os.SEEK_DATA)
            except OSError as error:
                if error.errno==6:break
                if error.errno not in (22,95):raise
                start=position
            try:end=min(size,os.lseek(src.fileno(),start,os.SEEK_HOLE))
            except OSError as error:
                if error.errno not in (22,95):raise
                end=size
            src.seek(start);dst.seek(start)
            while start<end:
                block=src.read(min(1<<20,end-start))
                if not block:raise EOFError('short physical namespace capture')
                dst.write(block);start+=len(block)
            position=end
    shutil.copystat(source,destination,follow_symlinks=False)
    return str(destination)

def snapshot(path):
    result={}
    for file in sorted(path.rglob('*')):
        mode=file.lstat().st_mode
        info={'mode':stat.S_IMODE(mode),'uid':file.lstat().st_uid,'links':file.lstat().st_nlink}
        if stat.S_ISREG(mode):info.update({'kind':'file',**file_identity(file)})
        elif stat.S_ISDIR(mode):info['kind']='directory'
        elif stat.S_ISLNK(mode):info.update({'kind':'symlink','target':os.fsdecode(os.readlink(file))})
        else:info['kind']='other'
        result[os.fsdecode(os.fsencode(file.relative_to(path)))]=info
    return result

def jsonable(value):
    if isinstance(value,bytes):return value.hex()
    if isinstance(value,dict):return {k:jsonable(v) for k,v in value.items()}
    if isinstance(value,(list,tuple)):return [jsonable(v) for v in value]
    return value

def outcome(case,result):
    problems=[]
    for key in ('failures','errors','skipped','expectedFailures','unexpectedSuccesses'):
        for item in getattr(result,key,[]):
            candidate=item[0] if isinstance(item,tuple) else item
            if candidate is case or getattr(candidate,'test_case',None) is case:problems.append(key)
    return {'test':case.id(),'status':'FAIL' if problems else 'PASS','problems':problems}

class Pair:
    def __init__(self,context,label,*,filename='lease.journal',prepare=None,preexec=None):
        self.context=context;self.root=context.output/'cases'/label
        self.root.mkdir(parents=True,mode=0o700);self.directories=[];self.paths=[];self.children=[];self.rows=[]
        self.opened=False
        for name,binary in (('native',context.native),('original',context.original)):
            directory=context.new_namespace(label+'-'+name)
            path=directory/filename
            if prepare:prepare(directory,path,name)
            self.directories.append(directory);self.paths.append(path)
            self.children.append(Child(binary,path,self.root/(name+'-process'),preexec=preexec))
        context.pairs.append(self)
    def compare(self,op=None,payload=b'',*,files=True):
        values=[child.receive() if op is None else child.call(op,payload) for child in self.children]
        record={'operation':op,'request':payload.hex(),'responses':jsonable(values),'equal':values[0]==values[1]}
        self.rows.append(record)
        (self.root/'comparisons.json').write_text(json.dumps(self.rows,indent=2,sort_keys=True)+'\n')
        need(values[0]==values[1],'Actual native/original response differs: '+str(self.root))
        if files:
            a,b=[snapshot(directory) for directory in self.directories]
            # Successful commands leave exact same named bytes. Failed temp
            # evidence is inspected separately with its real PID names intact.
            need(a==b,'Actual complete namespace differs: '+str(self.root))
        if op is None:self.opened=values[0]['category']==0
        return values[0]
    def close(self):
        if self.opened:
            self.compare(0,files=False);self.opened=False
        for c in self.children:c.finish()
        (self.root/'namespace-final.json').write_text(json.dumps([snapshot(p) for p in self.directories],indent=2,sort_keys=True)+'\n')
    def finish(self):
        for c in self.children:c.finish()
        (self.root/'namespace-final.json').write_text(json.dumps([snapshot(p) for p in self.directories],indent=2,sort_keys=True)+'\n')

class Context:
    def __init__(self,output,arguments):
        self.output=output;output.mkdir(parents=True,exist_ok=False,mode=0o700)
        self.arguments=arguments;self.expected=[];self.started=[];self.completed=[];self.pairs=[];self.children=[];self.controls=[]
        self.source_before={};self.source_after={};self.builder=None;self.original_builder=None;self.native=b'';self.original=b''
        self.finalized=False;self.failures=[];self.started_ns=time.monotonic_ns()
        self.authority=Path(tempfile.mkdtemp(prefix='trnm-peer-store-qual-',dir='/tmp'))
        self.namespaces={};self.physical_namespaces=[]
        (self.authority/'OWNERSHIP.txt').write_text('Isolated peer-store qualification; no deployed authority.\n')
        (self.output/'authority-root.json').write_text(json.dumps({'path':str(self.authority),'uid':self.authority.stat().st_uid,'mode':stat.S_IMODE(self.authority.stat().st_mode)},indent=2)+'\n')
    def new_namespace(self,label):
        need(label not in self.namespaces and Path(label).name==label,'Unique private namespace label')
        path=self.authority/label;path.mkdir(mode=0o700);self.namespaces[label]=path;return path
    def capture_namespaces(self):
        root=self.output/'physical-namespaces';root.mkdir()
        for name,path in self.namespaces.items():
            before=snapshot(path)
            shutil.copytree(path,root/name,symlinks=True,copy_function=sparse_copy)
            after=snapshot(path);need(before==after,'Actual namespace changed during capture')
            copied=snapshot(root/name)
            need(set(copied)==set(before),'Namespace capture membership differs')
            for item in before:
                for key in ('kind','bytes','sha256','target','mode'):
                    need(before[item].get(key)==copied[item].get(key),'Actual namespace byte/type capture differs')
            self.physical_namespaces.append({'label':name,'actual_path':str(path),'actual_root_mode':stat.S_IMODE(path.stat().st_mode),'actual_root_uid':path.stat().st_uid,'captured_path':'physical-namespaces/'+name,'files':before})
        # Raw trailing '/.' paths can legitimately derive a lock sidecar next
        # to their final directory. Preserve these actual root-level witnesses
        # too; they must not disappear from the qualification evidence.
        extras=root/'_authority-root-extras';extras.mkdir()
        extra_files={}
        for path in sorted(self.authority.iterdir()):
            if path.name in self.namespaces:continue
            mode=path.lstat().st_mode
            need(stat.S_ISREG(mode) and not path.is_symlink(),'Unexpected unregistered authority entry')
            before=file_identity(path);sparse_copy(path,extras/path.name)
            need(file_identity(path)==before==file_identity(extras/path.name),'Authority extra bytes changed')
            extra_files[path.name]=before|{'mode':stat.S_IMODE(mode),'uid':path.stat().st_uid,'links':path.stat().st_nlink}
        self.physical_namespaces.append({'label':'_authority-root-extras','actual_path':str(self.authority),
            'captured_path':'physical-namespaces/_authority-root-extras','files':extra_files})
    def save(self):
        complete=self.started==self.expected and [x['test'] for x in self.completed]==self.expected and all(x['status']=='PASS' for x in self.completed)
        source_same=bool(self.source_before) and self.source_before==self.source_after
        retained=self.original_builder.retained if self.original_builder else None
        original_tests=self.original_builder.unit_tests if self.original_builder and hasattr(self.original_builder,'unit_tests') else None
        native_ok=bool(self.native)
        success=complete and source_same and native_ok and retained and retained['status']=='PASS' and original_tests and original_tests['returncode']==0 and not self.failures
        status='RUNNING'
        if self.finalized:
            status='PASS' if success else ('FAIL' if self.failures or any(x['status']!='PASS' for x in self.completed) else 'INCOMPLETE')
        result={'schema':'trnm.hia.peer-lease-store-qualification.v1','status':status,'finalized':self.finalized,
            'expected_tests':self.expected,'started_tests':self.started,'completed_tests':self.completed,'complete_successful_roster':complete,
            'source_inputs':self.source_before,'source_after':self.source_after,'source_unchanged':source_same,
            'original_retained':retained,'original_store_protocol_tests':original_tests,'arguments':self.arguments,
            'comparisons':sum(len(p.rows) for p in self.pairs),'all_recorded_comparisons_match':all(r['equal'] for p in self.pairs for r in p.rows),
            'controls':self.controls,'failures':self.failures,'elapsed_ns':time.monotonic_ns()-self.started_ns,
            'native_business_logic':True,'runtime_host_proxy':False,'native_private_file_descriptions':True,
            'stored_schema_changed':False,'unix_daemon_implemented':False,'core_authentication_implemented':False,
            'payload_stores_implemented':False,'whole_package_retired':False,'production_activation':False,
            'physical_power_loss_qualified':False,'continuous_hostile_same_uid_safety':False,'physical_namespaces':self.physical_namespaces}
        if self.finalized:
            files={}
            for p in sorted(self.output.rglob('*')):
                if any(part=='cargo-target' for part in p.relative_to(self.output).parts):continue
                if p.is_file() and not p.is_symlink() and p!=self.output/'report.json':files[p.relative_to(self.output).as_posix()]=file_identity(p)
            result['files']=files
        (self.output/'report.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
        return result

class StoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if CTX.arguments.get('native_build_input'):
            from .replay_build import ReplayBuild
            CTX.builder=ReplayBuild(CTX.output/'build',Path(CTX.arguments['native_build_input']))
        else:
            CTX.builder=Build(CTX.output/'build')
        CTX.source_before=CTX.builder.manifest
        CTX.save()
        CTX.native,_=CTX.builder.build()
        CTX.original_builder=Original(CTX.output/'original',CTX.output/'build/source-snapshot')
        CTX.original=CTX.original_builder.build()
        CTX.builder.check();CTX.save()
    def run(self,result=None):
        CTX.started.append(self.id());CTX.save()
        result=super().run(result)
        CTX.completed.append(outcome(self,result));CTX.save()
        return result
    def pair(self,label,**kwargs):
        p=Pair(CTX,self._testMethodName+'-'+label,**kwargs);self.addCleanup(p.finish);return p
    def success(self,row):
        self.assertEqual((row['category'],row['code']),(0,0));return row['body']
    def test_01_public_lifecycle_and_exact_disk_bytes(self):
        p=self.pair('lifecycle');self.success(p.compare());self.success(p.compare(1))
        token=self.success(p.compare(4,request(1,1000)))
        self.assertEqual(len(token),185)
        self.assertEqual(p.compare(2,wire_scope())['body'],word(1)+token)
        self.assertEqual(p.compare(3,wire_scope())['body'],word(1))
        self.assertEqual(self.success(p.compare(4,request(1,1200,ttl=120000))),token)
        self.assertEqual(self.success(p.compare(4,token_request(3,1300,token))),token)
        token=self.success(p.compare(4,token_request(2,1400,token,ttl=4000)))
        released=self.success(p.compare(4,token_request(4,1500,token)))
        self.assertEqual(released[145:153],word(0));self.assertEqual(p.compare(2,wire_scope())['body'],word(0))
        self.assertEqual(p.compare(4,request(1,1600,generation=2))['code'],3)
        token=self.success(p.compare(4,request(1,1700,session=b'\x05'*32,generation=2)))
        self.assertEqual(p.compare(4,token_request(3,1699,token))['code'],9)
        self.assertEqual(p.compare(4,token_request(3,1800,token))['code'],10)
        self.assertEqual(p.compare(1)['body'][:8],word(1700));p.close()
        for name,binary,path in zip(('native','original'),(CTX.native,CTX.original),p.paths):
            child=Child(binary,path,p.root/(name+'-reopened'));CTX.children.append(child)
            self.success(child.receive());self.assertEqual(self.success(child.call(2,wire_scope())),word(1)+token)
            self.assertEqual(self.success(child.call(3,wire_scope())),word(2));self.success(child.call(0));child.finish()
    def test_02_validation_precedence_and_observed_clock(self):
        cases=[('session-before-generation',request(1,1000,session=bytes(32),generation=0,ttl=0),(1,10)),
               ('generation-before-ttl',request(1,1000,generation=0,ttl=0),(1,11)),
               ('ttl-before-lookup',request(2,1000,ttl=999),(1,12)),
               ('renew-absent',request(2,1000),(4,4)),('revalidate-zero-gen',request(3,1000,generation=0,ttl=MAX),(4,4)),
               ('release-zero-gen',request(4,1000,generation=0,ttl=MAX),(4,4)),
               ('wrong-next-gen',request(1,1000,generation=2),(4,3)),
               ('ttl-overflow',request(1,MAX-500,ttl=1000),(1,13))]
        for label,payload,wanted in cases:
            with self.subTest(label=label):
                p=self.pair(label);self.success(p.compare());row=p.compare(4,payload)
                self.assertEqual((row['category'],row['code']),wanted)
                now=struct.unpack_from('<Q',payload,8)[0]
                self.assertEqual(p.compare(4,request(1,now-1))['code'],9)
                self.assertEqual(p.compare(4,request(1,now))['code'],10)
                self.assertEqual(p.compare(1)['body'],bytes(40));p.close()
        p=self.pair('fenced-and-expired');self.success(p.compare());t=self.success(p.compare(4,request(1,1000)))
        bad=bytearray(token_request(3,1200,t));bad[-1]^=1
        self.assertEqual(p.compare(4,bytes(bad))['code'],6)
        self.assertEqual(p.compare(4,request(1,1300,session=b'\x05'*32))['code'],2)
        self.assertEqual(p.compare(4,token_request(3,2000,t))['code'],5)
        self.assertEqual(p.compare(4,request(1,2100))['code'],5)
        p.close()
    def test_03_multiple_scopes_generations_and_original_driven_requests(self):
        rng=random.Random(0x504c5354);p=self.pair('many');self.success(p.compare())
        scopes=[wire_scope(local=1,remote=2+i%40,direction=1+i%2,epoch=(i*9137) if i<70 else MAX,peer=4+i%30) for i in range(80)]
        tokens={};generations={};now=1000;session_counter=0
        for step in range(360):
            now+=rng.randrange(0,90);scope=scopes[rng.randrange(len(scopes))]
            if scope in tokens and rng.randrange(4):
                op=rng.choice([2,3,4]);payload=token_request(op,now,tokens[scope],ttl=rng.choice([1000,5000,120000]) if op==2 else 0)
            else:
                session_counter+=1;sid=hashlib.sha256(word(session_counter)).digest();op=1
                payload=request(1,now,scope=scope,session=sid,generation=generations.get(scope,0)+1,ttl=rng.choice([1000,9000,120000]))
            if step%19==0:
                bad=bytearray(payload);bad[-1]^=128;payload=bytes(bad)
            row=p.compare(4,payload)
            if row['category']==0:
                token=row['body'];generations[scope]=struct.unpack_from('<Q',token,137)[0]
                if op==4:tokens.pop(scope,None)
                else:tokens[scope]=token
            if step%13==0:
                p.compare(2,scope);p.compare(3,scope);p.compare(1)
        p.close()
    def seed(self,label):
        p=self.pair(label);self.success(p.compare())
        first=self.success(p.compare(4,request(1,1000,ttl=10000)))
        second=self.success(p.compare(4,token_request(2,2000,first,ttl=10000)))
        third=self.success(p.compare(4,token_request(4,3000,second)))
        p.close();return p.paths[0].read_bytes(),(p.paths[0].parent/'.lease.journal.head-v1').read_bytes()
    def test_04_replay_hash_semantics_and_anchor_relations(self):
        journal,head=self.seed('seed');records=[journal[i:i+236] for i in range(0,len(journal),236)]
        variants=[('complete',journal,head,0),('partial',journal[:-1],head,10),('complete-rollback',journal[:-236],head,10),
                  ('no-anchor',journal,None,10),('ahead-of-zero-anchor',journal,checked_head(0,bytes(32)),0),
                  ('anchor-ahead',journal,checked_head(4,head[16:48]),10),
                  ('same-count-wrong-head',journal,checked_head(3,b'\xff'*32),10),
                  ('behind-nonmatching-head-original-accepts',journal,checked_head(1,b'\xff'*32),0),
                  ('nonzero-zero-hash',journal,checked_head(1,bytes(32)),10),
                  ('zero-nonzero-hash',journal,checked_head(0,b'\x01'*32),10),
                  ('short-anchor',journal,head[:-1],10),('oversize-anchor',journal,head+b'x',10)]
        for label,at,value in [('magic',0,0),('version',4,2),('payload-size',6,161),('digest',204,0)]:
            raw=bytearray(journal);raw[at]=value if raw[at]!=value else value^1
            variants.append((label,bytes(raw),head,10))
        mutations=[('bad-outer-operation',5,3),('bad-inner-operation',42,0),('bad-direction',107,0),
                   ('wrong-generation',180,2),('zero-expiry',188,0),('inner-operation-valid-mismatch',42,4)]
        for label,at,value in mutations:
            row=bytearray(records[0]);row[at]=value
            if label=='zero-expiry':row[188:196]=bytes(8)
            altered=reseal([row,*records[1:]])
            code=0 if label=='inner-operation-valid-mismatch' else 10
            variants.append((label,altered,checked_head(3,altered[-32:]),code))
        # Hash-valid invalid transition and clock rollback are rejected by real replay.
        row=bytearray(records[1]);row[196:204]=word(999)
        altered=reseal([records[0],row,records[2]])
        variants.append(('observed-clock-rollback',altered,checked_head(3,altered[-32:]),10))
        for label,raw,anchor,wanted in variants:
            def prepare(directory,path,name,raw=raw,anchor=anchor):
                path.write_bytes(raw);path.chmod(0o600)
                if anchor is not None:
                    f=directory/'.lease.journal.head-v1';f.write_bytes(anchor);f.chmod(0o600)
            with self.subTest(label=label):
                p=self.pair(label,prepare=prepare);row=p.compare()
                self.assertEqual(row['code'],wanted)
                if wanted==0:p.compare(1);p.compare(3,wire_scope());p.close()
                else:p.finish()
    def test_05_parent_paths_namespaces_and_private_files(self):
        def case(label,prepare,wanted,filename='lease.journal'):
            p=self.pair(label,prepare=prepare,filename=filename);row=p.compare()
            self.assertEqual((row['category'],row['code']),wanted)
            if wanted==(0,0):p.close()
            else:p.finish()
        case('missing-parent-chain',None,(0,0),'one/two/lease.journal')
        case('dot-file',None,(0,0),'.lease')
        case('multi-extension',None,(0,0),'lease.one.two')
        case('unicode-name',None,(0,0),'租约.日志')
        case('nonutf8-name',None,(0,0),os.fsdecode(b'lease-\xff.log'))
        case('broad-parent',lambda d,p,n:d.chmod(0o755),(1,5))
        case('writable-parent',lambda d,p,n:d.chmod(0o777),(1,8))
        def filemode(name,mode):
            def make(d,p,n):
                target=d/name;target.write_bytes(b'');target.chmod(mode)
            return make
        case('broad-journal',filemode('lease.journal',0o644),(1,16))
        case('broad-lock',filemode('lease.lease-lock',0o644),(1,16))
        case('broad-anchor',filemode('.lease.journal.head-v1',0o644),(1,16))
        for filename in ('lease.journal','lease.lease-lock','.lease.journal.head-v1'):
            def hard(d,p,n,filename=filename):
                f=d/'real';f.write_bytes(b'');f.chmod(0o600);os.link(f,d/filename)
            case('hardlink-'+str(len(filename)),hard,(1,16))
            def sym(d,p,n,filename=filename):
                f=d/'real';f.write_bytes(b'');f.chmod(0o600);os.symlink('real',d/filename)
            case('symlink-'+str(len(filename)),sym,(2,40))
        def stale(d,p,n): (d/'..lease.journal.head-v1.tmp-123-0-0').write_bytes(b'evidence')
        case('stale-temp',stale,(4,10))
        def nonutf8(d,p,n):
            os.close(os.open(os.fsencode(d)+b'/..lease.journal.head-v1.tmp-\xff',os.O_CREAT|os.O_WRONLY,0o600))
        case('nonutf8-temp-original-ignores',nonutf8,(0,0))
        case('unrelated-entry',lambda d,p,n:(d/'unrelated').write_bytes(b'allowed'),(0,0))
    def test_06_failed_head_publication_preserves_real_poison_and_state(self):
        p=self.pair('create-failure');self.success(p.compare())
        witnesses=[]
        for path,child in zip(p.paths,p.children):
            temporary=path.parent/('..lease.journal.head-v1.tmp-'+str(child.process.pid)+'-1-1')
            temporary.write_bytes(b'preexisting actual evidence');temporary.chmod(0o600);witnesses.append(temporary)
        row=p.compare(4,request(1,1000),files=False)
        self.assertEqual((row['category'],row['code']),(2,17))
        self.assertEqual(p.compare(1,files=False)['body'],word(1000)+p.paths[0].read_bytes()[-32:])
        self.assertEqual(p.compare(2,wire_scope(),files=False)['body'][:8],word(1))
        self.assertEqual(p.compare(3,wire_scope(),files=False)['body'],word(1))
        self.assertEqual(p.compare(4,request(1,2000,session=b'\x05'*32,generation=2),files=False)['code'],10)
        for witness in witnesses:self.assertEqual(witness.read_bytes(),b'preexisting actual evidence')
        self.assertEqual(p.paths[0].read_bytes(),p.paths[1].read_bytes());p.close()
        p=self.pair('rename-failure');self.success(p.compare())
        for path in p.paths:
            anchor=path.parent/'.lease.journal.head-v1';anchor.unlink();anchor.mkdir(mode=0o700)
        row=p.compare(4,request(1,1000),files=False)
        self.assertEqual((row['category'],row['code']),(2,21))
        self.assertEqual(p.compare(1,files=False)['body'][:8],word(1000))
        active=p.compare(2,wire_scope(),files=False)['body'];self.assertEqual(active[:8],word(1))
        self.assertEqual(p.compare(3,wire_scope(),files=False)['body'],word(1))
        self.assertEqual(p.compare(4,request(1,2000,session=b'\x05'*32,generation=2),files=False)['code'],10)
        temporaries=[]
        for path in p.paths:
            files=list(path.parent.glob('..lease.journal.head-v1.tmp-*'))
            self.assertEqual(len(files),1);self.assertEqual(files[0].stat().st_size,80)
            temporaries.append(files[0].read_bytes())
        self.assertEqual(temporaries[0],temporaries[1]);self.assertEqual(p.paths[0].read_bytes(),p.paths[1].read_bytes())
        p.close()
    def test_07_cross_process_flock_and_release(self):
        for first_name,first_binary,second_name,second_binary in [('native',CTX.native,'original',CTX.original),('original',CTX.original,'native',CTX.native)]:
            directory=CTX.output/'cases'/('flock-'+first_name);directory.mkdir(parents=True,mode=0o700)
            namespace=CTX.new_namespace(directory.name);path=namespace/'lease.journal'
            first=Child(first_binary,path,directory/'first');CTX.children.append(first);self.success(first.receive())
            token=self.success(first.call(4,request(1,1000)))
            second=Child(second_binary,path,directory/'competing');CTX.children.append(second)
            row=second.receive();self.assertEqual((row['category'],row['code']),(2,11));second.finish()
            self.success(first.call(0));first.finish()
            third=Child(second_binary,path,directory/'after-close');CTX.children.append(third)
            self.success(third.receive());self.assertEqual(self.success(third.call(2,wire_scope())),word(1)+token)
            self.success(third.call(0));third.finish()
            CTX.controls.append({'control':'actual-cross-process-flock','first':first_name,'second':second_name,'status':'PASS','path':str(path)})
    def test_08_actual_rlimit_partial_write_and_recovery(self):
        import resource
        for limit in (0,1,79,80,235,236):
            captures=[]
            for name,binary in (('native',CTX.native),('original',CTX.original)):
                directory=CTX.output/'cases'/('rlimit-'+str(limit)+'-'+name);directory.mkdir(parents=True,mode=0o700)
                namespace=CTX.new_namespace(directory.name);path=namespace/'lease.journal'
                seed=Child(binary,path,directory/'seed');CTX.children.append(seed);self.success(seed.receive());self.success(seed.call(0));seed.finish()
                def apply_limit():
                    signal.signal(signal.SIGXFSZ,signal.SIG_IGN);resource.setrlimit(resource.RLIMIT_FSIZE,(limit,limit))
                child=Child(binary,path,directory/'limited',preexec=apply_limit);CTX.children.append(child);self.success(child.receive())
                rows=[child.call(4,request(1,1000)),child.call(1),child.call(2,wire_scope()),child.call(4,request(1,1100))]
                self.success(child.call(0));child.finish()
                if limit<236:
                    self.assertEqual((rows[0]['category'],rows[0]['code']),(2,27));self.assertEqual(rows[-1]['code'],10)
                    self.assertEqual(path.stat().st_size,limit);self.assertEqual(rows[1]['body'],bytes(40))
                else:self.success(rows[0])
                reopen=Child(binary,path,directory/'reopen');CTX.children.append(reopen);opening=reopen.receive()
                if 0<limit<236:self.assertEqual(opening['code'],10)
                else:self.success(opening);self.success(reopen.call(0))
                reopen.finish();captures.append({'rows':rows,'open':opening,'log':path.read_bytes(),'head':(namespace/'.lease.journal.head-v1').read_bytes()})
            self.assertEqual(captures[0],captures[1])
            CTX.controls.append({'control':'kernel-RLIMIT_FSIZE','limit':limit,'status':'PASS','comparisons':jsonable(captures)})
    def test_09_actual_sigkill_at_native_physical_boundaries(self):
        for target in range(2,11):
            directory=CTX.output/'cases'/('crash-'+str(target));directory.mkdir(parents=True,mode=0o700)
            namespace=CTX.new_namespace(directory.name);path=namespace/'lease.journal'
            child=Child(CTX.native,path,directory/'interrupted',gates=True);CTX.children.append(child)
            while True:
                gate=child.gate();child.resume()
                if gate['tag']==11:break
            self.success(child.receive());child.send(b'PLSC0001'+word(4)+request(1,1000))
            while True:
                gate=child.gate()
                if gate['tag']==target:break
                child.resume()
            child.finish(kill=True);self.assertEqual(child.process.returncode,-signal.SIGKILL)
            before=snapshot(namespace)
            # Each cold owner sees its own exact copy of the physical killed namespace.
            rows=[]
            for name,binary in (('native',CTX.native),('original',CTX.original)):
                copy=CTX.new_namespace(directory.name+'-'+name+'-recovery');shutil.copytree(namespace,copy,copy_function=sparse_copy,dirs_exist_ok=True);copy.chmod(0o700)
                owner=Child(binary,copy/'lease.journal',directory/(name+'-recovery'));CTX.children.append(owner)
                row=owner.receive();rows.append(row)
                if target in (7,8):self.assertEqual(row['code'],10)
                else:
                    self.success(row);rows.append(owner.call(1));rows.append(owner.call(2,wire_scope()));self.success(owner.call(0))
                owner.finish()
            midpoint=len(rows)//2;self.assertEqual(rows[:midpoint],rows[midpoint:])
            CTX.controls.append({'control':'actual-SIGKILL','gate':gate,'status':'PASS','before_recovery':before,'responses':jsonable(rows),
                                 'physical_power_loss':False})
    def test_10_original_retained_and_complete_source(self):
        self.assertEqual(CTX.original_builder.retained['status'],'PASS')
        self.assertEqual(CTX.original_builder.unit_tests['returncode'],0)
        self.assertFalse(CTX.original_builder.unit_tests['timed_out']);CTX.builder.check()
    def test_11_reporter_refuses_false_success(self):
        class Probe(unittest.TestCase):
            def runTest(self):pass
        functions=[lambda s:s.fail('intentional'),lambda s:(_ for _ in ()).throw(RuntimeError('intentional')),lambda s:s.skipTest('intentional')]
        for function in functions:
            case=Probe();case.runTest=types.MethodType(function,case);result=unittest.TestResult();case.run(result)
            self.assertEqual(outcome(case,result)['status'],'FAIL')
        class Sub(Probe):
            def runTest(self):
                with self.subTest(kind='actual-failure'):self.fail('intentional subtest')
        case=Sub();result=unittest.TestResult();case.run(result);self.assertEqual(outcome(case,result)['status'],'FAIL')
        self.assertNotEqual(CTX.expected[:1],CTX.expected)
        CTX.controls.append({'control':'actual-TestResult-failure-error-skip-subtest','status':'PASS','cases':4})

    def test_12_collision_resolution_keeps_full_scope_and_session_keys(self):
        def bucket(raw):
            result=14695981039346656037
            for value in raw:result=((result^value)*1099511628211)&MAX
            return result&2097151
        found={};collision=None
        for epoch in range(20000):
            value=wire_scope(epoch=int.from_bytes(hashlib.sha256(word(epoch)).digest()[:8],'little'));key=bucket(value)
            if key in found:collision=(found[key],value);break
            found[key]=value
        self.assertIsNotNone(collision)
        p=self.pair('scope-collision');self.success(p.compare());tokens=[]
        for i,scope in enumerate(collision):tokens.append(self.success(p.compare(4,request(1,1000+i,scope=scope,session=bytes([10+i])*32))))
        for scope,token in zip(collision,tokens):self.assertEqual(self.success(p.compare(2,scope)),word(1)+token)
        for i,token in enumerate(tokens):self.success(p.compare(4,token_request(4,1100+i,token)))
        for i,scope in enumerate(collision):self.assertEqual(p.compare(4,request(1,1200+i,scope=scope,session=bytes([10+i])*32,generation=2))['code'],3)
        p.close()
        found={};collision=None;scope=wire_scope()
        for i in range(20000):
            session=hashlib.sha256(word(i)).digest();key=bucket(scope+session)
            if key in found:collision=(found[key],session);break
            found[key]=session
        self.assertIsNotNone(collision)
        p=self.pair('session-collision');self.success(p.compare());now=1000
        for generation,session in enumerate(collision,1):
            token=self.success(p.compare(4,request(1,now,session=session,generation=generation)))
            self.success(p.compare(4,token_request(4,now+1,token)));now+=10
        for session in collision:self.assertEqual(p.compare(4,request(1,now,session=session,generation=3))['code'],3)
        p.close();CTX.controls.append({'control':'actual-full-key-scope-and-session-hash-collisions','status':'PASS'})
    def test_13_original_journal_extent_cap_without_reduced_profile(self):
        for size in (268435456,268435457):
            def prepare(d,p,n,size=size):
                with p.open('wb') as stream:stream.truncate(size)
                p.chmod(0o600)
            pair=self.pair('size-'+str(size),prepare=prepare)
            row=pair.compare();self.assertEqual((row['category'],row['code']),(4,10));pair.finish()
            CTX.controls.append({'control':'actual-sparse-journal-extent','size':size,'native_original_match':True})
    def test_14_canonical_alias_and_raw_posix_path_profile(self):
        def prepare(d,p,n):
            (d/'real').mkdir(mode=0o700);(d/'real/child').mkdir(mode=0o700);os.symlink('real',d/'alias')
        p=self.pair('intermediate-alias',filename='alias/child/lease.journal',prepare=prepare)
        row=p.compare();self.assertEqual((row['category'],row['code']),(1,7));p.finish()
        suffixes=(b'/./lease.journal',b'//lease.journal',b'/file\x00name.log',b'/bad\x00parent/lease.journal',b'/LONG4090',b'/LONG4095',
                  b'/.lease',b'/..lease',b'/.lease.one.',b'/lease..one.',b'/lease.',b'/lease./.',b'/lease/..',
                  b'/./.lease..',b'///lease.one.two//',b'/./',b'/../',b'/..x',b'/...x',b'/..x.y',b'/..x.',b'/...',
                  b'/..x/.',b'/..x//',b'/..x/./',b'/..lease////',b'/lease.ext/./',b'/lease.ext//')
        for index,suffix in enumerate(suffixes):
            rows=[];physical=[]
            for name,binary in (('native',CTX.native),('original',CTX.original)):
                namespace=CTX.new_namespace('path-'+str(index)+'-'+name)
                path=os.fsencode(namespace)+suffix
                long_path=suffix.startswith(b'/LONG')
                if long_path:
                    extent=int(suffix[5:]);prefix=os.fsencode(namespace);path=prefix+b'/'*(extent-len(prefix)-4)+b'file'
                process=CTX.output/'cases'/('path-'+str(index)+'-'+name)
                child=Child(binary,path,process);CTX.children.append(child);opening=child.receive();rows.append(opening)
                if long_path:self.assertEqual((opening['category'],opening['code']),(2,36))
                elif b'\x00' in suffix:self.assertEqual((opening['category'],opening['code']),(2,22))
                elif opening['category']==0:
                    self.success(opening);self.assertEqual(self.success(child.call(5)),path);self.success(child.call(0))
                child.finish()
                physical.append(snapshot(namespace))
            self.assertEqual(rows[0],rows[1]);self.assertEqual(physical[0],physical[1])

    def test_15_kernel_fsync_eio_poison_and_cold_recovery(self):
        captures=[]
        for name,binary in (('native',CTX.native),('original',CTX.original)):
            namespace=CTX.new_namespace('fsync-eio-'+name);path=namespace/'lease.journal'
            directory=CTX.output/'cases'/('fsync-eio-'+name)
            seed=Child(binary,path,directory/'seed');CTX.children.append(seed)
            self.success(seed.receive());self.success(seed.call(0));seed.finish()
            child=Child(binary,path,directory/'denied',sync_error=5);CTX.children.append(child)
            self.success(child.receive())
            actual_fds={int(f.name):os.readlink(f) for f in Path('/proc/'+str(child.process.pid)+'/fd').iterdir()}
            self.assertEqual(actual_fds[child.kernel_fault['fd']],str(path))
            (directory/'actual-private-fds.json').write_text(json.dumps(actual_fds,indent=2,sort_keys=True)+'\n')
            rows=[child.call(4,request(1,1000)),child.call(1),child.call(2,wire_scope()),child.call(4,request(1,1100))]
            self.assertEqual((rows[0]['category'],rows[0]['code']),(2,5))
            self.assertEqual(path.stat().st_size,236);self.assertEqual(rows[1]['body'],bytes(40));self.assertEqual(rows[-1]['code'],10)
            self.success(child.call(0));child.finish()
            reopen=Child(binary,path,directory/'reopen');CTX.children.append(reopen)
            self.success(reopen.receive());rows.append(reopen.call(1));rows.append(reopen.call(2,wire_scope()))
            self.assertEqual(rows[-2]['body'][:8],word(1000));self.success(reopen.call(0));reopen.finish()
            captures.append({'rows':rows,'journal':path.read_bytes(),'head':(namespace/'.lease.journal.head-v1').read_bytes()})
        self.assertEqual(captures[0],captures[1]);CTX.controls.append({'control':'actual-kernel-seccomp-fsync-EIO','status':'PASS',
            'responses':jsonable(captures),'physical_media_failure':False})

    def test_16_head_failure_syscalls_keep_committed_memory_and_poison(self):
        profiles=[('head-write','write:error=EIO:when=3',0,10),
                  ('head-fsync','fsync:error=EIO:when=3',80,10),
                  ('final-directory-fsync','fsync:error=EIO:when=4',None,0)]
        for label,injection,temp_extent,recovery_code in profiles:
            captures=[]
            for name,binary in (('native',CTX.native),('original',CTX.original)):
                directory=CTX.output/'cases'/('head-error-'+label+'-'+name)
                namespace=CTX.new_namespace(directory.name);path=namespace/'lease.journal'
                seed=Child(binary,path,directory/'seed');CTX.children.append(seed)
                self.success(seed.receive());self.success(seed.call(0));seed.finish()
                child=Child(binary,path,directory/'fault',inject=injection);CTX.children.append(child)
                self.success(child.receive())
                rows=[child.call(4,request(1,1000)),child.call(1),child.call(2,wire_scope()),child.call(3,wire_scope()),
                      child.call(4,request(1,2000,session=b'\x05'*32,generation=2))]
                self.assertEqual((rows[0]['category'],rows[0]['code']),(2,5))
                journal=path.read_bytes();self.assertEqual(len(journal),236)
                self.assertEqual(rows[1]['body'],word(1000)+journal[-32:])
                self.assertEqual(rows[2]['body'][:8],word(1));self.assertEqual(rows[2]['body'][-32:],journal[-32:])
                self.assertEqual(rows[3]['body'],word(1));self.assertEqual((rows[4]['category'],rows[4]['code']),(4,10))
                self.success(child.call(0));child.finish()
                trace=(directory/'fault/syscalls.raw').read_text()
                injected=[line for line in trace.splitlines() if '(INJECTED)' in line]
                self.assertEqual(len(injected),1);self.assertIn('= -1 EIO ',injected[0])
                if label=='final-directory-fsync':
                    self.assertIn('fsync(',injected[0]);self.assertIn('<'+str(namespace)+'>',injected[0])
                else:
                    self.assertIn('..lease.journal.head-v1.tmp-',injected[0])
                    self.assertIn('write(' if label=='head-write' else 'fsync(',injected[0])
                temporary=list(namespace.glob('..lease.journal.head-v1.tmp-*'))
                if temp_extent is None:self.assertEqual(temporary,[])
                else:self.assertEqual([f.stat().st_size for f in temporary],[temp_extent])
                reopen=Child(binary,path,directory/'reopen');CTX.children.append(reopen);opened=reopen.receive()
                self.assertEqual(opened['code'],recovery_code)
                if recovery_code==0:
                    self.success(opened);self.assertEqual(reopen.call(1),rows[1]);self.success(reopen.call(0))
                reopen.finish()
                captures.append({'rows':rows,'reopened':opened,'journal':journal,'head':(namespace/'.lease.journal.head-v1').read_bytes(),
                                 'temporary_bytes':[f.read_bytes() for f in temporary]})
            self.assertEqual(captures[0],captures[1])
            CTX.controls.append({'control':'actual-ptrace-syscall-error','phase':label,'injection':injection,
                'status':'PASS','committed_memory_preserved':True,'poison_preserved':True,'physical_media_failure':False,
                'comparisons':jsonable(captures)})

    def test_17_actual_syscall_order_covers_durable_publication(self):
        for name,binary in (('native',CTX.native),('original',CTX.original)):
            directory=CTX.output/'cases'/('syscall-order-'+name)
            namespace=CTX.new_namespace(directory.name);path=namespace/'lease.journal'
            seed=Child(binary,path,directory/'seed');CTX.children.append(seed)
            self.success(seed.receive());self.success(seed.call(0));seed.finish()
            child=Child(binary,path,directory/'traced',trace=True);CTX.children.append(child)
            self.success(child.receive());self.success(child.call(4,request(1,1000)));self.success(child.call(0));child.finish()
            lines=(directory/'traced/syscalls.raw').read_text().splitlines()
            def one(pattern):
                found=[(index,line) for index,line in enumerate(lines) if re.search(pattern,line)]
                self.assertEqual(len(found),1,pattern);return found[0]
            journal_write=one(r'write\(\d+<'+re.escape(str(path))+r'>,.*, 236\)\s+= 236$')
            journal_sync=one(r'fsync\(\d+<'+re.escape(str(path))+r'>\)\s+= 0$')
            head_write=one(r'write\(\d+<[^>]*\.\.lease\.journal\.head-v1\.tmp-[^>]+>,.*, 80\)\s+= 80$')
            head_sync=one(r'fsync\(\d+<[^>]*\.\.lease\.journal\.head-v1\.tmp-[^>]+>\)\s+= 0$')
            renamed=one(r'rename\("[^"\n]*\.\.lease\.journal\.head-v1\.tmp-[^"\n]+", "'+re.escape(str(namespace/'.lease.journal.head-v1'))+r'"\)\s+= 0$')
            directory_sync=[(index,line) for index,line in enumerate(lines) if re.search(r'fsync\(\d+<'+re.escape(str(namespace))+r'>\)\s+= 0$',line)]
            self.assertEqual(len(directory_sync),2)
            response=one(r'write\(1<[^>]*>,.*, 225\)\s+= 225$')
            actual=[journal_write,journal_sync,*directory_sync[:1],head_write,head_sync,renamed,*directory_sync[1:],response]
            self.assertEqual([index for index,line in actual],sorted(index for index,line in actual))
            first_fd=re.search(r'fsync\((\d+)<',directory_sync[0][1])[1]
            last_fd=re.search(r'fsync\((\d+)<',directory_sync[1][1])[1]
            self.assertNotEqual(first_fd,last_fd)
            CTX.controls.append({'control':'actual-syscall-publication-order','implementation':name,'status':'PASS',
                'steps':[{'line_index':index,'raw_line':line} for index,line in actual],
                'fresh_parent_directory_fd':int(first_fd),'retained_directory_fd':int(last_fd)})

    def test_18_interrupted_syscalls_follow_original_retry_contract(self):
        def injected_line(directory):
            lines=(directory/'syscalls.raw').read_text().splitlines()
            selected=[line for line in lines if '(INJECTED)' in line]
            self.assertEqual(len(selected),1);self.assertIn('= -1 EINTR ',selected[0])
            return selected[0],lines
        for kind in ('fsync','chmod'):
            captures=[]
            for name,binary in (('native',CTX.native),('original',CTX.original)):
                directory=CTX.output/'cases'/('eintr-retry-'+kind+'-'+name)
                namespace=CTX.new_namespace(directory.name)
                path=namespace/('missing/lease.journal' if kind=='chmod' else 'lease.journal')
                if kind=='fsync':
                    seed=Child(binary,path,directory/'seed');CTX.children.append(seed)
                    self.success(seed.receive());self.success(seed.call(0));seed.finish()
                child=Child(binary,path,directory/'fault',inject=kind+':error=EINTR:when=1');CTX.children.append(child)
                opening=child.receive();self.success(opening)
                token=self.success(child.call(4,request(1,1000)));stats=child.call(1)
                self.assertEqual(stats['body'],word(1000)+token[-32:]);self.success(child.call(0));child.finish()
                line,lines=injected_line(directory/'fault')
                self.assertIn(kind+'(',line)
                self.assertIn(str(path) if kind=='fsync' else str(namespace/'missing'),line)
                self.assertGreaterEqual(sum(kind+'(' in value for value in lines),2)
                captures.append({'open':opening,'token':token,'stats':stats,'physical':snapshot(namespace)})
            self.assertEqual(captures[0],captures[1])
            CTX.controls.append({'control':'actual-ptrace-EINTR-retry','syscall':kind,'status':'PASS','comparisons':jsonable(captures)})
        for kind in ('final-seek','journal-metadata'):
            captures=[]
            for name,binary in (('native',CTX.native),('original',CTX.original)):
                directory=CTX.output/'cases'/('eintr-refusal-'+kind+'-'+name)
                namespace=CTX.new_namespace(directory.name);path=namespace/'lease.journal'
                seed=Child(binary,path,directory/'seed');CTX.children.append(seed)
                self.success(seed.receive());token=self.success(seed.call(4,request(1,1000)));self.success(seed.call(0));seed.finish()
                before=snapshot(namespace)
                probe=Child(binary,path,directory/'probe',trace=True);CTX.children.append(probe)
                self.success(probe.receive());self.success(probe.call(0));probe.finish()
                trace=(directory/'probe/syscalls.raw').read_text().splitlines()
                if kind=='final-seek':pattern=r'\b(lseek)\(\d+<'+re.escape(str(path))+r'>, 0, SEEK_END\)'
                else:pattern=r'\b(fstat|statx|newfstatat)\(\d+<'+re.escape(str(path))+r'>,'
                matches=[(index,line,re.search(pattern,line)) for index,line in enumerate(trace) if re.search(pattern,line)]
                self.assertTrue(matches,'Actual relevant private-file syscall is absent')
                index,line,match=matches[0];syscall=match[1]
                ordinal=sum(re.search(r'\b'+syscall+r'\(',value) is not None for value in trace[:index+1])
                injection=syscall+':error=EINTR:when='+str(ordinal)
                selector={'actual_probe_line':line,'actual_probe_line_index':index,'syscall':syscall,'ordinal':ordinal,
                          'probe_trace':file_identity(directory/'probe/syscalls.raw'),'injection':injection}
                (directory/'injection-selector.json').write_text(json.dumps(selector,indent=2,sort_keys=True)+'\n')
                child=Child(binary,path,directory/'fault',inject=injection);CTX.children.append(child)
                opening=child.receive();self.assertEqual((opening['category'],opening['code']),(2,4));child.finish()
                actual,_=injected_line(directory/'fault');self.assertIn(syscall+'(',actual);self.assertIn('<'+str(path)+'>',actual)
                self.assertEqual(snapshot(namespace),before)
                recovery=Child(binary,path,directory/'reopened');CTX.children.append(recovery)
                self.success(recovery.receive());active=recovery.call(2,wire_scope());self.assertEqual(active['body'],word(1)+token)
                self.success(recovery.call(0));recovery.finish()
                captures.append({'open':opening,'active_after_reopen':active,'physical':snapshot(namespace)})
            self.assertEqual(captures[0],captures[1])
            CTX.controls.append({'control':'actual-ptrace-EINTR-propagation','phase':kind,'status':'PASS','comparisons':jsonable(captures)})

def main():
    global CTX
    if not __debug__ or os.environ.get('PYTHONOPTIMIZE'):raise RuntimeError('Optimized Python not admitted')
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--only');parser.add_argument('--inject-failure',action='store_true')
    parser.add_argument('--native-build-input',type=Path)
    args=parser.parse_args();CTX=Context(args.output.absolute(),vars(args)|{'output':str(args.output.absolute()),'native_build_input':str(args.native_build_input.absolute()) if args.native_build_input else None})
    names=unittest.defaultTestLoader.getTestCaseNames(StoreTests)
    CTX.expected=[StoreTests.__module__+'.'+StoreTests.__qualname__+'.'+name for name in names]
    CTX.save()
    selected=[args.only] if args.only else names
    if args.inject_failure:
        name=selected[0];old=getattr(StoreTests,name)
        def failure(self):old(self);self.fail('actual qualification negative control')
        setattr(StoreTests,name,failure)
    suite=unittest.TestSuite(StoreTests(name) for name in selected)
    result=None
    try:
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        CTX.failures=[{'kind':kind,'test':str(case),'traceback':text} for kind in ('errors','failures') for case,text in getattr(result,kind)]
        if result.skipped:CTX.failures += [{'kind':'skipped','test':str(case),'reason':reason} for case,reason in result.skipped]
    finally:
        for pair in CTX.pairs:pair.finish()
        for child in CTX.children:child.finish()
        try:
            if CTX.builder:
                CTX.builder.check();values=CTX.builder.current_inputs();CTX.source_after={k:identity(v) for k,v in sorted(values.items())}
        except Exception as error:CTX.failures.append({'kind':'source-closure','detail':str(error)})
        CTX.capture_namespaces()
        CTX.finalized=True;report=CTX.save()
        print(json.dumps({'status':report['status'],'tests':len(report['completed_tests']),'expected':len(report['expected_tests']),
                          'comparisons':report['comparisons'],'source_unchanged':report['source_unchanged']}))
    return 0 if report['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
