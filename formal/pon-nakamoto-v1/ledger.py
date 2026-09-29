"""Executable contract ledger: real Ed25519, full work verification and disk SQLite.
Not a production host. Local Python execution is an independently coded spec oracle,
not the existing Rust task kernel and not an ordinary Hepta product invocation.
"""
from __future__ import annotations
import copy,json,os,sqlite3,struct,fcntl,tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from cryptography.exceptions import InvalidSignature
from strict_signature import verify as verify_signature
from contract_wire import *
import work_backend as work
ZERO=bytes(32)
FAMILY=H('family',canonical(MODEL_FAMILY))
PLAN=H('plan',b'public-source-file-disjoint-v1')

def key(i):
    # Publicly known development seeds, never imported into a production signer.
    return Ed25519PrivateKey.from_private_bytes(H('DEV-ONLY-KEY',u64(i)))
def public(k):return k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
EVALUATORS={public(key(i)).hex()for i in range(3)}
def sign(k,nonce,name,fields,expiry=1000,fee_limit=100000):
    raw=tx_unsigned(NETWORK,public(k),nonce,expiry,fee_limit,NAMES[name],fields)
    return raw+k.sign(H('tx-sign',raw))
def account(s,who):return s.setdefault('account:'+who,{'balance':0,'nonce':0})
def require(ok,code):
    if not ok:raise ValueError(code)
def checked(n):require(type(n)is int and 0<=n<(1<<64),'RANGE');return n
A=[i%31 for i in range(work.CELLS)]
B=[(i*7)%37 for i in range(work.CELLS)]
MAINTENANCE=work.task_id(A,B)

def genesis_state():
    s={'meta:issued':0,'model:current':ZERO.hex(),'work:'+MAINTENANCE.hex():True}
    for i in range(PARAMS['genesis_accounts']):
        account(s,public(key(i)).hex())['balance']=PARAMS['genesis_funding_units_per_account']
        s['meta:issued']+=PARAMS['genesis_funding_units_per_account']
    return s
GENESIS=H('genesis',NETWORK,PARAMETER_HASH,state_root(genesis_state()),u64(PARAMS['genesis_timestamp']))
def total_funds(s):
    total=0
    for k,v in s.items():
        if k.startswith('account:'):total+=v['balance']
        elif k.startswith(('task:','quota:','release:')):total+=v['remaining']
        elif k.startswith('reward:'):total+=v['amount']
    return total

def release_id(parent,bundle,budget,root,total):return H('release',parent,bundle,u64(budget),root,u64(total))
def submission_round(height):return height//PARAMS['candidate_round_blocks']

def contribution_id(sender,family,parent,artifact,components,round_id=0):
    return H('contribution-v3',sender,family,parent,artifact,components,u64(round_id))

def task_identity(sender,nonce,provider,budget,deadline):
    return H('task-instance-v3',NETWORK,PARAMETER_HASH,sender,u64(nonce),provider,u64(budget),u64(deadline))

def quota_identity(sender,nonce,consumer,provider,units,deadline):
    return H('quota-instance-v3',NETWORK,PARAMETER_HASH,sender,u64(nonce),consumer,provider,u64(units),u64(deadline))

def candidate_active(value, current, height):
    return (value['parent']==current and value.get('submission_round',0)==submission_round(height) and
            value['status'] in {'submitted','evaluated'} and
            (value['status']!='evaluated' or value['score']>0) and
            height<=value.get('submitted_height',height)+PARAMS['candidate_lifetime_blocks'])


def retire_candidates(state, height):
    """Retire capacity, not historical truth. Current-parent nullifiers remain exact.

    Parent transitions permanently reject old-parent submissions. Immutable block/delta
    history retains retired records. Claims verify release-root payee membership and do
    not need a deleted candidate row. This is revision-2 consensus, not a v1 rewrite.
    """
    current=state['model:current']
    for name,value in list(state.items()):
        if name.startswith('contribution:'):
            if value['parent']!=current or value.get('submission_round',0)!=submission_round(height):
                del state[name]
            elif height>value.get('submitted_height',height)+PARAMS['candidate_lifetime_blocks'] and value['status']in {'submitted','evaluated'}:
                value['status']='expired';value['votes']={};value['score']=0
        elif name.startswith('artifact:'):
            parts=name.split(':')
            if len(parts)!=4 or parts[1]!=current or parts[2]!=str(submission_round(height)):del state[name]
        elif name.startswith(('task:','quota:')) and value['remaining']==0 and value['deadline']<height:
            del state[name]
        elif name.startswith('release:') and name[8:]!=current and value['remaining']==0:
            del state[name]


def execute_reference(parent,transactions,height,miner,parent_id):
    require(len(transactions)<=PARAMS['max_transactions'],'LIMIT')
    s=copy.deepcopy(parent);fees=0;receipts=[];miner=miner.hex()
    retire_candidates(s, height)
    # Mandatory expiry is sorted deterministically. Admission limits due slots to 16.
    due=[]
    for name,v in s.items():
        if name.startswith(('task:','quota:','release:'))and v['remaining'] and v['deadline']<=height:due.append((v['deadline'],name))
    for _,name in sorted(due)[:PARAMS['mandatory_expiry_per_block']]:
        obj=s[name];account(s,obj['owner'])['balance']=checked(account(s,obj['owner'])['balance']+obj['remaining'])
        obj['remaining']=0;obj['status']='expired';receipts.append(canonical({'expiry':name}))
    for name in sorted(list(s)):
        if name.startswith('reward:')and s[name]['maturity']<=height:
            v=s.pop(name);account(s,v['owner'])['balance']=checked(account(s,v['owner'])['balance']+v['amount'])
    for raw in transactions:
        tx=tx_decode(raw);f=tx['fields'];sender=tx['sender'].hex();tag=tx['tag'];acct=account(s,sender)
        require(tx['network']==NETWORK,'NETWORK');require(tx['nonce']==acct['nonce']+1,'NONCE');require(height<=tx['expiry'],'EXPIRED')
        try:verify_signature(tx['sender'],tx['signature'],H('tx-sign',tx['unsigned']))
        except (ValueError,InvalidSignature) as e:raise ValueError('SIGNATURE')from e
        fee=COMMANDS[tag]['base_fee_units']+len(raw)*PARAMS['byte_fee_units'];require(tx['fee_limit']>=fee,'FEE')
        if tag!=11:require(acct['balance']>=fee,'FUNDS');acct['balance']-=fee
        def pay(n):require(n>0 and acct['balance']>=n,'FUNDS');acct['balance']-=n
        def fetch(prefix,h):
            name=prefix+h.hex();require(name in s,'STATE');return s[name]
        def deadline(d,lifetime=None):
            require(height<d<=height+(PARAMS['max_task_lifetime_blocks']if lifetime is None else lifetime),'EXPIRED')
            active=[v for k,v in s.items()if k.startswith(('task:','quota:','release:'))and v['remaining']]
            require(len(active)<PARAMS['max_pending_tasks'],'LIMIT')
            require(sum(v['deadline']==d for v in active)<PARAMS['mandatory_expiry_per_block'],'LIMIT')
        if tag==1:
            pay(f['amount']);dest=account(s,f['recipient'].hex());dest['balance']=checked(dest['balance']+f['amount'])
        elif tag==2:
            require(f['task']==task_identity(tx['sender'],tx['nonce'],f['provider'],f['budget'],f['deadline']),'RESOURCE_ID')
            name='task:'+f['task'].hex();require(name not in s,'DUPLICATE');deadline(f['deadline']);pay(f['budget'])
            s[name]={'owner':sender,'provider':f['provider'].hex(),'remaining':f['budget'],'deadline':f['deadline'],'status':'reserved','output':None}
        elif tag==3:
            obj=fetch('task:',f['task']);require(obj['owner']==sender,'AUTHORITY');require(obj['status']=='reserved','STATE')
            acct['balance']=checked(acct['balance']+obj['remaining']);obj['remaining']=0;obj['status']='cancelled'
        elif tag==4:
            obj=fetch('task:',f['task']);require(obj['provider']==sender,'AUTHORITY');require(obj['status']=='reserved'and height<obj['deadline'],'STATE')
            require(f['output']!=ZERO,'EVIDENCE');obj['output']=f['output'].hex();obj['status']='receipt'
        elif tag==5:
            obj=fetch('task:',f['task']);require(obj['owner']==sender,'AUTHORITY');require(obj['status']=='receipt'and height<obj['deadline']and obj['output']==f['output'].hex(),'STATE')
            dest=account(s,obj['provider']);dest['balance']=checked(dest['balance']+obj['remaining']);obj['remaining']=0;obj['status']='settled'
        elif tag==6:
            cid=f['contribution'].hex();name='contribution:'+cid
            require(f['contribution']==contribution_id(tx['sender'],f['family'],f['parent_release'],f['artifact'],f['components_root'],f['submission_round']),'ROOT')
            require(f['submission_round']==submission_round(height),'SUBMISSION_ROUND')
            require(f['family']==FAMILY and f['parent_release'].hex()==s['model:current'],'STATE')
            require(sum(k.startswith('contribution:')for k in s)<PARAMS['max_candidate_history_per_round'],'CANDIDATE_WINDOW_FULL')
            require(0<f['size']<=PARAMS['max_artifact_bytes'],'LIMIT');require(f['artifact']!=ZERO,'EVIDENCE')
            require(sum(k.startswith('contribution:') and candidate_active(v, s['model:current'], height) for k,v in s.items())<PARAMS['max_model_candidates'],'LIMIT')
            duplicate='artifact:'+f['parent_release'].hex()+':'+str(f['submission_round'])+':'+f['artifact'].hex();require(name not in s and duplicate not in s,'DUPLICATE')
            s[name]={'owner':sender,'artifact':f['artifact'].hex(),'components_root':f['components_root'].hex(),'family':f['family'].hex(),'parent':f['parent_release'].hex(),'votes':{},'score':0,'status':'submitted','submitted_height':height,'submission_round':f['submission_round']};s[duplicate]=cid
        elif tag==7:
            obj=fetch('contribution:',f['contribution']);require(sender in EVALUATORS and sender!=obj['owner'],'AUTHORITY')
            require(obj['status']=='submitted' and obj['parent']==s['model:current'],'STATE');require(sender not in obj['votes'],'DUPLICATE')
            require(f['plan']==PLAN and f['evidence']!=ZERO and f['score']<=PARAMS['max_evidence_score'],'EVIDENCE')
            obj['votes'][sender]={'score':f['score'],'evidence':f['evidence'].hex()}
            if len(obj['votes'])>=PARAMS['evaluation_threshold']:
                obj['score']=min(v['score']for v in obj['votes'].values());obj['status']='evaluated'
        elif tag==8:
            require(f['parent_release'].hex()==s['model:current'],'STATE')
            bundle=fetch('contribution:',f['bundle']);require(bundle['status']=='evaluated'and bundle['score']>=PARAMS['minimum_adoption_score'],'EVIDENCE')
            require(bundle['parent']==s['model:current']and bundle['components_root']==f['allocation_root'].hex(),'ROOT')
            allocations=[]
            for cid,score in f['allocations']:
                obj=fetch('contribution:',cid);require(obj['status']=='evaluated'and obj['parent']==s['model:current']and obj['score']==score and score>0,'EVIDENCE')
                allocations.append((cid,bytes.fromhex(obj['owner']),score))
            root,_=allocation_root_and_proofs(allocations);total=sum(r[2]for r in allocations)
            require(root==f['allocation_root']and total==f['total_score'],'ROOT')
            require(f['release']==release_id(f['parent_release'],f['bundle'],f['budget'],root,total),'ROOT')
            name='release:'+f['release'].hex();require(name not in s,'DUPLICATE')
            horizon=PARAMS['reward_maturity_blocks']+PARAMS['release_claim_window_blocks'];expiry=height+horizon
            deadline(expiry,horizon);pay(f['budget'])
            s[name]={'owner':sender,'remaining':f['budget'],'budget':f['budget'],'total':total,'root':root.hex(),'maturity':height+PARAMS['reward_maturity_blocks'],'bundle':f['bundle'].hex(),'artifact':bundle['artifact'],'family':bundle['family'],'components_root':bundle['components_root'],'parent':f['parent_release'].hex(),'leaf_count':len(allocations),'claims':{},'deadline':expiry,'status':'open'}
            for cid,_,_ in allocations:s['contribution:'+cid.hex()]['status']='adopted'
            bundle['status']='adopted';s['model:current']=f['release'].hex()
        elif tag==9:
            rel=fetch('release:',f['release'])
            require(height>=rel['maturity'] and height<rel['deadline'] and rel['status']=='open','STATE');cid=f['contribution'].hex();require(cid not in rel['claims'],'DUPLICATE')
            require(len(f['siblings'])==(rel['leaf_count']-1).bit_length(),'ROOT')
            require(allocation_check(allocation_leaf(f['contribution'],tx['sender'],f['score']),f['siblings'],bytes.fromhex(rel['root'])),'ROOT')
            amount=rel['budget']*f['score']//rel['total'];require(amount<=rel['remaining'],'FUNDS')
            acct['balance']=checked(acct['balance']+amount);rel['remaining']-=amount;rel['claims'][cid]=amount
        elif tag==10:
            require(f['quota']==quota_identity(tx['sender'],tx['nonce'],f['consumer'],f['provider'],f['units'],f['deadline']),'RESOURCE_ID')
            name='quota:'+f['quota'].hex();require(name not in s,'DUPLICATE');deadline(f['deadline']);require(0<f['units']<=PARAMS['max_quota_units'],'LIMIT')
            cost=f['units']*PARAMS['quota_unit_price'];pay(cost)
            s[name]={'owner':sender,'consumer':f['consumer'].hex(),'provider':f['provider'].hex(),'remaining':cost,'units':f['units'],'deadline':f['deadline'],'status':'reserved'}
        elif tag==11:
            obj=fetch('quota:',f['quota']);require(sender==obj['provider'],'AUTHORITY');require(obj['status']=='reserved'and height<obj['deadline'],'STATE')
            require(0<f['units']<=obj['units']and f['result']!=ZERO,'LIMIT')
            digest=H('use',NETWORK,PARAMETER_HASH,f['quota'],tx['sender'],u64(tx['nonce']),u64(f['units']),f['result'])
            try:verify_signature(bytes.fromhex(obj['consumer']),f['consumer_signature'],digest)
            except (ValueError,InvalidSignature)as e:raise ValueError('SIGNATURE')from e
            cost=f['units']*PARAMS['quota_unit_price'];require(cost>=fee and obj['remaining']>=cost,'FUNDS')
            obj['remaining']-=cost;obj['units']-=f['units'];acct['balance']=checked(acct['balance']+cost-fee)
            if not obj['units']:obj['status']='spent'
        elif tag==12:
            name='work:'+f['task_commitment'].hex();require(name not in s and f['task_commitment']!=ZERO,'DUPLICATE');s[name]=True
        else:raise ValueError('VERSION')
        acct['nonce']=tx['nonce'];fees+=fee;receipts.append(canonical({'tx':H('tx-id',raw).hex(),'fee':fee,'status':'applied'}))
    halvings=min(height//PARAMS['subsidy_halving_interval'],64)
    subsidy=PARAMS['block_subsidy_units']>>halvings
    reward_name='reward:'+H('reward',parent_id,u64(height),bytes.fromhex(miner)).hex()
    s[reward_name]={'owner':miner,'amount':fees+subsidy,'maturity':height+PARAMS['reward_maturity_blocks']}
    s['meta:issued']=checked(s['meta:issued']+subsidy)
    require(total_funds(s)==s['meta:issued'],'CONSERVATION')
    state_root(s) # range/size checks precede persistence
    return s,receipts

def execute(parent,transactions,height,miner,parent_id):
    if os.environ.get('TRNM_NATIVE_EXECUTOR'):
        from native_execution import execute_native
        state,receipts,_=execute_native(parent,transactions,height,miner,parent_id)
        return state,receipts
    return execute_reference(parent,transactions,height,miner,parent_id)


SCHEMA_DDL = '''
CREATE TABLE metadata(key TEXT PRIMARY KEY,value BLOB NOT NULL);
CREATE TABLE blocks(id BLOB PRIMARY KEY,parent BLOB,height INTEGER NOT NULL,chainwork BLOB NOT NULL,header BLOB,body BLOB,proof BLOB,state_root BLOB NOT NULL);
CREATE TABLE deltas(block BLOB NOT NULL,key TEXT NOT NULL,before BLOB,after BLOB,PRIMARY KEY(block,key));
CREATE TABLE active(singleton INTEGER PRIMARY KEY CHECK(singleton=1),tip BLOB NOT NULL,generation INTEGER NOT NULL,state_slot INTEGER NOT NULL);
CREATE TABLE kv(generation INTEGER NOT NULL,key TEXT NOT NULL,value BLOB NOT NULL,PRIMARY KEY(generation,key));
CREATE TABLE reorg(singleton INTEGER PRIMARY KEY CHECK(singleton=1),old_tip BLOB,new_tip BLOB,generation INTEGER,steps BLOB,position INTEGER,status TEXT);
CREATE TABLE events(generation INTEGER NOT NULL,ordinal INTEGER NOT NULL,kind TEXT,block BLOB,PRIMARY KEY(generation,ordinal));
CREATE TABLE snapshots(block BLOB PRIMARY KEY,state BLOB NOT NULL);
CREATE INDEX work_order ON blocks(chainwork DESC,height,id);
'''
# Hash the exact schema into the initialization intent. Existing stores never auto-migrate.
SCHEMA_ID=H('storage-schema-v2',SCHEMA_DDL.encode())

def schema_projection(db):
    return {(kind,name):' '.join(sql.split()) for kind,name,sql in db.execute(
        "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}

def expected_schema():
    db=sqlite3.connect(':memory:')
    try:
        db.executescript(SCHEMA_DDL)
        return schema_projection(db)
    finally:db.close()



def sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


class Ledger:
    """Single existing reference owner; no duplicate production ledger introduced."""
    def __init__(self,directory,init_cut=None):
        self.directory=Path(directory);self.directory.mkdir(mode=0o700,parents=True,exist_ok=True)
        require(not self.directory.is_symlink(),'NAMESPACE')
        lock=self.directory/'owner.lock';require(not lock.is_symlink(),'NAMESPACE')
        fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        self.owner=os.fdopen(fd,'a+b');self.db=None;self.native_session=None
        try:
            try:fcntl.flock(self.owner.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('WRITER_BUSY')
            path=self.directory/'ledger.sqlite';marker=self.directory/'initializing.json'
            require(not path.is_symlink() and not marker.is_symlink(),'NAMESPACE')
            expected=canonical({'schema':SCHEMA_ID.hex(),'parameters':PARAMETER_HASH.hex(),'genesis':GENESIS.hex()})
            fresh=not path.exists()
            if fresh and not marker.exists():
                require(set(p.name for p in self.directory.iterdir())<={'owner.lock'},'NAMESPACE_NOT_EMPTY')
                fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb')as out:out.write(expected);out.flush();os.fsync(out.fileno())
                sync_directory(self.directory)
                if init_cut:init_cut('init-intent')
            intent=marker.exists()
            if intent:require(marker.read_bytes()==expected,'INITIALIZATION_CONTEXT')
            # Probe before writable PRAGMAs. A foreign/incomplete DB without our intent rejects.
            tables=set()
            if path.exists():
                from urllib.parse import quote
                probe=sqlite3.connect('file:'+quote(str(path.resolve()))+'?mode=ro',uri=True)
                try:
                    tables={r[0]for r in probe.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
                    if tables:
                        require(tables=={'metadata','blocks','deltas','active','kv','reorg','events','snapshots'},'SCHEMA')
                        require(schema_projection(probe)==expected_schema(),'SCHEMA')
                        row=probe.execute("SELECT value FROM metadata WHERE key='parameters'").fetchone()
                        require(row is not None and row[0]==PARAMETER_HASH,'NETWORK')
                        shape=probe.execute("SELECT value FROM metadata WHERE key='schema'").fetchone()
                        require(shape is not None and shape[0]==SCHEMA_ID,'SCHEMA')
                    else:require(intent,'INITIALIZATION_INTENT_REQUIRED')
                finally:probe.close()
            self.db=sqlite3.connect(path,timeout=10,isolation_level=None)
            self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
            if not tables:
                require(intent,'INITIALIZATION_INTENT_REQUIRED')
                self.db.execute('BEGIN IMMEDIATE')
                try:
                    for statement in SCHEMA_DDL.split(';'):
                        if statement.strip():self.db.execute(statement)
                    if init_cut:init_cut('init-schema')
                    state=genesis_state();root=state_root(state)
                    self.db.executemany('INSERT INTO metadata VALUES(?,?)',[('parameters',PARAMETER_HASH),('schema',SCHEMA_ID)])
                    self.db.execute('INSERT INTO blocks VALUES(?,?,?,?,?,?,?,?)',(GENESIS,None,0,bytes(64),None,None,None,root))
                    self.db.execute('INSERT INTO active VALUES(1,?,0,0)',(GENESIS,))
                    self.db.executemany('INSERT INTO kv VALUES(0,?,?)',[(k,canonical(v))for k,v in state.items()])
                    self.db.execute('INSERT INTO snapshots VALUES(?,?)',(GENESIS,canonical(state)))
                    if init_cut:init_cut('init-before-commit')
                    self.db.execute('COMMIT')
                except BaseException:
                    if self.db.in_transaction:self.db.execute('ROLLBACK')
                    raise
                if init_cut:init_cut('init-committed')
            if intent:
                marker.unlink();sync_directory(self.directory)
            self.read_active()
        except BaseException:
            if self.db is not None:self.db.close()
            self.owner.close();raise

    def close(self):
        try:
            if self.native_session is not None:self.native_session.close()
        finally:
            self.db.close();fcntl.flock(self.owner.fileno(),fcntl.LOCK_UN);self.owner.close()

    def execute_application(self, parent_state, transactions, height, miner, parent_id):
        selected=os.environ.get('TRNM_NATIVE_SESSION')
        require(not(selected and os.environ.get('TRNM_NATIVE_EXECUTOR')),'NATIVE_BACKEND_CONFLICT')
        if self.native_session is not None and (not selected or self.native_session.binary!=Path(selected).resolve()):
            self.native_session.close();self.native_session=None
        if selected:
            from native_session import NativeExecutionSession
            if self.native_session is None:self.native_session=NativeExecutionSession(selected)
            state,receipts,_=self.native_session.execute(parent_state,transactions,height,miner,parent_id,
                int(os.environ.get('TRNM_EXECUTION_WORKERS','1')))
            return state,receipts
        return execute(parent_state,transactions,height,miner,parent_id)

    def ready(self):
        pending=self.db.execute('SELECT status FROM reorg WHERE singleton=1').fetchone()
        require(not pending or pending[0]=='done','REORG_IN_PROGRESS')

    def block(self,tip):
        row=self.db.execute('SELECT parent,height,chainwork,header,body,proof,state_root FROM blocks WHERE id=?',(tip,)).fetchone()
        require(row is not None,'UNKNOWN_PARENT');return row

    def active(self):return self.db.execute('SELECT tip,generation FROM active WHERE singleton=1').fetchone()
    def slot(self):return self.db.execute('SELECT state_slot FROM active WHERE singleton=1').fetchone()[0]

    def read_active(self):
        self.db.execute('BEGIN')
        try:
            tip,g=self.active();slot=self.slot()
            state={k:json.loads(v,object_pairs_hook=unique)for k,v in self.db.execute('SELECT key,value FROM kv WHERE generation=?',(slot,))}
            require(state_root(state)==self.block(tip)[6],'ROOT');return tip,g,state
        finally:self.db.execute('COMMIT')

    def state_at(self,tip,progress=None):
        if tip==self.active()[0]:return self.read_active()[2]
        # Root-bound local checkpoints accelerate shallow forks at any height. Missing
        # checkpoints fall back to retained deltas, never a permanent 4096-height veto.
        # Spill ancestor identifiers above 8 KiB. Replay may grow with history,
        # but its path index cannot grow without bound in RAM or veto old height.
        with tempfile.SpooledTemporaryFile(max_size=32*256, mode='w+b') as ancestry:
            cur=tip;count=0
            while True:
                row=self.block(cur)
                snapshot=self.db.execute('SELECT state FROM snapshots WHERE block=?',(cur,)).fetchone()
                if snapshot:
                    state=json.loads(snapshot[0],object_pairs_hook=unique)
                    require(state_root(state)==row[6],'ROOT');break
                require(row[0]is not None and self.block(row[0])[1]+1==row[1],'HEIGHT')
                ancestry.write(cur);count+=1;cur=row[0]
                if progress and count%256==0:progress('ancestry',count)
            for i in range(count):
                ancestry.seek(32*(count-i-1));bid=ancestry.read(32)
                require(len(bid)==32,'ANCESTRY_IO')
                for k,before,after in self.db.execute('SELECT key,before,after FROM deltas WHERE block=? ORDER BY key',(bid,)):
                    require((canonical(state[k])if k in state else None)==before,'UNDO_ROOT')
                    if after is None:state.pop(k,None)
                    else:state[k]=json.loads(after,object_pairs_hook=unique)
                require(state_root(state)==self.block(bid)[6],'ROOT')
                if progress and (i+1)%256==0:progress('replay',i+1)
        return state

    def ancestor_headers(self,parent):
        headers=[]
        while parent!=GENESIS and len(headers)<max(PARAMS['retarget_interval'],PARAMS['median_time_width']):
            row=self.block(parent);headers.append(header_decode(row[3]));parent=row[0]
        if parent==GENESIS:headers.append({'timestamp':PARAMS['genesis_timestamp'],'target':bytes.fromhex(PARAMS['initial_target_hex'])})
        return headers

    def target(self,parent):
        from reference import retarget
        row=self.block(parent);height=row[1]+1;headers=self.ancestor_headers(parent);prior=int.from_bytes(headers[0]['target'],'big')
        if height%PARAMS['retarget_interval']==0:
            prior=retarget(prior,headers[PARAMS['retarget_interval']-1]['timestamp'],headers[0]['timestamp'],PARAMS['retarget_interval'],PARAMS['target_spacing_seconds'],int(PARAMS['pow_limit_hex'],16))
        return prior.to_bytes(32,'big')

    def make(self,parent,txs,miner=None,timestamp=None,max_attempts=4096,work_inputs=None):
        self.ready();wa,wb=(A,B)if work_inputs is None else work_inputs
        miner=public(key(0))if miner is None else miner;row=self.block(parent);height=row[1]+1
        state,receipts=self.execute_application(self.state_at(parent),txs,height,miner,parent)
        h=dict(network=NETWORK,parameters=PARAMETER_HASH,parent=parent,height=height,timestamp=timestamp if timestamp is not None else self.ancestor_headers(parent)[0]['timestamp']+10,target=self.target(parent),miner=miner,transactions=sequence_root('transactions',txs),state=state_root(state),receipts=sequence_root('receipts',receipts),work_task=work.task_id(wa,wb),nonce=0)
        for nonce in range(max_attempts):
            h['nonce']=nonce;hb=header_encode(h);challenge=H('challenge',hb);proof=work.prove(challenge,wa,wb)
            if H('ticket',challenge,proof[-32:])<=h['target']:return hb,txs,proof
        raise ValueError('WORK_BUDGET')

    def admit(self,hb,txs,proof,observed_now):
        from reference import timestamp_state,work as work_score
        self.ready()
        require(len(txs)<=PARAMS['max_transactions'],'LIMIT')
        require(all(159<=len(tx)<=PARAMS['max_transaction_bytes']for tx in txs),'LIMIT')
        require(len(hb)+2+sum(2+len(tx)for tx in txs)+len(proof)<=PARAMS['max_block_bytes'],'LIMIT')
        h=header_decode(hb);require(h['network']==NETWORK and h['parameters']==PARAMETER_HASH,'NETWORK')
        require(len(proof)==WORK_PROFILE['proof_bytes'],'WORK_LENGTH')
        bid=H('block',hb,proof[-32:])
        body=struct.pack('<H',len(txs))+b''.join(struct.pack('<H',len(tx))+tx for tx in txs)
        existing=self.db.execute('SELECT header,body,proof FROM blocks WHERE id=?',(bid,)).fetchone()
        if existing is not None:
            require(existing==(hb,body,proof),'DUPLICATE_CONTENT')
            return bid # Identical previously verified record, not new packet authority.
        for raw in txs:tx_decode(raw) # Cheap closed-codec rejection precedes heavy replay.

        parent=self.block(h['parent']);require(h['height']==parent[1]+1,'HEIGHT');require(h['target']==self.target(h['parent']),'TARGET')
        ts=[x['timestamp']for x in reversed(self.ancestor_headers(h['parent'])[:PARAMS['median_time_width']])]
        timing=timestamp_state(h['timestamp'],ts,observed_now,PARAMS['future_skew_seconds'])
        require(timing!='deferred-future','TIME_DEFERRED');require(timing=='admissible','TIME')
        require(h['transactions']==sequence_root('transactions',txs),'ROOT')
        # Reject malformed certificates before potentially long branch-state reconstruction.
        # A passed cheap filter is not verified work, not task admission, and not a block.
        work.precheck(H('challenge',hb),h['work_task'],h['target'],proof)
        prior=self.state_at(h['parent']);require(prior.get('work:'+h['work_task'].hex())is True,'TASK')
        work.verify(H('challenge',hb),h['work_task'],h['target'],proof)
        state,receipts=self.execute_application(prior,txs,h['height'],h['miner'],h['parent'])
        require(h['state']==state_root(state)and h['receipts']==sequence_root('receipts',receipts),'ROOT')
        bid=H('block',hb,proof[-32:]);cw=int.from_bytes(parent[2],'big')+work_score(int.from_bytes(h['target'],'big'));require(cw<(1<<512),'LIMIT')
        if self.db.execute('SELECT 1 FROM blocks WHERE id=?',(bid,)).fetchone():return bid
        body=struct.pack('<H',len(txs))+b''.join(struct.pack('<H',len(t))+t for t in txs)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('INSERT INTO blocks VALUES(?,?,?,?,?,?,?,?)',(bid,h['parent'],h['height'],cw.to_bytes(64,'big'),hb,body,proof,h['state']))
            for k in sorted(set(prior)|set(state)):
                before=canonical(prior[k])if k in prior else None;after=canonical(state[k])if k in state else None
                if before!=after:self.db.execute('INSERT INTO deltas VALUES(?,?,?,?)',(bid,k,before,after))
            if h['height']%128==0:
                self.db.execute('INSERT INTO snapshots VALUES(?,?)',(bid,canonical(state)))
                self.db.execute('DELETE FROM snapshots WHERE block!=? AND block NOT IN (SELECT snapshots.block FROM snapshots JOIN blocks ON blocks.id=snapshots.block ORDER BY blocks.height DESC,blocks.id LIMIT 64)',(GENESIS,))
            self.db.execute('COMMIT')
        except BaseException:self.db.execute('ROLLBACK');raise
        return bid

    def _apply_delta(self,bid,slot,detach=False):
        for k,before,after in self.db.execute('SELECT key,before,after FROM deltas WHERE block=? ORDER BY key',(bid,)).fetchall():
            expected,new=(after,before)if detach else(before,after)
            actual=self.db.execute('SELECT value FROM kv WHERE generation=? AND key=?',(slot,k)).fetchone()
            require((actual[0]if actual else None)==expected,'UNDO_ROOT')
            if new is None:self.db.execute('DELETE FROM kv WHERE generation=? AND key=?',(slot,k))
            else:self.db.execute('INSERT OR REPLACE INTO kv VALUES(?,?,?)',(slot,k,new))

    def activate(self,target,cut=None):
        pending=self.db.execute('SELECT status FROM reorg WHERE singleton=1').fetchone()
        if pending and pending[0]!='done':self._recover_intent(cut)
        old,g=self.active()
        if int.from_bytes(self.block(target)[2],'big')<=int.from_bytes(self.block(old)[2],'big'):return old
        # Ordinary extension writes only changed keys. SQLite WAL snapshots provide
        # reader atomicity; logical generation is not a request to clone the database.
        if self.block(target)[0]==old and cut is None:
            slot=self.slot();self.db.execute('BEGIN IMMEDIATE')
            try:
                self._apply_delta(target,slot)
                state={k:json.loads(v)for k,v in self.db.execute('SELECT key,value FROM kv WHERE generation=?',(slot,))}
                require(state_root(state)==self.block(target)[6],'ROOT')
                self.db.execute('UPDATE active SET tip=?,generation=? WHERE singleton=1',(target,g+1))
                self.db.execute('INSERT INTO events VALUES(?,0,?,?)',(g+1,'attach',target));self.db.execute('COMMIT')
            except BaseException:self.db.execute('ROLLBACK');raise
            return target
        left=old;right=target;detach=[];attach=[]
        while left!=right:
            if self.block(left)[1]>=self.block(right)[1]:detach.append(left);left=self.block(left)[0]
            else:attach.append(right);right=self.block(right)[0]
        steps=[['detach',x.hex()]for x in detach]+[['attach',x.hex()]for x in reversed(attach)]
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('DELETE FROM kv WHERE generation=?',(g+1,))
            self.db.execute('INSERT INTO kv SELECT ?,key,value FROM kv WHERE generation=?',(g+1,self.slot()))
            self.db.execute('INSERT OR REPLACE INTO reorg VALUES(1,?,?,?,?,0,?)',(old,target,g+1,canonical(steps),'staging'));self.db.execute('COMMIT')
        except BaseException:self.db.execute('ROLLBACK');raise
        if cut:cut('intent')
        return self._recover_intent(cut)

    def _recover_intent(self,cut=None):
        row=self.db.execute('SELECT old_tip,new_tip,generation,steps,position,status FROM reorg WHERE singleton=1').fetchone()
        if not row or row[5]=='done':return self.active()[0]
        old,target,g,encoded,pos,status=row;steps=json.loads(encoded,object_pairs_hook=unique)
        require(self.active()==(old,g-1),'GENERATION')
        for index in range(pos,len(steps)):
            kind,block=steps[index];require(kind in {'detach','attach'},'SCHEMA')
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self._apply_delta(bytes.fromhex(block),g,kind=='detach')
                self.db.execute('UPDATE reorg SET position=? WHERE singleton=1',(index+1,));self.db.execute('COMMIT')
            except BaseException:self.db.execute('ROLLBACK');raise
            if cut:cut(kind+':'+str(index))
        state={k:json.loads(v)for k,v in self.db.execute('SELECT key,value FROM kv WHERE generation=?',(g,))}
        require(state_root(state)==self.block(target)[6],'ROOT')
        if cut:cut('before-publish')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('UPDATE active SET tip=?,generation=?,state_slot=? WHERE singleton=1',(target,g,g))
            for i,(kind,b)in enumerate(steps):self.db.execute('INSERT INTO events VALUES(?,?,?,?)',(g,i,kind,bytes.fromhex(b)))
            self.db.execute("UPDATE reorg SET status='done' WHERE singleton=1")
            self.db.execute('DELETE FROM kv WHERE generation!=?',(g,));self.db.execute('COMMIT')
        except BaseException:self.db.execute('ROLLBACK');raise
        if cut:cut('published')
        return target

    def recover(self,cut=None):
        self._recover_intent(cut)
        best=self.db.execute('SELECT id,chainwork FROM blocks ORDER BY chainwork DESC,height,id LIMIT 1').fetchone()
        if best and best[1]>self.block(self.active()[0])[2]:self.activate(best[0],cut)
        return self.active()[0]


class EffectJournal:
    """Independent local facts; SQLite serializes revoke with entry across connections.

    This is the durable fact boundary, NOT the target-device effect or a Hepta permit.
    Coherent rollback of every copy still needs the independent frontier integration.
    """
    def __init__(self,path):
        self.db=sqlite3.connect(path,timeout=10,isolation_level=None)
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS effects(id BLOB PRIMARY KEY,payload BLOB NOT NULL,generation INTEGER NOT NULL,state TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS revoked(id BLOB PRIMARY KEY)')

    def enter(self,op,payload,generation):
        require(isinstance(op,bytes)and len(op)==32 and isinstance(payload,bytes)and len(payload)==32,'EFFECT_ID')
        require(type(generation)is int and 0<=generation<(1<<63),'GENERATION')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            require(not self.db.execute('SELECT 1 FROM revoked WHERE id=?',(op,)).fetchone(),'REVOKED')
            require(not self.db.execute('SELECT 1 FROM effects WHERE id=?',(op,)).fetchone(),'OPERATION_ALREADY_ENTERED')
            self.db.execute("INSERT INTO effects VALUES(?,?,?,'entered')",(op,payload,generation));self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise

    def revoke(self,op):
        require(isinstance(op,bytes)and len(op)==32,'EFFECT_ID')
        self.db.execute('BEGIN IMMEDIATE')
        try:self.db.execute('INSERT OR IGNORE INTO revoked VALUES(?)',(op,));self.db.execute('COMMIT')
        except BaseException:self.db.execute('ROLLBACK');raise
