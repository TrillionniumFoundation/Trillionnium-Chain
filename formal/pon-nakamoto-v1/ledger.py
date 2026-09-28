"""Executable contract ledger: real Ed25519, full work verification and disk SQLite.
Not a production host. Local Python execution is an independently coded spec oracle,
not the existing Rust task kernel and not an ordinary Hepta product invocation.
"""
from __future__ import annotations
import copy,json,os,sqlite3,struct,fcntl
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from cryptography.exceptions import InvalidSignature
from contract_wire import *
import work_oracle as work
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
def contribution_id(sender,family,parent,artifact,components):return H('contribution',sender,family,parent,artifact,components)

def execute(parent,transactions,height,miner,parent_id):
    require(len(transactions)<=PARAMS['max_transactions'],'LIMIT')
    s=copy.deepcopy(parent);fees=0;receipts=[];miner=miner.hex()
    # Mandatory expiry is sorted deterministically. Admission limits due slots to 16.
    due=[]
    for name,v in s.items():
        if name.startswith(('task:','quota:'))and v['remaining'] and v['deadline']<=height:due.append((v['deadline'],name))
    for _,name in sorted(due)[:PARAMS['mandatory_expiry_per_block']]:
        obj=s[name];account(s,obj['owner'])['balance']=checked(account(s,obj['owner'])['balance']+obj['remaining'])
        obj['remaining']=0;obj['status']='expired';receipts.append(canonical({'expiry':name}))
    for name in sorted(list(s)):
        if name.startswith('reward:')and s[name]['maturity']<=height:
            v=s.pop(name);account(s,v['owner'])['balance']=checked(account(s,v['owner'])['balance']+v['amount'])
    for raw in transactions:
        tx=tx_decode(raw);f=tx['fields'];sender=tx['sender'].hex();tag=tx['tag'];acct=account(s,sender)
        require(tx['network']==NETWORK,'NETWORK');require(tx['nonce']==acct['nonce']+1,'NONCE');require(height<=tx['expiry'],'EXPIRED')
        try:Ed25519PublicKey.from_public_bytes(tx['sender']).verify(tx['signature'],H('tx-sign',tx['unsigned']))
        except (ValueError,InvalidSignature) as e:raise ValueError('SIGNATURE')from e
        fee=COMMANDS[tag]['base_fee_units']+len(raw)*PARAMS['byte_fee_units'];require(tx['fee_limit']>=fee,'FEE')
        if tag!=11:require(acct['balance']>=fee,'FUNDS');acct['balance']-=fee
        def pay(n):require(n>0 and acct['balance']>=n,'FUNDS');acct['balance']-=n
        def fetch(prefix,h):
            name=prefix+h.hex();require(name in s,'STATE');return s[name]
        def deadline(d):
            require(height<d<=height+PARAMS['max_task_lifetime_blocks'],'EXPIRED')
            active=[v for k,v in s.items()if k.startswith(('task:','quota:'))and v['remaining']]
            require(len(active)<PARAMS['max_pending_tasks'],'LIMIT')
            require(sum(v['deadline']==d for v in active)<PARAMS['mandatory_expiry_per_block'],'LIMIT')
        if tag==1:
            pay(f['amount']);dest=account(s,f['recipient'].hex());dest['balance']=checked(dest['balance']+f['amount'])
        elif tag==2:
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
            require(f['contribution']==contribution_id(tx['sender'],f['family'],f['parent_release'],f['artifact'],f['components_root']),'ROOT')
            require(f['family']==FAMILY and f['parent_release'].hex()==s['model:current'],'STATE')
            require(0<f['size']<=PARAMS['max_artifact_bytes'],'LIMIT');require(f['artifact']!=ZERO,'EVIDENCE')
            require(sum(k.startswith('contribution:')for k in s)<PARAMS['max_model_candidates'],'LIMIT')
            duplicate='artifact:'+f['parent_release'].hex()+':'+f['artifact'].hex();require(name not in s and duplicate not in s,'DUPLICATE')
            s[name]={'owner':sender,'artifact':f['artifact'].hex(),'components_root':f['components_root'].hex(),'family':f['family'].hex(),'parent':f['parent_release'].hex(),'votes':{},'score':0,'status':'submitted'};s[duplicate]=cid
        elif tag==7:
            obj=fetch('contribution:',f['contribution']);require(sender in EVALUATORS and sender!=obj['owner'],'AUTHORITY')
            require(obj['status']=='submitted','STATE');require(sender not in obj['votes'],'DUPLICATE')
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
            name='release:'+f['release'].hex();require(name not in s,'DUPLICATE');pay(f['budget'])
            s[name]={'owner':sender,'remaining':f['budget'],'budget':f['budget'],'total':total,'root':root.hex(),'maturity':height+PARAMS['reward_maturity_blocks'],'bundle':f['bundle'].hex(),'leaf_count':len(allocations),'claims':{}}
            for cid,_,_ in allocations:s['contribution:'+cid.hex()]['status']='adopted'
            bundle['status']='adopted';s['model:current']=f['release'].hex()
        elif tag==9:
            rel=fetch('release:',f['release']);obj=fetch('contribution:',f['contribution']);require(obj['owner']==sender,'AUTHORITY')
            require(height>=rel['maturity'],'STATE');cid=f['contribution'].hex();require(cid not in rel['claims'],'DUPLICATE')
            require(len(f['siblings'])==(rel['leaf_count']-1).bit_length(),'ROOT')
            require(allocation_check(allocation_leaf(f['contribution'],tx['sender'],f['score']),f['siblings'],bytes.fromhex(rel['root'])),'ROOT')
            amount=rel['budget']*f['score']//rel['total'];require(amount<=rel['remaining'],'FUNDS')
            acct['balance']=checked(acct['balance']+amount);rel['remaining']-=amount;rel['claims'][cid]=amount
        elif tag==10:
            name='quota:'+f['quota'].hex();require(name not in s,'DUPLICATE');deadline(f['deadline']);require(0<f['units']<=PARAMS['max_quota_units'],'LIMIT')
            cost=f['units']*PARAMS['quota_unit_price'];pay(cost)
            s[name]={'owner':sender,'consumer':f['consumer'].hex(),'provider':f['provider'].hex(),'remaining':cost,'units':f['units'],'deadline':f['deadline'],'status':'reserved'}
        elif tag==11:
            obj=fetch('quota:',f['quota']);require(sender==obj['provider'],'AUTHORITY');require(obj['status']=='reserved'and height<obj['deadline'],'STATE')
            require(0<f['units']<=obj['units']and f['result']!=ZERO,'LIMIT')
            digest=H('use',f['quota'],tx['sender'],u64(tx['nonce']),u64(f['units']),f['result'])
            try:Ed25519PublicKey.from_public_bytes(bytes.fromhex(obj['consumer'])).verify(f['consumer_signature'],digest)
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

SCHEMA_SQL='''
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS blocks(id BLOB PRIMARY KEY,parent BLOB,height INTEGER NOT NULL,chainwork BLOB NOT NULL,header BLOB,body BLOB,proof BLOB,state_root BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS deltas(block BLOB NOT NULL,key TEXT NOT NULL,before BLOB,after BLOB,PRIMARY KEY(block,key));
CREATE TABLE IF NOT EXISTS active(singleton INTEGER PRIMARY KEY CHECK(singleton=1),tip BLOB NOT NULL,generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS kv(generation INTEGER NOT NULL,key TEXT NOT NULL,value BLOB NOT NULL,PRIMARY KEY(generation,key));
CREATE TABLE IF NOT EXISTS reorg(singleton INTEGER PRIMARY KEY CHECK(singleton=1),old_tip BLOB,new_tip BLOB,generation INTEGER,steps BLOB,position INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS events(generation INTEGER NOT NULL,ordinal INTEGER NOT NULL,kind TEXT,block BLOB,PRIMARY KEY(generation,ordinal));
'''
class Ledger:
    def __init__(self,directory):
        self.directory=Path(directory);self.directory.mkdir(mode=0o700,parents=True,exist_ok=True)
        require(not self.directory.is_symlink(),'NAMESPACE')
        lock_path=self.directory/'owner.lock';require(not lock_path.is_symlink(),'NAMESPACE')
        self.owner=open(lock_path,'a+b')
        try:fcntl.flock(self.owner.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:self.owner.close();raise ValueError('WRITER_BUSY')
        path=self.directory/'ledger.sqlite'
        try:
            require(not path.is_symlink(),'NAMESPACE')
            if path.exists():
                # Reject foreign/incomplete stores without creating tables or changing journal mode.
                from urllib.parse import quote
                probe=sqlite3.connect('file:'+quote(str(path.resolve()))+'?mode=ro',uri=True)
                try:
                    tables={r[0]for r in probe.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
                    require(tables=={'metadata','blocks','deltas','active','kv','reorg','events'},'SCHEMA')
                    stored=probe.execute("SELECT value FROM metadata WHERE key='parameters'").fetchone()
                    require(stored is not None and stored[0]==PARAMETER_HASH,'NETWORK')
                finally:probe.close()
            self.db=sqlite3.connect(path,timeout=10,isolation_level=None);self.db.executescript(SCHEMA_SQL)
        except BaseException:
            self.owner.close();raise
        network=self.db.execute("SELECT value FROM metadata WHERE key='parameters'").fetchone()
        if network:require(network[0]==PARAMETER_HASH,'NETWORK')
        else:
            s=genesis_state();self.db.execute('BEGIN IMMEDIATE')
            self.db.execute("INSERT INTO metadata VALUES('parameters',?)",(PARAMETER_HASH,))
            self.db.execute('INSERT INTO blocks VALUES(?,?,?,?,?,?,?,?)',(GENESIS,None,0,bytes(64),None,None,None,state_root(s)))
            self.db.execute('INSERT INTO active VALUES(1,?,0)',(GENESIS,))
            self.db.executemany('INSERT INTO kv VALUES(0,?,?)',[(k,canonical(v))for k,v in s.items()]);self.db.execute('COMMIT')
    def close(self):
        self.db.close();fcntl.flock(self.owner.fileno(),fcntl.LOCK_UN);self.owner.close()
    def ready(self):
        p=self.db.execute("SELECT status FROM reorg WHERE singleton=1").fetchone()
        require(not p or p[0]=='done','REORG_IN_PROGRESS')
    def block(self,tip):
        row=self.db.execute('SELECT parent,height,chainwork,header,body,proof,state_root FROM blocks WHERE id=?',(tip,)).fetchone();require(row is not None,'UNKNOWN_PARENT');return row
    def active(self):return self.db.execute('SELECT tip,generation FROM active WHERE singleton=1').fetchone()
    def read_active(self):
        self.db.execute('BEGIN')
        try:
            tip,g=self.active();s={k:json.loads(v)for k,v in self.db.execute('SELECT key,value FROM kv WHERE generation=?',(g,))};require(state_root(s)==self.block(tip)[6],'ROOT');return tip,g,s
        finally:self.db.execute('COMMIT')
    def state_at(self,tip):
        if tip==self.active()[0]:return self.read_active()[2]
        chain=[];cur=tip
        while cur!=GENESIS:
            require(len(chain)<PARAMS['max_header_candidates'],'LIMIT');chain.append(cur);cur=self.block(cur)[0]
        s=genesis_state()
        for b in reversed(chain):
            for k,before,after in self.db.execute('SELECT key,before,after FROM deltas WHERE block=? ORDER BY key',(b,)):
                require((canonical(s[k])if k in s else None)==before,'UNDO_ROOT')
                if after is None:s.pop(k,None)
                else:s[k]=json.loads(after)
            require(state_root(s)==self.block(b)[6],'ROOT')
        return s
    def ancestor_headers(self,parent):
        hs=[]
        while parent!=GENESIS and len(hs)<max(16,11):
            row=self.block(parent);hs.append(header_decode(row[3]));parent=row[0]
        if parent==GENESIS:hs.append({'timestamp':PARAMS['genesis_timestamp'],'target':bytes.fromhex(PARAMS['initial_target_hex'])})
        return hs
    def target(self,parent):
        from reference import retarget
        row=self.block(parent);height=row[1]+1;hs=self.ancestor_headers(parent);prior=int.from_bytes(hs[0]['target'],'big')
        if height%PARAMS['retarget_interval']==0:
            prior=retarget(prior,hs[PARAMS['retarget_interval']-1]['timestamp'],hs[0]['timestamp'],PARAMS['retarget_interval'],PARAMS['target_spacing_seconds'],int(PARAMS['pow_limit_hex'],16))
        return prior.to_bytes(32,'big')
    def make(self,parent,txs,miner=None,timestamp=None,max_attempts=4096,work_inputs=None):
        self.ready()
        wa,wb=(A,B)if work_inputs is None else work_inputs
        miner=public(key(0))if miner is None else miner;row=self.block(parent);height=row[1]+1
        s,receipts=execute(self.state_at(parent),txs,height,miner,parent)
        h=dict(network=NETWORK,parameters=PARAMETER_HASH,parent=parent,height=height,timestamp=timestamp if timestamp is not None else self.ancestor_headers(parent)[0]['timestamp']+10,target=self.target(parent),miner=miner,transactions=sequence_root('transactions',txs),state=state_root(s),receipts=sequence_root('receipts',receipts),work_task=work.task_id(wa,wb),nonce=0)
        for nonce in range(max_attempts):
            h['nonce']=nonce;hb=header_encode(h);challenge=H('challenge',hb);proof=work.prove(challenge,wa,wb)
            if H('ticket',challenge,proof[-32:])<=h['target']:return hb,txs,proof
        raise ValueError('WORK_BUDGET')
    def admit(self,hb,txs,proof,observed_now):
        from reference import timestamp_state,work as work_score
        self.ready()
        require(len(hb)+sum(map(len,txs))+len(proof)<=PARAMS['max_block_bytes'],'LIMIT')
        h=header_decode(hb);require(h['network']==NETWORK and h['parameters']==PARAMETER_HASH,'NETWORK')
        parent=self.block(h['parent']);require(h['height']==parent[1]+1,'HEIGHT');require(h['target']==self.target(h['parent']),'TARGET')
        ts=[x['timestamp']for x in reversed(self.ancestor_headers(h['parent'])[:11])]
        require(timestamp_state(h['timestamp'],ts,observed_now,PARAMS['future_skew_seconds'])=='admissible','TIME')
        prior=self.state_at(h['parent']);require(prior.get('work:'+h['work_task'].hex())is True,'TASK')
        require(h['transactions']==sequence_root('transactions',txs),'ROOT')
        work.verify(H('challenge',hb),h['work_task'],h['target'],proof)
        state,receipts=execute(prior,txs,h['height'],h['miner'],h['parent'])
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
            self.db.execute('COMMIT')
        except BaseException:self.db.execute('ROLLBACK');raise
        return bid
    def activate(self,target,cut=None):
        pending=self.db.execute("SELECT status FROM reorg WHERE singleton=1").fetchone()
        if pending and pending[0]!='done':return self.recover(cut)
        old,g=self.active()
        if int.from_bytes(self.block(target)[2],'big')<=int.from_bytes(self.block(old)[2],'big'):return old
        left=old;right=target;detach=[];attach=[]
        while left!=right:
            if self.block(left)[1]>=self.block(right)[1]:detach.append(left);left=self.block(left)[0]
            else:attach.append(right);right=self.block(right)[0]
        steps=[['detach',x.hex()]for x in detach]+[['attach',x.hex()]for x in reversed(attach)]
        self.db.execute('BEGIN IMMEDIATE')
        self.db.execute('DELETE FROM kv WHERE generation=?',(g+1,))
        self.db.execute('INSERT INTO kv SELECT ?,key,value FROM kv WHERE generation=?',(g+1,g))
        self.db.execute('INSERT OR REPLACE INTO reorg VALUES(1,?,?,?,?,0,?)',(old,target,g+1,canonical(steps),'staging'));self.db.execute('COMMIT')
        if cut:cut('intent')
        return self.recover(cut)
    def recover(self,cut=None):
        row=self.db.execute('SELECT old_tip,new_tip,generation,steps,position,status FROM reorg WHERE singleton=1').fetchone()
        if not row or row[5]=='done':return self.active()[0]
        old,target,g,encoded,pos,status=row;steps=json.loads(encoded)
        require(self.active()==(old,g-1),'GENERATION')
        for index in range(pos,len(steps)):
            kind,block=steps[index];changes=list(self.db.execute('SELECT key,before,after FROM deltas WHERE block=? ORDER BY key',(bytes.fromhex(block),)))
            self.db.execute('BEGIN IMMEDIATE')
            try:
                for k,before,after in changes:
                    expected,new=(after,before)if kind=='detach'else(before,after)
                    actual=self.db.execute('SELECT value FROM kv WHERE generation=? AND key=?',(g,k)).fetchone()
                    require((actual[0]if actual else None)==expected,'UNDO_ROOT')
                    if new is None:self.db.execute('DELETE FROM kv WHERE generation=? AND key=?',(g,k))
                    else:self.db.execute('INSERT OR REPLACE INTO kv VALUES(?,?,?)',(g,k,new))
                self.db.execute('UPDATE reorg SET position=? WHERE singleton=1',(index+1,));self.db.execute('COMMIT')
            except BaseException:self.db.execute('ROLLBACK');raise
            if cut:cut(kind+':'+str(index))
        s={k:json.loads(v)for k,v in self.db.execute('SELECT key,value FROM kv WHERE generation=?',(g,))}
        require(state_root(s)==self.block(target)[6],'ROOT')
        if cut:cut('before-publish')
        self.db.execute('BEGIN IMMEDIATE')
        self.db.execute('UPDATE active SET tip=?,generation=? WHERE singleton=1',(target,g))
        for i,(kind,b)in enumerate(steps):self.db.execute('INSERT INTO events VALUES(?,?,?,?)',(g,i,kind,bytes.fromhex(b)))
        self.db.execute("UPDATE reorg SET status='done' WHERE singleton=1");self.db.execute('COMMIT')
        if cut:cut('published')
        return target

class EffectJournal:
    """Separate irreversible local facts. Does not solve simultaneous rollback of all stores."""
    def __init__(self,path):
        self.db=sqlite3.connect(path,isolation_level=None);self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS effects(id BLOB PRIMARY KEY,payload BLOB NOT NULL,generation INTEGER NOT NULL,state TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS revoked(id BLOB PRIMARY KEY)')
    def enter(self,op,payload,generation):
        require(not self.db.execute('SELECT 1 FROM revoked WHERE id=?',(op,)).fetchone(),'REVOKED')
        require(not self.db.execute('SELECT 1 FROM effects WHERE id=?',(op,)).fetchone(),'OPERATION_ALREADY_ENTERED')
        self.db.execute("INSERT INTO effects VALUES(?,?,?,'entered')",(op,payload,generation))
    def revoke(self,op):self.db.execute('INSERT OR IGNORE INTO revoked VALUES(?)',(op,))
