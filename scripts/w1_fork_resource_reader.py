#!/usr/bin/env python3
"""Full-byte replay of finite native fork acquisition and adaptive miner traces.

Original scalar, signature, and encoding helpers are reused without altering old
readers. Native state/clocks are source-bound observations, not remote attestation.
A common-root finite set of actual sibling branches is not an arbitrary fork forest.
"""
from __future__ import annotations
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import w1_miner_budget_reader as base
from w1_lossless_raw import bounded_raw_lines
parent=base.parent
H=parent.H
same=base.same
exact=base.exact
require=base.require
uint64=base.uint64
SCHEMA='pon-w1-fork-resource-research-v1'
READBACK='pon-w1-fork-resource-readback-v1'
LIMIT=1024*1024*1024
COMMON=base.COMMON
PHASES=base.PHASES
FIELDS=dict(base.FIELDS)
FIELDS.update({
 'setup-acquisition':base.FIELDS['setup-acquisition']+' branch level miner_actor native_observation',
 'template':'template_index branch task_index source_id header_hex parent parent_height concurrently_retained_native_parent',
 'forest':'base branches depth leaves all_leaf_parents_present_simultaneously all_leaf_parents_nonactive arbitrary_fork_forest',
 'epoch':'epoch first_attempt started miner_elapsed_cpu_ns setup_cpu_ns one_total_miner_budget_ns reset_miner_budget adaptive_history_retained',
 'selection':'attempt_id epoch template_index branch task_index candidate header_hex screened score ticket_observed adaptive_observations receiver_feedback',
 'attempt':'attempt_id epoch template_index task_index material_task arm reuse cache_hit service_begin generated proof native_verifier_called node_called',
 'available':base.FIELDS['available']+' service_cpu_ns',
 'reconstruction':base.FIELDS['reconstruction']+' miner_actor',
 'end':base.FIELDS['end']+' all_epoch_windows_share_one_miner_budget arbitrary_strategy_cost_bound_established',
})
STAGES={k:set(v) for k,v in base.STAGES.items()}
STAGES['setup'].add('native-forest-seal')
STAGES['miner'].update(('reuse-window','adaptive-cost-selection'))
STAGE_DETAILS=dict(base.STAGE_DETAILS)
STAGE_DETAILS.update({
 'native-setup-acquisition':'task_index role source_id max_attempts branch level miner_actor parent',
 'native-forest-seal':'branches depth leaves',
 'arithmetic-prepare':'task_index material_task arm reuse epoch',
 'reuse-window':'epoch first_attempt reuse cache_before cache_after',
 'adaptive-cost-selection':'attempt_id',
})


def numeric_fields(row):
    base.numeric_fields(row)
    for key in ('branches','depth','miner_actor','first_attempt','setup_cpu_ns','one_total_miner_budget_ns','service_cpu_ns'):
        if key in row:parent.number(row[key],'NUMBER:'+key)
    for key in ('branch','level','epoch'):
        if key in row and row[key] is not None:parent.number(row[key],'NUMBER:'+key)


def options_from_args(argv):
    require(type(argv)is list and len(argv)%2==0 and all(type(x)is str for x in argv),'CLI_PAIRS')
    result=dict(setup_budget_ns=1_000_000_000,miner_budget_ns=128_000_000,branches=1,depth=1,max_attempts=4096,tasks='both',acquisition='shared',policy='round-robin',screen_width=1,arm='integer-paired-general',reuse='lifetime',window_attempts=8,seed=1)
    seen=set()
    for key,value in zip(argv[::2],argv[1::2]):
        name=key.removeprefix('--').replace('-','_')
        require(name in result and key=='--'+name.replace('_','-') and key not in seen,'CLI_OPTION');seen.add(key)
        if type(result[name])is int:
            require(value.isascii() and value.isdecimal(),'CLI_INTEGER');result[name]=int(value)
        else:result[name]=value
    return validate_options(result)


def validate_options(value):
    exact(value,'setup_budget_ns miner_budget_ns branches depth max_attempts tasks acquisition policy screen_width arm reuse window_attempts seed'.split(),'OPTIONS')
    for key in ('setup_budget_ns','miner_budget_ns','seed'):uint64(value[key],'OPTION:'+key)
    for key,upper in (('branches',4),('depth',4),('max_attempts',4096),('window_attempts',4096),('screen_width',4)):uint64(value[key],'OPTION:'+key,minimum=1,maximum=upper)
    for key,allowed in [('tasks',('maintenance','zero','both')),('acquisition',('selective','shared')),('policy',('round-robin','paid-noise-screen','adaptive-cost')),('arm',('prepared-generic','integer-paired-general','structure-specialized','structure-paired','structure-strassen')),('reuse',('lifetime','window','cold'))]:
        require(type(value[key])is str and value[key]in allowed,'OPTION_ENUM:'+key)
    return value


def tasks(options,acquired=False):
    if acquired and options['acquisition']=='shared':return [0,1]
    return [0] if options['tasks']=='maintenance' else [1] if options['tasks']=='zero' else [0,1]


def arm(options,index):
    if options['arm']=='structure-strassen':return ('maintenance-limb','blocked-zero-strassen-paired')[index]
    return base.arm(options,index)


def candidate(options,ordinal,template,candidate_id):
    header=dict(template['header'])
    header['nonce']=int.from_bytes(H('w1-fork-resource-nonce-v1',parent.u64(options['seed']),parent.u64(ordinal),parent.u64(template['branch']),parent.u64(template['task_index']),parent.u64(candidate_id))[:8],'little') | (1<<63)
    return parent.header_encode(header)


def proof(record,task_index,miner_actor=3):
    exact(record,parent.PROOF_FIELDS.split(),'PROOF_FIELDS')
    raw_header=parent.hx(record['header_hex'],318,'HEADER_HEX');header=parent.header_decode(raw_header)
    require(parent.header_encode(header)==raw_header,'HEADER_CANONICAL')
    _,network,parameters=parent.fixed_context();model,inputs,task=parent.material(task_index)
    require(header['network']==network and header['parameters']==parameters and header['miner']==parent.public(miner_actor) and header['work_task']==task and header['target'].hex()==parent.fixed_context()[0]['initial_target_hex'],'HEADER_CONTEXT')
    require(1<=header['height']<=6 and header['timestamp']==1+10*header['height'],'HEADER_HEIGHT_TIME')
    raw=parent.hx(record['proof_hex'],parent.PROOF_BYTES,'PROOF_HEX')
    require(raw[:4]==b'PNW1' and raw[4:16388]==model and raw[16388:32772]==inputs,'PROOF_MATERIAL')
    challenge=H('challenge',raw_header);trace=raw[-32:];ticket=H('ticket',challenge,trace)
    identity=H('w1-cost-game-semantic-ticket-v1',task,challenge,ticket).hex();block=H('block',raw_header,trace).hex()
    require(type(record['proof_bytes'])is int and record['proof_bytes']==parent.PROOF_BYTES and record['proof_sha256']==hashlib.sha256(raw).hexdigest(),'PROOF_DIGEST')
    expected=dict(parent=header['parent'].hex(),height=header['height'],timestamp=header['timestamp'],nonce=header['nonce'],task=task.hex(),target=header['target'].hex(),challenge=challenge.hex(),trace=trace.hex(),ticket=ticket.hex(),semantic_id=identity,block_id=block,target_hit=bool(header['target']!=bytes(32) and ticket<=header['target']))
    for key,value in expected.items():require(same(record[key],value),'PROOF_BINDING:'+key)
    replayed,_=parent.work_oracle.verify(challenge,task,b'\xff'*32,raw)
    require(replayed==ticket,'FULL_PYTHON_REPLAY')
    return dict(header=header,raw_header=raw_header,raw=raw,identity=identity,block=block,hit=expected['target_hit'],challenge=challenge,digest=record['proof_sha256'])


def load(path):
    path=Path(path).absolute();rows=[];digest=hashlib.sha256();size=0
    for line in bounded_raw_lines(path,LIMIT,2*1024*1024):
        require(line.endswith(b'\n'),'RAW_LINE');digest.update(line);size+=len(line)
        row=json.loads(line,object_pairs_hook=parent.unique)
        require(type(row)is dict and row.get('schema')==SCHEMA and type(row.get('sequence'))is int and row['sequence']==len(rows),'RAW_RECORD')
        require(row.get('kind')in FIELDS and row.get('phase')in PHASES,'RAW_KIND_PHASE')
        exact(row,COMMON|set(FIELDS[row['kind']].split()),'ROW_FIELDS:'+row['kind']);parent.stamp(row['observed']);numeric_fields(row)
        if rows:parent.before(rows[-1]['observed'],row['observed'],'OBSERVATION_ORDER')
        rows.append(row);require(len(rows)<=220000,'ROW_LIMIT')
    require(len(rows)>=6 and rows[0]['kind']=='start' and rows[-1]['kind']=='end','RAW_COMPLETENESS')
    return rows,dict(raw_path=str(path),raw_bytes=size,raw_sha256=digest.hexdigest(),raw_file_identity_checked=True,storage_compressed=path.suffix=='.gz')


class Reader(base.Reader):
    def __init__(self,rows,expected=None):
        self.rows=rows;self.options=validate_options(rows[0]['options'])
        if expected is not None:require(same(self.options,validate_options(expected)),'EXPECTED_OPTIONS')
        self.phase='setup';self.origin={'process_cpu_ns':0,'wall_ns':0};self.boundaries={};self.phase_cpu={};self.charges=[];self.used=set();self.stage_cpu=Counter();self.charge_end=dict(self.origin)
        self.tasks={};self.statement=None;self.acquisitions=[];self.templates=[];self.attempts=[];self.receivers=[];self.audits=[];self.reconstructions=[];self.screens=[];self.selection=None;self.preparations=[]
        self.initial=None;self.active=None;self.height=0;self.parents=[];self.blocks={};self.fees=0;self.transactions=0;self.proof_replays=0
        self.economy=dict(accounts={'account:'+parent.public(i).hex():dict(balance=10_000_000,nonce=0)for i in (0,2,3)},escrow_rows={})
        self.fork_nodes={};self.forest=None;self.epochs=[];self.cache={};self.history=[];self.selection_cache_hit=False
    def charge(self,row):
        require(row['stage']in STAGES[self.phase],'CHARGE_PHASE_STAGE');parent.before(self.charge_end,row['start'],'CHARGE_OVERLAP');parent.before(row['start'],row['end'],'CHARGE_ORDER');parent.before(row['end'],row['observed'],'CHARGE_OBSERVED')
        for key in ('process_cpu_ns','wall_ns'):require(type(row[key])is int and row[key]==row['end'][key]-row['start'][key],'CHARGE_DELTA')
        self.poll(row['budget_poll'],row['start'])
        if self.phase in ('setup','miner'):
            require(row['budget_poll']['permitted'],'NEW_WORK_AFTER_FAILED_POLL');parent.before(self.rows[row['sequence']-1]['observed'],row['budget_poll']['observed'],'STALE_POLL')
        exact(row['detail'],STAGE_DETAILS[row['stage']].split(),'STAGE_DETAIL');numeric_fields(row['detail'])
        self.charges.append(row);self.stage_cpu[self.phase+':'+row['stage']]+=row['process_cpu_ns'];self.charge_end=row['end'];d=row['detail']
        if row['stage']=='context-and-task-source':
            require(self.initial is None and not self.tasks,'CONTEXT_ORDER');self.initial=d['initial_stats'];self.stats(self.initial,True);self.active=self.initial['genesis'];parent.flags(d,false=('public_task_authority','real_training'));require(d['zero_source_constructed']is(1 in tasks(self.options,True)),'ZERO_ACQUISITION_SCOPE');self.used.add(row['sequence'])
        elif row['stage']=='construct-signed-registration':
            require(self.statement is not None and not self.acquisitions and same(d['transactions'],2),'REGISTRATION_CONSTRUCTION_DETAIL')
        elif row['stage']=='arithmetic-prepare':
            index=parent.number(d['task_index'],'PREPARE_TASK',1);key=parent.material(index)[2].hex()
            require(index in tasks(self.options) and d['arm']==arm(self.options,index) and d['reuse']==self.options['reuse'] and d['material_task']==key,'PREPARE_BINDING')
            if self.phase=='setup':
                hot=[c for c in self.preparations if c['phase']=='setup']
                require(self.forest is not None and self.options['reuse']=='lifetime' and d['epoch']is None and len(hot)<len(tasks(self.options)) and index==tasks(self.options)[len(hot)] and key not in self.cache,'LIFETIME_PREPARE_ORDER');self.used.add(row['sequence']);self.cache[key]=row
            else:
                require(self.selection is not None and d['epoch']==self.selection['epoch'] and same(d['epoch'],self.selection['epoch']) and index==self.selection['task_index'] and self.options['reuse']in('window','cold') and key not in self.cache,'MINER_PREPARE_ORDER')
                if self.options['reuse']=='window':self.cache[key]=row
            self.preparations.append(row)
        elif row['stage']=='reuse-window':
            require(self.phase=='miner' and self.selection is None and self.boundaries['setup']['detail']['complete'],'WINDOW_PHASE')
            require(same(d['epoch'],len(self.epochs)) and same(d['first_attempt'],len(self.attempts)) and d['first_attempt']%self.options['window_attempts']==0 and d['reuse']==self.options['reuse'],'WINDOW_ORDER')
            require(same(d['cache_before'],sorted(self.cache)) and same(d['cache_after'],[] if self.options['reuse']=='window' else sorted(self.cache)),'WINDOW_CACHE_RESET')
            if self.options['reuse']=='window':self.cache.clear()
    def task(self,row):
        require(self.phase=='setup' and self.initial is not None and row['task_index']not in self.tasks,'TASK_ORDER');index=parent.number(row['task_index'],'TASK_INDEX',1);m,i,t=parent.material(index)
        require(row['model_hex']==m.hex() and row['input_hex']==i.hex() and row['task']==t.hex(),'TASK_BYTES');require(row['mined']is(index in tasks(self.options)) and row['template_acquired']is(index in tasks(self.options,True)),'TASK_SELECTION_SCOPE')
        require(index==len(self.tasks) and (index==0 or 1 in tasks(self.options,True)),'SELECTIVE_TASK_SOURCE');self.tasks[index]=row
    def read_statement(self,row):
        require(self.phase=='setup' and self.statement is None and 1 in self.tasks and not self.acquisitions,'STATEMENT_ORDER');self.statement=parent.statement(row['lease_hex'],row['statement_hex'],1,dict(rounds=self.options['depth']))
    def observation(self,value,p):
        exact(value,'schema block stored_exact block_height block_chainwork_hex active_tip active_tip_height active_tip_chainwork_hex active_chain_member active_depth active_work_depth_hex active_membership_sql_lookups active_membership_sql_budget generation accepted_task local_target_only global_absence_authority confirmation_authority finality_authority execution_authority production_activation'.split(),'NATIVE_OBSERVATION_FIELDS')
        expected=dict(schema='pon-native-exact-packet-observation-v3',block=p['block'],stored_exact=True,block_height=p['header']['height'],block_chainwork_hex=(2*p['header']['height']).to_bytes(64,'big').hex(),active_tip=self.active,active_tip_height=self.height,active_tip_chainwork_hex=(2*self.height).to_bytes(64,'big').hex(),active_chain_member=False,active_depth=None,active_work_depth_hex=None,active_membership_sql_lookups=value['active_membership_sql_lookups'],active_membership_sql_budget=1024,generation=len(self.parents),accepted_task=None,local_target_only=True,global_absence_authority=False,confirmation_authority=False,finality_authority=False,execution_authority=False,production_activation=False)
        parent.number(value['active_membership_sql_lookups'],'MEMBERSHIP_LOOKUPS',1024);require(same(value,expected),'NATIVE_OBSERVATION_BINDING')
    def acquisition_grid(self):
        grid=[]
        if 1 in tasks(self.options,True):grid.append(('zero-registration',None,None,0,3))
        for branch in range(self.options['branches']):
            grid.extend(('fork-node',branch,level,0,3+branch) for level in range(1,self.options['depth']+1))
            grid.extend(('fork-template',branch,self.options['depth']+1,index,3) for index in tasks(self.options,True))
        return grid
    def acquisition(self,row):
        require(self.phase=='setup' and same(row['source_id'],len(self.acquisitions)) and len(self.acquisitions)<len(self.acquisition_grid()),'ACQUISITION_ORDER')
        role,branch,level,index,actor=self.acquisition_grid()[len(self.acquisitions)]
        require(same([row[k]for k in ('role','branch','level','task_index','miner_actor')],[role,branch,level,index,actor]),'ACQUISITION_GRID')
        if role=='zero-registration':expected_parent=self.active
        else:
            require((1 not in tasks(self.options,True) or len(self.parents)==1) and self.forest is None,'FORK_BASE_NOT_READY')
            expected_parent=self.active if level==1 else self.fork_nodes[(branch,level-1)]['block']
        p=proof(row['proof'],index,actor);self.proof_replays+=1;h=p['header']
        height=self.height+1 if role=='zero-registration' else self.height+level
        require(h['parent'].hex()==expected_parent and h['height']==height and p['hit'] and h['nonce']<64,'ACQUISITION_PARENT_TARGET')
        require(row['native_block_id']==p['block'] and same(row['original_complete_attempts'],h['nonce']+1),'ACQUISITION_ID_COUNT');parent.flags(row,false=('original_miss_bytes_retained','posthoc_reconstruction_adds_credit'))
        charge=self.consume(row,'native-setup-acquisition',source_id=row['source_id'],role=role,task_index=index,max_attempts=64,branch=branch,level=level,miner_actor=actor,parent=expected_parent)
        parent.before(charge['start'],row['made'],'MAKE_TIME');parent.before(row['made'],row['admitted'],'ADMISSION_TIME');parent.before(row['admitted'],charge['end'],'ACQUISITION_END')
        self.observation(row['native_observation'],p)
        txs=[parent.transaction(x,h['network'])for x in row['transactions_hex']];require(parent.sequence_root('transactions',[x['raw']for x in txs])==h['transactions'],'TX_ROOT')
        expected=self.economy
        if role=='zero-registration':
            require(self.statement is not None and index==0,'REGISTRATION_SOURCE')
            require([(t['tag'],t['sender'],t['nonce'])for t in txs]==[(18,parent.public(2),1),(21,parent.public(0),1)] and txs[0]['payload']==self.statement['lease'] and txs[1]['payload']==self.statement['signed'],'REGISTRATION_TX')
            self.consume(row,'construct-signed-registration',transactions=2);receipt=row['fee_receipt'];exact(receipt,'transactions fee_total receipt_root_matches_original_node_header before after fee_units cpu_units_separate'.split(),'FEE_FIELDS');parent.number(receipt['fee_total'],'FEE_TOTAL');require(type(receipt['transactions'])is list and same(receipt['before'],self.economy),'FEE_BEFORE')
            expected=json.loads(json.dumps(self.economy));encoded=[];total=0
            for t,r in zip(txs,receipt['transactions']):
                exact(r,'transaction_id tag sender nonce fee fee_limit before_balance after_balance'.split(),'FEE_TX_FIELDS')
                for k in ('tag','nonce','fee','fee_limit','before_balance','after_balance'):parent.number(r[k],'FEE_NUMBER:'+k)
                account=expected['accounts']['account:'+t['sender'].hex()];fee=parent.number(r['fee'],'FEE')
                require(r['transaction_id']==t['id'] and r['sender']==t['sender'].hex() and r['tag']==t['tag'] and r['nonce']==t['nonce'] and r['fee_limit']==t['fee_limit'] and 0<fee<=t['fee_limit'] and r['before_balance']==account['balance'] and r['after_balance']==account['balance']-fee,'FEE_TX_BINDING')
                account.update(balance=account['balance']-fee,nonce=t['nonce']);encoded.append(parent.canonical(dict(tx=t['id'],fee=fee,status='applied')));total+=fee
            require(len(receipt['transactions'])==len(txs) and receipt['fee_total']==row['fee_units']==total and same(receipt['after'],expected) and parent.sequence_root('receipts',encoded)==h['receipts'],'FEE_ROOT')
            parent.flags(receipt,true=('receipt_root_matches_original_node_header','cpu_units_separate'));require(receipt['fee_units']=='native-development-token-integer','FEE_UNITS');self.fees+=total;self.transactions+=2
        else:require(not txs and row['fee_receipt']is None and same(row['fee_units'],0) and h['receipts']==parent.sequence_root('receipts',[]),'EMPTY_FORK_ACQUISITION')
        p.update(id=row['source_id'],task_index=index,miner_actor=actor,branch=branch,level=level,role=role,row=row,nonce=h['nonce'],after_economy=expected)
        self.acquisitions.append(p);self.blocks[p['block']]=p
        if role=='fork-node':self.fork_nodes[(branch,level)]=p
    def read_parent(self,row):
        require(self.phase=='setup' and row['role']=='zero-registration' and not self.parents and len(self.acquisitions)==1,'ACTIVE_BASE_ORDER')
        id=row['stats']['tip'];p=self.acquisitions[0];require(p['role']=='zero-registration' and id==p['block'] and p['header']['parent'].hex()==self.active,'ACTIVE_BASE_BINDING')
        self.consume(row,'native-setup-activation',role=row['role'],block_id=id);self.active=id;self.height=p['header']['height'];self.economy=p['after_economy'];self.parents.append(row);self.stats(row['stats'])
    def template(self,row):
        require(self.phase=='setup' and same(row['template_index'],len(self.templates)),'TEMPLATE_ORDER')
        acquired=tasks(self.options,True);branch,index=divmod(len(self.templates),len(acquired))
        require(same(row['branch'],branch) and same(row['task_index'],acquired[index]) and branch<self.options['branches'],'TEMPLATE_GRID')
        require(same(row['source_id'],len(self.acquisitions)-1),'TEMPLATE_SOURCE');p=self.acquisitions[row['source_id']];leaf=self.fork_nodes[(branch,self.options['depth'])]
        require(p['role']=='fork-template' and p['task_index']==row['task_index'] and row['header_hex']==p['raw_header'].hex() and row['parent']==leaf['block']==p['header']['parent'].hex() and same(row['parent_height'],leaf['header']['height']),'TEMPLATE_PARENT')
        parent.flags(row,true=('concurrently_retained_native_parent',));self.templates.append(dict(row,header=p['header']));self.history.append(dict(samples=0,service_cpu_ns=0))
    def read_forest(self,row):
        require(self.phase=='setup' and self.forest is None and len(self.acquisitions)==len(self.acquisition_grid()) and len(self.templates)==self.options['branches']*len(tasks(self.options,True)),'FOREST_SEAL_ORDER')
        require(row['base']==self.active and same(row['branches'],self.options['branches']) and same(row['depth'],self.options['depth']) and type(row['leaves'])is list and len(row['leaves'])==self.options['branches'],'FOREST_TOPOLOGY')
        parent.flags(row,true=('all_leaf_parents_present_simultaneously','all_leaf_parents_nonactive'),false=('arbitrary_fork_forest',))
        self.consume(row,'native-forest-seal',branches=self.options['branches'],depth=self.options['depth'],leaves=len(row['leaves']))
        for branch,leaf in enumerate(row['leaves']):
            exact(leaf,'branch source_id parent parent_height state_root next_target native_observation'.split(),'FOREST_LEAF_FIELDS');p=self.fork_nodes[(branch,self.options['depth'])]
            expected=dict(branch=branch,source_id=p['id'],parent=p['block'],parent_height=p['header']['height'],state_root=p['header']['state'].hex(),next_target=p['header']['target'].hex(),native_observation=leaf['native_observation'])
            require(same(leaf,expected),'FOREST_LEAF_BINDING');self.observation(leaf['native_observation'],p)
        require(len({leaf['parent']for leaf in row['leaves']})==self.options['branches'],'FOREST_DISTINCT_LEAVES');self.forest=row
    def read_epoch(self,row):
        require(self.phase=='miner' and self.boundaries['setup']['detail']['complete'] and self.selection is None and same(row['epoch'],len(self.epochs)) and same(row['first_attempt'],len(self.attempts)) and row['first_attempt']%self.options['window_attempts']==0,'EPOCH_ORDER')
        charge=self.consume(row,'reuse-window',epoch=row['epoch'],first_attempt=row['first_attempt'],reuse=self.options['reuse'])
        parent.before(charge['end'],row['started'],'EPOCH_BEFORE_CACHE_RESET');parent.before(row['started'],row['observed'],'EPOCH_FUTURE')
        require(same(row['miner_elapsed_cpu_ns'],row['started']['process_cpu_ns']-self.origin['process_cpu_ns']) and same(row['setup_cpu_ns'],self.phase_cpu['setup']) and same(row['one_total_miner_budget_ns'],self.options['miner_budget_ns']),'EPOCH_ONE_BUDGET')
        parent.flags(row,true=('adaptive_history_retained',),false=('reset_miner_budget',));self.epochs.append(row)
    def eligible(self):return [i for i,t in enumerate(self.templates)if t['task_index']in tasks(self.options)]
    def expected_candidate(self,row):
        require(self.phase=='miner' and self.boundaries['setup']['detail']['complete'] and self.selection is None,'SELECTION_PHASE')
        ordinal=parent.number(row['attempt_id'],'ATTEMPT_ID',self.options['max_attempts']-1);require(ordinal==len(self.attempts),'SELECTION_ORDER')
        require(self.epochs and self.epochs[-1]['epoch']==ordinal//self.options['window_attempts'],'SELECTION_EPOCH')
        index=parent.number(row['template_index'],'TEMPLATE_INDEX',len(self.templates)-1);template=self.templates[index];require(index in self.eligible(),'UNACQUIRED_SELECTION')
        candidate_id=parent.number(row['candidate'],'CANDIDATE',self.options['screen_width']-1);raw=candidate(self.options,ordinal,template,candidate_id);require(row['header_hex']==raw.hex(),'SELECTION_HEADER')
        return ordinal,index,template,candidate_id,raw
    def read_screen(self,row):
        require(self.options['policy']=='paid-noise-screen','UNREGISTERED_SCREEN');ordinal,index,_,candidate_id,raw=self.expected_candidate(row)
        grid=[(i,c)for i in self.eligible()for c in range(self.options['screen_width'])];preceding=[r for r in self.screens if r['attempt_id']==ordinal]
        require(len(preceding)<len(grid) and (index,candidate_id)==grid[len(preceding)],'SCREEN_GRID')
        score,calls,digest=parent.noise(H('challenge',raw));require(same(row['score'],score) and same(row['noise_hash_calls'],calls) and row['noise_sha256']==digest,'SCREEN_REPLAY')
        require(type(row['selected'])is bool,'SCREEN_SELECTED_TYPE');parent.flags(row,false=('ticket_observed','noise_passed_to_producer'));self.screens.append(row)
    def adaptive_choice(self):
        eligible=self.eligible()
        unseen=[i for i in eligible if self.history[i]['samples']==0]
        if unseen:return unseen[0]
        best=eligible[0]
        for index in eligible[1:]:
            left=self.history[index]['service_cpu_ns']*self.history[best]['samples'];right=self.history[best]['service_cpu_ns']*self.history[index]['samples']
            if (left,index)<(right,best):best=index
        return best
    def read_selection(self,row):
        ordinal,index,template,candidate_id,_=self.expected_candidate(row)
        require(same(row['branch'],template['branch']) and same(row['task_index'],template['task_index']) and same(row['epoch'],ordinal//self.options['window_attempts']),'SELECTION_BINDING');parent.flags(row,false=('ticket_observed','receiver_feedback'))
        screens=[r for r in self.screens if r['attempt_id']==ordinal]
        if self.options['policy']=='paid-noise-screen':
            count=len(self.eligible())*self.options['screen_width'];require(len(screens)==count and same(row['screened'],count) and row['adaptive_observations']is None,'SCREEN_COUNT');best=min(screens,key=lambda s:(s['score'],s['template_index'],s['candidate']))
            require(same([index,candidate_id,row['score']],[best['template_index'],best['candidate'],best['score']]) and all(r['selected']is(r is best)for r in screens),'SCREEN_MINIMUM');self.consume(row,'paid-noise-screen',attempt_id=ordinal,candidates=count)
        else:
            require(not screens and same(row['screened'],0) and row['score']is None and candidate_id==0,'NONSCREENED_POLICY')
            if self.options['policy']=='adaptive-cost':
                expected=[dict(template_index=i,**self.history[i])for i in self.eligible()]
                require(same(row['adaptive_observations'],expected) and index==self.adaptive_choice(),'ADAPTIVE_PAID_HISTORY');self.consume(row,'adaptive-cost-selection',attempt_id=ordinal)
            else:
                require(row['adaptive_observations']is None and index==self.eligible()[ordinal%len(self.eligible())],'FIXED_POLICY');self.consume(row,'fixed-selection',attempt_id=ordinal)
        self.selection=row;self.selection_cache_hit=parent.material(row['task_index'])[2].hex()in self.cache
    def attempt(self,row):
        require(self.phase=='miner' and self.selection is not None and same(row['attempt_id'],len(self.attempts)),'ATTEMPT_ORDER');selection=self.selection
        require(all(same(row[k],selection[k])for k in ('attempt_id','epoch','template_index','task_index')) and row['arm']==arm(self.options,row['task_index']) and row['reuse']==self.options['reuse'],'ATTEMPT_SELECTION')
        key=parent.material(row['task_index'])[2].hex();require(row['material_task']==key and row['cache_hit']is self.selection_cache_hit,'MATERIAL_CACHE_BINDING')
        parent.flags(row,false=('native_verifier_called','node_called'));p=proof(row['proof'],row['task_index']);self.proof_replays+=1
        require(p['raw_header'].hex()==selection['header_hex'] and p['header']['transactions']==parent.sequence_root('transactions',[]) and p['header']['receipts']==parent.sequence_root('receipts',[]),'ATTEMPT_NATIVE_TEMPLATE')
        require(p['header']['nonce']>=(1<<63) and all(p['identity']!=a['identity']for a in self.acquisitions),'SETUP_WINNER_RECREDIT')
        charge=self.consume(row,'complete-proof-and-ticket',attempt_id=row['attempt_id'],task_index=row['task_index'],arm=row['arm']);parent.before(selection['observed'],row['service_begin'],'SERVICE_BEFORE_SELECTION');parent.before(row['service_begin'],charge['start'],'SERVICE_START');parent.before(charge['start'],row['generated'],'GENERATION_START');parent.before(row['generated'],charge['end'],'GENERATION_END')
        if not self.selection_cache_hit:
            require(self.options['reuse']in('cold','window'),'LIFETIME_PREPARATION_MISSING')
            preparation=self.consume(row,'arithmetic-prepare',task_index=row['task_index'],material_task=key,arm=row['arm'],reuse=row['reuse'],epoch=row['epoch']);parent.before(row['service_begin'],preparation['start'],'PREPARE_SERVICE_START');parent.before(preparation['end'],charge['start'],'PREPARE_BEFORE_PRODUCE')
        else:require(self.options['reuse']!='cold' and key in self.cache,'REUSED_PREPARATION_MISSING')
        p.update(row=row,id=row['attempt_id'],task_index=row['task_index'],template_index=row['template_index'],generation_charge=charge,availability=None,receiver=None);self.attempts.append(p);self.selection=None
    def available(self,row):
        super().available(row);attempt=self.attempts[-1]
        require(same(row['service_cpu_ns'],row['available']['process_cpu_ns']-attempt['row']['service_begin']['process_cpu_ns']),'SERVICE_CPU_BINDING')
        observed=self.history[attempt['template_index']];observed['samples']+=1;observed['service_cpu_ns']+=row['service_cpu_ns'];parent.number(observed['service_cpu_ns'],'HISTORY_CPU_OVERFLOW')
    def reconstruction(self,row):
        require(self.phase=='audit' and len(self.audits)==len(self.attempts),'RECONSTRUCTION_PHASE')
        source_id=parent.number(row['source_id'],'RECONSTRUCTION_SOURCE',len(self.acquisitions)-1);source=self.acquisitions[source_id];expected=[(a['id'],n)for a in self.acquisitions for n in range(a['nonce']+1)]
        require(len(self.reconstructions)<len(expected) and same([source_id,row['ordinal']],list(expected[len(self.reconstructions)])) and same(row['task_index'],source['task_index']) and same(row['miner_actor'],source['miner_actor']),'RECONSTRUCTION_ORDER')
        p=proof(row['proof'],row['task_index'],row['miner_actor']);self.proof_replays+=1;header=dict(source['header']);header['nonce']=row['ordinal'];require(p['raw_header']==parent.header_encode(header),'RECONSTRUCTION_HEADER');winner=row['ordinal']==source['nonce']
        require(row['original_winner']is winner and row['original_bytes_observed']is winner and p['hit']is winner,'RECONSTRUCTION_WINNER')
        if winner:require(p['raw']==source['raw'] and p['identity']==source['identity'],'ORIGINAL_WINNER_BYTES')
        parent.flags(row,false=('new_work_credit','miner_feedback'));self.reconstructions.append(row)
    def setup_detail(self,row):
        d=row['detail'];exact(d,'complete status templates requested_branches requested_depth fork_nodes forest_sealed complete_leaf_branches acquired_tasks miner_tasks original_acquisitions original_search_complete_attempts known_original_winning_semantics lifetime_preparations transaction_count transaction_fee_units fee_units_added_to_cpu native_stats economy'.split(),'SETUP_SUMMARY_FIELDS')
        require(type(d['complete'])is bool,'SETUP_COMPLETE_TYPE');complete=d['complete'];hot=[c for c in self.preparations if c['phase']=='setup']
        ready=self.forest is not None and len(hot)==(len(tasks(self.options))if self.options['reuse']=='lifetime'else 0)
        require(not complete or (ready and row['terminal_poll']['permitted'] and row['elapsed_cpu_ns']<=self.options['setup_budget_ns']),'SETUP_OVER_BUDGET_OR_INCOMPLETE')
        require(complete or not row['terminal_poll']['permitted'] or row['elapsed_cpu_ns']>self.options['setup_budget_ns'],'UNEXPLAINED_SETUP_STOP')
        if self.initial is not None:
            require(set(self.tasks)==({0,1}if 1 in tasks(self.options,True)else{0}) and (self.statement is not None)==(1 in tasks(self.options,True)),'MISSING_TASK_OR_STATEMENT');self.stats(d['native_stats']);require(same(d['economy'],self.economy),'ACTIVE_SETUP_ECONOMY')
        else:require(d['native_stats']is None and d['economy']is None and not self.tasks and not self.acquisitions,'SETUP_CONTEXT_ABSENT')
        require(len(self.templates)==sum(a['role']=='fork-template'for a in self.acquisitions),'ORPHAN_TEMPLATE_SOURCE');require(len({a['identity']for a in self.acquisitions})==len(self.acquisitions),'DUPLICATE_ORIGINAL_ACQUISITION')
        expected=dict(complete=complete,status='complete'if complete else'setup-cpu-budget-stopped',templates=len(self.templates),requested_branches=self.options['branches'],requested_depth=self.options['depth'],fork_nodes=len(self.fork_nodes),forest_sealed=self.forest is not None,complete_leaf_branches=sum(level==self.options['depth']for _,level in self.fork_nodes),acquired_tasks=tasks(self.options,True),miner_tasks=tasks(self.options),original_acquisitions=len(self.acquisitions),original_search_complete_attempts=sum(a['nonce']+1 for a in self.acquisitions),known_original_winning_semantics=self.unique(self.acquisitions),lifetime_preparations=len(hot),transaction_count=self.transactions,transaction_fee_units=self.fees,fee_units_added_to_cpu=False,native_stats=d['native_stats'],economy=d['economy'])
        require(same(d,expected),'SETUP_SUMMARY_BINDING')
    def miner_detail(self,row):
        d=row['detail'];complete=self.boundaries['setup']['detail']['complete'];require(all(a['availability']is not None for a in self.attempts),'UNAVAILABLE_RETAINED_PROOF')
        if not complete:
            require(not self.attempts and not self.epochs and self.selection is None and not self.screens and row['terminal_poll']is None,'MINING_WITHOUT_SETUP');status='setup-incomplete'
        else:
            require(row['terminal_poll']is not None,'MISSING_TERMINAL_MINER_POLL');status='miner-cpu-budget-stopped'if not row['terminal_poll']['permitted']else'safety-cap-censored'
            if status=='safety-cap-censored':require(len(self.attempts)==self.options['max_attempts'] and self.selection is None,'CAP_EARLY_STOP')
            if self.selection is not None:require(status=='miner-cpu-budget-stopped','UNFINISHED_SELECTION_WITHOUT_STOP')
        within=self.within();expected=dict(status=status,attempts=len(self.attempts),epochs_started=len(self.epochs),safety_cap_reached=len(self.attempts)==self.options['max_attempts'],miner_unique_complete_by_B=self.unique(within),miner_unique_target_hits_by_B=self.unique([a for a in within if a['hit']]),native_acceptance_known_during_mining=False,cache_drop_included=True,one_total_budget_across_epochs=True,adaptive_history=[dict(template_index=i,**v)for i,v in enumerate(self.history)])
        require(same(d,expected),'MINER_SUMMARY_BINDING')
    def boundary(self,row):
        index=PHASES.index(self.phase);require(index<4 and row['from']==self.phase and row['to']==row['phase']==PHASES[index+1] and same(row['begin'],self.origin),'PHASE_BOUNDARY_ORDER');parent.stamp(row['begin'])
        parent.before(self.rows[row['sequence']-1]['observed'],row['end'],'BOUNDARY_BEFORE_LAST_RECORD');parent.before(row['end'],row['observed'],'BOUNDARY_FUTURE');parent.before(self.charge_end,row['end'],'UNSEALED_CHARGE')
        require(same(row['elapsed_cpu_ns'],row['end']['process_cpu_ns']-self.origin['process_cpu_ns']),'PHASE_ELAPSED')
        if self.phase=='miner' and not self.boundaries['setup']['detail']['complete']:require(row['terminal_poll']is None,'SKIPPED_MINER_POLL')
        else:self.poll(row['terminal_poll'],row['end'])
        parent.flags(row,true=('boundary_encoding_charged_to_next_phase',));getattr(self,self.phase+'_detail')(row)
        unbound=[c for c in self.charges if c['phase']==self.phase and c['sequence']not in self.used]
        if self.phase=='setup':
            require(not unbound or (not row['detail']['complete'] and len(unbound)==1 and unbound[0]['stage']=='construct-signed-registration' and self.transactions==0),'UNBOUND_SETUP_CHARGE')
            if not row['detail']['complete']:self.cache.clear()
        elif self.phase=='miner':
            require(not unbound or (row['detail']['status']=='miner-cpu-budget-stopped' and len(unbound)==1 and unbound[0]['stage']=='arithmetic-prepare' and self.selection is not None and self.options['reuse']in('cold','window')),'UNBOUND_MINER_CHARGE')
        else:require(not unbound,'UNBOUND_POST_MINER_CHARGE')
        require(sum(c['process_cpu_ns']for c in self.charges if c['phase']==self.phase)<=row['elapsed_cpu_ns'],'CHARGES_EXCEED_PHASE');self.boundaries[self.phase]=row;self.phase_cpu[self.phase]=row['elapsed_cpu_ns'];self.phase=row['to'];self.origin=row['end'];self.charge_end=self.origin
    def end(self,row):
        super().end(row);parent.flags(row,true=('all_epoch_windows_share_one_miner_budget',),false=('arbitrary_strategy_cost_bound_established',))
    def run(self):
        first=self.rows[0];require(first['phase']=='setup' and same(first['phase_order'],list(PHASES)),'START_PHASES');parent.flags(first,false=('miner_has_node_or_verifier','physical_cost_lower_bound','production_activation'))
        for key,value in dict(budget_units='process-cpu-nanoseconds; setup P and one total miner B separately bounded; windows never reset B',proof_completion='full original bytes encoded/flushed before availability stamp',parent_bank='finite common-root sibling branches with distinct native miners; all leaves coexist; not arbitrary fork forest',native_task_authority='isolated disclosed development signers and continuity genesis').items():require(first[key]==value,'START_SCOPE:'+key)
        handlers={'charge':self.charge,'task':self.task,'task-statement':self.read_statement,'setup-acquisition':self.acquisition,'setup-parent':self.read_parent,'template':self.template,'forest':self.read_forest,'epoch':self.read_epoch,'screen':self.read_screen,'selection':self.read_selection,'attempt':self.attempt,'available':self.available,'receiver':self.receiver,'audit-proof':self.audit_proof,'reconstruction':self.reconstruction,'end':self.end}
        for row in self.rows[1:]:
            if self.attempts and self.attempts[-1]['availability']is None:require(row['kind']=='available','MISSING_IMMEDIATE_AVAILABILITY')
            if row['kind']=='boundary':self.boundary(row);continue
            require(row['phase']==self.phase and row['kind']in handlers,'PHASE_RECORD_ORDER');handlers[row['kind']](row)
        last=self.rows[-1];attempts=[]
        for a in self.attempts:
            r=a['row'];record=r['proof'];availability=a['availability'];attempts.append(dict(attempt_id=a['id'],epoch=r['epoch'],task_index=a['task_index'],template_index=a['template_index'],branch=self.templates[a['template_index']]['branch'],semantic_id=a['identity'],parent=record['parent'],height=record['height'],header_hex=record['header_hex'],challenge=record['challenge'],proof_sha256=a['digest'],target_hit=a['hit'],available=availability['available'],miner_elapsed_cpu_ns=availability['miner_elapsed_cpu_ns'],within_miner_budget=availability['within_miner_budget'],service_cpu_ns=availability['service_cpu_ns'],cache_hit=r['cache_hit'],material_task=r['material_task'],native_accepted=a['receiver']['accepted'],native_admission_completed=a['receiver']['completed'],native_admission_cpu_ns=next(c['process_cpu_ns']for c in self.charges if c['stage']=='original-node-admission' and c['detail']['attempt_id']==a['id']),producer_cpu_ns=a['generation_charge']['process_cpu_ns']))
        acquisitions=[dict(source_id=a['id'],task_index=a['task_index'],role=a['role'],branch=a['branch'],level=a['level'],miner_actor=a['miner_actor'],header_hex=a['raw_header'].hex(),parent=a['header']['parent'].hex(),height=a['header']['height'],challenge=a['challenge'].hex(),semantic_id=a['identity'],proof_sha256=a['digest'],block_id=a['block'],original_complete_attempts=a['nonce']+1,fee_units=a['row']['fee_units'],transactions_hex=a['row']['transactions_hex'],native_observation=a['row']['native_observation'])for a in self.acquisitions]
        templates=[{k:t[k]for k in ('template_index','branch','task_index','source_id','header_hex','parent','parent_height')}for t in self.templates]
        forest=None if self.forest is None else {k:self.forest[k]for k in ('base','branches','depth','leaves')}
        paid_identity=dict(acquisitions=acquisitions,templates=templates,forest=forest)
        return dict(schema=READBACK,options=self.options,status='verified',setup_complete=last['setup_complete'],miner_status=last['miner_status'],total_process_cpu_ns=last['total_process_cpu_ns'],total_wall_ns=last['total_wall_ns'],phase_cpu_ns=self.phase_cpu,phase_boundaries={k:dict(begin=v['begin'],end=v['end'],terminal_poll=v['terminal_poll'])for k,v in self.boundaries.items()},setup=last['setup'],miner=last['miner'],receiver=last['receiver'],audit=last['audit'],attempts=attempts,acquisitions=acquisitions,templates=templates,forest=forest,paid_forest_identity_sha256=hashlib.sha256(parent.canonical(paid_identity)).hexdigest(),epochs=[{k:e[k]for k in ('epoch','first_attempt','started','miner_elapsed_cpu_ns','setup_cpu_ns','one_total_miner_budget_ns')}for e in self.epochs],retained_proof_records_replayed=self.proof_replays,counts=dict(research_proof_records=len(self.attempts),original_winner_records=len(self.acquisitions),original_reconstruction_records=len(self.reconstructions),all_full_proof_records=self.proof_replays,research_target_hits=sum(a['hit']for a in self.attempts),research_late_proofs=sum(not a['availability']['within_miner_budget']for a in self.attempts),research_late_target_hits=sum(a['hit']and not a['availability']['within_miner_budget']for a in self.attempts),miner_unique_complete_by_B=last['miner_unique_complete_by_B'],miner_unique_target_hits_by_B=last['miner_unique_target_hits_by_B'],eventually_native_accepted_from_B=last['eventually_native_accepted_from_B']),charged_stage_cpu_ns=dict(self.stage_cpu),unattributed_phase_cpu_ns={phase:total-sum(c['process_cpu_ns']for c in self.charges if c['phase']==phase)for phase,total in self.phase_cpu.items()},limits=dict(physical_miner_phase=True,full_scalar_replay=True,native_state_and_clocks_are_source_bound_observations=True,finite_common_root_sibling_branches=True,arbitrary_fork_forest=False,arbitrary_adaptive_strategy=False,unbounded_reuse=False,one_total_miner_budget_across_epochs=True,public_task_authority=False,minimum_attacker_cost_established=False,production_activation=False,comparability_requires_exact_paid_forest_and_semantic_prefix=True,native_admission_is_after_miner_budget=True,mature_rewards_or_tip_throughput=False))


def read_fork(path,expected_options=None):
    rows,metadata=load(path);return dict(Reader(rows,expected_options).run(),**metadata)


if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('usage: w1_fork_resource_reader.py RAW.jsonl[.gz]')
    print(json.dumps(read_fork(sys.argv[1]),sort_keys=True,separators=(',',':')))
