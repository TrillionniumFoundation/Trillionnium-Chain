#!/usr/bin/env python3
"""Independent full-byte replay of physically separated native miner research.

The old canonical scalar oracle and signature/wire recipes are reused. Native
State execution, clock observations and authority checks remain source-bound
observations; proof replay is not hardware, Node or public-task attestation.
"""
from __future__ import annotations
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import w1_parent_reuse_reader as parent
from read_w1_cost_research import exact, require, uint64
H=parent.H
SCHEMA='pon-w1-miner-budget-research-v1'
READBACK='pon-w1-miner-budget-readback-v1'
LIMIT=1024*1024*1024
COMMON={'schema','sequence','phase','observed','kind'}
PHASES=('setup','miner','receiver','audit','done')
FIELDS={
 'start':'options phase_order budget_units miner_has_node_or_verifier proof_completion parent_bank native_task_authority physical_cost_lower_bound production_activation',
 'charge':'stage start end process_cpu_ns wall_ns budget_poll detail',
 'boundary':'from to begin end elapsed_cpu_ns terminal_poll detail boundary_encoding_charged_to_next_phase',
 'task':'task_index model_hex input_hex task mined template_acquired',
 'task-statement':'lease_hex statement_hex',
 'setup-acquisition':'source_id task_index role proof transactions_hex made admitted native_block_id original_complete_attempts original_miss_bytes_retained fee_receipt fee_units posthoc_reconstruction_adds_credit',
 'setup-parent':'role stats',
 'template':'template_index bank task_index source_id header_hex parent parent_height historical_native_parent',
 'selection':'attempt_id template_index bank task_index candidate header_hex screened score ticket_observed',
 'screen':'attempt_id template_index candidate header_hex score noise_hash_calls noise_sha256 selected ticket_observed noise_passed_to_producer',
 'attempt':'attempt_id template_index task_index arm cache generated proof native_verifier_called node_called',
 'available':'attempt_id available miner_elapsed_cpu_ns full_bytes_flushed within_miner_budget',
 'receiver':'attempt_id accepted block_id error completed from_within_miner_budget semantic_id native_acceptance_after_miner_sealed miss_is_cheap_target_rejection claim_of_mature_reward',
 'audit-proof':'attempt_id full_relation reference_relation provides_miner_feedback',
 'reconstruction':'source_id task_index ordinal original_winner original_bytes_observed proof new_work_credit miner_feedback',
 'end':'status setup_complete miner_status phase_cpu_ns total_process_cpu_ns total_wall_ns native_total_endpoint setup miner receiver audit miner_unique_complete_by_B miner_unique_target_hits_by_B eventually_native_accepted_from_B setup_known_winners_are_separate native_acceptance_completed_within_miner_B retained_records_are_distinct_tickets minimum_attacker_cost_established hardness_accepted production_activation',
}
STAGES={
 'setup':{'context-and-task-source','construct-signed-registration','native-setup-acquisition','native-setup-activation','arithmetic-prepare'},
 'miner':{'arithmetic-prepare','fixed-selection','paid-noise-screen','complete-proof-and-ticket'},
 'receiver':{'original-node-admission','native-owner-and-directory-teardown'},
 'audit':{'research-full-native-audit'},
}
STAGE_DETAILS={
 'context-and-task-source':'initial_stats zero_source_constructed public_task_authority real_training',
 'construct-signed-registration':'transactions',
 'native-setup-acquisition':'task_index role source_id max_attempts',
 'native-setup-activation':'role block_id',
 'arithmetic-prepare':'task_index arm cache',
 'fixed-selection':'attempt_id',
 'paid-noise-screen':'attempt_id candidates',
 'complete-proof-and-ticket':'attempt_id task_index arm',
 'original-node-admission':'attempt_id',
 'native-owner-and-directory-teardown':'owned_cleanup',
 'research-full-native-audit':'attempt_id',
}

def same(actual,expected):
    if type(actual)is not type(expected):return False
    if type(expected)is dict:return actual.keys()==expected.keys() and all(same(actual[k],v)for k,v in expected.items())
    if type(expected)is list:return len(actual)==len(expected) and all(same(a,b)for a,b in zip(actual,expected))
    return actual==expected

def numeric_fields(row):
    for key in ('sequence','task_index','source_id','ordinal','template_index','bank','parent_height','attempt_id','candidate','screened','noise_hash_calls','original_complete_attempts','fee_units','miner_elapsed_cpu_ns','process_cpu_ns','wall_ns','elapsed_cpu_ns','total_process_cpu_ns','total_wall_ns','miner_unique_complete_by_B','miner_unique_target_hits_by_B','eventually_native_accepted_from_B'):
        if key in row:parent.number(row[key],'NUMBER:'+key)
    if 'score'in row and row['score']is not None:parent.number(row['score'],'SCORE')

def options_from_args(argv):
    require(type(argv)is list and len(argv)%2==0 and all(type(x)is str for x in argv),'CLI_PAIRS')
    result=dict(setup_budget_ns=1_000_000_000,miner_budget_ns=100_000_000,parents=1,max_attempts=4096,
                acquisition='selective',policy='maintenance-only',parent_policy='round-robin',screen_width=1,
                arm='integer-paired-general',cache='hot',seed=1)
    seen=set()
    for key,value in zip(argv[::2],argv[1::2]):
        name=key.removeprefix('--').replace('-','_')
        require(name in result and key=='--'+name.replace('_','-') and key not in seen,'CLI_OPTION')
        seen.add(key)
        if type(result[name])is int:
            require(value.isascii() and value.isdecimal(),'CLI_INTEGER');result[name]=int(value)
        else:result[name]=value
    return validate_options(result)

def validate_options(value):
    exact(value,'setup_budget_ns miner_budget_ns parents max_attempts acquisition policy parent_policy screen_width arm cache seed'.split(),'OPTIONS')
    for key in ('setup_budget_ns','miner_budget_ns','seed'):uint64(value[key],'OPTION:'+key)
    for key,upper in (('parents',4),('max_attempts',4096),('screen_width',4)):uint64(value[key],'OPTION:'+key,minimum=1,maximum=upper)
    for key,allowed in [('acquisition',('selective','shared')),('policy',('maintenance-only','zero-only','round-robin','paid-noise-screen')),
                        ('parent_policy',('newest','round-robin')),('arm',('prepared-generic','integer-paired-general','structure-specialized','structure-paired')),('cache',('hot','cold'))]:
        require(value[key] in allowed,'OPTION_ENUM:'+key)
    return value

def tasks(options,acquired=False):
    if acquired and options['acquisition']=='shared':return [0,1]
    return [0] if options['policy']=='maintenance-only' else [1] if options['policy']=='zero-only' else [0,1]

def arm(options,index):
    return ('maintenance-limb','blocked-zero')[index] if options['arm']=='structure-specialized' else ('maintenance-limb','blocked-zero-integer-paired')[index] if options['arm']=='structure-paired' else options['arm']

def candidate(options,ordinal,template,candidate_id):
    h=dict(template['header'])
    h['nonce']=int.from_bytes(H('w1-miner-budget-nonce-v1',parent.u64(options['seed']),parent.u64(ordinal),parent.u64(template['bank']),parent.u64(template['task_index']),parent.u64(candidate_id))[:8],'little') | (1<<63)
    return parent.header_encode(h)

def load(path):
    path=Path(path).absolute();initial=path.lstat()
    require(stat.S_ISREG(initial.st_mode) and not path.is_symlink() and 0<initial.st_size<=LIMIT,'RAW_SIZE_OR_SYMLINK')
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    rows=[];digest=hashlib.sha256()
    with path.open('rb')as stream:
        opened=os.fstat(stream.fileno());require(identity(opened)==identity(initial),'RAW_REPLACED_ON_OPEN')
        for line in stream:
            require(len(line)<=2*1024*1024 and line.endswith(b'\n'),'RAW_LINE')
            digest.update(line);row=json.loads(line,object_pairs_hook=parent.unique)
            require(type(row)is dict and row.get('schema')==SCHEMA and type(row.get('sequence'))is int and row['sequence']==len(rows),'RAW_RECORD')
            require(row.get('kind')in FIELDS and row.get('phase')in PHASES,'RAW_KIND_PHASE')
            exact(row,COMMON|set(FIELDS[row['kind']].split()),'ROW_FIELDS:'+row['kind'])
            parent.stamp(row['observed']);numeric_fields(row)
            if rows:parent.before(rows[-1]['observed'],row['observed'],'OBSERVATION_ORDER')
            rows.append(row);require(len(rows)<=200000,'ROW_LIMIT')
        require(identity(os.fstat(stream.fileno()))==identity(opened),'RAW_MUTATED_DURING_READ')
    require(not path.is_symlink() and identity(path.lstat())==identity(opened),'RAW_PATH_REPLACED')
    require(len(rows)>=6 and rows[0]['kind']=='start' and rows[-1]['kind']=='end','RAW_COMPLETENESS')
    return rows,dict(raw_path=str(path),raw_bytes=opened.st_size,raw_sha256=digest.hexdigest(),raw_file_identity_checked=True)

class Reader:
    def __init__(self,rows,expected):
        self.rows=rows;self.options=validate_options(rows[0]['options'])
        if expected is not None:require(self.options==validate_options(expected),'EXPECTED_OPTIONS')
        self.phase='setup';self.origin={'process_cpu_ns':0,'wall_ns':0};self.boundaries={};self.phase_cpu={};self.charges=[];self.used=set();self.stage_cpu=Counter();self.charge_end=dict(self.origin)
        self.tasks={};self.statement=None;self.acquisitions=[];self.templates=[];self.attempts=[];self.receivers=[];self.audits=[];self.reconstructions=[];self.screens=[];self.selection=None;self.preparations=[]
        self.initial=None;self.active=None;self.height=0;self.parents=[];self.blocks={};self.fees=0;self.transactions=0;self.proof_replays=0
        self.economy=dict(accounts={'account:'+parent.public(i).hex():dict(balance=10_000_000,nonce=0)for i in (0,2,3)},escrow_rows={})
    def limit(self):return self.options['setup_budget_ns'] if self.phase=='setup' else self.options['miner_budget_ns'] if self.phase=='miner' else None
    def poll(self,value,at):
        if self.limit()is None:require(value is None,'UNEXPECTED_PHASE_POLL');return
        exact(value,'phase observed elapsed_cpu_ns permitted'.split(),'POLL_FIELDS')
        require(value['phase']==self.phase,'POLL_PHASE');parent.before(self.origin,value['observed'],'POLL_BEFORE_PHASE');parent.before(value['observed'],at,'POLL_TIME')
        require(type(value['elapsed_cpu_ns'])is int and value['elapsed_cpu_ns']==value['observed']['process_cpu_ns']-self.origin['process_cpu_ns'],'POLL_ELAPSED')
        require(type(value['permitted'])is bool and value['permitted']==(value['elapsed_cpu_ns']<self.limit()),'POLL_PREDICATE')
    def consume(self,row,stage,**detail):
        matches=[c for c in self.charges if c['sequence']not in self.used and c['phase']==self.phase and c['stage']==stage and c['sequence']<row['sequence'] and all(same(c['detail'].get(k),v) for k,v in detail.items())]
        require(len(matches)==1,'CHARGE_BINDING:'+stage);c=matches[0];self.used.add(c['sequence']);return c
    def stats(self,value,initial=False):
        exact(value,parent.STATS_FIELDS.split(),'STATS_FIELDS');_,network,parameters=parent.fixed_context()
        require(value['network']==network.hex() and value['parameters']==parameters.hex(),'NATIVE_CONTEXT')
        parent.flags(value,false=('production_activation',))
        for key in ('height','generation','state_keys','stored_blocks','events','authenticated_sessions','authenticated_pending','authenticated_audit_rows','authenticated_outbox_sessions','authenticated_outbox_pending'):parent.number(value[key],'STATS_NUMBER:'+key)
        for key in ('authenticated_sessions','authenticated_pending','authenticated_audit_rows','authenticated_outbox_sessions','authenticated_outbox_pending'):require(value[key]==0,'UNEXPECTED_NATIVE_SESSION')
        parent.hx(value['state_root'],32,'STATS_ROOT');parent.hx(value['chainwork_hex'],64,'CHAINWORK_HEX')
        if initial:
            root=parent.hx(value['state_root'],32,'INITIAL_ROOT');genesis=H('genesis',network,parameters,root,parent.u64(1)).hex()
            require(value['tip']==value['genesis']==genesis and value['height']==value['generation']==value['events']==0 and int(value['chainwork_hex'],16)==0 and value['stored_blocks']==1,'INITIAL_STATS')
        else:
            require(value['genesis']==self.initial['genesis'] and value['tip']==self.active and value['height']==self.height and int(value['chainwork_hex'],16)==2*self.height and value['generation']==value['events']==len(self.parents) and value['stored_blocks']==1+len(self.blocks),'NATIVE_STATS')
            if self.height:require(value['state_root']==self.blocks[self.active]['header']['state'].hex(),'NATIVE_STATE_ROOT')
            else:require(value['state_root']==self.initial['state_root'],'INITIAL_STATE_ROOT')
    def charge(self,row):
        require(row['stage']in STAGES[self.phase],'CHARGE_PHASE_STAGE');parent.before(self.charge_end,row['start'],'CHARGE_OVERLAP');parent.before(row['start'],row['end'],'CHARGE_ORDER');parent.before(row['end'],row['observed'],'CHARGE_OBSERVED')
        for key in ('process_cpu_ns','wall_ns'):require(type(row[key])is int and row[key]==row['end'][key]-row['start'][key],'CHARGE_DELTA')
        self.poll(row['budget_poll'],row['start'])
        if self.phase in ('setup','miner'):
            require(row['budget_poll']['permitted'],'NEW_WORK_AFTER_FAILED_POLL')
            parent.before(self.rows[row['sequence']-1]['observed'],row['budget_poll']['observed'],'STALE_POLL')
        exact(row['detail'],STAGE_DETAILS[row['stage']].split(),'STAGE_DETAIL');numeric_fields(row['detail'])
        self.charges.append(row);self.stage_cpu[self.phase+':'+row['stage']]+=row['process_cpu_ns'];self.charge_end=row['end']
        if row['stage']=='context-and-task-source':
            require(self.initial is None and not self.tasks,'CONTEXT_ORDER');d=row['detail'];self.initial=d['initial_stats'];self.stats(self.initial,True);self.active=self.initial['genesis'];parent.flags(d,false=('public_task_authority','real_training'))
            require(d['zero_source_constructed'] is (1 in tasks(self.options,True)),'ZERO_ACQUISITION_SCOPE');self.used.add(row['sequence'])
        elif row['stage']=='construct-signed-registration':
            require(self.statement is not None and not self.acquisitions and same(row['detail']['transactions'],2),'REGISTRATION_CONSTRUCTION_DETAIL')
        elif row['stage']=='arithmetic-prepare':
            d=row['detail'];require(d['task_index']in tasks(self.options) and d['arm']==arm(self.options,d['task_index']) and d['cache']==self.options['cache'],'PREPARE_BINDING')
            require(self.phase==('setup' if self.options['cache']=='hot' else 'miner'),'PREPARE_PHASE')
            if self.phase=='setup':require(len(self.preparations)<len(tasks(self.options)) and d['task_index']==tasks(self.options)[len(self.preparations)],'HOT_PREPARE_ORDER');self.used.add(row['sequence'])
            else:require(self.selection is not None and d['task_index']==self.selection['task_index'],'COLD_PREPARE_SELECTION')
            self.preparations.append(row)
    def task(self,row):
        require(self.phase=='setup' and self.initial is not None and row['task_index']not in self.tasks,'TASK_ORDER');index=parent.number(row['task_index'],'TASK_INDEX',1);m,i,t=parent.material(index)
        require(row['model_hex']==m.hex() and row['input_hex']==i.hex() and row['task']==t.hex(),'TASK_BYTES');require(row['mined'] is (index in tasks(self.options)) and row['template_acquired'] is (index in tasks(self.options,True)),'TASK_SELECTION_SCOPE')
        require(index==len(self.tasks) and (index==0 or 1 in tasks(self.options,True)),'SELECTIVE_TASK_SOURCE');self.tasks[index]=row
    def read_statement(self,row):
        require(self.phase=='setup' and self.statement is None and 1 in self.tasks and not self.acquisitions,'STATEMENT_ORDER');self.statement=parent.statement(row['lease_hex'],row['statement_hex'],1,dict(rounds=self.options['parents']))
    def acquisition(self,row):
        require(self.phase=='setup' and row['source_id']==len(self.acquisitions),'ACQUISITION_ORDER');index=parent.number(row['task_index'],'SOURCE_TASK',1);p=parent.proof(row['proof'],index);self.proof_replays+=1
        h=p['header'];require(h['parent'].hex()==self.active and h['height']==self.height+1 and p['hit'] and h['nonce']<64,'ACQUISITION_PARENT_TARGET')
        require(row['native_block_id']==p['block'] and row['original_complete_attempts']==h['nonce']+1,'ACQUISITION_ID_COUNT');parent.flags(row,false=('original_miss_bytes_retained','posthoc_reconstruction_adds_credit'))
        charge=self.consume(row,'native-setup-acquisition',source_id=row['source_id'],role=row['role'],task_index=index,max_attempts=64)
        parent.before(charge['start'],row['made'],'MAKE_TIME');parent.before(row['made'],row['admitted'],'ADMISSION_TIME');parent.before(row['admitted'],charge['end'],'ACQUISITION_END')
        txs=[parent.transaction(x,h['network'])for x in row['transactions_hex']];require(parent.sequence_root('transactions',[x['raw']for x in txs])==h['transactions'],'TX_ROOT')
        if row['role']=='zero-registration':
            require(len(self.acquisitions)==0 and self.statement is not None and index==0,'REGISTRATION_SOURCE')
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
            parent.flags(receipt,true=('receipt_root_matches_original_node_header','cpu_units_separate'));require(receipt['fee_units']=='native-development-token-integer','FEE_UNITS')
            self.fees+=total;self.transactions+=2
        else:
            require(row['role']=='bank-template' and not txs and row['fee_receipt']is None and row['fee_units']==0 and h['receipts']==parent.sequence_root('receipts',[]),'TEMPLATE_ACQUISITION')
            if 1 in tasks(self.options,True):require(self.statement is not None and self.height>=1,'ZERO_NOT_REGISTERED')
        p.update(id=row['source_id'],task_index=index,role=row['role'],row=row,nonce=h['nonce'],after_economy=expected if row['role']=='zero-registration' else self.economy);self.acquisitions.append(p);self.blocks[p['block']]=p
    def read_parent(self,row):
        require(self.phase=='setup','PARENT_PHASE');id=row['stats']['tip'];require(id in self.blocks,'PARENT_NOT_ADMITTED');p=self.blocks[id];require(p['header']['parent'].hex()==self.active,'PARENT_CHAIN')
        if row['role']=='zero-registration':require(p['role']=='zero-registration' and len(self.parents)==0,'REGISTERED_PARENT')
        else:
            require(row['role']=='ancestor-bank-advance','PARENT_ROLE');bank=sum(r['role']=='ancestor-bank-advance'for r in self.parents);candidates=[t for t in self.templates if t['bank']==bank];require(len(candidates)==len(tasks(self.options,True)) and any(t['source_id']==p['id'] and t['task_index']==tasks(self.options)[0]for t in candidates),'ADVANCE_CHOICE')
        self.consume(row,'native-setup-activation',role=row['role'],block_id=id);self.active=id;self.height=p['header']['height'];self.economy=p['after_economy'];self.parents.append(row);self.stats(row['stats'])
    def template(self,row):
        require(self.phase=='setup' and row['template_index']==len(self.templates),'TEMPLATE_ORDER');acquired=tasks(self.options,True);bank,index=divmod(len(self.templates),len(acquired));require(row['bank']==bank and row['task_index']==acquired[index] and bank<self.options['parents'],'TEMPLATE_GRID')
        require(row['source_id']==len(self.acquisitions)-1,'TEMPLATE_SOURCE');p=self.acquisitions[row['source_id']];require(p['role']=='bank-template' and p['task_index']==row['task_index'] and row['header_hex']==p['raw_header'].hex() and row['parent']==self.active==p['header']['parent'].hex() and row['parent_height']==self.height,'TEMPLATE_PARENT')
        parent.flags(row,true=('historical_native_parent',));self.templates.append(dict(row,header=p['header']))
    def expected_candidate(self,row):
        require(self.phase=='miner' and self.boundaries['setup']['detail']['complete'] and self.selection is None,'SELECTION_PHASE')
        ordinal=parent.number(row['attempt_id'],'ATTEMPT_ID',self.options['max_attempts']-1)
        require(ordinal==len(self.attempts),'SELECTION_ORDER')
        index=parent.number(row['template_index'],'TEMPLATE_INDEX',len(self.templates)-1);template=self.templates[index]
        require(template['task_index']in tasks(self.options),'UNACQUIRED_SELECTION')
        candidate_id=parent.number(row['candidate'],'CANDIDATE',self.options['screen_width']-1)
        raw=candidate(self.options,ordinal,template,candidate_id)
        require(row['header_hex']==raw.hex(),'SELECTION_HEADER')
        return ordinal,index,template,candidate_id,raw
    def read_screen(self,row):
        require(self.options['policy']=='paid-noise-screen','UNREGISTERED_SCREEN')
        ordinal,index,_,candidate_id,raw=self.expected_candidate(row)
        grid=[(i,c)for i,t in enumerate(self.templates)if t['task_index']in tasks(self.options) and (self.options['parent_policy']!='newest' or t['bank']==self.options['parents']-1)for c in range(self.options['screen_width'])]
        preceding=[r for r in self.screens if r['attempt_id']==ordinal]
        require(len(preceding)<len(grid) and (index,candidate_id)==grid[len(preceding)],'SCREEN_GRID')
        score,calls,digest=parent.noise(H('challenge',raw))
        require(type(row['score'])is int and row['score']==score and type(row['noise_hash_calls'])is int and row['noise_hash_calls']==calls and row['noise_sha256']==digest,'SCREEN_REPLAY')
        require(type(row['selected'])is bool,'SCREEN_SELECTED_TYPE');parent.flags(row,false=('ticket_observed','noise_passed_to_producer'));self.screens.append(row)
    def read_selection(self,row):
        ordinal,index,template,candidate_id,_=self.expected_candidate(row)
        require(row['bank']==template['bank'] and row['task_index']==template['task_index'],'SELECTION_BINDING');parent.flags(row,false=('ticket_observed',))
        screens=[r for r in self.screens if r['attempt_id']==ordinal]
        if self.options['policy']=='paid-noise-screen':
            expected_count=len(tasks(self.options))*self.options['screen_width']*(1 if self.options['parent_policy']=='newest' else self.options['parents'])
            require(len(screens)==expected_count and row['screened']==expected_count,'SCREEN_COUNT');best=min(screens,key=lambda s:(s['score'],s['template_index'],s['candidate']))
            require((index,candidate_id,row['score'])==(best['template_index'],best['candidate'],best['score']) and all(r['selected'] is (r is best)for r in screens),'SCREEN_MINIMUM')
            self.consume(row,'paid-noise-screen',attempt_id=ordinal,candidates=expected_count)
        else:
            selected=tasks(self.options);bank=self.options['parents']-1 if self.options['parent_policy']=='newest' else (ordinal//len(selected))%self.options['parents']
            require(not screens and row['screened']==0 and row['score']is None and candidate_id==0 and template['task_index']==selected[ordinal%len(selected)] and template['bank']==bank,'FIXED_POLICY')
            self.consume(row,'fixed-selection',attempt_id=ordinal)
        self.selection=row
    def attempt(self,row):
        require(self.phase=='miner' and self.selection is not None and type(row['attempt_id'])is int and row['attempt_id']==len(self.attempts),'ATTEMPT_ORDER')
        selection=self.selection
        require(all(row[k]==selection[k]for k in ('attempt_id','template_index','task_index')) and row['arm']==arm(self.options,row['task_index']) and row['cache']==self.options['cache'],'ATTEMPT_SELECTION')
        parent.flags(row,false=('native_verifier_called','node_called'));p=parent.proof(row['proof'],row['task_index']);self.proof_replays+=1
        require(p['raw_header'].hex()==selection['header_hex'] and p['header']['transactions']==parent.sequence_root('transactions',[]) and p['header']['receipts']==parent.sequence_root('receipts',[]),'ATTEMPT_NATIVE_TEMPLATE')
        require(p['header']['nonce']>=(1<<63) and all(p['identity']!=a['identity']for a in self.acquisitions),'SETUP_WINNER_RECREDIT')
        charge=self.consume(row,'complete-proof-and-ticket',attempt_id=row['attempt_id'],task_index=row['task_index'],arm=row['arm'])
        parent.before(charge['start'],row['generated'],'GENERATION_START');parent.before(row['generated'],charge['end'],'GENERATION_END')
        if self.options['cache']=='cold':self.consume(row,'arithmetic-prepare',task_index=row['task_index'],arm=row['arm'],cache='cold')
        else:require(any(c['phase']=='setup' and c['detail']['task_index']==row['task_index']for c in self.preparations),'HOT_PREPARATION_MISSING')
        p.update(row=row,id=row['attempt_id'],task_index=row['task_index'],template_index=row['template_index'],generation_charge=charge,availability=None,receiver=None)
        self.attempts.append(p);self.selection=None
    def available(self,row):
        require(self.phase=='miner' and self.attempts and row['attempt_id']==len(self.attempts)-1,'AVAILABILITY_ORDER');attempt=self.attempts[-1]
        require(attempt['availability']is None and self.rows[row['sequence']-1]['kind']=='attempt','AVAILABILITY_DUPLICATE_OR_DELAYED')
        parent.before(attempt['row']['observed'],row['available'],'AVAILABILITY_BEFORE_BYTES');parent.before(row['available'],row['observed'],'AVAILABILITY_FUTURE')
        require(type(row['miner_elapsed_cpu_ns'])is int and row['miner_elapsed_cpu_ns']==row['available']['process_cpu_ns']-self.origin['process_cpu_ns'],'AVAILABILITY_ELAPSED')
        parent.flags(row,true=('full_bytes_flushed',));require(row['within_miner_budget'] is (row['miner_elapsed_cpu_ns']<=self.options['miner_budget_ns']),'AVAILABILITY_BUDGET')
        attempt['availability']=row
    def receiver(self,row):
        require(self.phase=='receiver' and type(row['attempt_id'])is int and row['attempt_id']==len(self.receivers)<len(self.attempts),'RECEIVER_ORDER');attempt=self.attempts[row['attempt_id']]
        require(row['accepted'] is attempt['hit'] and row['block_id']==(attempt['block'] if attempt['hit']else None) and row['error']==(None if attempt['hit']else 'WORK:Target'),'NATIVE_ADMISSION_RESULT')
        require(row['semantic_id']==attempt['identity'] and row['from_within_miner_budget'] is attempt['availability']['within_miner_budget'],'RECEIVER_CREDIT_BINDING')
        parent.flags(row,true=('native_acceptance_after_miner_sealed',),false=('claim_of_mature_reward',));require(row['miss_is_cheap_target_rejection'] is (not attempt['hit']),'MISS_REJECTION_PATH')
        charge=self.consume(row,'original-node-admission',attempt_id=row['attempt_id']);parent.before(charge['start'],row['completed'],'ADMISSION_START');parent.before(row['completed'],charge['end'],'ADMISSION_END')
        parent.before(self.boundaries['miner']['end'],charge['start'],'VERIFICATION_BEFORE_MINER_SEAL')
        if attempt['hit']:self.blocks[attempt['block']]=attempt
        attempt['receiver']=row;self.receivers.append(row)
    def audit_proof(self,row):
        require(self.phase=='audit' and type(row['attempt_id'])is int and row['attempt_id']==len(self.audits)<len(self.attempts) and not self.reconstructions,'AUDIT_ORDER')
        parent.flags(row,true=('full_relation','reference_relation'),false=('provides_miner_feedback',));self.consume(row,'research-full-native-audit',attempt_id=row['attempt_id']);self.audits.append(row)
    def reconstruction(self,row):
        require(self.phase=='audit' and len(self.audits)==len(self.attempts),'RECONSTRUCTION_PHASE')
        source_id=parent.number(row['source_id'],'RECONSTRUCTION_SOURCE',len(self.acquisitions)-1);source=self.acquisitions[source_id]
        expected=[(a['id'],n)for a in self.acquisitions for n in range(a['nonce']+1)]
        require(len(self.reconstructions)<len(expected) and (source_id,row['ordinal'])==expected[len(self.reconstructions)] and row['task_index']==source['task_index'],'RECONSTRUCTION_ORDER')
        p=parent.proof(row['proof'],row['task_index']);self.proof_replays+=1;header=dict(source['header']);header['nonce']=row['ordinal']
        require(p['raw_header']==parent.header_encode(header),'RECONSTRUCTION_HEADER');winner=row['ordinal']==source['nonce']
        require(row['original_winner'] is winner and row['original_bytes_observed'] is winner and p['hit'] is winner,'RECONSTRUCTION_WINNER')
        if winner:require(p['raw']==source['raw'] and p['identity']==source['identity'],'ORIGINAL_WINNER_BYTES')
        parent.flags(row,false=('new_work_credit','miner_feedback'));self.reconstructions.append(row)
    def within(self):return [a for a in self.attempts if a['availability']['within_miner_budget']]
    def unique(self,values):return len({a['identity']for a in values})
    def setup_detail(self,row):
        d=row['detail'];exact(d,'complete status templates requested_parent_bank acquired_tasks miner_tasks original_acquisitions original_search_complete_attempts known_original_winning_semantics hot_preparations transaction_count transaction_fee_units fee_units_added_to_cpu native_stats economy'.split(),'SETUP_SUMMARY_FIELDS')
        require(type(d['complete'])is bool,'SETUP_COMPLETE_TYPE');complete=d['complete'];hot=[c for c in self.preparations if c['phase']=='setup']
        ready=(len(self.templates)==self.options['parents']*len(tasks(self.options,True)) and len(hot)==(len(tasks(self.options)) if self.options['cache']=='hot'else 0))
        require(not complete or (ready and row['terminal_poll']['permitted'] and row['elapsed_cpu_ns']<=self.options['setup_budget_ns']),'SETUP_OVER_BUDGET_OR_INCOMPLETE')
        require(complete or not row['terminal_poll']['permitted'] or row['elapsed_cpu_ns']>self.options['setup_budget_ns'],'UNEXPLAINED_SETUP_STOP')
        if self.initial is not None:
            require(set(self.tasks)==({0,1} if 1 in tasks(self.options,True)else {0}),'MISSING_TASK_SOURCE')
            require((self.statement is not None)==(1 in tasks(self.options,True)),'MISSING_REGISTRATION_STATEMENT');self.stats(d['native_stats'])
            # A fee receipt may belong to a stored candidate that a setup tail
            # never activated. Active balances therefore follow activation.
            require(same(d['economy'],self.economy),'ACTIVE_SETUP_ECONOMY')
        else:require(d['native_stats']is None and d['economy']is None and not self.tasks and not self.acquisitions,'SETUP_CONTEXT_ABSENT')
        require(len(self.templates)==sum(a['role']=='bank-template'for a in self.acquisitions),'ORPHAN_TEMPLATE_SOURCE')
        require(len({a['identity']for a in self.acquisitions})==len(self.acquisitions),'DUPLICATE_ORIGINAL_ACQUISITION')
        expected=dict(complete=complete,status='complete' if complete else 'setup-cpu-budget-stopped',templates=len(self.templates),requested_parent_bank=self.options['parents'],acquired_tasks=tasks(self.options,True),miner_tasks=tasks(self.options),original_acquisitions=len(self.acquisitions),original_search_complete_attempts=sum(a['nonce']+1 for a in self.acquisitions),known_original_winning_semantics=self.unique(self.acquisitions),hot_preparations=len(hot),transaction_count=self.transactions,transaction_fee_units=self.fees,fee_units_added_to_cpu=False,native_stats=d['native_stats'],economy=d['economy'])
        require(same(d,expected),'SETUP_SUMMARY_BINDING')
    def miner_detail(self,row):
        d=row['detail'];complete=self.boundaries['setup']['detail']['complete'];require(all(a['availability']is not None for a in self.attempts),'UNAVAILABLE_RETAINED_PROOF')
        if not complete:
            require(not self.attempts and self.selection is None and not self.screens and row['terminal_poll']is None,'MINING_WITHOUT_SETUP');status='setup-incomplete'
        else:
            require(row['terminal_poll']is not None,'MISSING_TERMINAL_MINER_POLL')
            status='miner-cpu-budget-stopped' if not row['terminal_poll']['permitted']else 'safety-cap-censored'
            if status=='safety-cap-censored':require(len(self.attempts)==self.options['max_attempts'] and self.selection is None,'CAP_EARLY_STOP')
            if self.selection is not None:require(status=='miner-cpu-budget-stopped','UNFINISHED_SELECTION_WITHOUT_STOP')
        within=self.within();expected=dict(status=status,attempts=len(self.attempts),safety_cap_reached=len(self.attempts)==self.options['max_attempts'],miner_unique_complete_by_B=self.unique(within),miner_unique_target_hits_by_B=self.unique([a for a in within if a['hit']]),native_acceptance_known_during_mining=False,cache_drop_included=True)
        require(same(d,expected),'MINER_SUMMARY_BINDING')
    def receiver_detail(self,row):
        d=row['detail'];require(len(self.receivers)==len(self.attempts),'MISSING_NATIVE_ADMISSIONS')
        if self.initial is not None:self.stats(d['native_stats']);self.consume(row,'native-owner-and-directory-teardown',owned_cleanup=True)
        else:require(d['native_stats']is None,'RECEIVER_WITHOUT_CONTEXT')
        expected=dict(attempt_records=len(self.attempts),eventually_native_accepted=self.unique([a for a in self.attempts if a['hit']]),eventually_native_accepted_from_B=self.unique([a for a in self.within()if a['hit']]),native_stats=d['native_stats'],active_chain_growth_from_research=0,node_teardown_included=True,verification_feedback_to_miner=False)
        require(same(d,expected),'RECEIVER_SUMMARY_BINDING')
    def audit_detail(self,row):
        expected_records=sum(a['nonce']+1 for a in self.acquisitions);require(len(self.audits)==len(self.attempts) and len(self.reconstructions)==expected_records,'AUDIT_COMPLETENESS')
        expected=dict(research_full_native_audits=len(self.attempts),original_reconstruction_records=expected_records,original_winner_repetitions=len(self.acquisitions),original_target_miss_reconstructions=expected_records-len(self.acquisitions),new_work_credit=0,all_owned_proof_material_teardown_included=True)
        require(same(row['detail'],expected),'AUDIT_SUMMARY_BINDING')
    def boundary(self,row):
        index=PHASES.index(self.phase);require(index<4 and row['from']==self.phase and row['to']==row['phase']==PHASES[index+1] and same(row['begin'],self.origin),'PHASE_BOUNDARY_ORDER')
        parent.stamp(row['begin'])
        parent.before(self.rows[row['sequence']-1]['observed'],row['end'],'BOUNDARY_BEFORE_LAST_RECORD');parent.before(row['end'],row['observed'],'BOUNDARY_FUTURE');parent.before(self.charge_end,row['end'],'UNSEALED_CHARGE')
        require(type(row['elapsed_cpu_ns'])is int and row['elapsed_cpu_ns']==row['end']['process_cpu_ns']-self.origin['process_cpu_ns'],'PHASE_ELAPSED')
        if self.phase=='miner' and not self.boundaries['setup']['detail']['complete']:require(row['terminal_poll']is None,'SKIPPED_MINER_POLL')
        else:self.poll(row['terminal_poll'],row['end'])
        parent.flags(row,true=('boundary_encoding_charged_to_next_phase',))
        getattr(self,self.phase+'_detail')(row)
        unbound=[c for c in self.charges if c['phase']==self.phase and c['sequence']not in self.used]
        if self.phase=='setup':
            require(not unbound or (not row['detail']['complete'] and len(unbound)==1 and unbound[0]['stage']=='construct-signed-registration' and self.transactions==0),'UNBOUND_SETUP_CHARGE')
        elif self.phase=='miner':
            require(not unbound or (row['detail']['status']=='miner-cpu-budget-stopped' and len(unbound)==1 and unbound[0]['stage']=='arithmetic-prepare' and self.selection is not None and self.options['cache']=='cold'),'UNBOUND_MINER_CHARGE')
        else:require(not unbound,'UNBOUND_POST_MINER_CHARGE')
        require(sum(c['process_cpu_ns']for c in self.charges if c['phase']==self.phase)<=row['elapsed_cpu_ns'],'CHARGES_EXCEED_PHASE')
        self.boundaries[self.phase]=row;self.phase_cpu[self.phase]=row['elapsed_cpu_ns'];self.phase=row['to'];self.origin=row['end'];self.charge_end=self.origin
    def end(self,row):
        require(self.phase=='done' and row['sequence']==len(self.rows)-1 and len(self.boundaries)==4 and row['status']=='complete','FINAL_PHASE')
        require(same(row['phase_cpu_ns'],self.phase_cpu) and row['total_process_cpu_ns']==self.boundaries['audit']['end']['process_cpu_ns']==sum(self.phase_cpu.values()) and row['total_wall_ns']==self.boundaries['audit']['end']['wall_ns'],'GLOBAL_CPU_ENDPOINT')
        require(row['native_total_endpoint']=='all four phases and owned node/material/proof teardown; final boundary/summary encoding remains in whole-child residual','GLOBAL_ENDPOINT_SCOPE')
        for phase in PHASES[:4]:require(same(row[phase],self.boundaries[phase]['detail']),'END_PHASE_DETAIL:'+phase)
        require(row['setup_complete'] is row['setup']['complete'] and row['miner_status']==row['miner']['status'],'END_STATUS')
        for key in ('miner_unique_complete_by_B','miner_unique_target_hits_by_B'):require(row[key]==row['miner'][key],'END_MINER_COUNT')
        require(row['eventually_native_accepted_from_B']==row['receiver']['eventually_native_accepted_from_B'],'END_NATIVE_COUNT')
        parent.flags(row,true=('setup_known_winners_are_separate',),false=('native_acceptance_completed_within_miner_B','retained_records_are_distinct_tickets','minimum_attacker_cost_established','hardness_accepted','production_activation'))
    def run(self):
        first=self.rows[0];require(first['phase']=='setup' and first['phase_order']==list(PHASES),'START_PHASES')
        parent.flags(first,false=('miner_has_node_or_verifier','physical_cost_lower_bound','production_activation'))
        for key,value in dict(budget_units='process-cpu-nanoseconds; setup P and miner B separately bounded',proof_completion='full original bytes encoded/flushed before availability stamp',parent_bank='finite historical ancestors of one paid native chain, not arbitrary fork forest',native_task_authority='isolated disclosed development signers and continuity genesis').items():require(first[key]==value,'START_SCOPE:'+key)
        handlers={'charge':self.charge,'task':self.task,'task-statement':self.read_statement,'setup-acquisition':self.acquisition,'setup-parent':self.read_parent,'template':self.template,'screen':self.read_screen,'selection':self.read_selection,'attempt':self.attempt,'available':self.available,'receiver':self.receiver,'audit-proof':self.audit_proof,'reconstruction':self.reconstruction,'end':self.end}
        for row in self.rows[1:]:
            if self.attempts and self.attempts[-1]['availability']is None:require(row['kind']=='available','MISSING_IMMEDIATE_AVAILABILITY')
            if row['kind']=='boundary':self.boundary(row);continue
            require(row['phase']==self.phase and row['kind']in handlers,'PHASE_RECORD_ORDER');handlers[row['kind']](row)
        last=self.rows[-1];attempts=[]
        for a in self.attempts:
            record=a['row']['proof'];attempts.append(dict(attempt_id=a['id'],task_index=a['task_index'],template_index=a['template_index'],bank=self.templates[a['template_index']]['bank'],semantic_id=a['identity'],parent=record['parent'],height=record['height'],header_hex=record['header_hex'],challenge=record['challenge'],proof_sha256=a['digest'],target_hit=a['hit'],available=a['availability']['available'],miner_elapsed_cpu_ns=a['availability']['miner_elapsed_cpu_ns'],within_miner_budget=a['availability']['within_miner_budget'],native_accepted=a['receiver']['accepted'],native_admission_completed=a['receiver']['completed'],native_admission_cpu_ns=next(c['process_cpu_ns']for c in self.charges if c['stage']=='original-node-admission' and c['detail']['attempt_id']==a['id']),producer_cpu_ns=a['generation_charge']['process_cpu_ns']))
        acquisitions=[dict(source_id=a['id'],task_index=a['task_index'],role=a['role'],header_hex=a['raw_header'].hex(),parent=a['header']['parent'].hex(),height=a['header']['height'],challenge=a['challenge'].hex(),semantic_id=a['identity'],proof_sha256=a['digest'],block_id=a['block'],original_complete_attempts=a['nonce']+1,fee_units=a['row']['fee_units'],transactions_hex=a['row']['transactions_hex'])for a in self.acquisitions]
        templates=[{k:t[k]for k in ('template_index','bank','task_index','source_id','header_hex','parent','parent_height')}for t in self.templates]
        return dict(schema=READBACK,options=self.options,status='verified',setup_complete=last['setup_complete'],miner_status=last['miner_status'],total_process_cpu_ns=last['total_process_cpu_ns'],total_wall_ns=last['total_wall_ns'],phase_cpu_ns=self.phase_cpu,phase_boundaries={k:dict(begin=v['begin'],end=v['end'],terminal_poll=v['terminal_poll'])for k,v in self.boundaries.items()},setup=last['setup'],miner=last['miner'],receiver=last['receiver'],audit=last['audit'],attempts=attempts,acquisitions=acquisitions,templates=templates,retained_proof_records_replayed=self.proof_replays,counts=dict(research_proof_records=len(self.attempts),original_winner_records=len(self.acquisitions),original_reconstruction_records=len(self.reconstructions),all_full_proof_records=self.proof_replays,research_target_hits=sum(a['hit']for a in self.attempts),research_late_proofs=sum(not a['availability']['within_miner_budget']for a in self.attempts),research_late_target_hits=sum(a['hit'] and not a['availability']['within_miner_budget']for a in self.attempts),miner_unique_complete_by_B=last['miner_unique_complete_by_B'],miner_unique_target_hits_by_B=last['miner_unique_target_hits_by_B'],eventually_native_accepted_from_B=last['eventually_native_accepted_from_B']),charged_stage_cpu_ns=dict(self.stage_cpu),unattributed_phase_cpu_ns={phase:total-sum(c['process_cpu_ns']for c in self.charges if c['phase']==phase)for phase,total in self.phase_cpu.items()},limits=dict(physical_miner_phase=True,full_scalar_replay=True,native_state_and_clocks_are_source_bound_observations=True,arbitrary_fork_forest=False,public_task_authority=False,minimum_attacker_cost_established=False,production_activation=False,shared_selective_comparability_requires_exact_paid_history=True,native_admission_is_after_miner_budget=True,mature_rewards_or_tip_throughput=False))

def read_miner(path,expected_options=None):
    rows,metadata=load(path);return dict(Reader(rows,expected_options).run(),**metadata)

if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('usage: w1_miner_budget_reader.py RAW.jsonl')
    print(json.dumps(read_miner(sys.argv[1]),sort_keys=True,separators=(',',':')))
