#!/usr/bin/env python3
"""Replay native CLI observations and actual frozen model claims, not public acceptance."""
from __future__ import annotations
import hashlib,json,os,sys,tempfile
from pathlib import Path
from unittest.mock import patch
from check_invariant_evidence import ROOT, load, require, safe


def same(left,right):
    return json.dumps(left,sort_keys=True,separators=(',',':')) == json.dumps(right,sort_keys=True,separators=(',',':'))


def unique(pairs):
    result={}
    for key,value in pairs:
        require(key not in result,'supplement duplicate JSON field')
        result[key]=value
    return result


def source_identity(report,q):
    require(report['source_commit']==q['source_commit'] and report['source_tree']==q['source_tree'], 'supplement source')
    require(report['source_clean'] is True and report['all_passed'] is True,'supplement failure')


def replay_expectations(root,folder):
    """Actually verify the retained work/signatures/state with the existing Python owner."""
    sys.path.insert(0,str(root/'formal/pon-nakamoto-v1'))
    from contract_wire import H, NETWORK, PARAMETER_HASH, state_root
    from ledger import Ledger, GENESIS, PARAMS
    from client_confirmation import confirmations
    expected=[]
    original=root/'evidence/pon-native-session-v1/pipeline'
    for case in ['independent','hot-sender']:
        packets=load(original/(case+'-packets.json'));calls=[];queries=[]
        with tempfile.TemporaryDirectory(prefix='pon-native-receipt-replay-') as tmp, patch.dict(os.environ,{'TRNM_NATIVE_SESSION':'','TRNM_NATIVE_EXECUTOR':''}):
            os.environ.pop('TRNM_NATIVE_WORK',None)
            ledger=Ledger(tmp)
            try:
                for packet in packets:
                    hb=bytes.fromhex(packet['header']);txs=[bytes.fromhex(t)for t in packet['transactions']];proof=bytes.fromhex(packet['proof'])
                    raw=hb+len(txs).to_bytes(2,'little')+b''.join(len(t).to_bytes(2,'little')+t for t in txs)+proof
                    bid=ledger.admit(hb,txs,proof,1_800_010_000);ledger.recover()
                    require(bid.hex()==packet['block'],'supplement work identity')
                    tip,generation,state=ledger.read_active();row=ledger.block(tip)
                    stats={'network':NETWORK.hex(),'parameters':PARAMETER_HASH.hex(),'genesis':GENESIS.hex(),
                           'tip':tip.hex(),'height':row[1],'chainwork_hex':row[2].hex(),
                           'state_root':state_root(state).hex(),'generation':generation,'state_keys':len(state),
                           'stored_blocks':row[1]+1,'events':generation,'production_activation':False}
                    for store in ['source','receiver']:
                        calls.append(('submit',store,{'block':bid.hex(),'state':stats},hashlib.sha256(raw).hexdigest(),None))
                    if packet['phase']=='application':
                        queries.extend((H('tx-id',t),bid)for t in txs)
                for store in ['source','receiver']:calls.append(('status',store,stats,None,None))
                facts=confirmations(ledger,queries,observed_now=1_800_010_000)
                observations=[]
                for fact in facts:
                    obs={k:fact[k]for k in ['transaction','genesis','network','parameters','included_block','observed_tip','included_height','observed_height','depth','active_generation','observed_now','finalized','execution_authority']}
                    obs.update(policy='installed-depth-and-required-work',
                        required_work_delta=int(fact['required_work_delta']).to_bytes(64,'big').hex(),
                        work_delta=int(fact['cumulative_work_delta']).to_bytes(64,'big').hex(),
                        confirmed=fact['status']=='confirmed',reorged=fact['status']=='reorged')
                    observations.append(obs)
                query_json=[{'transaction':t.hex(),'block':b.hex()}for t,b in queries]
                require(same(load(folder/(case+'-queries.json')),query_json),'supplement query input')
                batch={'observations':observations,'ancestry_checked':len(packets),'distinct_bodies_checked':len({b for _,b in queries})}
                groups=[]
                for sample in range(3):
                    group={}
                    for variant in (['serial','batch']if sample%2==0 else ['batch','serial']):
                        start=len(calls)
                        if variant=='serial':
                            for observation,query in zip(observations,query_json):
                                calls.append(('confirm','receiver',observation,None,query))
                        else:calls.append(('confirm-batch','receiver',batch,None,case+'-queries.json'))
                        group[variant]=(start,len(calls))
                    groups.append(group)
                expected.append({'case':case,'calls':calls,'groups':groups,'queries':query_json,'blocks':len(packets),'stats':stats,
                    'transactions':sum(len(p['transactions'])for p in packets)})
            finally:ledger.close()
    return expected


def validate_batch_report(report,q,expectations):
    source_identity(report,q)
    require(report['binary_sha256']==q['native_binary_sha256']['trnm-pon-node'],'supplement native binary')
    require(report['clock_scope']=='explicit-logical-test-clock'and report['public_confirmed_tps']is None,'supplement clock/TPS')
    for key in ['production_activation','independent_operators','physical_power_loss','new_model_experiments']:
        require(report[key]is False,'supplement overclaim '+key)
    require(len(report['scenarios'])==len(expectations),'supplement scenario count')
    total_calls=sum(len(case['calls'])for case in expectations)
    require(len(report['results'])==total_calls,'supplement call count')
    comparisons=report['confirmation_comparisons'];require(len(comparisons)==sum(len(e['groups'])for e in expectations),'supplement comparison count')
    offset=0;ci=0
    for expected,scenario in zip(expectations,report['scenarios']):
        calls=report['results'][offset:offset+len(expected['calls'])];offset+=len(calls)
        for actual,(operation,store,value,packet_hash,extra)in zip(calls,expected['calls']):
            argv=actual['command']
            require(len(argv)>=7 and Path(argv[0]).name=='trnm-pon-node'and argv[1:4]==[operation,'--development','--store']
                    and Path(argv[4]).name==store and Path(argv[4]).parent.name==expected['case']
                    and argv[5:7]==['--logical-now','1800010000'],'supplement command')
            if operation=='confirm':require(argv[7:]==['--transaction',extra['transaction'],'--block',extra['block']],'supplement query command')
            if operation=='confirm-batch':require(argv[7]=='--queries'and Path(argv[8]).name==extra and len(argv)==9,'supplement batch command')
            if operation=='submit':require(len(argv)==9 and argv[7]=='--packet','supplement packet command')
            if operation=='status':require(len(argv)==7,'supplement status command')
            require(type(actual['returncode'])is int and actual['returncode']==0,'supplement command failure')
            require(type(actual['elapsed_ns'])is int and actual['elapsed_ns']>0,'supplement timing')
            require(actual['input_packet_sha256']==packet_hash,'supplement packet bytes')
            result=json.loads(actual['stdout'],object_pairs_hook=unique)
            require(same(result,{'result':value,'clock_scope':'logical-test','production_activation':False}),'supplement result replay')
        expected_scenario={'scenario':expected['case'],'input_blocks':expected['blocks'],
            'native_block_admission_executions':2*expected['blocks'],'source_transactions':expected['transactions'],
            'receiver_transactions':expected['transactions'],'application_confirmations':len(expected['queries']),
            'confirmed_transaction_ids':[query['transaction']for query in expected['queries']],
            'final_tip':expected['stats']['tip'],'final_state_root':expected['stats']['state_root']}
        require(same(scenario,expected_scenario),'supplement scenario accounting')
        for sample,group in enumerate(expected['groups']):
            item=comparisons[ci];ci+=1
            require(item['scenario']==expected['case']and type(item['sample'])is int and item['sample']==sample,'supplement sample identity')
            require(same(item['commands'],{key:end-start for key,(start,end)in group.items()})and item['queries']==len(expected['queries'])
                    and item['batch_ancestry_checks']==expected['blocks'],'supplement sample accounting')
            require(item['scope']=='process-inclusive read observation amortization; not new transactions or public throughput','supplement sample scope')
            for variant,(start,end)in group.items():
                elapsed=item['elapsed_ns'][variant]
                require(type(elapsed)is int and elapsed>=sum(row['elapsed_ns']for row in calls[start:end]),'supplement timing sum')
    return {'native_cli_invocations_checked':total_calls,'native_packet_admission_observations_checked':sum(2*e['blocks']for e in expectations),
            'reference_work_blocks_replayed':sum(e['blocks']for e in expectations),
            'application_confirmation_targets':sum(len(e['queries'])for e in expectations),'confirmation_comparison_pairs':len(comparisons)}


def validate_owned_host_report(report,q,expected,packet):
    """Check raw owned-host observations; does not rerun SSH or create independence."""
    import shlex,re
    source_identity(report,q)
    require(report['source_clean_after'] is True and report['same_operator'] is True,'owned source/operator')
    require(report['binary_sha256']==q['native_binary_sha256']['trnm-pon-node'],'owned binary')
    require(report['packet_sha256']==hashlib.sha256(packet).hexdigest(),'owned packet')
    require(report['clock_scope']=='explicit-logical-test','owned clock')
    for flag in ['independent_accepted','public_network_ready','physical_power_loss','production_activation','installed_services']:
        require(report[flag] is False,'owned unsupported authority')
    hosts=report['hosts'];rows=report['commands']
    require([h['host_alias']for h in hosts]==['rog','pocket4','x230-ts']and len(rows)==27,'owned host/call matrix')
    for index,host in enumerate(hosts):
        group=rows[9*index:9*(index+1)];alias=host['host_alias'];directory=host['directory']
        prefix='/tmp/trnm-owned-native-'+q['source_commit'][:9]+'-'
        require(re.fullmatch(re.escape(prefix)+'[A-Za-z0-9]{6}',directory),'owned private directory')
        require(all(type(r['returncode'])is int and r['returncode']==0 and type(r['elapsed_ns'])is int and r['elapsed_ns']>0 for r in group),'owned failed invocation')
        ssh=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8',alias]
        require(group[0]['command']==ssh+['mktemp -d '+prefix+'XXXXXX']
                and group[0]['stdout'].strip()==directory,'owned setup')
        require(group[1]['stdout']==host['environment']and group[1]['command'][:len(ssh)]==ssh,'owned environment')
        for row,name in zip(group[2:4],['trnm-pon-node','accepted.packet']):
            require(row['command'][:6]==['scp','-q','-o','BatchMode=yes','-o','ConnectTimeout=8']
                    and row['command'][-1]==alias+':'+directory+'/'+name,'owned copy')
        require(group[4]['command']==ssh+['sha256sum '+directory+'/trnm-pon-node '+directory+'/accepted.packet'],'owned hash command')
        require([line.split()[0]for line in group[4]['stdout'].splitlines()]==[report['binary_sha256'],report['packet_sha256']],'owned transferred bytes')
        common=['--development','--store',directory+'/store','--logical-now','1800010000']
        operations=[('submit',['--packet',directory+'/accepted.packet']),('status',[]),
                    ('submit',['--packet',directory+'/accepted.packet']),
                    ('confirm',['--transaction',expected['tx_id'],'--block',expected['block_id']])]
        values=[]
        for row,(operation,args)in zip(group[5:],operations):
            require(row['command'][:len(ssh)]==ssh and len(row['command'])==len(ssh)+1,'owned SSH command')
            require(shlex.split(row['command'][-1])==[directory+'/trnm-pon-node',operation,*common,*args],'owned native command')
            value=json.loads(row['stdout'],object_pairs_hook=unique)
            require(value['clock_scope']=='logical-test'and value['production_activation']is False,'owned output authority')
            values.append(value['result'])
        first,reopened,duplicate,observation=values
        require(first['block']==expected['block_id'] and same(first,duplicate) and same(first['state'],reopened),'owned replay/reopen')
        require(reopened['genesis']==expected['genesis'] and reopened['state_root']==expected['post_state_root']
                and type(reopened['height'])is int and reopened['height']==1,'owned state root')
        require(observation['transaction']==expected['tx_id']and observation['included_block']==expected['block_id']
                and observation['observed_tip']==expected['block_id'] and observation['genesis']==expected['genesis'],'owned inclusion')
        require(type(observation['depth'])is int and observation['depth']==0 and observation['work_delta']=='00'*64,'owned depth/work')
        for flag in ['confirmed','reorged','finalized','execution_authority']:
            require(observation[flag] is False,'owned confirmation authority')
        require(type(host['admissions'])is int and host['admissions']==1 and type(host['reopens'])is int and host['reopens']==1,'owned counters')
        require(host['all_passed']is True and host['exact_duplicate_no_change']is True and host['inclusion_checked']is True
                and host['confirmed']is False and host['observed_root']==expected['post_state_root'],'owned host summary')
    return {'owned_host_observations_checked':3,'owned_host_commands_checked':27,'owned_host_experiments_reexecuted_by_checker':False}


def validate(root=ROOT,folder=None):
    root=Path(root).resolve();folder=Path(folder or root/'evidence/pon-native-node-v1').resolve()
    q=load(folder/'qualification.json');manifest=load(folder/'manifest.json')
    for relative,digest in manifest['files'].items():
        require(hashlib.sha256(safe(folder,relative).read_bytes()).hexdigest()==digest,'supplement artifact hash')
    for relative,digest in q['source_files_sha256'].items():
        require(hashlib.sha256(safe(root,relative).read_bytes()).hexdigest()==digest,'supplement current source')
    batch_folder=folder/'native-batch-replay';batch=load(batch_folder/'report.json')
    for name,digest in batch['inputs_sha256'].items():
        require(hashlib.sha256(safe(root,name).read_bytes()).hexdigest()==digest,'supplement original input')
    require(hashlib.sha256((batch_folder/'driver.py').read_bytes()).hexdigest()==batch['driver_sha256'],'supplement driver')
    result=validate_batch_report(batch,q,replay_expectations(root,batch_folder))
    vectors=root/'formal/pon-nakamoto-v1/vectors/accepted-block'
    tx=(vectors/'transaction.bin').read_bytes()
    packet=(vectors/'header.bin').read_bytes()+b'\x01\x00'+len(tx).to_bytes(2,'little')+tx+(vectors/'work.bin').read_bytes()
    owned=folder/'owned-host-smoke'
    require((owned/'accepted.packet').read_bytes()==packet and same(load(owned/'expected.json'),load(vectors/'expected.json')),'owned original vector')
    result.update(validate_owned_host_report(load(owned/'report.json'),q,load(vectors/'expected.json'),packet))
    model=folder/'model-current';record=load(model/'execution.json');source_identity(record,q)
    for flag in ['ordinary_hepta_entry','independent_operators','future_window_accepted','funded_public_serving','production_activation']:
        require(record[flag]is False,'model supplement overclaim')
    require(record['source_clean_after']is True and type(record['paid_provider_calls'])is int and record['paid_provider_calls']==0,'model supplement scope')
    from experiments.settle_model import verify_observation
    observed,_=verify_observation(model/'model',record['evaluation_bundle'])
    require(observed['source']==record['input_source_commit']==q['input_source_commit'],'model source input')
    claims={name:observed['results'][name]['value_claim']for name in ['evaluation_a','evaluation_b']}
    require(all(observed['results'][name]['independent_administration']is False and observed['results'][name]['public_reward_eligible']is False for name in claims),'model worker overclaim')
    require(same(claims,record['value_claims']),'model value claims')
    outcome=load(model/'settlement/report.json')
    require(same(outcome,record['model_outcome']),'model settlement observation')
    eligible=[i for i in range(3)if min(observed['results'][p]['marginal'][i]['score']for p in ['evaluation_a','evaluation_b'])>0]
    whole=min(observed['results'][p]['whole_gain']['score']for p in ['evaluation_a','evaluation_b'])
    require(not eligible or not whole,'this supplement does not certify an opaque positive settlement')
    require(outcome['outcome']=='not_adopted'and type(outcome['model_reward'])is int and outcome['model_reward']==0,'model no-gain settlement')
    require([row['name']for row in record['results']]==['model-learning','model-settlement','learning-cycles']
            and all(type(row['returncode'])is int and row['returncode']==0 for row in record['results']),'model execution matrix')
    return {**result,'measured_commit':q['source_commit'],'frozen_model_claims_recomputed':True,'model_reward':0,'independent_accepted':False,
            'public_confirmed_tps':None,'production_activation':False}

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--evidence',type=Path)
    parser.add_argument('--root',type=Path,default=ROOT)
    parser.add_argument('--historical',action='store_true')
    args=parser.parse_args()
    if args.historical:
        from historical_evidence import validate_historical_cli
        result=validate_historical_cli(__file__,args.root,args.evidence or args.root/'evidence/pon-native-node-v1')
    else:
        result=validate(root=args.root,folder=args.evidence)
    print(json.dumps(result,sort_keys=True))
