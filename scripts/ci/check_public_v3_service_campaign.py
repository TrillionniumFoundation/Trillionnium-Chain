#!/usr/bin/env python3
"""Validate finite local V3 service observations; never infer independent/public readiness."""
from __future__ import annotations
import argparse
import json
import re
import sys
from pathlib import Path
from check_public_readiness_evidence import decode_packet, digest, integer, load, require, safe, sha, validate_source

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'formal/pon-nakamoto-v1'))
from contract_wire import H, header_decode
TEST = 'public_v3_mixed_calls_reopen_with_complete_failure_denominators'
FLAGS = ('public_network_ready', 'independent_accepted', 'resource_fairness_qualified',
         'work_profile_qualified', 'physical_power_loss', 'production_activation')
LANES = {'honest_probe': 16, 'honest_mutation': 8, 'paid_invalid': 16,
         'unpaid_invalid': 16, 'injected_eof': 1, 'paid_false_transcript': 8}
GAP_RULE = 'phase boundaries and consecutive successful honest Head completions; includes failed attempts and idle scheduling; finite observation only'
SCOPE = 'one process, local TCP, public development identities; paid false-transcript W1 and malformed-packet load with unpaid prefixes; not a public fairness or fastest-attacker bound'

def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names.split()), 'field set')

def flags(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FLAGS or key == 'identity_authority':
                require(item is False, 'unsupported authority '+key)
            flags(item)
    elif isinstance(value, list):
        for item in value: flags(item)

def gap(rows, start, end):
    completions = sorted(r['ended_ns'] for r in rows
                         if r['lane'] == 'honest_probe' and r['status'] == 'ok')
    bounds = [start, *completions, end]
    return max(b-a for a,b in zip(bounds, bounds[1:]))

def snapshot(value, report, height):
    fields(value, 'tip generation state_root stats')
    digest(value['tip']); digest(value['state_root']); integer(value['generation'])
    stats = value['stats']
    for field in ('network', 'parameters', 'genesis'):
        require(stats[field] == report[field], 'snapshot context')
    for field in ('tip', 'state_root', 'generation'):
        require(stats[field] == value[field], 'snapshot consistency')
    require(integer(stats['height']) == height and integer(stats['stored_blocks']) == height+1, 'native block progression')
    for field in ('authenticated_sessions', 'authenticated_pending', 'authenticated_audit_rows',
                  'authenticated_outbox_sessions', 'authenticated_outbox_pending'):
        require(integer(stats[field]) == 0, 'guest acquired durable authority')

def false_transcript_fixture(fixture, report, phase, parent):
    fields(fixture,'reference_packet forged_packet construction_ns reference_verification_ns ticket_search_ns ticket_trials scope')
    require(fixture['scope']=='real reference construction and verification followed by hash-only false-trace search; not a fastest-attacker bound',
            'false-transcript setup scope')
    for key in ('construction_ns','reference_verification_ns','ticket_search_ns'):
        integer(fixture[key],1)
    packets=[]
    for key in ('reference_packet','forged_packet'):
        raw=fixture[key]
        require(isinstance(raw,str) and 99016<=len(raw)<=2_097_152 and len(raw)%2==0
                and re.fullmatch('[0-9a-f]+',raw),'false-transcript packet wire')
        packets.append(bytes.fromhex(raw))
    reference,forged=packets
    require(reference[:-32]==forged[:-32] and reference[-32:]!=forged[-32:], 'false trace must be the only packet change')
    raw,txs,proof=decode_packet(forged)
    header=header_decode(raw)
    require(not txs and header['network'].hex()==report['network'] and header['parameters'].hex()==report['parameters']
            and header['parent'].hex()==parent and header['height']==phase*2+1,'false-transcript retained-parent context')
    challenge=H('challenge',raw)
    trials=integer(fixture['ticket_trials'],1,4096)
    for nonce in range(trials):
        trace=H('public-v3-false-trace-v2',challenge,nonce.to_bytes(8,'little'))
        wins=trace!=reference[-32:] and H('ticket',challenge,trace)<=header['target']
        require(wins is (nonce==trials-1),'false-transcript search count/predicate')
    require(trace==proof[-32:], 'claimed trace/search mismatch')
    return fixture['forged_packet']

def validate_report(report):
    fields(report, 'schema transport_profile policy_id bits ttl_ms network parameters genesis genesis_time '
           'call_deadline_ms phase_count probes_per_phase paid_attempts_per_phase unpaid_attempts_per_phase false_transcript_attempts_per_phase '
           'honest_probe_gap_target_ns honest_probe_max_gap_including_restart_ns gap_rule scope restart phases '
           'attempts finite_target_met '+' '.join(FLAGS))
    flags(report)
    require(report['schema'] == 'public-v3-local-mixed-service-v2'
            and report['transport_profile'] == 'public-protected-development-v3', 'campaign profile')
    for field in ('policy_id','network','parameters','genesis'): digest(report[field])
    for field, expected in [('bits',8),('ttl_ms',2000),('call_deadline_ms',500),('phase_count',2),
                            ('probes_per_phase',16),('paid_attempts_per_phase',16),
                            ('unpaid_attempts_per_phase',16),('false_transcript_attempts_per_phase',8),('honest_probe_gap_target_ns',2_000_000_000)]:
        require(integer(report[field]) == expected, 'changed campaign limits '+field)
    integer(report['genesis_time'],1)
    require(report['gap_rule'] == GAP_RULE and report['scope'] == SCOPE, 'scope/rule changed')
    rows, phases = report['attempts'], report['phases']
    require(isinstance(rows,list) and len(rows) == 2*sum(LANES.values()), 'attempt denominator')
    require(isinstance(phases,list) and len(phases) == 2, 'phase denominator')
    last_start = 0
    for ordinal,row in enumerate(rows,1):
        fields(row, 'ordinal phase lane caller_fixture request started_ns ended_ns status response error metrics unpaid_written_bytes')
        require(integer(row['ordinal'],1) == ordinal and integer(row['phase'],0,1) in (0,1), 'attempt identity')
        require(row['lane'] in LANES, 'unknown lane')
        start, end = integer(row['started_ns']), integer(row['ended_ns'],1)
        require(start >= last_start and end > start, 'attempt clock order')
        last_start = start
        if row['lane'] == 'unpaid_invalid':
            require(all(row[k] is None for k in ('request','response','metrics','caller_fixture')), 'unpaid invented protocol observation')
            if row['status'] == 'sent':
                require(row['unpaid_written_bytes'] == 4 and row['error'] is None, 'unpaid write count')
            else:
                require(row['status'] == 'error' and row['unpaid_written_bytes'] in (None,4)
                        and isinstance(row['error'],str) and row['error'], 'unknown unpaid write')
            continue
        request, metrics, response = row['request'], row['metrics'], row['response']
        require(row['unpaid_written_bytes'] is None, 'paid/unpaid accounting alias')
        integer(row['caller_fixture'],0,255)
        fields(metrics, 'construction_ns challenge_ns solution_search_ns solution_trials solution_found solution_body_response_ns total_elapsed_ns failed_stage')
        for key in ('construction_ns','challenge_ns','solution_search_ns','solution_trials','solution_body_response_ns','total_elapsed_ns'):
            integer(metrics[key])
        require(type(metrics['solution_found']) is bool and metrics['total_elapsed_ns'] <= end-start, 'call cost interval')
        operation = request.get('op') if isinstance(request,dict) else None
        if operation in ('head','pool_status'): fields(request,'op')
        elif operation == 'submit':
            fields(request,'op packet')
            require(isinstance(request['packet'],str) and 2 <= len(request['packet']) <= 2_097_152
                    and len(request['packet'])%2 == 0 and re.fullmatch('[0-9a-f]+',request['packet']), 'packet wire')
        elif operation == 'pool_submit_bundle':
            fields(request,'op pool_context transactions'); digest(request['pool_context'])
            require(isinstance(request['transactions'],list) and len(request['transactions']) == 1, 'bundle count')
            raw = request['transactions'][0]
            require(isinstance(raw,str) and 318 <= len(raw) <= 4096 and len(raw)%2 == 0
                    and re.fullmatch('[0-9a-f]+',raw), 'transaction wire')
        else: raise ValueError('unknown operation')
        if row['status'] == 'error':
            require(response is None and isinstance(row['error'],str) and 0<len(row['error'])<=2048
                    and metrics['failed_stage'] in ('construction','challenge','solution-search','solution-body-response'), 'failed attempt evidence')
        else:
            require(row['status'] in ('ok','refused') and row['error'] is None, 'signed outcome shape')
            fields(response,'ok value solve_trials solve_elapsed_ns body_bytes_sent public_network_ready identity_authority')
            require(response['ok'] is (row['status']=='ok') and metrics['failed_stage'] is None
                    and metrics['solution_found'] is True, 'signed response status')
            require(response['solve_trials'] == metrics['solution_trials'] > 0
                    and 0 < integer(response['solve_elapsed_ns']) <= metrics['solution_search_ns']
                    and response['body_bytes_sent'] == len(json.dumps(request,separators=(',',':')).encode()), 'paid call accounting')
        if row['lane'] in ('honest_probe','injected_eof'):
            require(operation == 'head' and row['caller_fixture']==72, 'probe/fault operation')
        if row['lane']=='paid_invalid':
            require(request == {'op':'submit','packet':'00'} and 100<=row['caller_fixture']<=107, 'paid load identity')
        if row['lane']=='paid_false_transcript':
            require(operation=='submit' and 120<=row['caller_fixture']<=127,'false-transcript load identity')
    previous_end = 0
    for index,phase in enumerate(phases):
        fields(phase, 'phase started_ns ended_ns honest_probe_successes honest_probe_max_gap_ns mutations_ok injected_fault_refused '
               'invalid_paid_requests_refused false_transcript_load_refused false_transcript_rejections full_work_observed false_transcript_fixture '
               'byte_equal_producer_state owner producer server_metrics finite_target_met')
        start,end = integer(phase['started_ns']),integer(phase['ended_ns'],1)
        require(phase['phase']==index and previous_end<=start<end and end-start <= 30_000_000_000, 'phase interval')
        previous_end=end
        attempts=[r for r in rows if r['phase']==index]
        for lane,count in LANES.items():
            require(sum(r['lane']==lane for r in attempts)==count,'lane denominator '+lane)
        require(all(start<=r['started_ns']<r['ended_ns']<=end for r in attempts), 'attempt outside phase')
        probes=[r for r in attempts if r['lane']=='honest_probe']
        paid=[r for r in attempts if r['lane']=='paid_invalid']
        full=[r for r in attempts if r['lane']=='paid_false_transcript']
        require(any(max(a['started_ns'],b['started_ns'])<min(a['ended_ns'],b['ended_ns']) for a in probes for b in paid), 'no actual mixed overlap')
        require(any(max(a['started_ns'],b['started_ns'])<min(a['ended_ns'],b['ended_ns']) for a in probes for b in full), 'no actual false-transcript-call/probe overlap')
        mutations=[r for r in attempts if r['lane']=='honest_mutation']
        require([r['request']['op'] for r in mutations] == ['pool_status','pool_submit_bundle','submit','head']*2, 'honest workload sequence')
        parent=report['genesis'] if index==0 else phases[0]['owner']['tip']
        forged_packet=false_transcript_fixture(phase['false_transcript_fixture'],report,index,parent)
        require(all(r['request']['packet']==forged_packet for r in full),'false-transcript request bytes')
        for block_index in range(2):
            bundle,submit=mutations[block_index*4+1],mutations[block_index*4+2]
            header_raw,txs,proof=decode_packet(bytes.fromhex(submit['request']['packet']))
            header=header_decode(header_raw)
            block=H('block',header_raw,proof[-32:]).hex()
            require([tx.hex() for tx in txs]==bundle['request']['transactions'], 'queued/submitted bytes mismatch')
            require(header['network'].hex()==report['network'] and header['parameters'].hex()==report['parameters']
                    and header['parent'].hex()==parent and header['height']==index*2+block_index+1,'submitted chain context')
            if submit['status']=='ok':
                require(submit['response']['value']['block']==submit['response']['value']['active']==block,
                        'native acknowledgement packet binding')
            parent=block
        require(parent==phase['owner']['tip'] and header['state'].hex()==phase['owner']['state_root'],'final submitted state binding')
        successes=sum(r['status']=='ok' for r in probes)
        observed_gap=gap(attempts,start,end)
        require(phase['honest_probe_successes']==successes
                and phase['honest_probe_max_gap_ns']==observed_gap, 'probe gap/count mismatch')
        computed={'mutations_ok':all(r['status']=='ok' for r in mutations),
                  'injected_fault_refused':all(r['status']=='error' for r in attempts if r['lane']=='injected_eof'),
                  'invalid_paid_requests_refused':all(r['status']!='ok' for r in paid),
                  'false_transcript_load_refused':all(r['status']!='ok' for r in full)}
        for key,value in computed.items(): require(phase[key] is value,'derived outcome '+key)
        snapshot(phase['owner'],report,2*(index+1)); snapshot(phase['producer'],report,2*(index+1))
        equal=all(phase['owner'][k]==phase['producer'][k] for k in ('tip','state_root'))
        require(phase['byte_equal_producer_state'] is True and equal, 'owner/producer native state')
        metrics=phase['server_metrics']
        rejections=sum(r['status']=='refused' and r['response']['value'].get('error')=='WORK:Transcript' for r in full)
        require(integer(phase['false_transcript_rejections'],0,8)==rejections,'full-work rejection denominator')
        started=integer(metrics['work_started']);finished=integer(metrics['work_finished']);failed=integer(metrics['work_failed'])
        require(started==finished==failed+2 and rejections<=failed<=8 and started<=10,'full-work server accounting')
        observed=rejections>0 and started>=2+rejections and failed>=rejections and finished==started
        require(phase['full_work_observed'] is observed,'full-work observation claim')
        for key in ('paid_body_reserved_bytes_after_shutdown','output_reserved_bytes_after_shutdown',
                    'mutating_grants_after_shutdown','read_grants_after_shutdown',
                    'mutation_cpu_in_flight_after_shutdown','unknown_caller_durable_rows'):
            require(integer(metrics[key])==0,'shutdown resource/authority '+key)
        require(metrics['completed_submit']==2 and metrics['completed_pool_submit']==2
                and metrics['completed_pool_status']==2, 'native operation denominator')
        met=all(computed.values()) and observed and successes>0 and observed_gap<=report['honest_probe_gap_target_ns'] and equal
        require(phase['finite_target_met'] is met, 'phase result mismatch')
    restart=report['restart']
    fields(restart,'kind before after same_active_state')
    require(restart['kind']=='same-process-owner-and-server-restart', 'restart scope')
    snapshot(restart['before'],report,2);snapshot(restart['after'],report,2)
    require(restart['before']==phases[0]['owner'], 'restart pre-state')
    require(all(restart['before'][k]==restart['after'][k] for k in ('tip','state_root'))
            and restart['same_active_state'] is True,'restart state mismatch')
    observed_gap=gap(rows,phases[0]['started_ns'],phases[-1]['ended_ns'])
    require(report['honest_probe_max_gap_including_restart_ns']==observed_gap,'restart-inclusive gap mismatch')
    met=all(p['finite_target_met'] for p in phases) and observed_gap<=report['honest_probe_gap_target_ns']
    require(report['finite_target_met'] is met,'campaign result mismatch')
    return {'attempts':len(rows),'honest_probe_max_gap_including_restart_ns':observed_gap,
            'false_transcript_rejections':sum(p['false_transcript_rejections'] for p in phases),
            'finite_target_met':met,'public_network_ready':False,'independent_accepted':False}

def validate_bundle(folder, root=ROOT, current=True):
    folder=Path(folder)
    manifest=load(safe(folder,'manifest.json'))
    require(manifest['schema']=='public-v3-local-service-bundle-v2', 'bundle schema')
    flags(manifest)
    require(manifest['source_clean_before'] is True and manifest['source_clean_after'] is True, 'unclean source')
    validate_source(root,manifest,{'implementation_commit':manifest['source_commit'],
                                 'implementation_tree':manifest['source_tree']},current=current)
    observed={p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file() and p!=folder/'manifest.json'}
    require(set(manifest['files'])==observed, 'bundle inventory')
    for name,fingerprint in manifest['files'].items():
        path=safe(folder,name)
        require(path.stat().st_size<=16*1024*1024 and sha(path.read_bytes())==digest(fingerprint),'artifact changed '+name)
    require(manifest['build_returncode']==manifest['run_returncode']==manifest['negative_returncode']==0
            and manifest['timed_out'] is False and manifest['source_changed'] is False, 'failed native execution')
    require(manifest['binary_sha256_before']==manifest['binary_sha256_after'], 'binary changed')
    digest(manifest['binary_sha256_before'])
    text=safe(folder,'run.log').read_text()
    require('test '+TEST+' ...' in text and 'test result: ok. 1 passed; 0 failed;' in text
            and 'panicked at' not in text and 'test result: FAILED' not in text,'actual native test result')
    negative=safe(folder,'negative.log').read_text()
    require('Ran 6 tests' in negative and negative.rstrip().endswith('OK') and 'FAILED' not in negative,
            'actual negative validation result')
    commands=manifest['commands']
    require(isinstance(commands,list) and [c['name'] for c in commands]==['build','run','negative'], 'execution stages')
    require(commands[0]['command']==['cargo','test','--offline','--locked','--manifest-path','trillionnium/Cargo.toml',
            '-p','trnm-pon-node','--test','public_v3_service_campaign','--no-run','--message-format=json'], 'exact native build')
    require(commands[1]['command'][1:]==[TEST,'--exact','--nocapture','--test-threads=1']
            and Path(commands[1]['command'][0]).is_absolute(), 'exact native execution')
    require(len(commands[2]['command'])==4 and commands[2]['command'][1:3]==['scripts/ci/test_public_v3_service_campaign.py','--report'],
            'exact negative execution')
    for command in commands:
        require(integer(command['returncode'])==0 and integer(command['elapsed_ns'],1)>0,'execution result')
    result=validate_report(load(safe(folder,'native/report.json')))
    require(result['finite_target_met'] is True, 'finite service target not met')
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('folder');parser.add_argument('--historical',action='store_true')
    args=parser.parse_args()
    print(json.dumps(validate_bundle(args.folder,current=not args.historical),sort_keys=True))
