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
    extended=report.get('schema')=='public-v3-local-mixed-service-v3'
    fields(fixture,'reference_packet forged_packet construction_ns reference_verification_ns ticket_search_ns ticket_trials scope'
           + (' total_preparation_ns' if extended else ''))
    if extended:
        total=integer(fixture['total_preparation_ns'],1)
        require(total>=sum(integer(fixture[k],1) for k in ('construction_ns','reference_verification_ns','ticket_search_ns')),
                'complete reference-seeded preparation cost')
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

FROM_ZERO_SCOPE = 'public legacy maintenance operands; arbitrary zero state, receipts and claimed product; hash-only from-zero construction before all verifier audits; one retained packet reused by four paid calls'
MIXED_SCOPE = 'one process, local TCP, public development identities; alternating reference-seeded and from-zero false-transcript W1 with unchanged shared server budget, malformed packets and unpaid prefixes; not a public fairness or fastest-attacker bound'

def fake_trace_search(search, challenge, target, budget):
    fields(search, 'target budget attempts winners elapsed_ns per_winner_ns')
    require(digest(search['target']) == target.hex() and integer(search['budget'],0,4096) == budget,
            'from-zero search binding')
    attempts=search['attempts']
    require(isinstance(attempts,list) and len(attempts)<=budget, 'from-zero attempt count')
    trace=None
    for nonce,row in enumerate(attempts):
        fields(row, 'nonce trace ticket hit')
        require(integer(row['nonce'])==nonce, 'from-zero contiguous nonce stream')
        actual=H('public-v3-from-zero-trace-v1',challenge,nonce.to_bytes(8,'little'))
        ticket=H('ticket',challenge,actual)
        require(digest(row['trace'])==actual.hex() and digest(row['ticket'])==ticket.hex(),
                'from-zero actual hash stream')
        require(row['hit'] is (ticket<=target), 'from-zero actual target result')
        if row['hit']:
            require(nonce==len(attempts)-1, 'from-zero first winner')
            trace=actual
    require(trace is not None or len(attempts)==budget, 'from-zero incomplete exhaustion')
    elapsed=integer(search['elapsed_ns'],1)
    require(integer(search['winners'],0,1)==int(trace is not None), 'from-zero winner count')
    if trace is None:
        require(search['per_winner_ns'] is None, 'from-zero undefined winner ratio')
    else:
        require(integer(search['per_winner_ns'],1)==elapsed, 'from-zero winner ratio')
    return trace

def from_zero_fixture(fixture, report, phase, parent, reference):
    fields(fixture, 'packet header setup_ns search encode_ns construction_ns empty_search exhausted_search audit_verifications scope')
    require(fixture['scope']==FROM_ZERO_SCOPE, 'from-zero scope')
    text=fixture['packet']
    require(isinstance(text,str) and len(text)==99016 and re.fullmatch('[0-9a-f]+',text),
            'from-zero fixed packet')
    raw,txs,proof=decode_packet(bytes.fromhex(text))
    header=header_decode(raw)
    reference_header=header_decode(decode_packet(bytes.fromhex(reference))[0])
    require(fixture['header']==raw.hex() and not txs, 'from-zero packet/header binding')
    require(header['network'].hex()==report['network'] and header['parameters'].hex()==report['parameters']
            and header['parent'].hex()==parent and header['height']==phase*2+1
            and header['timestamp']==report['genesis_time']+phase*2+2 and header['nonce']==0,
            'from-zero actual parent statement')
    require(header['target']==reference_header['target'] and header['miner']==reference_header['miner'],
            'from-zero same-parent target/miner')
    a=b''.join((i%31).to_bytes(4,'little') for i in range(4096))
    b=b''.join(((i*7)%37).to_bytes(4,'little') for i in range(4096))
    require(header['work_task']==H('task',a,b) and proof[:-32]==b'PNW1'+a+b+bytes(16384),
            'from-zero public material and uncomputed product')
    require(header['state']==header['receipts']==bytes(32)
            and header['transactions']==H('transactions-empty'), 'from-zero uncomputed roots')
    challenge=H('challenge',raw)
    trace=fake_trace_search(fixture['search'],challenge,header['target'],4096)
    require(trace is not None and trace==proof[-32:], 'from-zero submitted trace')
    require(fake_trace_search(fixture['empty_search'],challenge,header['target'],0) is None,
            'from-zero empty control')
    require(fake_trace_search(fixture['exhausted_search'],challenge,(1).to_bytes(32,'big'),1) is None,
            'from-zero exhausted control')
    total=integer(fixture['construction_ns'],1)
    require(total>=integer(fixture['setup_ns'],1)+fixture['search']['elapsed_ns']+integer(fixture['encode_ns'],1),
            'from-zero complete nonoverlapping construction cost')
    audits=fixture['audit_verifications']
    require(isinstance(audits,list) and len(audits)==3, 'from-zero audit count')
    for kernel,entry in zip(('production','scalar-reference','limb'),audits):
        fields(entry, 'kernel elapsed_ns transcript_tiles product_started verified_boundary error')
        require(entry['kernel']==kernel and integer(entry['transcript_tiles'])==512
                and entry['product_started'] is False and entry['verified_boundary'] is False
                and entry['error']=='Transcript', 'from-zero late audit stage')
        integer(entry['elapsed_ns'],1)
    return text

def server_resources(snapshot, metrics, attempts):
    fields(snapshot, 'schema capacity accepted_connections_seen records_not_retained measurement_failures counter_overflow records '
           'observation_has_consensus_authority cpu_intervals_are_nested_not_additive '
           'cpu_includes_reactor_authentication_or_response_signing stream_bytes_are_physical_network_bytes')
    require(snapshot['schema']=='public-v3-local-request-resource-observation-v1'
            and integer(snapshot['capacity'])==128, 'receiver observation format')
    require(snapshot['observation_has_consensus_authority'] is False
            and snapshot['cpu_intervals_are_nested_not_additive'] is True
            and snapshot['cpu_includes_reactor_authentication_or_response_signing'] is False
            and snapshot['stream_bytes_are_physical_network_bytes'] is False, 'receiver resource scope')
    require(integer(snapshot['records_not_retained'])==integer(snapshot['measurement_failures'])==0
            and snapshot['counter_overflow'] is False, 'receiver observations lost')
    rows=snapshot['records']
    require(isinstance(rows,list) and len(rows)==integer(snapshot['accepted_connections_seen'])
            ==integer(metrics['accepted_connections']) and len(rows)<=128, 'receiver observation denominator')
    ids=set()
    for row in rows:
        fields(row, 'connection_id operation body_digest frames application_bytes_read application_bytes_written '
               'physical_network_bytes full_work_started full_work_accepted full_work_thread_cpu_ns '
               'dispatch_started dispatch_accepted dispatch_thread_cpu_ns terminal_phase response_frame_complete '
               'connection_closed task_created task_closed observation_failed complete')
        identifier=integer(row['connection_id'])
        require(identifier not in ids, 'receiver duplicate connection'); ids.add(identifier)
        require(row['complete'] is True and row['connection_closed'] is True and row['observation_failed'] is False,
                'receiver unfinished observation')
        for name in ('full_work_started','dispatch_started','response_frame_complete','task_created','task_closed'):
            require(type(row[name]) is bool, 'receiver boolean '+name)
        require(not row['task_created'] or row['task_closed'], 'receiver task not joined')
        require(row['physical_network_bytes'] is None, 'receiver invented physical bytes')
        if row['operation'] is not None: integer(row['operation'],1,5)
        if row['body_digest'] is not None:
            require(isinstance(row['body_digest'],list) and len(row['body_digest'])==32, 'receiver body digest')
            for byte in row['body_digest']: integer(byte,0,255)
        frames=row['frames']
        require(isinstance(frames,list) and len(frames)==6, 'receiver frame count')
        for name,frame in zip(('hello','challenge','solution','ready','body','response'),frames):
            fields(frame, 'phase bytes_read bytes_written complete')
            require(frame['phase']==name and type(frame['complete']) is bool, 'receiver frame phase')
            integer(frame['bytes_read']); integer(frame['bytes_written'])
        for direction in ('read','written'):
            require(integer(row['application_bytes_'+direction])==sum(f['bytes_'+direction] for f in frames),
                    'receiver frame byte conservation')
        for prefix in ('dispatch','full_work'):
            if row[prefix+'_started']:
                require(type(row[prefix+'_accepted']) is bool, 'receiver missing execution outcome')
                integer(row[prefix+'_thread_cpu_ns'],1)
            else:
                require(row[prefix+'_accepted'] is None and row[prefix+'_thread_cpu_ns'] is None,
                        'receiver invented unstarted cost')
        if row['full_work_started']:
            require(row['dispatch_started'] and row['full_work_thread_cpu_ns']<=row['dispatch_thread_cpu_ns'],
                    'receiver nested CPU intervals')
    work=[r for r in rows if r['full_work_started']]
    require(len(work)==integer(metrics['work_started'])==integer(metrics['work_finished'])
            and sum(r['full_work_accepted'] is False for r in work)==integer(metrics['work_failed']),
            'receiver full-work execution count')
    require(integer(metrics['mutation_cpu_clock_failures'])==0 and metrics['mutation_cpu_unavailable_after_shutdown'] is False,
            'receiver unknown CPU settlement')
    require(integer(metrics['mutation_cpu_charged_ns'])==integer(metrics['mutation_full_work_cpu_ns'])
            +integer(metrics['mutation_dispatch_excluding_work_cpu_ns']), 'receiver CPU charge conservation')
    result={}
    for lane in ('paid_false_transcript','paid_from_zero'):
        clients=[r for r in attempts if r['lane']==lane]
        bodies={H('public-request-body-v3',json.dumps(r['request'],separators=(',',':')).encode()) for r in clients}
        require(len(bodies)==1, 'receiver fixed attack request')
        observed=[r for r in rows if r['body_digest'] is not None and bytes(r['body_digest']) in bodies]
        full=[r for r in observed if r['full_work_started']]
        acknowledged=sum(r['status']=='refused' and r['response']['value'].get('error')=='WORK:Transcript' for r in clients)
        require(0<acknowledged<=len(full)<=len(observed)<=len(clients), 'receiver matched late rejections')
        require(all(r['operation']==1 and r['full_work_accepted'] is False for r in full), 'receiver attack gained acceptance')
        result[lane]={'attempts':len(clients),'matched_receiver_records':len(observed),'late_rejections':len(full),
                      'client_call_wall_ns':sum(r['ended_ns']-r['started_ns'] for r in clients),
                      'receiver_dispatch_cpu_ns':sum(r['dispatch_thread_cpu_ns'] or 0 for r in observed),
                      'receiver_work_cpu_ns':sum(r['full_work_thread_cpu_ns'] for r in full)}
    return result

def validate_report(report):
    require(isinstance(report,dict), 'report object')
    from_zero=report.get('schema')=='public-v3-local-mixed-service-v3'
    lanes=dict(LANES)
    if from_zero:
        lanes.update(paid_false_transcript=4,paid_from_zero=4)
    resource_costs=[]
    fields(report, 'schema transport_profile policy_id bits ttl_ms network parameters genesis genesis_time '
           'call_deadline_ms phase_count probes_per_phase paid_attempts_per_phase unpaid_attempts_per_phase false_transcript_attempts_per_phase '
           'honest_probe_gap_target_ns honest_probe_max_gap_including_restart_ns gap_rule scope restart phases '
           'attempts finite_target_met '+' '.join(FLAGS)+(' from_zero_attempts_per_phase' if from_zero else ''))
    flags(report)
    require(report['schema'] in ('public-v3-local-mixed-service-v2','public-v3-local-mixed-service-v3')
            and report['transport_profile'] == 'public-protected-development-v3', 'campaign profile')
    for field in ('policy_id','network','parameters','genesis'): digest(report[field])
    for field, expected in [('bits',8),('ttl_ms',2000),('call_deadline_ms',500),('phase_count',2),
                            ('probes_per_phase',16),('paid_attempts_per_phase',16),
                            ('unpaid_attempts_per_phase',16),('false_transcript_attempts_per_phase',lanes['paid_false_transcript']),('honest_probe_gap_target_ns',2_000_000_000)]:
        require(integer(report[field]) == expected, 'changed campaign limits '+field)
    if from_zero: require(integer(report['from_zero_attempts_per_phase'])==4, 'from-zero campaign calls')
    integer(report['genesis_time'],1)
    require(report['gap_rule'] == GAP_RULE and report['scope'] == (MIXED_SCOPE if from_zero else SCOPE), 'scope/rule changed')
    rows, phases = report['attempts'], report['phases']
    require(isinstance(rows,list) and len(rows) == 2*sum(lanes.values()), 'attempt denominator')
    require(isinstance(phases,list) and len(phases) == 2, 'phase denominator')
    last_start = 0
    for ordinal,row in enumerate(rows,1):
        fields(row, 'ordinal phase lane caller_fixture request started_ns ended_ns status response error metrics unpaid_written_bytes')
        require(integer(row['ordinal'],1) == ordinal and integer(row['phase'],0,1) in (0,1), 'attempt identity')
        require(row['lane'] in lanes, 'unknown lane')
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
        if row['lane'] in ('paid_false_transcript','paid_from_zero'):
            require(operation=='submit' and 120<=row['caller_fixture']<=127,'false-transcript load identity')
    previous_end = 0
    for index,phase in enumerate(phases):
        fields(phase, 'phase started_ns ended_ns honest_probe_successes honest_probe_max_gap_ns mutations_ok injected_fault_refused '
               'invalid_paid_requests_refused false_transcript_load_refused false_transcript_rejections full_work_observed false_transcript_fixture '
               'byte_equal_producer_state owner producer server_metrics finite_target_met'
               + (' from_zero_fixture from_zero_rejections from_zero_load_refused server_observations resource_observations_complete' if from_zero else ''))
        start,end = integer(phase['started_ns']),integer(phase['ended_ns'],1)
        require(phase['phase']==index and previous_end<=start<end and end-start <= 30_000_000_000, 'phase interval')
        previous_end=end
        attempts=[r for r in rows if r['phase']==index]
        for lane,count in lanes.items():
            require(sum(r['lane']==lane for r in attempts)==count,'lane denominator '+lane)
        require(all(start<=r['started_ns']<r['ended_ns']<=end for r in attempts), 'attempt outside phase')
        probes=[r for r in attempts if r['lane']=='honest_probe']
        paid=[r for r in attempts if r['lane']=='paid_invalid']
        full=[r for r in attempts if r['lane']=='paid_false_transcript']
        zero=[r for r in attempts if r['lane']=='paid_from_zero']
        require(any(max(a['started_ns'],b['started_ns'])<min(a['ended_ns'],b['ended_ns']) for a in probes for b in paid), 'no actual mixed overlap')
        require(any(max(a['started_ns'],b['started_ns'])<min(a['ended_ns'],b['ended_ns']) for a in probes for b in full), 'no actual false-transcript-call/probe overlap')
        mutations=[r for r in attempts if r['lane']=='honest_mutation']
        require([r['request']['op'] for r in mutations] == ['pool_status','pool_submit_bundle','submit','head']*2, 'honest workload sequence')
        parent=report['genesis'] if index==0 else phases[0]['owner']['tip']
        forged_packet=false_transcript_fixture(phase['false_transcript_fixture'],report,index,parent)
        require(all(r['request']['packet']==forged_packet for r in full),'false-transcript request bytes')
        if from_zero:
            packet=from_zero_fixture(phase['from_zero_fixture'],report,index,parent,
                                     phase['false_transcript_fixture']['reference_packet'])
            require(all(r['request']['packet']==packet for r in zero), 'from-zero request bytes')
            require(any(max(a['started_ns'],b['started_ns'])<min(a['ended_ns'],b['ended_ns']) for a in probes for b in zero),
                    'no actual from-zero-call/probe overlap')
            ordered=[r['lane'] for r in attempts if r['lane'] in ('paid_false_transcript','paid_from_zero')]
            expected=['paid_from_zero' if (i+index)%2 else 'paid_false_transcript' for i in range(8)]
            require(ordered==expected, 'attack order/restart counterbalance')
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
        if from_zero: computed['from_zero_load_refused']=all(r['status']!='ok' for r in zero)
        for key,value in computed.items(): require(phase[key] is value,'derived outcome '+key)
        snapshot(phase['owner'],report,2*(index+1)); snapshot(phase['producer'],report,2*(index+1))
        equal=all(phase['owner'][k]==phase['producer'][k] for k in ('tip','state_root'))
        require(phase['byte_equal_producer_state'] is True and equal, 'owner/producer native state')
        metrics=phase['server_metrics']
        rejections=sum(r['status']=='refused' and r['response']['value'].get('error')=='WORK:Transcript' for r in full)
        require(integer(phase['false_transcript_rejections'],0,lanes['paid_false_transcript'])==rejections,'full-work rejection denominator')
        seeded_rejections=rejections
        if from_zero:
            zero_rejections=sum(r['status']=='refused' and r['response']['value'].get('error')=='WORK:Transcript' for r in zero)
            require(integer(phase['from_zero_rejections'],0,4)==zero_rejections, 'from-zero rejection denominator')
            rejections+=zero_rejections
            costs=server_resources(phase['server_observations'],metrics,attempts)
            costs['paid_false_transcript']['preparation_ns']=phase['false_transcript_fixture']['total_preparation_ns']
            costs['paid_from_zero']['preparation_ns']=phase['from_zero_fixture']['construction_ns']
            resource_costs.append(costs)
            require(phase['resource_observations_complete'] is True, 'resource observation incomplete')
        started=integer(metrics['work_started']);finished=integer(metrics['work_finished']);failed=integer(metrics['work_failed'])
        require(started==finished==failed+2 and rejections<=failed<=8 and started<=10,'full-work server accounting')
        observed=seeded_rejections>0 and (not from_zero or zero_rejections>0) and started>=2+rejections and failed>=rejections and finished==started
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
            'from_zero_rejections':sum(p.get('from_zero_rejections',0) for p in phases),
            'matched_resource_costs':resource_costs,
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
    report=load(safe(folder,'native/report.json'))
    negative_count=8 if report.get('schema')=='public-v3-local-mixed-service-v3' else 6
    require(f'Ran {negative_count} tests' in negative and negative.rstrip().endswith('OK') and 'FAILED' not in negative,
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
    result=validate_report(report)
    require(result['finite_target_met'] is True, 'finite service target not met')
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('folder');parser.add_argument('--historical',action='store_true')
    args=parser.parse_args()
    print(json.dumps(validate_bundle(args.folder,current=not args.historical),sort_keys=True))
