#!/usr/bin/env python3
"""Read retained evidence only; do not execute tests, modify source or contact CI."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import re
import subprocess
import zipfile

ROOT = Path('/workspace/scratch/a66f84888260')
OUT = ROOT / 'hosted-d873'
REPO = ROOT / 'chain-integration'
HEAD = 'd87357de197db5ff750d08c96d52432e5d22a0b4'
TREE = '323d99df3155b2242aec70c1cc11215bbade2807'
BASE = 'a3e9002cd12ef90d62f8b252cad570e72dab6fa3'
PROSPECTIVE = '6f03626963aa2145b53acce3f5f9254e7ff81410'
OLD = '0ca272d09d1522b0ffd740e441b6d3de1ed81de6'
checks = Counter()
errors = []
files = {}
raw_cache = {}

def digest(p):
    p = Path(p)
    if str(p) not in files:
        h = hashlib.sha256()
        with p.open('rb') as f:
            for b in iter(lambda: f.read(1024 * 1024), b''):
                h.update(b)
        files[str(p)] = {'path': str(p), 'sha256': h.hexdigest(), 'bytes': p.stat().st_size}
    return files[str(p)]['sha256']

def read(p):
    p = Path(p)
    if str(p) not in raw_cache:
        raw_cache[str(p)] = json.loads(p.read_text())
    return raw_cache[str(p)]

def eq(group, name, actual, expected):
    checks[group] += 1
    if actual != expected:
        errors.append({'group': group, 'check': name,
                       'actual': str(actual)[:1200], 'expected': str(expected)[:1200]})

def hashes(obj, base, group):
    if isinstance(obj, dict):
        if isinstance(obj.get('path'), str) and 'sha256' in obj:
            p = Path(obj['path'])
            if not p.is_absolute(): p = base / p
            eq(group, 'sha256:' + str(p), digest(p), obj['sha256'])
            if 'bytes' in obj: eq(group, 'size:' + str(p), p.stat().st_size, obj['bytes'])
        for v in obj.values(): hashes(v, base, group)
    elif isinstance(obj, list):
        for v in obj: hashes(v, base, group)

def git(*args):
    return subprocess.check_output(['git', *args], cwd=REPO, text=True).strip()

def source():
    return {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
            'parents': git('show', '-s', '--format=%P', 'HEAD').split(),
            'status_porcelain': git('status', '--porcelain=v1')}

before = source()
eq('source', 'frozen head', before['commit'], HEAD)
eq('source', 'frozen tree', before['tree'], TREE)
eq('source', 'clean before', before['status_porcelain'], '')
inputs = {
    'original_gate_summary': OUT / 'original-gates-d873-summary.json',
    'failure_latency': OUT / 'latency-diagnosis/retained-failure-latency.json',
    'server_latency': OUT / 'latency-diagnosis/retained-server-latency.json',
    'native_validation': ROOT / 'integration-validation/d873-native-validation-summary.json',
    'network_audit': ROOT / 'd873-local-network-evidence-audit.json',
    'prospective_identity': OUT / 'pr-source-identity.json',
}
summary, latency, server, local, netaudit, identity = [read(p) for p in inputs.values()]
for p in inputs.values(): digest(p)
hashes(summary, OUT, 'root_summary_file_hashes')
hashes(local, ROOT, 'local_summary_file_hashes')
eq('source', 'root qualification', summary['qualification'], False)
eq('source', 'root gate passed', summary['gate_passed'], False)
eq('source', 'ordered prospective parents receipt', identity['ordered_merge_parents'], [BASE, HEAD])
eq('source', 'ordered prospective parents summary', summary['ordered_prospective_parents'], [BASE, HEAD])
eq('source', 'prospective commit receipt', identity['merge_commit'], PROSPECTIVE)
eq('source', 'prospective tree receipt', identity['merge_tree'], TREE)
remote_commit_path = OUT / 'prospective-git-commit.json'
remote_commit = read(remote_commit_path)
digest(remote_commit_path)
eq('source', 'remote prospective object SHA', remote_commit['sha'], PROSPECTIVE)
eq('source', 'remote prospective object tree', remote_commit['tree']['sha'], TREE)
eq('source', 'remote prospective object ordered parents', [x['sha'] for x in remote_commit['parents']], [BASE, HEAD])
prospective_local = subprocess.run(['git', 'cat-file', '-e', PROSPECTIVE + '^{commit}'], cwd=REPO, capture_output=True).returncode == 0
if prospective_local:
    eq('source', 'local prospective tree', git('rev-parse', PROSPECTIVE + '^{tree}'), TREE)
    eq('source', 'local prospective parents', git('show', '-s', '--format=%P', PROSPECTIVE).split(), [BASE, HEAD])

# Verify published four-second lane claims against actual retained client/report rows.
fresh_rows = []
binary_hashes = []
for lane in summary['fresh_service']:
    folder = OUT / ('fresh-head-artifact' if lane['lane'] == 'head' else 'fresh-prospective-artifact')
    manifest = read(folder / 'fresh-service/manifest.json')
    src, endsrc = read(folder / 'source.json'), read(folder / 'source-after.json')
    expected_commit = HEAD if lane['lane'] == 'head' else PROSPECTIVE
    eq('fresh_identity', lane['lane'] + ' before/after', src, endsrc)
    eq('fresh_identity', lane['lane'] + ' source receipt', src, lane['source_before']['receipt'])
    eq('fresh_identity', lane['lane'] + ' commit', src['tested_commit'], expected_commit)
    eq('fresh_identity', lane['lane'] + ' tree', src['tested_tree'], TREE)
    eq('fresh_identity', lane['lane'] + ' tracked verified', src['tracked_worktree_verified'], True)
    eq('fresh_identity', lane['lane'] + ' manifest commit', manifest['source_before']['commit'], expected_commit)
    eq('fresh_identity', lane['lane'] + ' manifest unchanged', manifest['source_before'], manifest['source_after'])
    eq('fresh_identity', lane['lane'] + ' build', manifest['build']['exit_code'], 0)
    binary = digest(folder / 'fresh-service/public_v3_from_zero')
    binary_hashes.append(binary)
    eq('fresh_identity', lane['lane'] + ' binary before', binary, manifest['binary_sha256_before'])
    eq('fresh_identity', lane['lane'] + ' binary after', binary, manifest['binary_sha256_after'])
    for case in ('original', 'fresh'):
        path = folder / 'fresh-service' / case / 'report.json'
        report = read(path)
        eq('fresh_business', lane['lane'] + case + ' final target', report['finite_target_met'], False)
        for p in report['phases']:
            sp = next(x for x in lane['phases'] if x['case'] == case and x['mode'] == p['mode'])
            tag = lane['lane'] + ':' + case + ':' + p['mode']
            for key in ('workers', 'requested_window_ns', 'business_started_ns', 'confirmation_ended_ns',
                        'client_confirmation_latency_ns', 'client_confirmed_transactions',
                        'client_confirmed_before_original_window_end', 'finite_business_target_met',
                        'full_native_state_equal', 'no_attack_accepted', 'accounting_closed', 'verification_errors'):
                eq('fresh_business', tag + ':' + key, p[key], sp[key])
            subs = p['honest_submissions']; hs = p['honest_history']; replays = p['independent_history_page_replay']
            ack = sum(s['status'] == 'ok' and (s.get('response') or {}).get('ok') is True for s in subs)
            eq('fresh_business', tag + ':total submits', len(subs), 7)
            eq('fresh_business', tag + ':successful ACK', ack, 7)
            eq('fresh_business', tag + ':summary ACK', ack, sp['submissions']['successful_ack'])
            eq('fresh_business', tag + ':history calls', len(hs), 1)
            eq('fresh_business', tag + ':history ok', hs[0]['status'], 'ok')
            value = hs[0]['response']['value']
            eq('fresh_business', tag + ':history page packets', len(value['packets']), 7)
            eq('fresh_business', tag + ':history page complete', value['complete'], True)
            eq('fresh_business', tag + ':signed packet bytes', value['packets'], report['signed_honest_packets'])
            eq('fresh_business', tag + ':window', p['requested_window_ns'], 4_000_000_000)
            pressure = p['workers'] == 16
            eq('fresh_business', tag + ':confirmation expected', p['client_confirmed_transactions'], 0 if pressure else 1)
            for idx, replay in enumerate(replays):
                sr = sp['replay'][idx]
                for key in ('replay_started_ns', 'replay_ended_ns', 'replay_wall_ns', 'replay_thread_cpu_ns', 'replay_accepted', 'replay_error'):
                    eq('fresh_business', tag + ':' + key, replay[key], sr[key])
            observation = replays[0]['native_import_observation']
            packet_work = [(packet['packet_index'], ph) for packet in observation['packets']
                           for ph in packet['phases'] if ph['phase'] == 'work' and ph['started']]
            failed = [{'packet_index': i, 'phase': ph['phase'], 'error_code': ph['error_code']} for i, ph in packet_work if ph['accepted'] is False]
            failed_page = [{'phase': ph['phase'], 'error_code': ph['error_code']} for ph in observation['phases'] if ph['started'] and ph['accepted'] is False]
            fresh_rows.append({'lane': lane['lane'], 'case': case, 'mode': p['mode'],
                               'raw_report_sha256': digest(path), 'workers': p['workers'], 'window_ns': p['requested_window_ns'],
                               'ack': ack, 'submissions': len(subs), 'history_calls': len(hs),
                               'history_packets': len(value['packets']), 'history_complete': value['complete'],
                               'history_ended_ns': hs[0]['ended_ns'], 'confirmed_transactions': p['client_confirmed_transactions'],
                               'confirmation_latency_ns': p['client_confirmation_latency_ns'],
                               'finite_business_target_met': p['finite_business_target_met'],
                               'replay_cpu_ns': replays[0]['replay_thread_cpu_ns'], 'replay_wall_ns': replays[0]['replay_wall_ns'],
                               'work_packets_started': [i for i, _ in packet_work], 'failed_work': failed, 'failed_page': failed_page})
eq('fresh_identity', 'head/prospective same retained binary', binary_hashes[0], binary_hashes[1])

# Independently recompute import aggregate metrics and native before/after counter deltas.
def verify_imports(record, imports, tag):
    s = record['import_summary']
    eq('latency_aggregates', tag + ':replay calls', s['replay_calls'], len(imports))
    for dst, first, second in (('replay_cpu_ns', 'replay_thread_cpu_ns', 'thread_cpu_ns'), ('replay_wall_ns', 'replay_wall_ns', 'wall_ns')):
        eq('latency_aggregates', tag + ':' + dst, s[dst], sum(i.get(first, i.get(second, 0)) or 0 for i in imports))
    obs = [i['native_import_observation'] for i in imports if i.get('native_import_observation')]
    categories = [
        ('host_checks', [h for o in obs for h in o['host_checks']], ('calls_started','calls_completed','calls_accepted','calls_rejected','thread_cpu_ns','wall_ns','cpu_clock_unknown_calls','calls_unfinished')),
        ('page_phases', [p for o in obs for p in o['phases']], ('thread_cpu_ns','wall_ns')),
        ('packet_phases', [p for o in obs for packet in o['packets'] for p in packet['phases']], ('thread_cpu_ns','wall_ns')),
    ]
    for name, rows, fields in categories:
        by = defaultdict(list)
        for row in rows:
            if row.get('started') is not False: by[row['phase']].append(row)
        eq('latency_aggregates', tag + ':' + name + ':names', sorted(s[name]), sorted(by))
        for phase, values in by.items():
            expected = {'observations': len(values)}
            if 'accepted' in values[0]:
                expected['accepted_observations'] = sum(x['accepted'] is True for x in values)
                expected['rejected_observations'] = sum(x['accepted'] is False for x in values)
            for field in fields:
                known = [x.get(field) for x in values if x.get(field) is not None]
                if known: expected[field] = sum(known)
                unknown = len(values) - len(known)
                if unknown: expected[field + '_unknown_observations'] = unknown
            if name == 'host_checks':
                expected['mean_cpu_ns_per_completed_call'] = expected['thread_cpu_ns'] / expected['calls_completed'] if expected['calls_completed'] else None
            eq('latency_aggregates', tag + ':' + name + ':' + phase, s[name][phase], expected)

baseline_comparison = []
for c in latency['fresh_candidates']:
    eq('latency_hashes', c['label'] + ':manifest', digest(c['manifest']), c['manifest_sha256'])
    for p in c['phases']:
        raw = read(p['raw_report']); actual = next(x for x in raw['phases'] if x['mode'] == p['mode'])
        tag = c['label'] + ':' + p['case'] + ':' + p['mode']
        eq('latency_hashes', tag, digest(p['raw_report']), p['raw_report_sha256'])
        for k in ('workers','requested_window_ns','business_started_ns','confirmation_ended_ns','client_confirmation_latency_ns','client_confirmed_transactions','finite_business_target_met','independent_replay_and_confirmation_cpu_ns','independent_replay_and_confirmation_wall_ns','verification_errors'):
            eq('latency_aggregates', tag + ':' + k, p[k], actual[k])
        packet_hash = hashlib.sha256(b''.join(bytes.fromhex(x) for x in raw['signed_honest_packets'])).hexdigest()
        eq('latency_aggregates', tag + ':packet sequence', packet_hash, p['signed_packet_sequence_sha256'])
        verify_imports(p, actual['independent_history_page_replay'], tag)
        if actual['workers'] == 0:
            h = p['import_summary']['host_checks']['checkpoint']
            baseline_comparison.append({'candidate': c['label'], 'case': p['case'], 'checkpoint_calls': h['calls_completed'],
                                        'checkpoint_cpu_ns': h['thread_cpu_ns'], 'checkpoint_mean_cpu_ns': h['mean_cpu_ns_per_completed_call'],
                                        'replay_cpu_ns': p['import_summary']['replay_cpu_ns'],
                                        'replay_and_confirmation_cpu_ns': p['independent_replay_and_confirmation_cpu_ns'],
                                        'confirmation_latency_ns': p['client_confirmation_latency_ns']})

native_rows = []
results = read(OUT / 'native-artifact/results.json')
eq('native_business', 'build success', results['build']['complete_success'], True)
eq('native_business', 'build exit', results['build']['returncode'], 0)
eq('native_business', 'planned attempts complete', len(results['attempts']), 3)
eq('native_business', 'campaign accepted', results['complete_success'], False)
for attempt in results['attempts']:
    run = attempt['number']; sr = next(x for x in summary['native']['runs'] if x['number'] == run)
    rp = OUT / 'native-artifact' / attempt['report_directory'] / 'report.json'; report = read(rp)
    eq('native_business', f'run{run}:raw hash', digest(rp), attempt['report_sha256'])
    eq('native_business', f'run{run}:process exit', attempt['step']['returncode'], 101)
    eq('native_business', f'run{run}:no startup errors', attempt['phase_startup_errors'], [])
    eq('native_business', f'run{run}:report validated', attempt['report_validation_failure'], None)
    eq('native_business', f'run{run}:criteria', report['finite_experiment_criteria_met'], False)
    eq('native_business', f'run{run}:three phases', len(report['phases']), 3)
    for channel in ('stdout', 'stderr'):
        eq('native_logs', f'run{run}:{channel}', digest(OUT / 'native-artifact' / attempt['step'][channel]), attempt['step'][channel + '_sha256'])
    for p in report['phases']:
        tag = f'run{run}:' + p['mode']
        sp = next(x for x in sr['phases'] if x['mode'] == p['mode'])
        phasepath = OUT / 'native-artifact' / attempt['report_directory'] / (p['mode'] + '.json')
        eq('native_business', tag + ':standalone equals nested raw', read(phasepath), p)
        for key in ('duration_seconds','attacker_processes_requested','attacker_processes_ready','all_signed_rounds_confirmed_in_window','finite_phase_criteria_met','receiver_client_state_equal','actor_reports_successful_without_cap_or_kill','observer_complete','genuine_budget_depletion_observed','verifier_errors','full_work_accepted','full_work_failed'):
            eq('native_business', tag + ':' + key, p[key], sp[key])
        eq('native_business', tag + ':failed full criteria', p['finite_phase_criteria_met'], False)
        host = read(phasepath.parent / (p['mode'] + '-host-control/host/controller-result.json'))
        eq('native_business', tag + ':Host completed', host['passed'], True)
        eq('native_business', tag + ':Host final errors', host['final_host_errors'], [])
        confirmations = sum(x['confirmed_inside_pressure_window'] is True for x in p['confirmations'])
        eq('native_business', tag + ':confirmations summary', confirmations, sp['confirmed_rounds_in_window'])
        eq('native_business', tag + ':expected confirmations', confirmations, 1 if p['mode'] == 'baseline' else 0)
        ack = sum(x['status'] == 'ok' and x.get('response', {}).get('ok') is True for x in p['submissions'])
        eq('native_business', tag + ':ACK summary', ack, sp['successful_ack'])
        lp = next(x for x in latency['native_phases'] if x['run'] == run and x['mode'] == p['mode'])
        eq('latency_hashes', tag + ':phase hash', digest(phasepath), lp['raw_report_sha256'])
        imports = [h['client_import'] for h in p['history'] if h.get('client_import')]
        verify_imports(lp, imports, tag)
        for role, prefix in (('client','client_native_history_arithmetic'),('receiver','native_history_arithmetic')):
            beforec, afterc = p[prefix + '_before'], p[prefix + '_after']
            for dest, b, a, rowskey, namekey in (
                    ('stages', beforec, afterc, 'stages','stage'),
                    ('sql_commit_api',beforec['sql_commit'],afterc['sql_commit'],'sites','site')):
                previous = {x[namekey]: x['totals'] for x in b[rowskey]}
                for current in a[rowskey]:
                    name = current[namekey]
                    expected = {key:(v or 0) - (previous[name].get(key) or 0) for key,v in current['totals'].items() if isinstance(v,(int,type(None)))}
                    eq('native_counter_deltas', tag + ':' + role + ':' + dest + ':' + name, lp['native_owner_deltas'][role][dest][name], expected)
            for dest, b, a in (('counters', beforec['counters'],afterc['counters']),('account_node_decode_arithmetic',beforec['account_node_decode_arithmetic']['counters'],afterc['account_node_decode_arithmetic']['counters'])):
                expected = {k:v-b[k] for k,v in a.items() if isinstance(v,int) and isinstance(b.get(k),int)}
                eq('native_counter_deltas', tag + ':' + role + ':' + dest, lp['native_owner_deltas'][role][dest], expected)
        native_rows.append({'run': run,'mode':p['mode'],'duration_seconds':p['duration_seconds'],
                            'attacker_processes':p['attacker_processes_requested'],'host_passed':host['passed'],
                            'finite_phase_criteria_met':p['finite_phase_criteria_met'],'confirmed_rounds_in_window':confirmations,
                            'confirmation_end_ns':[x['ended_ns'] for x in p['confirmations']],
                            'successful_ack':ack,'history_calls':len(p['history']),'errors':p['verifier_errors']})

# Check retained receiver metrics using original record matching and exact request-body hashing.
server_counts = Counter()
def request_digest(value):
    body = json.dumps(value,separators=(',',':')).encode(); tag=b'public-request-body-v3'
    return hashlib.sha256(b'TRNM-PON1\0'+len(tag).to_bytes(2,'little')+tag+len(body).to_bytes(4,'little')+body).hexdigest()

for p in server['phases']:
    report=read(p['raw_report']); raw=next(x for x in report['phases'] if x['mode']==p['mode'])
    tag=p['candidate']+':'+p['case']+':'+p['mode']
    eq('server_raw_binding',tag+':hash',digest(p['raw_report']),p['raw_report_sha256'])
    eq('server_raw_binding',tag+':measurement failures',raw['observations']['measurement_failures'],p['observer_measurement_failures'])
    eq('server_raw_binding',tag+':records omitted',raw['observations']['records_not_retained'],p['observer_records_not_retained'])
    recordmap={(r['operation'],bytes(r['body_digest']).hex()):r for r in raw['observations']['records'] if r['body_digest']}
    for category, rows in (('honest_submissions',p['honest_submissions']),('history',[h['receiver'] for h in p['history'] if h['receiver']])):
        totals=Counter(); stages=defaultdict(Counter)
        for idx, r in enumerate(rows):
            if category=='honest_submissions':
                expected_digest=request_digest({'op':'submit','packet':report['signed_honest_packets'][r['honest_packet_index']]})
            else:
                call=raw['honest_history'][idx]; req=call['request']
                expected_digest=request_digest({'op':'history','tip':req['tip'],'after':req['after']})
            eq('server_raw_binding',tag+f':{category}{idx}:body digest',r['public_body_digest'],expected_digest)
            rawr=recordmap[(r['operation'],expected_digest)]
            eq('server_raw_binding',tag+f':{category}{idx}:connection',r['connection_id'],rawr['connection_id'])
            observed={x['phase']:x for x in rawr['submit_phases'] if x['started']}
            eq('server_metrics',tag+f':{category}{idx}:all started phases',r['observed_stages'],observed)
            eq('server_metrics',tag+f':{category}{idx}:dispatch cpu',r['dispatch_cpu_ns'],rawr['dispatch_thread_cpu_ns'])
            start=rawr['paid_task_queue_wait'].get('ended_ns'); end=rawr['lifecycle'].get('task_closed_ns')
            wall=end-start if end is not None and start is not None else None
            eq('server_metrics',tag+f':{category}{idx}:dispatch wall bounds',r['dispatch_enclosing_wall_ns'],wall)
            eq('server_metrics',tag+f':{category}{idx}:SQL count unobserved',r['actual_history_sql_step_count'],None)
            totals['matched_records']+=1;totals['dispatch_cpu_ns']+=rawr['dispatch_thread_cpu_ns'] or 0;totals['dispatch_enclosing_wall_ns']+=wall or 0
            for stage in ('response_write','challenge_wait','grant_wait','paid_task_queue_wait'):
                eq('server_metrics',tag+f':{category}{idx}:'+stage,r[stage],rawr[stage])
                totals[stage+'_wall_ns']+=rawr[stage]['wall_ns'] or 0
            for name, ph in observed.items():
                for k,v in {'observations':1,'accepted':int(ph['accepted'] is True),'rejected':int(ph['accepted'] is False),'thread_cpu_ns':ph['thread_cpu_ns'] or 0,'wall_ns':ph['wall_ns'] or 0}.items():stages[name][k]+=v
            server_counts[category]+=1
        expected={**dict(totals),'phases':{k:dict(v) for k,v in stages.items()}}
        target=p['honest_submit_totals' if category=='honest_submissions' else 'history_totals']
        eq('server_metrics',tag+':'+category+':totals',target,expected)

# Validate execution counts from retained Rust harness logs, source receipts, and exact binaries.
local_rows=[]
for phase in local['phases']:
    result=read(phase['result_manifest']); name=phase['phase']
    eq('local_validation',name+':result hash',digest(phase['result_manifest']),phase['result_manifest_sha256'])
    eq('local_validation',name+':complete',result['complete_success'],True)
    eq('local_validation',name+':same source',result['source_before'],result['source_after'])
    eq('local_validation',name+':head',result['source_before']['commit'],HEAD)
    eq('local_validation',name+':tree',result['source_before']['tree'],TREE)
    if 'groups' not in result:
        eq('local_validation',name+':exit',result['returncode'],0)
        local_rows.append({'phase':name,'returncode':result['returncode'],'profile_scope':result['profile_scope']})
        continue
    totals=Counter();unique=set();ignored=set()
    for group in result['groups']:
        log=Path(group['log']);text=log.read_text()
        eq('local_test_logs',name+':loghash:'+str(group['index']),digest(log),group['log_sha256'])
        matches=re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;',text)
        eq('local_test_logs',name+':one harness result:'+str(group['index']),len(matches),1)
        status,passed,failed,ignore,measured,filtered=matches[-1]
        observed={'passed':int(passed),'failed':int(failed),'ignored':int(ignore),'measured':int(measured),'filtered_out':int(filtered)}
        for k,v in observed.items():eq('local_test_logs',name+':'+str(group['index'])+':'+k,v,group[k])
        eq('local_test_logs',name+':selection count:'+str(group['index']),len(group['selected_tests']),int(passed)+int(failed)+int(ignore))
        eq('local_test_logs',name+':nonzero selection:'+str(group['index']),len(group['selected_tests'])>0,True)
        eq('local_test_logs',name+':binary hash:'+str(group['index']),digest(group['command'][0]),group['binary_sha256'])
        for k in ('passed','failed','ignored','measured'):totals[k]+=observed[k]
        totals['selected_count']+=len(group['selected_tests'])
        unique.update(group['selected_tests']);ignored.update(group['ignored_tests'])
    eq('local_test_logs',name+':totals',dict(totals),result['totals'])
    eq('local_test_logs',name+':unique selected',len(unique),result['unique_selected_count'])
    eq('local_test_logs',name+':unique ignored',len(ignored),result['unique_ignored_count'])
    eq('local_test_logs',name+':unique passed',len(unique)-len(ignored),result['unique_passed_count'])
    local_rows.append({'phase':name,'groups':len(result['groups']),'totals':dict(totals),
                       'unique_selected':len(unique),'unique_passed':len(unique)-len(ignored),'unique_ignored':len(ignored),
                       'profile_scope':result['profile_scope']})

# Recompute actual independent local confirmations; inspect source ordering of the time bound.
network=read(netaudit['report_path'])
eq('local_network', 'report hash', digest(netaudit['report_path']), netaudit['report_sha256'])
confirmations=network['confirmation']['observations']
eq('local_network','confirmed count',sum(x['confirmed'] is True for x in confirmations),24)
eq('local_network','unique transaction count',len({x['transaction'] for x in confirmations}),24)
eq('local_network','reported count',network['native_verified_confirmed_transactions'],24)
eq('local_network','attack window',network['window_ns'],6_000_000_000)
eq('local_network','worker count',network['workers'],4)
eq('local_network','actual policy',network['policy'],netaudit['actual_policy_id'])
groups=Counter((x['included_height'],x['depth'],int(x['work_delta'],16),int(x['required_work_delta'],16)) for x in confirmations)
eq('local_network','depth/work/count groups',groups,Counter({(1,8,16,12):8,(2,7,14,12):8,(3,6,12,12):8}))
sourcepath='trillionnium/crates/trnm-pon-node/tests/public_v3_service_campaign.rs'
text=(REPO/sourcepath).read_text();text=text[text.index('mod network_only_business'):]
positions={s:text.index(s) for s in ('const WINDOW: Duration = Duration::from_secs(6);','let end = epoch + WINDOW;','Instant::now() >= end','h.join()','let server_result = service.finish();','let confirmation = consumer.confirmations(')}
eq('local_network','attack loop bounded before join/shutdown/confirm',list(positions.values()),sorted(positions.values()))
eq('local_network','source blob',git('rev-parse',HEAD+':'+sourcepath),netaudit['audited_source_blobs'][sourcepath])
eq('local_network','no six second whole chain gate',netaudit['has_end_to_end_six_second_confirmation_gate'],False)
eq('local_network','no confirmation monotonic timestamp',netaudit['confirmation_monotonic_completion_timestamp_retained'],False)
eq('local_network','stale r10 scope preserved','original r10 resource policy' in network['scope'],True)
eq('local_network','fixed host not qualified',netaudit['fixed_host_environment_qualified'],False)

# Source and causal-scope checks: no claim of a code-only regression from unlike runners.
for path, commits in latency['unchanged_relevant_source_blobs'].items():
    eq('causal_scope',path+':same old/new blob',commits[OLD],commits[HEAD])
    for commit,blob in commits.items():eq('causal_scope',path+':'+commit,git('rev-parse',commit+':'+path),blob)
limits={'cpu.max':'25000 100000','cpu.max.burst':'0','memory.max':'2147483648','memory.swap.max':'0','pids.max':'256'}
old_zip = Path('/workspace/scratch/ab286a535ac8/w1-fresh-current-0ca272.zip')
eq('causal_scope', 'old full artifact ZIP hash', digest(old_zip), '95e919c1ab96334797b01f9b57c958677738445daeb0015d36aedf2235a99edf')
with zipfile.ZipFile(old_zip) as z:
    old_host = json.loads(z.read('fresh-service-host/inside-before.json'))
eq('causal_scope', 'old Host raw receipt', old_host, latency['actual_host_receipts']['old'])
for lane, folder in (('head', 'fresh-head-artifact'), ('prospective', 'fresh-prospective-artifact')):
    hostpath = OUT / folder / 'fresh-service-host/inside-before.json'
    digest(hostpath)
    eq('causal_scope', lane + ':Host raw receipt', read(hostpath), latency['actual_host_receipts'][lane])
    controller = read(OUT / folder / 'fresh-service-host/controller-result.json')
    eq('causal_scope', lane + ':Host preparation completed', controller['preparation']['completed'], True)
    eq('causal_scope', lane + ':Host preparation exit', controller['preparation']['process']['exit_code'], 0)
    eq('causal_scope', lane + ':final Host errors', controller['final_host_errors'], [])
for label, receipt in latency['actual_host_receipts'].items():
    for k,v in limits.items():eq('causal_scope',label+':'+k,receipt['limits'][k],v)
eq('causal_scope','nested CPU scope failure latency',latency['nested_intervals_are_not_additive'],True)
eq('causal_scope','nested CPU scope server latency',server['nested_intervals_not_additive'],True)
policy=(REPO/'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs').read_text()
eq('source','r16 history policy owner semantics','history-up-to16-total-hex2096128-shared-sql1024-same-owner-current-reads' in policy,True)
eq('source','current contract has no false single snapshot','history-up-to16-total-hex2096128-shared-sql1024-single-snapshot' in policy,False)
for b in local['binary_identities']:eq('local_binaries',b['target'],digest(b['path']),b['sha256'])
after=source()
eq('source','source unchanged during audit',after,before)

out={
 'schema':'d873-publication-independent-retained-evidence-audit-v1',
 'generated_utc':datetime.now(timezone.utc).isoformat(),
 'scope':'Read-only cross-check of retained reports, execution logs, source receipts and binaries, plus one explicitly requested read of the prospective remote Git commit object. No native tests, builds, CI jobs or source changes executed by this audit.',
 'audit_script':{'path':str(Path(__file__)), 'sha256':digest(Path(__file__))},
 'input_summaries':[{'name':name,**files[str(path)]} for name,path in inputs.items()],
 'source_before':before,'source_after':after,
 'check_counts':dict(checks),'checks_total':sum(checks.values()),'discrepancies':errors,'consistent':not errors,
 'qualification':False,'original_four_second_gate_passed':False,
 'prospective_identity':{'commit':PROSPECTIVE,'tree':TREE,'ordered_parents':[BASE,HEAD],
                         'same_tree_as_head':True,'same_retained_fresh_service_binary':binary_hashes[0],
                         'local_git_object_available':prospective_local,
                         'parent_order_evidence':'Direct read-only GitHub Git commits API JSON, independently checked for exact SHA, tree and ordered parents; also agrees with retained PR identity and outer hosted CI source receipts. No local Git object imported.',
                         'remote_git_object':files[str(remote_commit_path)], 'remote_git_object_url':remote_commit['url'],
                         'inner_manifest_source_kind':'The reusable service harness records its exact tested commit as kind=head internally; outer CI source.json correctly records kind=prospective-merge with candidate/base.'},
 'fresh_service':fresh_rows,'native_campaign':{'complete_runs':len(results['attempts']),'phase_count':len(native_rows),'failed_business_phases':sum(not x['finite_phase_criteria_met'] for x in native_rows),'rows':native_rows},
 'latency_crosscheck':{'fresh_phases':sum(len(c['phases']) for c in latency['fresh_candidates']),'native_phases':len(latency['native_phases']),
                      'server_phases':len(server['phases']),'receiver_records_reidentified_by_exact_digest':dict(server_counts),
                      'host_checkpoint_baselines':baseline_comparison,
                      'cross_runner_code_regression_attribution_supported':False,
                      'same_source_binary_head_and_prospective_checkpoint_cost_differs':True,
                      'measured_history_sql_count_available':False,'measured_history_owner_wait_only_available':False},
 'local_native_validation':{'phases':local_rows,'fixed_host_qualified':False,'release_library_build_attempted_for_d873':False},
 'local_network':{'confirmed_unique_transactions':24,'confirmation_groups':[{'included_height':h,'depth':d,'work_delta':w,'required_work_delta':req,'transactions':n} for (h,d,w,req),n in sorted(groups.items())],
                  'workers':4,'attack_window_ns':6_000_000_000,'confirmation_checked_after_attack_join_and_service_finish':True,
                  'whole_chain_six_second_confirmation_proven':False,'confirmation_monotonic_completion_timestamp_retained':False,
                  'actual_policy_revision':'r16','actual_policy_id':network['policy'],'legacy_r10_scope_text_stale':True},
 'publication_caveats':[
  'All four current pressure phases returned seven successful submit ACKs and one complete seven-packet History page, but confirmed zero transactions in the original four-second business gate.',
  'Head original/fresh and prospective original fail during first-packet W1. Prospective fresh exhausts the initial page cpu_wait before any packet W1 starts.',
  'All nine native phases fail their complete original business criterion. Each of the three baseline phases nevertheless confirms the first round once; only the six attack phases have zero confirmed rounds.',
  'The native campaign is a separate thirty-second, 24-external-attacker, authenticated-state workload; it is not interchangeable with the four-second sixteen-worker fresh-service workload.',
  'Local release regressions execute 29 tests, not every compiled target test. Debug0 components execute 77 passes with one deliberate repeat, yielding 76 unique passes and two ignored helpers; debug assertions and overflow checks remain enabled.',
  'The local network report contains 24 real native consumer confirmations, checked after attacker join and service shutdown; six seconds bounds attack call initiation and does not prove end-to-end confirmation latency.',
  'Local network raw scope prose says r10, but exact signed policy hash and source bind the test to r16. Preserve the raw scope and use the actual hash for attribution.',
  'Same exact fresh-service binary has roughly 54 microseconds per Host checkpoint on head versus 25 microseconds on prospective. Across-runner timing does not establish a code-only regression; hardware and scheduling equivalence are not demonstrated.',
  'Host, page, packet admission and account-graph CPU observations are nested. SQL commit API timing is not all SQL traversal or an isolated physical fsync measurement. History SQL count and isolated owner-wait duration are not recorded.',
  'Resource policy describes same-owner current reads, not a single SQLite transaction snapshot. No acknowledgement, complete History page, local functional pass or build success closes the original failed Host business gate.'
 ],
 'raw_file_hashes_checked_count':len(files)
}
destination=OUT/'publication-audit.json'
temporary=destination.with_suffix('.json.tmp')
with temporary.open('w') as f: json.dump(out,f,indent=2,ensure_ascii=False);f.write('\n')
temporary.replace(destination)
print(json.dumps({'path':str(destination),'sha256':digest(destination),'bytes':destination.stat().st_size,'checks':sum(checks.values()),'discrepancies':errors,'consistent':not errors},ensure_ascii=False,indent=2))
