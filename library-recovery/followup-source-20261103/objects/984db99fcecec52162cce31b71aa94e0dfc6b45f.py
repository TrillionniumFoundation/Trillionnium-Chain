"""Read-only audit of the failed 96f5e502 native History campaigns.

Audits original artifact integrity and recorded outcomes. Does not run a new
native campaign, change a resource boundary, or turn cleanup into a PASS.
"""
from pathlib import Path
from zipfile import ZipFile
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parent
HEAD = '96f5e502d677fa37d53e0241208ce228a913d907'
TREE = 'd2581b3fd4fc0c5cb8fdfab4d695a0b3698cc986'
SPECS = [
    (12889490469, 40852779415, 'ffb51184690a57f41f913d7358b32de1f49e40503737c7ff4db2459bd4d3e175', ['strict/', 'n8/']),
    (12888432211, 40852779337, '6b4d0e8f61e4ce943843333a5aadaf72542573e6aba92f0aadf877c326f53140', ['']),
    (12888322275, 40852779337, 'cf356083e733c73ce68324444153a17269a66c555f31ed72df9ae98b36e95750', ['']),
]
LIMITS = {'cpu.max': '25000 100000', 'cpu.max.burst': '0',
          'memory.max': '2147483648', 'memory.swap.max': '0', 'pids.max': '256'}
STAGES = ['after-node-open-before-seed', 'after-public-import-before-response',
          'after-node-close-before-report']


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(archive, path):
    return json.loads(archive.read(path))


def parent_limits(observation):
    require(all(observation[k] == v for k, v in LIMITS.items()), 'actual fixed verifier parent limits')


def outer_limits(observation):
    require(observation['nice'] == 10 and observation['cpu_affinity'] == [0, 1, 2, 3], 'actual outer nice/affinity')
    actual = observation['limits'][0]
    require(actual['cpu.max'] == '400000 100000' and actual['memory.max'] == '17179869184', 'actual outer CPU/memory')
    return {k: actual[k] for k in ['cpu.max', 'memory.max', 'memory.events']}


def audit_arm(archive, prefix, hashed):
    outcome = read(archive, prefix + 'results.json')
    source = read(archive, prefix + 'source-before.json')
    require(source['tested_commit'] == HEAD and source['tested_tree'] == TREE
            and source['tracked_worktree_verified'] is True, 'source identity')
    source_records = []
    for name in archive.namelist():
        relative = name[len(prefix):] if name.startswith(prefix) else ''
        if '/' not in relative and relative.endswith('.json') and (
                relative.startswith('source-') or re.fullmatch(r'run-[123]-source-after\.json', relative)):
            require(read(archive, name) == source, ('source before/after unchanged', name))
            source_records.append(relative)
    require('source-after.json' in source_records and 'source-after-native.json' in source_records,
            'final source readbacks completed')
    binary = outcome['binary']
    binary_sha = hashed[prefix + binary['retained']]['sha256']
    require(binary_sha == binary['sha256_before'] == binary['sha256_after'], 'native binary stable and retained')
    require(outcome['complete_success'] is False and outcome['failure'] == 'ORIGINAL_THREE_RUN_CAMPAIGN_FAILED'
            and outcome['finalization_failures'] == [], 'original gate failure preserved')
    require(outcome['original_campaign_outer_timeout_seconds'] == 600
            and outcome['original_inputs'] == {'attacker_processes': [0, 24, 24], 'business_blocks': 21,
            'modes': ['baseline', 'from-zero', 'late-product'], 'phase_seconds': 30,
            'seed_blocks': 4, 'seed_transfers': 1024}, 'unchanged original budgets and inputs')
    cleanup = {}
    for name in ['fixed-parent-cleanup.json', 'fixed-parent-probe-cleanup.json']:
        d = read(archive, prefix + name)
        require(d['complete_success'] is True and d['root_only_lease_is_authority'] is True, 'root-owned cleanup')
        cleanup[name] = {'sha256': hashed[prefix + name]['sha256'], 'complete_success': True}
    phases = []
    attempts = []
    for attempt in outcome['attempts']:
        n = attempt['number']
        step = attempt['step']
        require(step['returncode'] == 101 and step['error'] is None
                and step['outer_stage_timeout_seconds'] == 600 and step['elapsed_seconds'] < 600,
                'native assertion failed, not outer-stage timeout')
        stderr = archive.read(prefix + step['stderr']).decode()
        require('public_v3_multiprocess.rs:1746:5' in stderr and
                'finite experiment criteria failed' in stderr and
                'public_v3_multiprocess.rs:1521:9' in stderr, 'actual native failure boundary')
        resource = {}
        for side in ['before', 'after']:
            resource[side] = outer_limits(read(archive, prefix + f'run-{n}-resource-{side}.json'))
        attempts.append({'number': n, 'returncode': step['returncode'], 'elapsed_seconds': step['elapsed_seconds'],
                         'outer_stage_timeout_seconds': 600, 'actual_outer_resources': resource,
                         'original_criteria_met': attempt['original_criteria_met'],
                         'actual_verifier_boundary_readback': attempt.get('actual_verifier_boundary_readback'),
                         'report_validation_failure': attempt['report_validation_failure'],
                         'stderr_file': prefix + step['stderr'], 'stderr_sha256': sha(stderr.encode())})
        report = read(archive, prefix + f'run-{n}-raw/report.json')
        require(report['finite_experiment_criteria_met'] is False and report['economics_complete'] is True,
                'campaign fails original finite service criteria, economics report complete')
        for mode in ['baseline', 'from-zero', 'late-product']:
            name = prefix + f'run-{n}-raw/{mode}.json'
            p = read(archive, name)
            v = p['history_verifier_process']
            flow = p['final_actual_flow']
            meter = p['final_meter']
            vr = v['report']['result']
            require(v['completed_successfully'] is True and v['exit_success'] is True
                    and v['parent_forced_kill'] is False and p['verifier_errors'] == [], 'actual verifier completed normally')
            require(v['report']['error'] is None and vr['clean_node_close'] is True
                    and vr['binary_sha256'] == binary_sha, 'exact binary clean Node close')
            for boundary in ['parent_before_spawn', 'parent_after_reap']:
                parent_limits(v[boundary])
            require(v['parent_after_reap']['pids.current'] == 0, 'actual verifier parent empty after reap')
            require(flow['balance_identity_verified'] is True and flow['live_owners'] == 0
                    and flow['unsettled_known_live_cpu_ns'] == 0 and flow['booked_reservation_ns'] == 0,
                    'normal public CPU settlement quiescent')
            require(flow['initial_credit_ns'] + flow['credited_refill_ns']
                    == flow['stored_credit_ns'] + flow['paid_cpu_debit_ns'] + flow['settlement_discard_ns'],
                    'independently recomputed final credit identity')
            require(flow['paid_cpu_debit_ns'] == flow['live_debited_cpu_ns'] + flow['settlement_residual_cpu_ns'],
                    'independently recomputed residual settlement identity')
            require(meter['accounting_unavailable'] is False and meter['in_flight'] == 0, 'normal accounting closed')
            graph = vr['history_graph_resource']
            if p['history_resource_profile'] == 'history-account-graph-resource-fence-v1':
                counts = graph['counters']
                require(counts['imports'] == counts['imports_closed'] and counts['unfinished_scopes'] == 0
                        and counts['scope_failures'] == 0 and graph['live_known_close_pending'] is False,
                        'actual graph import scopes closed')
            last = p['history'][-1] if p['history'] else {}
            ci = last.get('client_import', {})
            responses = last.get('response', {}).get('value', {})
            phases.append({
                'run': n, 'mode': mode, 'raw_file': name, 'raw_sha256': hashed[name]['sha256'],
                'finite_phase_criteria_met': p['finite_phase_criteria_met'],
                'full_work_accepted': p['full_work_accepted'], 'full_work_failed': p['full_work_failed'],
                'all_signed_rounds_confirmed_in_window': p['all_signed_rounds_confirmed_in_window'],
                'confirmations': [{k: c.get(k) for k in ['round', 'started_ns', 'ended_ns', 'confirmed_inside_pressure_window']}
                                  for c in p['confirmations']],
                'receiver_client_state_equal': p['receiver_client_state_equal'],
                'final_client_tip': p['final_client_tip'], 'final_receiver_tip': p['final_receiver_tip'],
                'genuine_budget_depletion_observed': p['genuine_budget_depletion_observed'],
                'actor_reports_successful_without_cap_or_kill': p['actor_reports_successful_without_cap_or_kill'],
                'verifier_completed_successfully': v['completed_successfully'],
                'verifier_parent_forced_kill': v['parent_forced_kill'],
                'verifier_errors': p['verifier_errors'], 'verifier_clean_node_close': vr['clean_node_close'],
                'verifier_parent_pids_after_reap': v['parent_after_reap']['pids.current'],
                'verifier_parent_cpu_delta_usec': v['parent_after_reap']['cpu.stat']['usage_usec'] - v['parent_before_spawn']['cpu.stat']['usage_usec'],
                'verifier_process_cpu_ns': vr['whole_verifier_process_cpu_ns'],
                'history_request_count': len(p['history']),
                'last_history_import': {'succeeded': ci.get('succeeded'), 'ended_ns': ci.get('ended_ns'),
                                        'response_complete': responses.get('complete'), 'response_next': responses.get('next')},
                'final_graph_resource_observation': graph,
                'final_public_cpu_flow': flow, 'final_public_cpu_meter': meter,
                'credit_and_residual_equations_independently_verified': True,
            })
    lf = read(archive, prefix + 'verifier-lifeline/results.json')
    require(lf['complete_success'] is True and lf['failure'] is None and lf['finalization_failures'] == [], 'lifeline lane completed')
    require(lf['planned_native_boundaries'] == STAGES and lf['small_controls']['required_methods'] == 6
            and lf['small_controls']['raw_controls_read'] is True, 'lifeline exact scope')
    deaths = []
    for i, stage in enumerate(STAGES, 1):
        name = prefix + f'verifier-lifeline/native-{i}-raw/result.json'
        d = read(archive, name)
        require(d['stage'] == stage and d['controller_signal'] == 9 and d['completed_control'] is True
                and d['administrative_stop_before_observation'] is False
                and d['clean_completion_report_exists'] is False and d['binary_sha256'] == binary_sha,
                'actual controller death before administrative cleanup, no fabricated settlement')
        require(d['parent_after_death']['pids.current'] == 0
                and d['death_to_empty_ns'] <= d['maximum_death_to_empty_ns'] == 5_000_000_000,
                'actual native descendants empty within original bound')
        parent_limits(d['parent_before_death'])
        parent_limits(d['parent_after_death'])
        readback = lf['cases'][i-1]['readback']
        require(readback['actual_self_exit_before_admin_cleanup'] is True
                and readback['no_clean_settlement_fabricated'] is True, 'owner-death reader scope')
        for relative, digest in readback['raw_files_sha256'].items():
            require(hashed[prefix + f'verifier-lifeline/native-{i}-raw/' + relative]['sha256'] == digest,
                    'owner-death raw receipt hash binding')
        deaths.append({'stage': stage, 'raw_file': name, 'raw_sha256': hashed[name]['sha256'],
                       'controller_signal': 9, 'death_to_empty_ns': d['death_to_empty_ns'],
                       'parent_pids_after_death': 0, 'administrative_stop_before_observation': False,
                       'clean_completion_report_exists': False, 'verifier_exit_status': d['after']['ExecMainStatus']})
    return {
        'prefix': prefix, 'profile': outcome['history_resource_profile'],
        'source': source, 'source_readbacks_verified': source_records,
        'binary_sha256': binary_sha, 'binary_bytes': binary['bytes'],
        'campaign_complete_success': False, 'campaign_failure': outcome['failure'],
        'finalization_failures': outcome['finalization_failures'],
        'attempts': attempts, 'phase_passes': sum(p['finite_phase_criteria_met'] for p in phases),
        'phase_count': len(phases), 'phases': phases,
        'root_cleanup': cleanup, 'lifeline_complete_success': True,
        'lifeline_small_methods': lf['planned_small_methods'], 'actual_owner_death_controls': deaths,
    }


def main():
    records = []
    for aid, run, expected, prefixes in SPECS:
        path = ROOT / f'history-96f-{aid}.zip'
        require(sha(path.read_bytes()) == expected, 'original ZIP digest')
        with ZipFile(path) as archive:
            names = archive.namelist()
            require(len(names) == len(set(names)), 'unique ZIP entries')
            hashed = {}
            for name in names:
                h = hashlib.sha256()
                size = 0
                with archive.open(name) as stream:
                    while chunk := stream.read(1 << 20):
                        h.update(chunk)
                        size += len(chunk)
                hashed[name] = {'sha256': h.hexdigest(), 'bytes': size}
            manifests = []
            for prefix in prefixes:
                manifest = read(archive, prefix + 'artifact-files.json')
                for row in manifest['files']:
                    actual = hashed[prefix + row['path']]
                    require(actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256'],
                            ('original artifact inventory mismatch', prefix + row['path']))
                manifests.append({'path': prefix + 'artifact-files.json', 'verified_entries': len(manifest['files'])})
            arms = [audit_arm(archive, prefix, hashed) for prefix in prefixes]
            item = {'artifact_id': aid, 'original_run': run, 'archive_sha256': expected,
                    'archive_bytes': path.stat().st_size, 'archive_members': len(names),
                    'all_member_crcs_and_sha256_computed': True, 'original_manifests': manifests,
                    'arms': arms}
            if len(prefixes) == 2:
                pair = read(archive, 'pair-results.json')
                require(pair['order'] == ['strict', 'n8'] and pair['controller_interrupted_signal'] is None
                        and pair['safety_cleanup']['complete_success'] is True, 'pair lifecycle')
                require(pair['pair_binding_valid'] is False and pair['all_required_steps_passed'] is False
                        and pair['all_original_campaigns_passed'] is False, 'failed required step cannot pass')
                require(pair['arms'][0]['binary_sha256'] == pair['arms'][1]['binary_sha256'], 'paired native ELF')
                hosts = [a[k] for a in pair['arms'] for k in ['host_before', 'host_after']]
                require(all(h == hosts[0] for h in hosts), 'same observed host and boot for both arms')
                for arm in pair['arms']:
                    require(len(arm['steps']) == 12 and all(s.get('executed') is True
                            and s['timed_out'] is False and s['interrupted_signal'] is None
                            for s in arm['steps']), 'both arms actually executed all original steps')
                    failed = [s for s in arm['steps'] if s['returncode'] != 0]
                    require(len(failed) == 1 and failed[0]['name'] == 'Run three original campaigns under verified actual limits',
                            'actual first failing original step')
                item['pair_result'] = pair
                item['same_host_boot_source_elf_observations_independently_equal'] = True
            records.append(item)
        print(json.dumps({'artifact_id': aid, 'integrity_pass': True,
                          'profiles': [{'profile': a['profile'], 'phase_passes': a['phase_passes'],
                                        'phase_count': a['phase_count'], 'lifeline_pass': a['lifeline_complete_success']}
                                       for a in arms]}), flush=True)
    report = {
        'schema': 'history-96f-terminal-independent-artifact-audit-v1',
        'head': HEAD, 'tree': TREE, 'artifact_integrity_audit_passed': True,
        'native_original_campaign_qualified': False, 'p0_durable_loop_closed': False,
        'new_source_fix_proposed': False,
        'failure_classification': 'Original 30-second signed-confirmation/depletion criteria fail under retained limits; no outer 600-second timeout or swallowed cancellation is present.',
        'records': records,
        'scope': [
            'All source/binary bindings, original artifact inventory entries, phase results and explicit final public CPU balance equations are checked from the original ZIPs.',
            'The paired controller executed both arms and rejected actual campaign failures. Its pair_binding_valid flag additionally requires successful mandatory steps; independent same-host/source/ELF observation equality does not turn the campaign into PASS.',
            'All 36 recorded ordinary phase verifiers exited cleanly, with no forced kill, no verifier errors, an empty parent, no known live CPU owners and no unsettled known live CPU.',
            'The 12 actual owner-death controls are between named native-call boundaries; actor exit precedes administrative cleanup and no successful clean settlement is fabricated.',
            'These new artifacts do not add a physical power-loss, mid-journal-write recovery, or general durable application-subtask settlement qualification. Public CPU ledger closure is narrower.',
            'The independent original N8 full-state reader failures coincide with the original phase ending before full-page synchronization; inspected imports succeed and incomplete pages leave the previous active state. This is not evidence of journal corruption.',
            'No thresholds, budgets, source paths or activation semantics were changed. No new native campaign or unrelated historical test has been counted as this audit.',
        ],
    }
    target = ROOT / 'history-96f-terminal-independent-audit.json'
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'report': str(target), 'sha256': sha(target.read_bytes()),
                      'artifact_integrity_audit_passed': True, 'native_original_campaign_qualified': False}))


if __name__ == '__main__':
    main()
