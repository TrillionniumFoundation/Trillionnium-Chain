from dataclasses import asdict
import hashlib, json, pathlib, sys
from quantum_network_sim import NetworkScenario, ParticipationShock, run_network_scenario
records = []
for processors in (1, 4):
    case = NetworkScenario('frozen_setup_interruption', duration_seconds=4,
        classical_block_rate_at_initial_target=0, quantum_processors=processors,
        quantum_fixed_iterations=0, quantum_prepare_seconds=0,
        quantum_measure_seconds=0.5, quantum_candidate_check_seconds=0.5,
        quantum_domain_size=16, quantum_domain_marked_count=0,
        quantum_domain_setup_seconds=2,
        shocks=(ParticipationShock(0.5, 1, 0), ParticipationShock(1, 1, 1)))
    summary, rows = run_network_scenario(case)
    raw = b''.join((json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode() for row in rows)
    trace = pathlib.Path(sys.argv[1] + '-p' + str(processors) + '.jsonl')
    with trace.open('xb') as output:
        output.write(raw)
    adversarial, q = summary['adversarial'], summary['miners']['q']
    records.append({'parameters':asdict(case),'termination':summary['termination'],
        'domains_created':adversarial['domains_created'],
        'domain_setup_seconds_charged':adversarial['domain_setup_seconds_charged'],
        'domain_setup_processor_seconds_charged':adversarial['domain_setup_processor_seconds_charged'],
        'searches_started':q['searches_started'],'searches_cancelled':q['searches_cancelled'],
        'searches_completed':q['searches_completed'],'candidate_checks_completed':q['candidate_checks_completed'],
        'started_setup_seconds':[row['domain_setup_seconds'] for row in rows if row['kind']=='search-start'],
        'domain_ids':sorted({row['domain_id'] for row in rows if row['kind']=='search-start'}),
        'trace_file':str(trace),'trace_rows':len(rows),'trace_sha256':hashlib.sha256(raw).hexdigest()})
print(json.dumps(records,sort_keys=True))
