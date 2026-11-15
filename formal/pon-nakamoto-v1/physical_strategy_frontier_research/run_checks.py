#!/usr/bin/env python3
"""Reproduce only this increment; upstream's retained 21 checks are not rerun."""
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json
import platform
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parent

def run(args, log):
    result=subprocess.run([sys.executable,'-B',*args],cwd=ROOT,capture_output=True,text=True)
    (ROOT/log).write_text(result.stdout+result.stderr)
    if result.returncode:
        raise SystemExit(f'{args[0]} failed; see {log}; exit={result.returncode}')
    return result

def main():
    run(['test_frontier.py'],'tests.log')
    match=re.search(r'Ran (\d+) tests?',(ROOT/'tests.log').read_text())
    if match is None:raise SystemExit('test count missing')
    run(['run_frontier.py'],'run.log')
    result=json.loads((ROOT/'results/frontier_result.json').read_text())
    rows=json.loads((ROOT/'results/candidate_rows.json').read_text())
    if len(rows)!=result['draws_per_strategy']:raise SystemExit('row count mismatch')
    if any(not s['all_witnesses_match_dense_direct'] for s in result['strategies']):
        raise SystemExit('witness mismatch')
    files=['frontier.py','selector_policy.py','run_frontier.py','test_frontier.py','run_checks.py',
           'UPSTREAM_SOURCE.json','README.md','THEOREMS.md','SOURCE_NOTES.md','NODE_ACCEPTANCE_MINIMUM.md',
           'results/frontier_result.json','results/candidate_rows.json','results/policy_result.json',
           'tests.log','run.log']
    summary={'schema':'selected-legal-cost-frontier-checks-v1',
             'completed_utc':datetime.now(timezone.utc).isoformat(),'python':platform.python_version(),
             'new_unittest_cases':int(match.group(1)),
             'retained_upstream_checks_counted_as_new':False,
             'strategies':len(result['strategies']),'nonce_draws_each':len(rows),
             'candidate_generations':len(rows)*len(result['strategies']),
             'cross_strategy_exact_byte_comparisons':len(rows)*(len(result['strategies'])-1),
             'fresh_complete_acceptance_replays':sum(s['fresh_acceptance_replays'] for s in result['strategies']),
             'all_losing_candidate_rows_retained':True,
             'exact_integer_and_fraction_model':True,
             'native_benchmark_or_production_node_invocation':False,
             'universal_physical_lower_bound_closed':False,
             'qualification':'HOLD_NO_GO',
             'files_sha256':{name:sha256((ROOT/name).read_bytes()).hexdigest() for name in files}}
    (ROOT/'checks_summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    paths=sorted(p for p in ROOT.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p not in (ROOT/'SHA256SUMS',ROOT/'checks.log'))
    (ROOT/'SHA256SUMS').write_text(''.join(f'{sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ROOT).as_posix()}\n' for p in paths))
    print(json.dumps({k:v for k,v in summary.items() if k!='files_sha256'},indent=2))

if __name__=='__main__':main()
