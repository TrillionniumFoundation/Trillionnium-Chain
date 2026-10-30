#!/usr/bin/env python3
"""Run the explicit v1 physical boundary gate with the original History22 ELF."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import signal
import sys
import time

from history_graph_resource_guardian_v1 import CASES, CASE_SECONDS, HELPER, PROFILE
import read_history_graph_resource_native_v1 as reader
from run_history_effect_v6_native import bounded, sha, write
from run_history_reorg_continuation_native_v1 import baseline, restore
from verify_ci_source import verify

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-source',required=True)
    parser.add_argument('--baseline-terminal',type=Path,required=True)
    parser.add_argument('--owner',required=True); parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args(); output=args.out.resolve()
    reader.require(not output.is_relative_to(ROOT), 'new independent output outside exact source required')
    output.mkdir(parents=True,exist_ok=False)
    result={'schema':'history-graph-resource-physical-native-terminal-v1','expected_source':args.expected_source,
            'profile':PROFILE,'passed':False,'new_lane_budget_seconds':reader.TOTAL_SECONDS,
            'original_22_7_12_budgets_unchanged':True,'original_campaign_budgets_unchanged':True,
            'original_history22_gate_required':True,'planned_cases':CASES,'cases':[],
            'production_qualified':False,'whole_history_p0_closed':False,
            'wall_clock_revocation_bound_claimed':False,'source_stable':False}
    source_ok=False; started=time.monotonic(); deadline=started+reader.TOTAL_SECONDS
    env={key:value for key,value in os.environ.items() if not key.startswith('TRNM_')}
    env.update(RUST_TEST_THREADS='1',PYTHONDONTWRITEBYTECODE='1')
    sys.path.insert(0,str(ROOT/'scripts'))
    import run_pon_w1_native_campaign as bounds
    def resource(name):
        value=bounds.resource_observation();bounds.validate_resources(value,10)
        reader.require(not value['cgroup'].startswith('/trnmponpublic.slice'), 'independent original outer budget')
        write(output/(name+'.json'),value);return value
    def step(command,name,seconds):
        remaining=deadline-time.monotonic();reader.require(remaining>0,'finite new physical lane exhausted')
        return bounded(command,output/name,min(seconds,remaining),env)
    try:
        before=verify('head',args.expected_source);source_ok=True;write(output/'source-before.json',before)
        resource('resource-before')
        original_dir=args.baseline_terminal.resolve(strict=True).parent
        original,manifest=baseline(original_dir,args.expected_source,before)
        executable=output/'actual-binary';binary_sha=restore(original_dir/'actual-binary',manifest,executable)
        result.update(binary_sha256=binary_sha,binary_bytes=manifest['binary_bytes'],
                      original_terminal_sha256=sha(args.baseline_terminal),binary_same_as_history22=True,
                      original_binary_archive=manifest)
        listing=step([str(executable),'graph_resource_v1','--list'],'inventory',30)
        reader.require(listing['passed'],'actual compiled roster required')
        rows=sorted(line.removesuffix(': test') for line in (output/'inventory/native.log').read_text().splitlines() if line.endswith(': test'))
        reader.require(rows==sorted(reader.PURE_ROSTER+[HELPER]),'all exact new unit tests and one actual physical helper required')
        pure=step([str(executable),'graph_resource_v1','--test-threads=1','--show-output'],'unit-controls',30)
        reader.test_terminal((output/'unit-controls/native.log').read_text(),reader.PURE_ROSTER,[HELPER])
        reader.require(pure['passed'],'all actual unit controls must pass')
        result['unit_controls']=pure
        for spec in CASES:
            directory=output/spec['case'];directory.mkdir(mode=0o700)
            write(directory/'job.json',{**spec,'schema':'history-graph-resource-physical-job-v1',
                  'parent':reader.PARENT,'profile':PROFILE,'binary_sha256':binary_sha})
            command=['sudo','-n',sys.executable,str(ROOT/'scripts/ci/history_graph_resource_guardian_v1.py'),
                     '--owner',args.owner,'--directory',str(directory),'--binary',str(executable),
                     '--uid',str(os.getuid()),'--gid',str(os.getgid())]
            actual=step(command,spec['case']+'-guardian',CASE_SECONDS+20)
            row={'case':spec['case'],'actual_guardian_process':actual,'passed':False}
            result['cases'].append(row);write(output/'progress.json',result)
            reader.require(actual['passed'],'actual owned physical guardian failed: '+spec['case'])
            row['readback']=reader.validate_case(directory,spec,binary_sha);row['passed']=True
            reader.require(sha(executable)==binary_sha,'original retained ELF changed')
            write(output/'progress.json',result)
        result['passed']=len(result['cases'])==len(CASES) and all(row['passed'] for row in result['cases'])
    except BaseException as error:
        result.update(passed=False,error=f'{type(error).__name__}: {error}')
    finally:
        if source_ok:
            try:
                after=verify('head',args.expected_source);write(output/'source-after.json',after)
                result['source_stable']=before==after
                result['passed']=result['passed'] and result['source_stable']
                resource('resource-after')
            except BaseException as error:
                result.update(passed=False,finalization_error=f'{type(error).__name__}: {error}')
        result['elapsed_seconds']=time.monotonic()-started
        if result['elapsed_seconds']>reader.TOTAL_SECONDS:result['passed']=False
        result['inventory']=[{'path':str(path.relative_to(output)),'bytes':path.stat().st_size,'sha256':sha(path)}
                             for path in sorted(output.rglob('*')) if path.is_file()]
        write(output/'terminal.json',result)
        print(json.dumps({key:value for key,value in result.items() if key not in ('inventory','original_binary_archive')}))
    return 0 if result['passed'] else 1


if __name__=='__main__':
    def cancelled(signum,_frame):
        raise InterruptedError(f'workflow signalled {signum}')
    signal.signal(signal.SIGTERM,cancelled)
    raise SystemExit(main())
