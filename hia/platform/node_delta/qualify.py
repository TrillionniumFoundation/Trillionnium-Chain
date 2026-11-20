"""Qualify the native typed Delta actor and its test-only transaction fixture."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from hia.platform.build import new_output, write_json
from hia.platform.transport_request.rust_oracle import command


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-rust', action='store_true')
    args = parser.parse_args()
    output = new_output(args.output)
    source_paths = [path for path in HERE.iterdir()
                    if path.is_file() and path.suffix in ('.py','.hepta','.rs','.json','.md')
                    and path.name != 'development-observations.json']
    source_paths.extend(REPO / name for name in (
        'hia/components.json','hia/tools/toolchain.py','hia/src/codec/json_primitives.hepta',
        'hia/tests/native_support.py','hia/platform/build.py',
        'hia/platform/transport_request/rust_oracle.py','hia/toolchain.lock.json',
        'hia/qualification/compiler-binding.json'))
    captured = {path:path.read_bytes() for path in source_paths}
    base = {'schema':'trnm.hia.native-node-delta-qualification.v1',
        'scope':'Original Legacy apply_delta_with_progress typed staging; not outer Node commit/reorg publication',
        'sources':{path.relative_to(REPO).as_posix():{'bytes':len(raw),'sha256':digest(raw)}
                   for path,raw in captured.items()},
        'production_host_business_state':False,
        'whole_node_or_durable_transaction_qualified':False,
        'maximum_complete_state_byte_extent_qualified':False,
        'constructor_scan_copy_before_first_progress':True,
        'physical_sql_materialization_retired':False,
        'sql_conversion_error_order_qualified':False,
        'original_cpu_or_input_acquisition_budget_qualified':False}
    stages, reports = [], {}
    try:
        for name, script, variable in (
            ('relations','test_delta.py','TRNM_DELTA_OUTPUT'),
            ('contracts','test_delta_contracts.py','TRNM_DELTA_CONTRACT_OUTPUT'),
            ('caller-extents','test_delta_wide.py','TRNM_DELTA_WIDE_OUTPUT')):
            environment = dict(os.environ)
            environment[variable] = str(output/name)
            _, receipt = command([sys.executable,'-B',str(HERE/script)], REPO, output,
                'invoke-'+name, env=environment, timeout=180)
            stages.append(receipt)
            report_path = output/name/'report.json'
            report = json.loads(report_path.read_bytes())
            if report['status'] != 'PASS' or not report['source_inputs_stable']:
                raise ValueError('Native stage did not pass: '+name)
            reports[name] = {'status':'PASS',
                'controls':report.get('native_cases',report.get('native_controls')),
                'report':str(report_path),'sha256':digest(report_path.read_bytes())}
        argv = [sys.executable,'-B',str(HERE/'rust_delta_oracle.py'),
                '--repository',str(REPO),'--output',str(output/'original-rust')]
        if args.require_rust:
            argv.append('--require-rust')
        _, receipt = command(argv, REPO, output, 'invoke-original-rust', timeout=1000)
        stages.append(receipt)
        rust_path = output/'original-rust/report.json'
        rust = json.loads(rust_path.read_bytes())
        if args.require_rust and rust['status'] != 'PASS':
            raise ValueError('Required original Rust differential did not pass')
        reports['original-rust'] = {'status':rust['status'],
            'selected_cases':rust['selected_corpus_cases'], 'report':str(rust_path),
            'sha256':digest(rust_path.read_bytes())}
        for path,raw in captured.items():
            if path.is_symlink() or path.read_bytes() != raw:
                raise ValueError('Qualification source changed: '+str(path))
        result = dict(base,status='PASS' if rust['status']=='PASS' else 'NATIVE_PASS_ORIGINAL_NOT_RUN',
            native='PASS',original_rust=rust['status'],reports=reports,stages=stages,
            source_inputs_stable=True,native_controls=sum(row['controls'] for key,row in reports.items()
                                                        if key!='original-rust'))
        write_json(output/'report.json',result)
        print(json.dumps({'status':result['status'],'native_controls':result['native_controls'],
                          'original_rust':result['original_rust'],'report':str(output/'report.json')}))
        return 0
    except Exception as error:
        write_json(output/'report.json',dict(base,status='FAIL',error=repr(error),
                   completed_reports=reports,stages=stages))
        raise


if __name__ == '__main__':
    raise SystemExit(main())
