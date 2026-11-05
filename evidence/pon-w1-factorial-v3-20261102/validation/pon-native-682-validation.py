#!/usr/bin/env python3
"""Retain bounded native checks of the published PoN integration source."""
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path('/workspace/scratch/e08750459604/pon-work')
OUT = Path('/workspace/scratch/e08750459604/pon-native-2b250859-observations')
COMMIT = '2b250859e7c07088e6c3c01f75006372c684de61'
sys.path.insert(0, str(ROOT / 'scripts/ci'))
from ci_observation import run, source, digest

def main():
    OUT.mkdir(exist_ok=True)
    env = dict(os.environ)
    env.update(PATH='/tmp/pon-build-tools/bin:/tmp/trnm-original-budget-cargo/bin:' + env['PATH'],
               RUSTUP_HOME='/tmp/trnm-original-budget-rustup',
               CARGO_HOME='/tmp/trnm-original-budget-cargo',
               CARGO_TARGET_DIR='/workspace/scratch/e08750459604/pon-v3-target-682',
               CARGO_BUILD_JOBS='4',
               OPENSSL_DIR='/tmp/trnm-original-budget-provider/build/trnm-pq-provider-3.5.9.MV1bGG14/install')
    before = source()
    assert before['commit'] == COMMIT and before['source_state'] == 'committed-clean'
    report = {'schema':'pon-v3-integrated-native-controls-v1','expected_source':COMMIT,
              'source_before':before,'observations':[],'result':'FAIL',
              'work_profile_qualified':False,'resource_fairness_qualified':False,
              'public_service_measured':False,'independent_hardware_qualified':False,
              'public_network_ready':False,'production_activation':False,
              'scope':'source-bound local correctness/lint controls; no work-cost or public Host qualification'}
    prefix = ['cargo','+1.95.0','test','--locked','--release','--target','x86_64-unknown-linux-gnu',
              '--manifest-path','trillionnium/Cargo.toml']
    cases = [
        ('w1-complete', ['-p','trnm-crypto-primitives','--lib','pon_work::'], 113, 0),
        ('host-parent', ['-p','trnm-pon-node','--lib','host_kernel_parent::kernel_parent::tests::'], 19, 0),
        ('history-import', ['-p','trnm-pon-node','--lib','ingress::history_import::tests::'], 20, 1),
        ('cache-explicit', ['-p','trnm-pon-node','--lib','ingress::public_v3::tests::w1_negative_cache_is_explicit_bounded_and_never_activated_by_default'], 1, 0),
        ('protocol-wire', ['-p','trnm-protocol','--lib','pon_wire::'], 18, 1),
        ('header-binding', ['-p','trnm-pon-node','--test','work_header_binding'], 1, 0),
        ('factorial-example', ['-p','trnm-pon-node','--example','pon_w1_legal_strategy_v3'], 6, 0),
        ('cpu-completion', ['-p','trnm-pon-node','--lib','ingress::public_v3::scalar_cpu::completion_tests::'], 11, 0),
        ('work-fuzz', ['-p','trnm-pon-node','--test','work_fuzz_semantics'], 6, 0),
        ('retained-rejection', ['-p','trnm-crypto-primitives','--example','pon_rejection_cost'], 3, 0),
    ]
    commands = [('preflight',['bash','scripts/project-preflight.sh'],None),
                ('cargo-metadata',['cargo','+1.95.0','metadata','--locked','--offline','--manifest-path','trillionnium/Cargo.toml','--format-version','1'],None),
                ('format',['cargo','+1.95.0','fmt','--manifest-path','trillionnium/Cargo.toml','--all','--','--check'],None)]
    commands += [(name,prefix+args+['--','--test-threads=1']+(['--exact'] if name=='cache-explicit' else []),(passed,ignored))
                 for name,args,passed,ignored in cases]
    commands += [('strict-clippy',['cargo','+1.95.0','clippy','--locked','--target','x86_64-unknown-linux-gnu',
                 '--manifest-path','trillionnium/Cargo.toml','-p','trnm-crypto-primitives','-p','trnm-pon-node',
                 '--all-targets','--all-features','--','-D','warnings'],None)]
    try:
        failed = False
        for name,command,expected in commands:
            item = run(command, OUT/(name+'.log'), timeout=900, env=env, expected_source=COMMIT)
            item['name']=name
            if expected is not None:
                rows=re.findall(r'^test result: ok\. ([0-9]+) passed; 0 failed; ([0-9]+) ignored;',
                                (OUT/(name+'.log')).read_text(),re.M)
                item['expected_counts']={'passed':expected[0],'ignored':expected[1]}
                item['observed_count_rows']=rows
                item['expected_counts_met']=rows==[tuple(map(str,expected))]
                failed |= not item['expected_counts_met']
            report['observations'].append(item)
            failed |= item['exit_code'] != 0
            print(json.dumps({'name':name,'exit_code':item['exit_code'],
                              'counts':item.get('observed_count_rows'),'source_verified':item.get('source_verified')}),flush=True)
        report['result']='FAIL' if failed else 'PASS'
    except Exception as exc:
        report['error']=str(exc)
        raise
    finally:
        report['source_after']=source()
        report['source_changed']=report['source_after']!=before
        if report['source_changed']: report['result']='FAIL'
        report['artifact_sha256']={p.name:digest(p) for p in sorted(OUT.iterdir()) if p.is_file() and p.name!='native-manifest.json'}
        (OUT/'native-manifest.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    return 0 if report['result']=='PASS' else 1

if __name__ == '__main__':
    sys.exit(main())
