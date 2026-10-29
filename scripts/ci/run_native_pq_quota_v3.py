#!/usr/bin/env python3
"""Exact-head NPQ3 quota experiment plus retained NPQ2/PQ1 regression; no activation."""
from __future__ import annotations
import argparse
import gzip
import json
import os
from pathlib import Path
import time
from ci_observation import ROOT, checked, digest, finish, pin_source
from run_native_pq_accounts_v2 import (AUTHORITY_CAPACITY_CASES, M00_CASES, M06_CASES,
    NATIVE_CASES, PQ1_NATIVE_CASES, phase_result, test_result)

QUOTA_CASES = {
    'actual_dual_pq_quota_conserves_escrow_fee_nonce_and_consumer_identity',
    'both_real_proofs_current_state_consumer_and_nonconsuming_rejections_are_required',
    'consumer_and_provider_rotations_are_exclusive_in_both_block_orders',
    'full_dual_proof_capacity_allows_71_and_refuses_72_without_mutation',
    'v2_cannot_opt_into_quota_and_v3_context_cannot_be_relabelled',
    'rotated_provider_uses_stable_account_and_rejects_retired_proof_without_spending',
    'consumer_registration_and_quota_use_require_separate_parent_authority',
    'same_block_quota_creation_cannot_supply_consumer_authority',
}
NATIVE_QUOTA_CASES = {
    'dual_pq_quota_actual_pool_work_sql_cut_cold_recovery_and_heavier_fork',
    'actual_consumer_rotation_rejects_retired_proof_and_reorg_restores_original_authority',
    'exact_new_packet_settings_and_sql_namespaces_refuse_old_profile_fallback',
    'actual_source_checkpoint_claimed_consumer_uses_quota_and_reorg_restores_import_lock',
    'full_dual_proof_capacity_reaches_native_pool_packet_sql_and_cold_read',
}
QUOTA_CODEC_CASE = 'pq_native_accounts_v2::tests::quota_successor_has_fresh_exact_roles_and_full_dual_proof_bytes'
PHASE_SCHEMA = 'native-pq3-actual-phase-v1'
PHASE_SCOPE = 'shared host actual calls, not isolated cost or worst case'

def quota_phases(text: str) -> list[dict]:
    rows=[]
    for line in text.splitlines():
        if '"schema":"'+PHASE_SCHEMA+'"' not in line:
            continue
        row=json.loads(line)
        if (set(row) != {'schema','phase','transactions','raw_bytes','wall_nanoseconds','block','scope'}
            or row['schema'] != PHASE_SCHEMA
            or row['phase'] != 'make-complete-w1-independent-reference-admit-sql'
            or row['scope'] != PHASE_SCOPE
            or any(type(row[k]) is not int or row[k]<0 for k in ('transactions','raw_bytes','wall_nanoseconds'))
            or (row['transactions'],row['raw_bytes']) not in ((0,0),(1,3821),(1,7314),(1,9272),(1,9432),(71,519294))
            or (row['transactions']==0) != (row['raw_bytes']==0)
            or not isinstance(row['block'],str) or len(row['block'])!=64
            or any(c not in '0123456789abcdef' for c in row['block'])):
            raise ValueError('invalid actual NPQ3 phase observation')
        rows.append(row)
    if len(rows)!=21 or sorted(r['raw_bytes'] for r in rows)!=sorted([3821,7314,0,0,7314,3821,9272,7314,0,0,0,9432,3821,7314,0,0,0,0,9432,3821,519294]):
        raise ValueError('complete native quota phase set required')
    return rows

def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-head',required=True)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    output=args.output.resolve()
    if output.is_relative_to(ROOT): raise ValueError('observations must be outside source')
    output.mkdir(parents=True,exist_ok=False)
    report={'schema':'native-pq-quota-v3-research-ci-v1','result':'FAIL','source_expected':args.expected_head,
        'observations':[],'tests':{},'production_activation':False,'whole_chain_post_quantum':False,
        'p1_complete':False,'source_chain_retirement_proved':False,'sqlite_physical_io_qualified':False,
        'scope':'NPQ3 quota composition and retained profiles; other authority owners remain open',
        'total_command_budget_seconds':2400}
    env=os.environ.copy()
    env.update(CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='1',CARGO_PROFILE_TEST_DEBUG='0',CARGO_PROFILE_DEV_DEBUG='0',
        RUST_TEST_THREADS='1',PYTHONDONTWRITEBYTECODE='1',CARGO_TERM_COLOR='never')
    report['selected_environment']={k:env.get(k) for k in ('CARGO_HOME','CARGO_TARGET_DIR','CARGO_INCREMENTAL',
        'CARGO_BUILD_JOBS','CARGO_PROFILE_TEST_DEBUG','CARGO_PROFILE_DEV_DEBUG','RUST_TEST_THREADS')}
    deadline=time.monotonic()+2400
    def command(label: str,argv: list[str],ceiling: int) -> Path:
        remaining=int(deadline-time.monotonic())
        if remaining<=0: raise TimeoutError('NPQ3 command budget exhausted')
        log=output/(label+'.log')
        checked(argv,log,report['observations'],timeout=min(ceiling,remaining),env=env,expected_source=args.expected_head)
        if time.monotonic()>deadline: raise TimeoutError('NPQ3 command budget exhausted after source checks')
        return log
    try:
        if pin_source()!=args.expected_head: raise ValueError('head differs from checked source')
        compiler=command('rustc',['rustc','+1.95.0','-vV'],60)
        if '\nrelease: 1.95.0\n' not in '\n'+compiler.read_text(): raise ValueError('unexpected compiler')
        command('preflight',['bash','scripts/project-preflight.sh','--audit'],120)
        command('source-negatives',['python3','scripts/ci/test_ci_source_integrity.py'],120)
        command('inventory',['python3','scripts/refresh_distributed_source_inventory.py','--check'],120)
        manifest=['--manifest-path','trillionnium/Cargo.toml'];cargo=['cargo','+1.95.0']
        command('cargo-graph',cargo+['metadata','--locked','--format-version','1']+manifest,300)
        command('fmt',cargo+['fmt']+manifest+['--all','--','--check'],180)
        for name,package,target,required,exact in (
            ('m00','trnm-protocol',['--lib'],M00_CASES|{QUOTA_CODEC_CASE},False),
            ('m06','trnm-mvcc-fee',['--lib'],M06_CASES,False),
            ('quota-authority','trnm-mvcc-fee',['--test','pq3_quota_authority'],QUOTA_CASES,True),
            ('retained-authority-capacity','trnm-mvcc-fee',['--test','pq2_authority_capacity'],AUTHORITY_CAPACITY_CASES,True),
            ('native-quota','trnm-pon-node',['--test','native_pq_v3'],NATIVE_QUOTA_CASES,True),
            ('retained-pq2','trnm-pon-node',['--test','native_pq_v2'],NATIVE_CASES,True),
            ('retained-pq1','trnm-pon-node',['--test','native_pq_v1'],PQ1_NATIVE_CASES,True),
        ):
            log=command(name,cargo+['test','--locked']+manifest+['-p',package]+target+['--','--show-output','--test-threads=1'],1500)
            report['tests'][name]=test_result(log.read_text(),required,exact=exact)
            if name=='native-quota':
                rows=quota_phases(log.read_text())
                (output/'native-quota-phases.json').write_text(json.dumps(rows,indent=2)+'\n')
                report['native_quota_phase_count']=len(rows)
            if name=='retained-pq2':
                (output/'retained-pq2-phases.json').write_text(json.dumps(phase_result(log.read_text()),indent=2)+'\n')
        target=Path(env['CARGO_TARGET_DIR']).resolve()
        binaries=[p for p in (target/'debug/deps').glob('native_pq_v3-*') if p.is_file() and not p.is_symlink() and not p.suffix and os.access(p,os.X_OK)]
        if len(binaries)!=1 or not 0<binaries[0].stat().st_size<=64*1024*1024: raise ValueError('one bounded actual binary required')
        binary=binaries[0];retained=output/'native-quota-test.bin.gz'
        retained.write_bytes(gzip.compress(binary.read_bytes(),compresslevel=6,mtime=0))
        report['native_binary']={'cargo_path':str(binary),'bytes':binary.stat().st_size,'sha256':digest(binary),
            'retained_gzip':retained.name,'gzip_sha256':digest(retained),'keys':'public fixture seeds only'}
        command('clippy',cargo+['clippy','--locked']+manifest+['-p','trnm-protocol','-p','trnm-mvcc-fee','-p','trnm-pon-node','--all-targets','--all-features','--','-D','warnings'],900)
        report['result']='PASS'
    except Exception as error:
        report['error']=f'{type(error).__name__}: {error}'
    finally:
        finish(output,report,['rust-toolchain.toml','trillionnium/Cargo.lock','scripts/ci/run_native_pq_quota_v3.py',
            'scripts/ci/run_native_pq_accounts_v2.py','scripts/ci/test_native_pq_quota_v3_research.py',
            'trillionnium/crates/trnm-mvcc-fee/tests/pq3_quota_authority.rs',
            'trillionnium/crates/trnm-pon-node/tests/native_pq_v3.rs',
            'trillionnium/crates/trnm-protocol/src/pq_native_accounts_v2.rs',
            'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2.rs',
            'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/migration.rs',
            'trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs',
            'trillionnium/crates/trnm-pon-node/src/pq_quota_v3.rs',
            'trillionnium/crates/trnm-pon-node/src/store/pq_quota_v3.rs'])
    raise SystemExit(0 if report['result']=='PASS' else 1)
if __name__=='__main__': main()
