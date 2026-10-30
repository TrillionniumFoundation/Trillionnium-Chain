#!/usr/bin/env python3
"""Finite exact-source NPQ5 task permission qualification plus all retained PQ lanes."""
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
from run_native_pq_quota_v3 import QUOTA_CASES, NATIVE_QUOTA_CASES, QUOTA_CODEC_CASE, quota_phases
from native_pq_tasks_v4_unit_contract import EXPECTED_OUTCOMES
from run_native_pq_tasks_v4 import (TASK_CASES as V4_TASK_CASES, NATIVE_TASK_CASES as V4_NATIVE_TASK_CASES,
    task_phases as v4_task_phases)

TASK_CASES = {
    'actual_two_state_owners_charge_two_proofs_and_retain_five_bounded_witness_leaves',
    'either_bad_inner_or_outer_proof_wrong_account_and_wrong_source_never_spend_nonce_or_fee',
    'actual_signed_nonce_previous_statement_and_parent_lease_bindings_refuse_cross_branch_replay',
    'source_and_requester_rotations_exclude_task_use_in_both_orders_then_accept_current_keys',
    'retired_registration_cannot_authorize_work_and_current_dual_proofs_restore_the_same_meter',
    'open_register_and_revoke_register_pairs_refuse_both_block_orders_without_partial_effects',
    'missing_reordered_duplicate_oversized_and_other_task_witness_fragments_cannot_authorize',
    'full_32_task_slot_capacity_counts_64_real_proofs_and_never_enlarges_state_values',
    'legacy_commands_old_profiles_wrong_material_and_unsigned_inner_wrappers_are_refused',
    'atomic_renewal_exact_codec_two_real_proofs_five_chunks_and_old_profile_refusal',
    'requester_only_renewal_is_cold_valid_but_awaits_new_source_and_preserves_past_output',
    'renewal_block_may_credit_verified_parent_output_without_granting_pending_future_work',
    'atomic_renewal_bad_each_proof_role_account_nonce_branch_or_prior_spends_nothing',
    'renewal_rejects_expired_gap_wrong_revision_changed_scope_and_changed_material_atomically',
    'renew_rotate_revoke_and_register_pairs_refuse_both_orders_then_use_current_authority',
    'atomic_all_five_fragment_boundaries_and_mixed_statement_bytes_fail_cold_authorization',
    'incremental_atomic_renewal_prefix_uses_original_parent_and_rolls_back_rejected_suffix',
}
NATIVE_TASK_CASES = {
    'dual_pq_task_pool_ordinary_material_actual_w1_output_and_cold_read_form_one_namespace',
    'actual_source_rotation_new_dual_proofs_and_heavier_fork_reauthorize_from_cold_state',
    'activation_cut_recovery_and_heavier_reorg_never_rewind_local_revocation_or_change_remote_validity',
    'cold_missing_witness_and_deleted_local_revocation_evidence_refuse_without_legacy_fallback',
    'all_32_task_slots_reach_actual_pool_w1_sql_bounded_leaves_and_cold_material_use',
    'atomic_22_in_actual_material_block_preserves_output_then_cold_uses_extended_window',
    'staged_19_waits_across_cold_start_until_21_actual_source_proof_then_reads_next_task',
}
TASK_CODEC_CASE = 'qualified_work_task::pq_lifecycle_v4::tests::native_pq_lease_revocation_domains_lengths_and_exact_branch_identity_are_fresh'
TASK_APPLY_CASE = 'pon_executor::pq_accounts_v2::tasks_v5_tests::prepared_pq5_atomic_renewal_rechecks_revision_prior_source_and_requester_before_fee_patch'
PHASE_SCHEMA = 'native-pq5-actual-phase-v1'
PHASE_SCOPE = 'actual shared-host complete W1/reference/admit/SQL; not isolated worst-case cost'
EXPECTED_RAW_BYTES = [4053]*6 + [7894]*8 + [9272] + [4057]*2 + [8274]*2 + [4121] + [129696,252608,264768] + [0]*14

def unit_result(text: str, target: str) -> dict:
    expected=EXPECTED_OUTCOMES[target]
    result=test_result(text,{name for name,value in expected.items() if value=='ok'})
    if result['test_outcomes'] != expected:
        raise ValueError('complete retained unit roster and original ignores required')
    return result

def task_phases(text: str) -> list[dict]:
    rows=[]
    for line in text.splitlines():
        if '"schema":"'+PHASE_SCHEMA+'"' not in line:
            continue
        row=json.loads(line)
        if (set(row) != {'schema','phase','transactions','raw_bytes','proof_bytes','packet_bytes','wall_nanoseconds','block','scope'}
            or row['schema'] != PHASE_SCHEMA or row['scope'] != PHASE_SCOPE
            or row['phase'] not in ('maintenance','registered-material')
            or any(type(row[k]) is not int or row[k]<0 for k in ('transactions','raw_bytes','proof_bytes','packet_bytes','wall_nanoseconds'))
            or row['packet_bytes'] != 8+318+2+2*row['transactions']+row['raw_bytes']+row['proof_bytes']
            or row['packet_bytes'] > 1048576
            or row['proof_bytes'] != 49188 or row['wall_nanoseconds'] == 0
            or (row['transactions'],row['raw_bytes']) not in ((0,0),(1,4053),(1,7894),(1,9272),(1,4057),(1,4121),(1,8274),(32,129696),(32,252608),(32,264768))
            or (row['phase']=='registered-material' and (row['transactions'],row['raw_bytes']) not in ((0,0),(1,4121),(1,8274)))
            or not isinstance(row['block'],str) or len(row['block'])!=64
            or any(c not in '0123456789abcdef' for c in row['block'])):
            raise ValueError('invalid actual NPQ5 task phase')
        rows.append(row)
    if (len(rows)!=37 or sorted(r['raw_bytes'] for r in rows)!=sorted(EXPECTED_RAW_BYTES)
        or sum(r['phase']=='registered-material' for r in rows)!=10
        or sorted(r['raw_bytes'] for r in rows if r['phase']=='registered-material') != [0]*8+[4121,8274]):
        raise ValueError('complete NPQ5 task phase set required')
    return rows

def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-head',required=True)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    output=args.output.resolve()
    if output.is_relative_to(ROOT): raise ValueError('observations must be outside source')
    output.mkdir(parents=True,exist_ok=False)
    report={'schema':'native-pq-tasks-v5-research-ci-v1','result':'FAIL','source_expected':args.expected_head,
        'observations':[],'tests':{},'production_activation':False,'whole_chain_post_quantum':False,
        'p1_complete':False,'real_demand_proved':False,'useful_model_work_qualified':False,
        'local_revocation_contract':'activation-event/actual-tx-root-bound monotonic stable-lineage local production refusal across revisions; not a consensus rule',
        'supported_new_commands':[18,19,20,21,22],'renewal_19_22_source_candidate':True,'renewal_19_22_qualified':False,'model_commands_supported':False,'migration_supported':False,'retired_key_model_governance_qualified':False,
        'source_chain_retirement_proved':False,'sqlite_physical_io_qualified':False,
        'scope':'fresh NPQ5 task permissions and retained NPQ1/2/3/4; no whole-chain or product authority',
        'total_command_budget_seconds':2400}
    env=os.environ.copy()
    env.update(CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='1',CARGO_PROFILE_TEST_DEBUG='0',CARGO_PROFILE_DEV_DEBUG='0',
        RUST_TEST_THREADS='1',PYTHONDONTWRITEBYTECODE='1',CARGO_TERM_COLOR='never')
    report['selected_environment']={k:env.get(k) for k in ('CARGO_HOME','CARGO_TARGET_DIR','CARGO_INCREMENTAL',
        'CARGO_BUILD_JOBS','CARGO_PROFILE_TEST_DEBUG','CARGO_PROFILE_DEV_DEBUG','RUST_TEST_THREADS')}
    deadline=time.monotonic()+2400
    def command(label: str,argv: list[str],ceiling: int) -> Path:
        remaining=int(deadline-time.monotonic())
        if remaining<=0: raise TimeoutError('NPQ5 command budget exhausted')
        log=output/(label+'.log')
        checked(argv,log,report['observations'],timeout=min(ceiling,remaining),env=env,expected_source=args.expected_head)
        if time.monotonic()>deadline: raise TimeoutError('NPQ5 command budget exhausted after source checks')
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
            ('m00','trnm-protocol',['--lib'],M00_CASES|{QUOTA_CODEC_CASE,TASK_CODEC_CASE},False),
            ('m06','trnm-mvcc-fee',['--lib'],M06_CASES|{TASK_APPLY_CASE},False),
            ('task-renewal','trnm-mvcc-fee',['--test','pq5_task_renewal'],TASK_CASES,True),
            ('native-task','trnm-pon-node',['--test','native_pq_v5'],NATIVE_TASK_CASES,True),
            ('retained-task-authority','trnm-mvcc-fee',['--test','pq4_task_authority'],V4_TASK_CASES,True),
            ('retained-native-task','trnm-pon-node',['--test','native_pq_v4'],V4_NATIVE_TASK_CASES,True),
            ('retained-quota-authority','trnm-mvcc-fee',['--test','pq3_quota_authority'],QUOTA_CASES,True),
            ('retained-authority-capacity','trnm-mvcc-fee',['--test','pq2_authority_capacity'],AUTHORITY_CAPACITY_CASES,True),
            ('retained-native-quota','trnm-pon-node',['--test','native_pq_v3'],NATIVE_QUOTA_CASES,True),
            ('retained-pq2','trnm-pon-node',['--test','native_pq_v2'],NATIVE_CASES,True),
            ('retained-pq1','trnm-pon-node',['--test','native_pq_v1'],PQ1_NATIVE_CASES,True),
        ):
            log=command(name,cargo+['test','--locked']+manifest+['-p',package]+target+['--','--show-output','--test-threads=1'],1500)
            report['tests'][name]=(unit_result(log.read_text(),name) if name in EXPECTED_OUTCOMES
                else test_result(log.read_text(),required,exact=exact))
            if name=='native-task':
                rows=task_phases(log.read_text())
                (output/'native-task-phases.json').write_text(json.dumps(rows,indent=2)+'\n')
                report['native_task_phase_count']=len(rows)
            if name=='retained-native-task':
                (output/'retained-task-phases.json').write_text(json.dumps(v4_task_phases(log.read_text()),indent=2)+'\n')
            if name=='retained-native-quota':
                (output/'retained-quota-phases.json').write_text(json.dumps(quota_phases(log.read_text()),indent=2)+'\n')
            if name=='retained-pq2':
                (output/'retained-pq2-phases.json').write_text(json.dumps(phase_result(log.read_text()),indent=2)+'\n')
        target=Path(env['CARGO_TARGET_DIR']).resolve()
        binaries=[p for p in (target/'debug/deps').glob('native_pq_v5-*') if p.is_file() and not p.is_symlink() and not p.suffix and os.access(p,os.X_OK)]
        if len(binaries)!=1 or not 0<binaries[0].stat().st_size<=64*1024*1024: raise ValueError('one bounded actual binary required')
        binary=binaries[0];retained=output/'native-task-test.bin.gz'
        retained.write_bytes(gzip.compress(binary.read_bytes(),compresslevel=6,mtime=0))
        report['native_binary']={'cargo_path':str(binary),'bytes':binary.stat().st_size,'sha256':digest(binary),
            'retained_gzip':retained.name,'gzip_sha256':digest(retained),'keys':'public fixture seeds only'}
        command('clippy',cargo+['clippy','--locked']+manifest+['-p','trnm-protocol','-p','trnm-mvcc-fee','-p','trnm-pon-node','--all-targets','--all-features','--','-D','warnings'],900)
        report['renewal_19_22_qualified']=True
        report['result']='PASS'
    except Exception as error:
        report['error']=f'{type(error).__name__}: {error}'
    finally:
        finish(output,report,['rust-toolchain.toml','trillionnium/Cargo.lock','scripts/ci/run_native_pq_tasks_v4.py',
            'scripts/ci/run_native_pq_quota_v3.py','scripts/ci/run_native_pq_accounts_v2.py',
            'scripts/ci/native_pq_tasks_v4_unit_contract.py',
            'scripts/ci/test_native_pq_tasks_v4_research.py','trillionnium/crates/trnm-mvcc-fee/tests/pq4_task_authority.rs',
            'trillionnium/crates/trnm-pon-node/tests/native_pq_v4.rs',
            'trillionnium/crates/trnm-protocol/src/qualified_work_task/pq_lifecycle_v4.rs',
            'trillionnium/crates/trnm-crypto-primitives/src/qualified_work_task/pq_lifecycle_v4.rs',
            'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/tasks_v4.rs',
            'trillionnium/crates/trnm-pon-node/src/store/pq_tasks_v4.rs',
            'scripts/ci/run_native_pq_tasks_v5.py','scripts/ci/test_native_pq_tasks_v5_research.py',
            'trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs',
            'trillionnium/crates/trnm-pon-node/src/store.rs',
            'trillionnium/crates/trnm-mvcc-fee/tests/pq5_task_renewal.rs',
            'trillionnium/crates/trnm-pon-node/tests/native_pq_v5.rs',
            'trillionnium/crates/trnm-protocol/src/qualified_work_task/pq_lifecycle_v5.rs',
            'trillionnium/crates/trnm-crypto-primitives/src/qualified_work_task/pq_lifecycle_v5.rs',
            'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/tasks_v5.rs',
            'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/tasks_v5_tests.rs',
            'trillionnium/crates/trnm-pon-node/src/store/pq_tasks_v5.rs'])
    raise SystemExit(0 if report['result']=='PASS' else 1)
if __name__=='__main__': main()
