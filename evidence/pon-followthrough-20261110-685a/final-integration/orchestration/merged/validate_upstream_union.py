#!/usr/bin/env python3
"""Observe one exact two-parent successor without inheriting parent test results.

This recorder does not merge, fetch, edit source, commit or publish. It uses a
fresh external output directory and preserves actual command exits and streams.
Its selected checks are not a full node-library run or a security qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

BASE = 'da1374a200022bc14dc2bd325cc9ba29dbcd24ab'
C2 = '8d8c0e64e7a301fc111a6720721a14816639e5aa'
C2_TREE = '7c003a3d183ad33ff4f3349cbcce61564f73a2ba'
FIRST_PARENT = 'a715b2c8e89732ce356ebae67f978ef232156c04'
FIRST_TREE = 'cc44e4c526d9b52d04697169a9b1d3eeb5079451'
UPSTREAM_FIRST = 'fcc3c86631c4fb5a1be59ba6da49d9d98d560761'
UPSTREAM = 'df927b6ffaecff293b9e9428e3ba516f47cd101a'
UPSTREAM_TREE = 'a883a05b590fb8b0113b3715f4294eee7a00275b'
VERIFY = 'scripts/ci/verify_ci_source.py'
INVENTORY = 'trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs'
LEDGER = 'evidence/pon-w1-lifetime-current-20261110-685a'
HISTORICAL_LOCK = ('7ddfe2bfa480d1ebd91c07d03d56a963fff038c5', 'trillionnium/Cargo.lock',
                   'f9e57d73899c5d9fabd4f5b4fedf45256b8db4efb448d15680d070bbcfcb30bd')
HISTORICAL_LOCK_BLOB = '2ff1e1c42dfa7061f4a77620c0bb65b656d158a5'
UPSTREAM_NATIVE = {
    'trillionnium/crates/trnm-mvcc-fee/src/public_evaluation.rs': '662ec394bffc84f568bca0f117456aa13f03e8b5',
    'trillionnium/crates/trnm-mvcc-fee/src/public_evaluation/quorum_v2.rs': 'e0c9345b649d138bc239b9c698c27ce124bd1572',
    'trillionnium/crates/trnm-mvcc-fee/tests/evaluation_quorum_v2.rs': '45dc4d2a8d88c61af6e978034b29792c91d10b65',
    'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs': 'af04938d292dd28bb52d75a22fed2e45dff8e78c',
}
ARCHIVE_ROOT = 'evidence/pon-open-consensus-continuation-20261110-2334/validation/cost/historical-v4/historical-source/'
ARCHIVED_RUST = {
    ARCHIVE_ROOT + 'trillionnium/crates/trnm-crypto-primitives/examples/support/w1_material.rs': '83ab348459f3e5cae409d4dcffba359ef90aaf64',
    ARCHIVE_ROOT + 'trillionnium/crates/trnm-pon-node/examples/pon_w1_lifecycle_cost_v4.rs': 'e1870e82a3ddfb9e117d6c0e232acb23ca9c4008',
    ARCHIVE_ROOT + 'trillionnium/crates/trnm-pon-node/examples/support/w1_cost_producers.rs': '7109064c900422e23f3ad2c2769e6d3a7386e8c8',
}
CI_UNION = {
    'scripts/ci/w1_native_controls.py': '63fb1d15fbc9fa52f880fca3c66dd300b907cb17',
    'scripts/ci/test_w1_factorial_native_gate.py': '02c78134f2bacd9ddd6df68dfdd878f02f5a8e1c',
    '.github/workflows/pon-w1-work-security.yml': '08d044a5f4c69ac6022446e7fd03965f0d35da90',
    '.github/workflows/pon-recent-batch-acceptance.yml': '89171c7274109594c3b5d82df8664d66eda710f8',
}
CANCEL_TEST = 'ingress::public_v3::tests::write_half_closed_or_disconnected_signed_submits_waiting_or_queued_do_not_start_work'
CONFIRMATION_TESTS = {
    'store::confirmation_chainwork_tests::full_width_retained_work_corruption_refuses_tip_inclusion_and_middle',
    'store::confirmation_chainwork_tests::a_common_work_offset_cannot_replace_the_zero_work_genesis_anchor',
    'store::confirmation_chainwork_tests::final_callback_same_connection_write_cannot_return_a_stale_confirmation',
    'store::confirmation_chainwork_tests::final_callback_foreign_commit_cannot_return_a_stale_confirmation',
}
QUORUM_TESTS = {
    'independent_reference_vectors_match_native_domains_counts_and_records',
    'fresh_profile_refuses_attested_models_and_cross_version_replay',
    'retained_reveals_recheck_commitments_at_restore_close_and_adoption',
    'classic_retained_closure_rejects_substituted_summary_at_use_and_restore',
    'classic_retained_closure_recounts_aborts_and_accepts_complete_zero_score',
    'classic_retained_closure_preserves_legal_appeals_and_late_conflicts',
    'quorum_retained_closure_cannot_authorize_adoption_before_its_height',
    'quorum_retained_closure_rejects_substituted_summary_at_use_and_restore',
    'quorum_retained_closure_preserves_nonempty_history_after_more_conflicts',
}
CI_UNION_TESTS = {
    'LegalGateTests.test_complete_current_native_roster_passes',
    'LegalGateTests.test_every_retained_versioned_material_and_observer_control_executes_once',
    'LegalGateTests.test_summary_only_stale_filtered_duplicate_or_failed_summaries_are_refused',
    'NativeGateTests.test_actual_workflow_uses_both_strict_gates_without_changing_native_selectors',
    'NativeGateTests.test_cli_failure_never_writes_success_report',
    'NativeGateTests.test_cli_fifo_and_symlink_log_refuse_without_waiting',
    'NativeGateTests.test_complete_roster_passes',
    'NativeGateTests.test_every_named_control_requires_one_successful_terminal',
    'NativeGateTests.test_every_suite_rejects_wrong_count_failure_ignored_and_duplicate_summary',
    'NativeGateTests.test_factorial_example_does_not_accept_filtered_or_measured_tests',
    'NativeGateTests.test_factorial_example_rejects_missing_duplicate_replaced_or_failed_named_control',
    'NativeGateTests.test_frozen_names_equal_current_native_source_and_retained_counts',
    'NativeGateTests.test_history_named_controls_remain_required_once',
    'NativeGateTests.test_ignored_child_is_exact_and_parent_still_must_pass',
    'NativeGateTests.test_kernel_rejects_missing_duplicate_or_replaced_named_control',
    'NativeGateTests.test_nocapture_retains_name_until_its_serial_success_terminal',
    'NativeGateTests.test_original_old_counts_cannot_certify_the_current_roster',
    'NativeGateTests.test_selected_native_suites_keep_nonzero_filtered_observations',
}
LEDGER_TESTS = {'LifetimeLedgerTests.' + name for name in (
    'test_project_unknowns_do_not_produce_a_target_or_qualification',
    'test_processors_failed_roots_and_recursive_nodes_are_all_charged',
    'test_complete_relation_event_count_cannot_drop_failed_attempts',
    'test_offline_adaptive_delegated_and_unclassified_queries_accumulate',
    'test_missing_phase_group_or_unknown_field_is_not_a_free_zero',
    'test_unknown_factor_survives_known_zero',
    'test_scope_cannot_reset_by_identity_upgrade_or_reorganization',
    'test_native_permutation_count_cannot_be_the_query_unit',
    'test_mass_and_reduction_overheads_are_independent_inputs',
    'test_numeric_inputs_need_explicit_unverified_references',
    'test_conditional_union_is_exact_and_does_not_require_independence',
    'test_marginal_or_accepted_only_error_bound_is_refused',
    'test_bound_domain_cannot_be_extrapolated_to_larger_lifetime_queries',
    'test_lifetime_reset_and_per_event_target_counterexamples',
    'test_exact_lottery_rounding_and_weight_cost_counterexample',
    'test_source_mutation_missing_source_and_symlink_are_refused',
    'test_source_lines_remain_independent_of_existing_qualification_labels',
    'test_nonexact_numbers_duplicate_json_and_qualification_injection_are_refused',
    'test_cli_rejects_malformed_input_without_emitting_a_report',
)}
PYTHON_SUITES = (
    'scripts/ci/test_pq_research_integration.py',
    'scripts/ci/test_ci_source_integrity.py',
    'scripts/ci/test_ci_contract.py',
    'scripts/ci/test_w1_factorial_native_gate.py',
    'scripts/ci/test_prepare_artifact_upload.py',
    'scripts/ci/test_cell_storage_convergence_ci.py',
    'scripts/ci/test_cell_discovery_v3_ci.py',
    'scripts/ci/test_fresh_rejection_report.py',
    'scripts/ci/test_w1_qrom_current_ci.py',
    'scripts/ci/test_pq_authority_effect_register.py',
    'scripts/ci/test_pq_lifetime_budget.py',
    'scripts/ci/test_w1_lifetime_ledger.py',
    'scripts/ci/test_w1_lifecycle_cost_v4.py',
)
NATIVE_LABELS = ('mvcc-library', 'evaluation-quorum-v2', 'cancel-exact', 'confirmation-four')
REGISTRY_SCHEMA = 'pon-upstream-union-validation-plan-v1'
MAX_OUTPUT = 64 * 1024 * 1024


class Refusal(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Refusal(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(Refusal('nonfinite JSON value')))


def read_regular(path):
    require(path.is_absolute() and path == path.resolve(), 'regular input path must be absolute and unaliased')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_OUTPUT, 'nonregular or oversized observation')
        with os.fdopen(descriptor, 'rb', closefd=False) as source:
            raw = source.read(MAX_OUTPUT + 1)
        after = os.fstat(descriptor)
        require(len(raw) == before.st_size and len(raw) <= MAX_OUTPUT
                and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'observation changed during read')
        return raw
    finally:
        os.close(descriptor)


def emit(path, value):
    raw = encoded(value)
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def native_observation(label, raw, code):
    """Preserve all child harness summaries; identify the final selected target."""
    summaries = [dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered'), map(int, row[1:])), outcome=row[0].decode())
                 for row in re.findall(rb'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', raw, re.M)]
    result = {'all_reported_harness_summaries': summaries, 'terminal_harness': summaries[-1] if summaries else None,
              'command_exit_code': code, 'successful_selected_target_observed': False}
    if code != 0:
        return result
    require(summaries and summaries[-1]['outcome'] == 'ok' and summaries[-1]['failed'] == 0
            and summaries[-1]['passed'] > 0 and summaries[-1]['measured'] == 0,
            'successful Cargo exit lacks a successful executed native target: ' + label)
    terminal = summaries[-1]
    expected = {'evaluation-quorum-v2': QUORUM_TESTS, 'cancel-exact': {CANCEL_TEST},
                'confirmation-four': CONFIRMATION_TESTS}.get(label)
    if expected is not None:
        rows = re.findall(rb'^test (\S+) \.\.\. (\S+)$', raw, re.M)
        selected = [(name.decode(), outcome.decode()) for name, outcome in rows if name.decode() in expected]
        require(terminal['passed'] == len(expected) and terminal['ignored'] == 0
                and len(selected) == len(expected) and {name for name, _ in selected} == expected
                and all(outcome == 'ok' for _, outcome in selected), 'exact native names/counts differ: ' + label)
        result['expected_names'] = sorted(expected)
        result['observed_selected_names'] = sorted(name for name, _ in selected)
    if label in ('mvcc-library', 'evaluation-quorum-v2'):
        require(terminal['filtered'] == 0, 'an unfiltered native target gained a harness filter: ' + label)
    result['successful_selected_target_observed'] = True
    return result


def evidence_union(ours, theirs, merged):
    retained = {}
    for origin, entries in (('first_parent', ours), ('second_parent', theirs)):
        for path, entry in entries.items():
            if not path.startswith('evidence/'):
                continue
            if path in retained:
                require(retained[path]['entry'] == entry, 'parents disagree on an original evidence path: ' + path)
                retained[path]['parents'].append(origin)
            else:
                retained[path] = {'entry': entry, 'parents': [origin]}
            require(merged.get(path) == entry, 'merged original evidence blob or mode differs: ' + path)
    require(retained, 'no original evidence was identified')
    return retained


def native_source_changes(ours, theirs, merged, retained):
    all_changes = sorted(path for path in ours.keys() | merged.keys()
                         if (path.endswith('.rs') or Path(path).name in ('Cargo.toml', 'Cargo.lock'))
                         and ours.get(path) != merged.get(path))
    archived = {}
    for path, oid in ARCHIVED_RUST.items():
        require(path in all_changes and path in retained
                and theirs.get(path, {}).get('kind') == 'blob' and theirs[path]['git_blob'] == oid
                and merged.get(path) == theirs[path] == retained[path]['entry'],
                'one of the three reviewed historical Rust archives differs: ' + path)
        archived[path] = {'entry': retained[path]['entry'], 'source_parent': UPSTREAM, 'native_execution_credit': False}
    # Only the three exact, independently retained historical paths are removed
    # from live-source classification. An unknown Rust/Cargo path is still seen,
    # including an unreviewed fourth .rs placed under evidence/.
    live = [path for path in all_changes if path not in ARCHIVED_RUST]
    return live, archived


def python_named_observation(label, raw, code):
    expected = {'test_w1_factorial_native_gate': CI_UNION_TESTS, 'test_w1_lifetime_ledger': LEDGER_TESTS}[label]
    text = raw.decode(errors='replace')
    rows = []
    for method, qualified, outcome in re.findall(r'^([A-Za-z0-9_]+) \(([^)\n]+)\)(?:\n[^\n]*)? \.\.\. ([^\n]+)$', text, re.M):
        parts = qualified.split('.')
        require(len(parts) >= 2 and parts[-1] == method, 'Python test identity differs: ' + label)
        rows.append({'name': '.'.join(parts[-2:]), 'outcome': outcome})
    summaries = [int(value) for value in re.findall(r'^Ran (\d+) tests? in [^\n]+$', text, re.M)]
    result = {'expected_names': sorted(expected), 'observed_tests': rows, 'reported_summary_counts': summaries,
              'command_exit_code': code, 'successful_named_suite_observed': False}
    if code != 0:
        return result
    require(summaries == [len(expected)] and len(rows) == len(expected)
            and {row['name'] for row in rows} == expected and all(row['outcome'] == 'ok' for row in rows)
            and re.search(r'^OK$', text, re.M), 'complete original Python named roster did not pass: ' + label)
    result['successful_named_suite_observed'] = True
    return result


def plan(root, out, head):
    py = ['python3', '-B']
    cargo = ['cargo', 'test', '--manifest-path', 'trillionnium/Cargo.toml', '--locked', '--offline']
    qrom = out / 'qrom-current'
    checks = [dict(label='locked-offline-graph', argv=['cargo', 'metadata', '--manifest-path', 'trillionnium/Cargo.toml',
                                                       '--locked', '--offline', '--format-version', '1'], timeout=1800),
              dict(label='rustc-version', argv=['rustc', '-Vv'], timeout=1800),
              dict(label='cargo-version', argv=['cargo', '-V'], timeout=1800)]
    for path in PYTHON_SUITES:
        checks.append(dict(label=Path(path).stem, argv=py + [path, '-v'],
                           timeout=3600 if path == 'scripts/ci/test_pq_research_integration.py' else 1800))
    extra = (
        ('corpus', py + ['scripts/ci/check_pq_research_integration.py']),
        ('ci-contract', py + ['scripts/ci/check_ci_contract.py']),
        ('qrom-current-named', py + ['scripts/ci/w1_qrom_current_ci.py', 'named', '--repo-root', str(root), '--out', str(qrom)]),
        ('qrom-historical-drift', py + ['scripts/ci/w1_qrom_current_ci.py', 'drift', '--repo-root', str(root), '--out', str(qrom)]),
        ('qrom-current-implementation', py + ['scripts/w1_qrom_current_implementation_audit.py', '--repo-root', str(root),
                                           '--output', str(qrom / 'implementation.json')]),
        ('authority-register', py + ['scripts/ci/pq_authority_effect_register.py']),
        ('pq128-lifetime', py + ['scripts/ci/pq_lifetime_budget.py']),
        ('w1-lifetime-report', py + ['scripts/w1_lifetime_ledger.py', '--input', LEDGER + '/project-input.json']),
        ('w1-lifetime-report-identical', ['cmp', str(out / 'w1-lifetime-report.stdout.log'), str(root / LEDGER / 'project-report.json')]),
        ('distributed-inventory', py + ['scripts/refresh_distributed_source_inventory.py', '--check']),
        ('repository-and-markdown-links', py + ['scripts/ci/check_repository.py']),
        ('source-diff-whitespace', ['git', 'diff', '--check', FIRST_PARENT, head, '--', '.', ':(exclude)evidence/**']),
        ('format', ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check']),
        ('mvcc-library', cargo + ['-p', 'trnm-mvcc-fee', '--lib', '--', '--test-threads=1']),
        ('evaluation-quorum-v2', cargo + ['-p', 'trnm-mvcc-fee', '--test', 'evaluation_quorum_v2', '--', '--test-threads=1']),
        ('cancel-exact', cargo + ['-p', 'trnm-pon-node', '--lib', CANCEL_TEST, '--', '--exact', '--test-threads=1']),
        ('confirmation-four', cargo + ['-p', 'trnm-pon-node', '--lib', 'confirmation_chainwork_tests', '--', '--test-threads=1']),
        ('four-owner-strict-clippy', ['cargo', 'clippy', '--manifest-path', 'trillionnium/Cargo.toml', '--locked', '--offline',
                                    '-p', 'trnm-mvcc-fee', '-p', 'trnm-pon-node', '-p', 'trnm-service-settlement',
                                    '-p', 'trnm-crypto-primitives', '--all-targets', '--', '-D', 'warnings']),
    )
    checks.extend(dict(label=label, argv=argv, timeout=3600 if label == 'corpus' else 1800) for label, argv in extra)
    require(len({row['label'] for row in checks}) == len(checks), 'duplicate selected command label')
    return {'schema': REGISTRY_SCHEMA, 'source': head, 'checks_already_passed': False, 'checks': checks,
            'native_full_suite_passed': False, 'full_node_suite_executed': False,
            'parent_test_results_reused': False, 'hosted_ci_observed_complete': False, 'security_status': 'HOLD'}


class Recorder:
    def __init__(self, args):
        self.args, self.owns_output = args, False
        self.root, self.out, self.target, self.merge_output = args.root, args.output, args.target, args.merge_output
        for path in (self.root, self.out.parent, self.target, self.merge_output):
            require(path.is_absolute() and path == path.resolve() and path.is_dir(), 'absolute existing unaliased directories required')
        require(self.out.is_absolute() and self.out == self.out.resolve() and not self.out.exists(), 'fresh absolute output directory required')
        require(not self.out.is_relative_to(self.root) and not self.target.is_relative_to(self.root)
                and not self.out.is_relative_to(self.target) and not self.target.is_relative_to(self.out)
                and not self.merge_output.is_relative_to(self.root) and not self.out.is_relative_to(self.merge_output)
                and not self.merge_output.is_relative_to(self.out), 'output/target/merge receipts overlap source or each other')
        require(all(re.fullmatch('[0-9a-f]{40}', value) for value in (args.head, args.first_parent, args.second_parent)), 'exact commit IDs required')
        require(args.first_parent == FIRST_PARENT and args.second_parent == UPSTREAM, 'unreviewed merge parents')
        for name in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR', 'GIT_OBJECT_DIRECTORY',
                     'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_CONFIG_COUNT'):
            require(not os.environ.get(name), 'external Git override refused: ' + name)
        self.env = dict(os.environ, CARGO_TERM_COLOR='never', CARGO_BUILD_JOBS='2', CARGO_TARGET_DIR=str(self.target),
                        CARGO_NET_OFFLINE='true', PYTHONDONTWRITEBYTECODE='1', GIT_NO_REPLACE_OBJECTS='1',
                        GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
        self.out.mkdir(mode=0o755)
        self.owns_output = True
        self.commands, self.source, self.expected_tree = [], None, None
        self.merge_summary_raw = None
        self.recorder_bytes = read_regular(Path(__file__).absolute())
        self.recorder_sha = sha(self.recorder_bytes)
        emit(self.out / 'commands.json', self.commands)

    def git(self, *argv):
        result = subprocess.run(['git', '--no-replace-objects', *argv], cwd=self.root, env=self.env,
                                capture_output=True, timeout=90, check=False)
        require(result.returncode == 0, 'Git read failed: ' + ' '.join(argv) + ': ' + result.stderr.decode(errors='replace')[-1000:])
        return result.stdout

    def text(self, *argv):
        return self.git(*argv).decode().strip()

    def commit(self, revision):
        raw = self.git('cat-file', 'commit', revision)
        require(hashlib.sha1(b'commit ' + str(len(raw)).encode() + b'\0' + raw, usedforsecurity=False).hexdigest() == revision,
                'actual commit object differs')
        header = raw.split(b'\n\n', 1)[0].splitlines()
        trees = [row[5:].decode() for row in header if row.startswith(b'tree ')]
        require(len(trees) == 1, 'commit has no unique tree')
        parents = [row[7:].decode() for row in header if row.startswith(b'parent ')]
        require(self.text('rev-list', '--parents', '-n', '1', revision).split() == [revision, *parents],
                'required parent object traversal was shallow-cut or differs')
        return {'commit': revision, 'tree': trees[0], 'parents': parents}

    def tree(self, revision):
        result = {}
        for row in self.git('ls-tree', '-r', '-z', revision).split(b'\0'):
            if row:
                metadata, path = row.split(b'\t', 1)
                mode, kind, oid = metadata.decode().split()
                result[path.decode()] = {'mode': mode, 'kind': kind, 'git_blob': oid}
        return result

    def guard(self):
        require(self.text('rev-parse', '--show-toplevel') == str(self.root), 'source root is not the real Git worktree')
        require(self.text('rev-parse', 'HEAD') == self.args.head, 'merge HEAD changed')
        require(not self.git('status', '--porcelain'), 'merge source is not clean')
        require(all(not row or row.startswith(b'H ') for row in self.git('ls-files', '-v', '-z').split(b'\0')),
                'nonordinary index flags or incomplete materialization')
        require(not self.git('ls-files', '--deleted', '-z'), 'tracked source file is missing')
        require(not self.git('ls-files', '--unmerged', '-z'), 'unmerged source index')
        if self.expected_tree is not None:
            require(self.text('write-tree') == self.expected_tree, 'index differs from the actual merge commit')
        require(read_regular(Path(__file__).absolute()) == self.recorder_bytes, 'recorder source changed')
        if self.merge_summary_raw is not None:
            require(read_regular(self.merge_output / 'summary.json') == self.merge_summary_raw, 'original merge source-only receipt changed')

    def status(self, stage, phase, code=None):
        emit(self.out / 'status.json', {'schema': 'pon-upstream-union-status-v1', 'stage': stage, 'phase': phase,
             'last_exit': code, 'source': self.args.head, 'recorded_unix_ns': time.time_ns(),
             'native_full_suite_passed': False, 'security_status': 'HOLD'})

    def provenance(self):
        self.status('source-provenance', 'running')
        self.guard()
        sparse = subprocess.run(['git', 'config', '--bool', 'core.sparseCheckout'], cwd=self.root, env=self.env, capture_output=True)
        require(sparse.returncode in (0, 1) and sparse.stdout.strip() in (b'', b'false'), 'sparse checkout refused')
        current, first, second = (self.commit(value) for value in (self.args.head, FIRST_PARENT, UPSTREAM))
        require(current['parents'] == [FIRST_PARENT, UPSTREAM], 'merge must have the exact two ordered parents')
        require(first['tree'] == FIRST_TREE and first['parents'] == [C2], 'first parent is not the actual failed C3')
        require(second['tree'] == UPSTREAM_TREE and second['parents'] == [UPSTREAM_FIRST], 'upstream source identity differs')
        require(self.commit(UPSTREAM_FIRST)['parents'] == [BASE], 'selected upstream parent chain differs')
        require(self.commit(C2)['tree'] == C2_TREE, 'selected C2 source tree differs')
        require(self.text('merge-base', FIRST_PARENT, UPSTREAM) == BASE, 'selected parents do not share the reviewed base')
        self.git('merge-base', '--is-ancestor', C2, FIRST_PARENT)
        self.expected_tree = current['tree']
        self.merge_summary_raw = read_regular(self.merge_output / 'summary.json')
        merge_summary = strict_json(self.merge_summary_raw)
        require(merge_summary.get('schema') == 'pon-reviewed-upstream-merge-v1'
                and merge_summary.get('merged_source') == self.args.head and merge_summary.get('merged_tree') == self.expected_tree
                and merge_summary.get('first_parent') == FIRST_PARENT and merge_summary.get('second_parent') == UPSTREAM
                and merge_summary.get('source_integration_complete') is True and merge_summary.get('source_binding_verified') is True
                and merge_summary.get('merged_required_checks_complete') is False and merge_summary.get('merged_native_tests_executed') is False
                and merge_summary.get('historical_c3_checks_passed') is False
                and merge_summary.get('historical_c2_full_node_suite_passed') is False
                and merge_summary.get('published') is False and merge_summary.get('open_consensus_qualified') is False
                and merge_summary.get('production_activation') is False and merge_summary.get('security_status') == 'HOLD',
                'actual source-only merge receipt is incomplete, differs or claims inherited test success')
        with (self.out / 'merge-source-only-summary.json').open('xb') as stream:
            stream.write(self.merge_summary_raw)
        ours, theirs, merged = (self.tree(value) for value in (FIRST_PARENT, UPSTREAM, self.args.head))
        retained = evidence_union(ours, theirs, merged)
        native_delta, archived_rust = native_source_changes(ours, theirs, merged, retained)
        require(set(native_delta) - {INVENTORY} == set(UPSTREAM_NATIVE), 'unreviewed native/Cargo source delta')
        require(merged.get(INVENTORY, {}).get('mode') == '100644'
                and merged[INVENTORY]['kind'] == 'blob', 'generated inventory was removed or changed type')
        for path, oid in UPSTREAM_NATIVE.items():
            expected = {'mode': '100644', 'kind': 'blob', 'git_blob': oid}
            require(theirs.get(path) == merged.get(path) == expected, 'upstream native bytes differ: ' + path)
        for path, oid in CI_UNION.items():
            require(merged.get(path) == {'mode': '100644', 'kind': 'blob', 'git_blob': oid}, 'reviewed CI union bytes differ: ' + path)
        require(merged.get(VERIFY) == ours.get(VERIFY) == self.tree(BASE).get(VERIFY), 'original source verifier changed')
        emit(self.out / 'retained-evidence.json', {'schema': 'pon-upstream-union-retained-evidence-v1',
             'source': self.args.head, 'first_parent': FIRST_PARENT, 'second_parent': UPSTREAM,
             'retained_paths': retained, 'retained_path_count': len(retained), 'all_entries_identical': True})
        revision, lock_path, expected_sha = HISTORICAL_LOCK
        historical = self.git('show', revision + ':' + lock_path)
        require(sha(historical) == expected_sha, 'actual historical Cargo.lock negative-control input differs')
        require(hashlib.sha1(b'blob ' + str(len(historical)).encode() + b'\0' + historical,
                            usedforsecurity=False).hexdigest() == HISTORICAL_LOCK_BLOB,
                'actual historical Cargo.lock Git object differs')
        history_shallow = self.text('rev-parse', '--is-shallow-repository')
        require(history_shallow in ('true', 'false'), 'unknown Git history depth')
        self.source = {'schema': 'pon-upstream-union-source-v1', 'recorder_sha256': self.recorder_sha,
             'merge': current, 'first_parent': first, 'second_parent': second, 'common_base': BASE,
             'first_parent_tests_inherited': False, 'second_parent_tests_inherited': False,
             'merge_receipt_source': str(self.merge_output / 'summary.json'),
             'merge_source_only_summary_sha256': sha(self.merge_summary_raw),
             'native_changed_from_first_parent': native_delta, 'reviewed_upstream_native_blobs': UPSTREAM_NATIVE,
             'historical_rust_archive_provenance': archived_rust,
             'reviewed_ci_union_blobs': CI_UNION, 'cargo_inputs_unchanged_from_first_parent': True,
             'retained_evidence_count': len(retained), 'original_evidence_blobs_and_modes_preserved': True,
             'historical_lock': {'revision': revision, 'path': lock_path, 'bytes': len(historical),
                                 'sha256': expected_sha, 'git_blob': HISTORICAL_LOCK_BLOB},
             'git_history_shallow': history_shallow == 'true', 'complete_global_history_claimed': False,
             'history_fetched_or_rewritten': False, 'source_mutations_performed': False,
             'explicit_environment': {name: self.env[name] for name in ('CARGO_TERM_COLOR', 'CARGO_BUILD_JOBS',
                 'CARGO_TARGET_DIR', 'CARGO_NET_OFFLINE', 'PYTHONDONTWRITEBYTECODE', 'GIT_NO_REPLACE_OBJECTS', 'GIT_NO_LAZY_FETCH')},
             'other_rust_environment': {name: self.env.get(name) for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'CARGO_INCREMENTAL')},
             'native_full_suite_passed': False, 'full_node_suite_executed': False, 'parent_test_results_reused': False,
             'open_consensus_qualified': False, 'production_activation': False, 'security_status': 'HOLD'}
        emit(self.out / 'source.json', self.source)
        self.guard()
        self.status('source-provenance', 'finished', 0)

    @staticmethod
    def stop_owned(process):
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)

    def run(self, label, argv, timeout=1800):
        require(re.fullmatch('[a-zA-Z0-9_-]+', label), 'unsafe command label')
        self.status(label, 'running')
        print('START', label, flush=True)
        start, process, error, timed_out, interrupted = time.time_ns(), None, None, False, False
        stdout, stderr = self.out / (label + '.stdout.log'), self.out / (label + '.stderr.log')
        with stdout.open('xb') as out, stderr.open('xb') as err:
            try:
                process = subprocess.Popen(argv, cwd=self.root, env=self.env, stdout=out, stderr=err, start_new_session=True)
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out, code = True, 124
                self.stop_owned(process)
            except (KeyboardInterrupt, InterruptedError) as exc:
                interrupted, code, error = True, 130, repr(exc)
                if process is not None:
                    self.stop_owned(process)
            except OSError as exc:
                code, error = 127, repr(exc)
        row = {'label': label, 'argv': argv, 'cwd': str(self.root), 'exit_code': code,
               'process_exit_code': process.returncode if process is not None else None,
               'start_unix_ns': start, 'end_unix_ns': time.time_ns(), 'timeout_seconds': timeout,
               'timed_out': timed_out, 'interrupted': interrupted, 'recorder_error': error}
        streams = {}
        for name, path in (('stdout', stdout), ('stderr', stderr)):
            raw = read_regular(path)
            streams[name] = raw
            row[name] = {'file': path.name, 'bytes': len(raw), 'sha256': sha(raw)}
        if label in NATIVE_LABELS:
            try:
                row['native_observation'] = native_observation(label, streams['stdout'], code)
            except Refusal as exc:
                row['observation_error'] = str(exc)
        if label in ('test_w1_factorial_native_gate', 'test_w1_lifetime_ledger'):
            try:
                row['python_named_observation'] = python_named_observation(label, streams['stderr'], code)
            except Refusal as exc:
                row['observation_error'] = str(exc)
        self.commands.append(row)
        emit(self.out / (label + '.command.json'), row)
        emit(self.out / 'commands.json', self.commands)
        self.status(label, 'finished' if code == 0 and not row.get('observation_error') else 'failed', code)
        print('END', label, code, flush=True)
        if interrupted:
            raise InterruptedError('selected command interrupted; original streams retained')
        return row

    def execute(self):
        self.provenance()
        schedule = plan(self.root, self.out, self.args.head)
        emit(self.out / 'planned-checks.json', schedule)
        (self.out / 'qrom-current').mkdir()
        verifier = ['python3', '-B', VERIFY, '--kind', 'head', '--expected-head', self.args.head, '--output']
        complete, failure = False, None
        try:
            require(self.run('preflight', ['bash', 'scripts/project-preflight.sh'])['exit_code'] == 0, 'actual project preflight failed')
            require(self.run('source-before', verifier + [str(self.out / 'source-before.json')])['exit_code'] == 0,
                    'actual merge source-before verification failed')
            for command in schedule['checks']:
                self.guard()
                self.run(command['label'], command['argv'], command['timeout'])
            complete = True
        except (Refusal, OSError, ValueError, subprocess.SubprocessError, InterruptedError) as exc:
            failure = str(exc)
        finally:
            # A failed selected test is never hidden by omitting the final source
            # observation. Neither this verifier nor cmp changes the checkout.
            self.run('source-after', verifier + [str(self.out / 'source-after.json')])
            self.run('source-identical', ['cmp', str(self.out / 'source-before.json'), str(self.out / 'source-after.json')])
        bracket = False
        try:
            self.guard()
            before = read_regular(self.out / 'source-before.json')
            after = read_regular(self.out / 'source-after.json')
            value = strict_json(before)
            require(before == after and value.get('schema') == 'trnm-ci-source-v1' and value.get('kind') == 'head'
                    and value.get('candidate') == value.get('tested_commit') == self.args.head
                    and value.get('tested_tree') == self.expected_tree and value.get('tracked_worktree_verified') is True
                    and value.get('tests_executed_by_identity_check') is False, 'actual merge source bracket differs')
            retained = strict_json(read_regular(self.out / 'retained-evidence.json'))
            actual = self.tree(self.args.head)
            require(all(actual.get(path) == item['entry'] for path, item in retained['retained_paths'].items()),
                    'original evidence changed after checks')
            bracket = True
        except (Refusal, OSError, ValueError, subprocess.SubprocessError) as exc:
            failure = str(exc) if failure is None else failure + '; final guard: ' + str(exc)
        expected = ['preflight', 'source-before', *[row['label'] for row in schedule['checks']], 'source-after', 'source-identical']
        observation_complete = complete and bracket and [row['label'] for row in self.commands] == expected
        failures = [{'label': row['label'], 'exit_code': row['exit_code'], 'timed_out': row['timed_out'],
                     'observation_error': row.get('observation_error')}
                    for row in self.commands if row['exit_code'] != 0 or row.get('observation_error')]
        passed = observation_complete and not failures and failure is None
        result = {'schema': 'pon-upstream-union-observations-v1', 'source': self.args.head, 'tree': self.expected_tree,
             'parents': [FIRST_PARENT, UPSTREAM], 'recorder_sha256': self.recorder_sha,
             'observation_complete': observation_complete, 'all_required_checks_passed': passed,
             'source_bracket_identical': bracket, 'original_evidence_blobs_and_modes_preserved': bracket,
             'commands': len(self.commands), 'planned_commands': len(expected), 'failed_commands': failures,
             'native_targeted_results': {row['label']: row.get('native_observation') for row in self.commands if row['label'] in NATIVE_LABELS},
             'python_named_results': {row['label']: row.get('python_named_observation') for row in self.commands
                                      if row['label'] in ('test_w1_factorial_native_gate', 'test_w1_lifetime_ledger')},
             'merge_source_only_summary_sha256': sha(self.merge_summary_raw),
             'full_node_suite_executed': False, 'full_node_suite_passed': False, 'native_full_suite_passed': False,
             'prior_c2_full_node_failure_retained': {'source': C2, 'exit_code': 101, 'passed': 1285, 'failed': 2, 'ignored': 39},
             'first_parent_test_results_reused': False, 'second_parent_test_results_reused': False,
             'original_c3_failed_observation_rewritten': False, 'source_mutations_performed': False,
             'history_fetched_or_rewritten': False, 'published': False, 'hosted_ci_observed_complete': False,
             'draft_only': True, 'open_consensus_qualified': False, 'production_activation': False,
             'failure_reason': failure, 'security_status': 'HOLD'}
        emit(self.out / 'summary.json', result)
        if not passed:
            emit(self.out / 'failure.json', {'schema': 'pon-upstream-union-failure-v1', 'reason': failure or 'actual selected command failures',
                 'failed_commands': failures, 'observation_complete': observation_complete, 'no_automatic_rollback': True,
                 'source': self.args.head, 'native_full_suite_passed': False, 'security_status': 'HOLD'})
        self.status('complete-observation', 'finished' if passed else 'checks-failed', 0 if passed else 2)
        print(json.dumps(result, sort_keys=True), flush=True)
        return 0 if passed else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--head', required=True, help='actual committed merge HEAD, never an uncommitted staged tree')
    parser.add_argument('--first-parent', required=True, help='actual failed C3 a715b2c8...')
    parser.add_argument('--second-parent', required=True, help='reviewed upstream df927b6f...')
    parser.add_argument('--output', type=Path, required=True, help='fresh external observation directory; never overwrite a prior attempt')
    parser.add_argument('--target', type=Path, required=True, help='existing external Cargo target directory')
    parser.add_argument('--merge-output', type=Path, required=True, help='completed source-only merge recorder output; no inherited tests')
    args = parser.parse_args()
    owner = None
    def interrupted(signum, frame):
        raise InterruptedError('recorder received signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        owner = Recorder.__new__(Recorder)
        owner.__init__(args)
        return owner.execute()
    except (Refusal, OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError, InterruptedError) as exc:
        failure = {'schema': 'pon-upstream-union-refusal-v1', 'reason': str(exc), 'source': args.head,
                   'observation_complete': False, 'all_required_checks_passed': False,
                   'no_automatic_rollback': True, 'native_full_suite_passed': False,
                   'published': False, 'production_activation': False, 'security_status': 'HOLD'}
        if owner is not None and getattr(owner, 'owns_output', False):
            emit(owner.out / 'failure.json', failure)
            owner.status('recorder', 'failed', 2)
        print(json.dumps(failure, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
