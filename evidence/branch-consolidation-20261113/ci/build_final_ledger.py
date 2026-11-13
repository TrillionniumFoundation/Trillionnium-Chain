"""Assemble reviewed decisions and exact cached input receipts; no Git mutation."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil

parser = argparse.ArgumentParser()
parser.add_argument('--source-checkpoint', required=True)
args = parser.parse_args()
assert len(args.source_checkpoint) == 40 and all(c in '0123456789abcdef' for c in args.source_checkpoint)
base = Path('/workspace/scratch/415d5ba2202d')
audit = base / 'ci-audit'
review = audit / 'branch-review'
repo = base / 'ci-fixes'
out = repo / 'evidence/branch-consolidation-20261113/ci'
out.mkdir(parents=True, exist_ok=True)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def read(path):
    return json.loads(path.read_text())

inputs = {}
rows = []
for name in ('workflow_and_archive-branch-review.json', 'pq-source-branch-review.json',
             'root-extra-ci-review.json'):
    path = base / name
    raw = path.read_bytes()
    entries = json.loads(raw)
    inputs[name] = {'sha256': digest(raw), 'bytes': len(raw), 'tips': len(entries)}
    (out / name).write_bytes(raw)
    for row in entries:
        rows.append({**row, 'worklist': name})
assert len(rows) == len({row['sha'] for row in rows}) == 103
legacy = read(audit / 'legacy-workflows/dispositions.json')
legacy_by_head = {row['head']: row for row in legacy['items']}
decisions = {}
for name in ('decisions-workflow.json', 'decisions-pq.json', 'decisions-extra-ci.json'):
    values = read(review / name)
    assert not set(values) & set(decisions)
    decisions.update(values)
assert len(decisions) == 64
detail_by_head = {row['sha']: row for row in read(review / 'review-inputs.json')}
items = []
missing_anchors = []
for row in rows:
    head = row['sha']
    if head in legacy_by_head:
        old = legacy_by_head[head]
        decision = {
            'decision': 'HISTORICAL_WORKFLOW_ONLY',
            'reason': old['reason'],
            'legacy_category': old['category'],
            'workflow_review': old,
            'selected_anchors': [],
        }
    else:
        assert head[:10] in decisions, head
        decision = decisions[head[:10]].copy()
        decision['integration_commits'] = [
            args.source_checkpoint if value == 'OUTBOUND_CHECKPOINT' else value
            for value in decision.get('integration_commits', [])]
    for anchor in decision.get('selected_anchors', []):
        if not (repo / anchor).exists() and not (base / 'Trillionnium-Chain' / anchor).exists():
            missing_anchors.append({'head': head, 'anchor': anchor})
    detail = detail_by_head.get(head, {})
    items.append({
        'branch': row['name'], 'head': head,
        'source_url': 'https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/' + head,
        'worklist': row['worklist'], 'merge_base': row.get('merge_base'),
        'unique_commits': row.get('unique_commits'),
        'core_paths_reviewed': row.get('core_paths', []),
        'cached_core_diff_sha256': detail.get('core_diff_sha256'),
        'cached_core_diff_bytes': detail.get('core_diff_bytes'),
        **decision,
        'legacy_workflow_executed': False,
        'remote_mutation_performed': False,
    })
if missing_anchors:
    (review / 'missing-selected-anchors.json').write_text(json.dumps(missing_anchors, indent=2) + '\n')
    raise SystemExit('Resolve selected anchors before final ledger: ' + str(len(missing_anchors)))

ledger = {
    'schema': 'trnm-ci-pq-branch-consolidation-review-v1',
    'date': '2026-11-13',
    'selected_source_review_base': 'e531765329ef1eb3698222e8ab0fb4d141197c63',
    'ci_agent_source_checkpoint': args.source_checkpoint,
    'source_checkpoint_is_final_composed_source': False,
    'canonical_publication_verified_by_this_ledger': False,
    'input_worklists': inputs,
    'tips_reviewed': 103,
    'legacy_tips_with_exact_workflow_review': 39,
    'additional_tips_with_core_diff_review': 64,
    'decision_counts': dict(sorted(Counter(item['decision'] for item in items).items())),
    'legacy_workflows_executed': False,
    'remote_mutations': False,
    'whole_repository_security_qualified': False,
    'ancestry_verification_owned_by_root': True,
    'ancestry_verified_by_this_ledger': False,
    'source_checkpoint_command_receipts': 'final-source-checks.json',
    'source_commit_receipt': 'final-source-commit.json',
    'interrupted_writer_receipt': 'cancelled-writer-29600-receipt.json',
    'scope': ('Semantic disposition of assigned source families, compatible ports, '
              'selected successors, and explicitly retained alternatives. A declaration '
              'or path match alone is not treated as behavioral equivalence. Historical '
              'source and failed observations keep their original identities. This '
              'ledger does not certify native execution of the final composed source.'),
    'items': items,
}
(out / 'ledger.json').write_text(json.dumps(ledger, indent=2, ensure_ascii=False) + '\n')

copies = {
    'legacy-workflow-dispositions.json': audit / 'legacy-workflows/dispositions.json',
    'legacy-workflow-review.md': audit / 'legacy-workflows/workflow-disposition-report.md',
    'additional-tip-source-inventory.json': review / 'review-inputs.json',
    'static-source-coverage-e531.json': review / 'source-coverage-e531.json',
    'extended-workflow-inventory.json': audit / 'extended-workflows/inventory.json',
    'archive-preservation-e531.json': review / 'archive-preservation-e531.json',
    'current-four-workflow-paths.json': audit / 'extended-workflows/current-four-path-check.json',
    'FINAL_REBINDING.md': review / 'FINAL_REBINDING.md',
    'plan_source_rebindings.py': review / 'plan_source_rebindings.py',
    'build_final_ledger.py': review / 'build_final_ledger.py',
    'decisions-workflow.json': review / 'decisions-workflow.json',
    'decisions-pq.json': review / 'decisions-pq.json',
    'decisions-extra-ci.json': review / 'decisions-extra-ci.json',
    'final-source-checks.json': audit / 'final-source-checks.json',
    'final-source-commit.json': audit / 'final-source-commit.json',
    'cancelled-writer-29600-receipt.json': audit / 'cancelled-writer-29600-receipt.json',
    'cancelled-writer-29600-index-lock.bin': audit / 'cancelled-writer-29600-index.lock',
    'final-evidence-ast.json': audit / 'final-evidence-ast.json',
}
retained = []
for name, source in copies.items():
    if not source.is_file():
        alternate = review / source.parent.name / source.name
        if alternate.is_file():
            source = alternate
    if not source.is_file():
        continue
    raw = source.read_bytes()
    (out / name).write_bytes(raw)
    retained.append({'path': name, 'sha256': digest(raw), 'bytes': len(raw)})

remote = audit / 'remote-current'
if remote.is_dir():
    destination = out / 'remote-current'
    destination.mkdir(exist_ok=True)
    for source in sorted(remote.iterdir()):
        if source.is_file() and source.suffix in ('.log', '.json'):
            raw = source.read_bytes()
            (destination / source.name).write_bytes(raw)
            retained.append({'path': 'remote-current/' + source.name,
                             'sha256': digest(raw), 'bytes': len(raw)})

attributes = repo / '.gitattributes'
text = attributes.read_text()
rules = ['/evidence/branch-consolidation-20261113/ci/logs/*.log -text -whitespace',
         '/evidence/branch-consolidation-20261113/ci/remote-current/*.log -text -whitespace']
missing = [rule for rule in rules if rule not in text.splitlines()]
if missing:
    attributes.write_text(text + '\n# Preserve exact consolidation command and Actions logs.\n'
                          + '\n'.join(missing) + '\n')

log_names = (
    'research-evidence-reader-validation.log', 'research-material-after-fixture.log',
    'research-evidence-ci-controls.log', 'research-evidence-ci-after-drift.log',
    'research-evidence-ci-complete-literals.log', 'exit-mm-v5-validation.log',
    'exit-mm-v5-registered-plan.log', 'exit-mm-v5-ci-controls.log',
    '550-compatible-controls.log', '550-attempt-journal-restored.log',
    '550-useful-cell-restored.log', '550-w1-observer-restored.log', '550-ci-controls.log',
    'outbound-native-preliminary.log', 'outbound-native-after-context-fix.log',
    'outbound-rustfmt-initial.log', 'outbound-roster-tests.log',
    'outbound-roster-final.log', 'outbound-ci-controls.log', 'outbound-doctest.log',
    'reference-call-boundary.log',
    'final-source-preflight.log', 'final-source-ci-contracts.log',
    'final-source-native-rosters.log', 'final-source-rustfmt.log',
    'final-source-diff-check.log', 'final-source-commit.log',
    'final-evidence-preflight.log',
)
(out / 'logs').mkdir(exist_ok=True)
logs = []
for name in log_names:
    source = audit / name
    if not source.is_file():
        continue
    raw = source.read_bytes()
    (out / 'logs' / name).write_bytes(raw)
    text = raw.decode(errors='replace')
    # This labels transcript completeness only; command exit codes and selected
    # native source qualification are never inferred from a generic 'ok' word.
    outcome = ('FAILURE_RETAINED' if 'FAILED (' in text or 'error: could not compile' in text
               else 'TERMINAL_TEST_SUMMARY_PRESENT' if '\nOK\n' in text or 'test result: ok.' in text
               else 'NO_TEST_COMPLETION_ESTABLISHED')
    logs.append({'path': 'logs/' + name, 'sha256': digest(raw), 'bytes': len(raw),
                 'transcript_state': outcome})
(out / 'retained-files.json').write_text(json.dumps({'files': retained, 'logs': logs}, indent=2) + '\n')

lines = [
    '# CI and PQ branch consolidation review', '',
    'Status: **HOLD for final composed-source qualification**. This records 103 assigned tips,',
    'including 39 detailed legacy-workflow reviews and 64 additional source-family reviews.',
    'The exact input worklists, original heads, merge bases, core paths and decisions are in',
    '[ledger.json](ledger.json). Source declaration matches are supporting inventory only;',
    'they are not used as a substitute for semantic decisions.', '',
    '## Compatible integration', '',
    'The selected ports retain full-name CI assertions, read-only CodeQL permissions,',
    'declared-control/local-material/WAN readers, an always-HOLD P0–P6 reader, the declared',
    'admission-cost model, explicit V5 exit-mm observations, complete legal reference-search',
    'journals, read-only anchored trial reconciliation, explicit V4 recovery handoff, and',
    'the create-only durable PQ outbound journal with sealed reply authority. Existing',
    'consensus, cancellation, release, public-submit recovery and current signed domains',
    'remain owned by their selected implementations. Cross-owned TLS and History ports',
    'are identified by their actual integration commits in the ledger.', '',
    '## Historical alternatives', '',
    'Old source publishers, blob stagers, toolchain exporters, destructive maintenance,',
    'self-hosted relay recovery and frozen campaign readbacks remain historical. No such',
    'workflow was dispatched or reactivated. Alternate initial-root optimizations, Rust1.99',
    'qualification, frozen W1 continuation/succinct profiles, old Node PQ codecs and old',
    'global reservation accounting are explicit alternatives, not falsely claimed as',
    'implemented equivalents. The root integrator verifies their original Git ancestry.', '',
    '## Validation limits that remain visible', '',
    '- Original CI drift, native compile failures, sparse-material failures and local host',
    '  ownership refusals are retained with their exact log bytes.',
    '- Native outbound9/9 passed on unchanged source bytes using local OpenSSL3.5.7.',
    '  Hosted pinned3.5.9 and the final composed-source gate remain independently required.',
    '- The preliminary outbound doctest was not observed complete and is not counted PASS.',
    '- After host recovery, 16 scoped CI contract tests and three outbound roster tests',
    '  passed; Rust1.95 formatting and diff checks also passed. No new native build was run.',
    '- The interrupted source writer and two readers returned exit130. Their original',
    '  stale zero-byte index lock was retained before the reviewed source commit resumed.',
    '- Two actual nonroot installed-ELF handoff controls fail because this container lacks',
    '  root-owned /usr ancestors. Neither the ownership rule nor required controls changed.',
    '- Original30s source replay could time out under the shared-host load. No deadline',
    '  was extended to turn a resource-limited run into qualification.',
    '- Current source registers and corpus pins must be rebound only after composition;',
    '  original frozen artifact, source, run and failure identities must remain immutable.', '',
    '## Per-tip disposition', '',
    '| Original head | Branch | Decision |',
    '| --- | --- | --- |',
]
for item in items:
    lines.append('| [' + item['head'][:10] + '](' + item['source_url'] + ') | `'
                 + item['branch'] + '` | ' + item['decision'] + ' |')
(out / 'README.md').write_text('\n'.join(lines) + '\n')
print(json.dumps({'result': 'WRITTEN', 'tips': len(items), 'destination': str(out),
                  'retained_logs': len(logs), 'counts': ledger['decision_counts']}))
