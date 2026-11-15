#!/usr/bin/env python3
"""Seal actual r8 backend observations; update only enumerated reviewed source pins."""
from pathlib import Path
import copy
import difflib
import hashlib
import json
import shutil
import subprocess

ROOT = Path('/workspace/scratch/56818e4fba76/chain-recovered')
RAW = Path(__file__).resolve().parent
OUT = ROOT / 'evidence/pon-pq-backend-contract-20261028-r8'
OUT.mkdir(exist_ok=False)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def save(name, data):
    (OUT / name).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


for name in ('pq-backend-controls', 'pq-m06-bounded-native', 'pq-reference-bounded-real'):
    shutil.copytree(RAW / name, OUT / name)
shutil.copytree('/tmp/chain-pq-helper-fix-r8', OUT / 'provider-alias-review')
for name in ('run_pq_m06_fixture_r8.py', 'run_pq_reference_r8.py'):
    shutil.copy2(RAW / name, OUT / name)

manifest_path = ROOT / 'config/pon/pq-cross-branch-corpus-v1.json'
before_bytes = manifest_path.read_bytes()
before = json.loads(before_bytes)
after = copy.deepcopy(before)
inherited = {
    'docs/security/PQ_NATIVE_ACCOUNT_OWNER_V1.md': 'Preserve the earlier unqualified-e642 observation; new r8 runtime records are separate.',
    'trillionnium/crates/trnm-pon-node/Cargo.toml': 'Existing rusqlite hooks feature for bounded paid reorg termination; no dependency/version removal.',
    'trillionnium/crates/trnm-pon-node/src/ingress.rs': 'Existing detached M06 admission, exact pending activation retry, typed cancellation and original budget owner.',
    'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs': 'Existing r14 signed resource commitment and same-account termination checkpoint; original resource numbers remain.',
    'trillionnium/crates/trnm-pon-node/src/store.rs': 'Existing single-use detached state/fence and reorg_lifecycle_v1 schema; full PQ/default-profile migration remains unaccepted.',
    'trillionnium/crates/trnm-pon-node/src/store/authenticated_migration/growth_rehearsal.rs': 'Existing Node initializer fields for detached capacity and test-only activation cut.',
}
changed = {
    'formal/pon-nakamoto-v1/' + name for name in (
        'pq_envelope.py', 'pq_genesis_handoff.py', 'pq_pql4_signed_frontier.py',
        'pq_pql5_quorum.py', 'pq_pql6_equivocation.py',
        'test_pq_cell_swarm_deadline.py', 'test_pq_envelope.py',
        'test_pq_genesis_handoff.py', 'test_pq_pql4_signed_frontier.py',
        'test_pq_pql5_quorum.py', 'test_pq_pql6_equivocation.py',
    )
}
added = ['formal/pon-nakamoto-v1/pq_openssl_backend.py',
         'formal/pon-nakamoto-v1/test_pq_openssl_backend.py']
rows = []
(OUT / 'source-pin-deltas').mkdir()
for path, old in before['pinned_blobs'].items():
    data = (ROOT / path).read_bytes()
    new = blob(data)
    if old == new:
        continue
    assert path in inherited or path in changed, ('unreviewed pin delta', path)
    old_data = subprocess.check_output(['git', 'show', old], cwd=ROOT)
    assert blob(old_data) == old
    prior = subprocess.check_output(['git', 'show', '189ba3adfd9a22c7cfc1537eab535e9eb7c442df:' + path], cwd=ROOT)
    if path in inherited:
        assert prior == data, ('inherited path changed during r8', path)
    delta = ''.join(difflib.unified_diff(old_data.decode().splitlines(True),
                                       data.decode().splitlines(True), fromfile=old, tofile=path))
    diff_path = 'source-pin-deltas/' + str(len(rows)).zfill(2) + '.diff'
    (OUT / diff_path).write_text(delta)
    rows.append({'path': path, 'old_git_blob': old, 'new_git_blob': new,
                 'old_sha256': sha(old_data), 'new_sha256': sha(data), 'diff': diff_path,
                 'unchanged_from_published_189': prior == data,
                 'review_scope': inherited.get(path, 'Explicit pinned CLI/provider and unchanged protocol/test assertions; actual r8 runtime recorded separately.')})
    after['pinned_blobs'][path] = new
assert len(rows) == len(inherited) + len(changed), rows
for path in added:
    assert path not in after['pinned_blobs'] and path not in after['required_paths']
    after['pinned_blobs'][path] = blob((ROOT / path).read_bytes())
    after['required_paths'].append(path)
after['pinned_blobs'] = dict(sorted(after['pinned_blobs'].items()))
after['required_paths'].sort()
assert {k:v for k,v in before.items() if k not in ('required_paths','pinned_blobs')} == {
    k:v for k,v in after.items() if k not in ('required_paths','pinned_blobs')}
manifest_path.write_text(json.dumps(after, indent=2) + '\n')
save('source-pin-review.json', {
    'schema': 'pon-r8-pq-source-pin-review-v1', 'base_commit': '189ba3adfd9a22c7cfc1537eab535e9eb7c442df',
    'before_manifest_sha256': sha(before_bytes), 'after_manifest_sha256': sha(manifest_path.read_bytes()),
    'updated_existing_pins': rows, 'added_required_pins': {p: after['pinned_blobs'][p] for p in added},
    'original_required_paths_retained': True, 'activation_flags_and_native_contracts_unchanged': True,
    'source_binding_is_runtime_acceptance': False})

runtime = {}
for name in ('pq-m06-bounded-native', 'pq-reference-bounded-real'):
    receipt = json.loads((OUT/name/'result.json').read_text())
    assert receipt['returncode'] == 0 and receipt['source_unchanged'] and not receipt['interrupted']
    for leaf, expected in receipt['logs'].items():
        data = (OUT/name/leaf).read_bytes()
        assert len(data) == expected['bytes'] and sha(data) == expected['sha256']
    runtime[name] = receipt
save('readback.json', {
    'schema': 'pon-r8-pq-backend-readback-v1',
    'scope': 'Original offline synthetic fixtures and real protocol reference tests; dirty source digests are retained.',
    'm06_tests': {'passed':8,'failed':0,'ignored':0},
    'reference_tests': {'passed':72,'failed':0,'skipped':0,'suites':{'genesis':23,'envelope':9,'pql4':12,'pql5':18,'pql6':10}},
    'backend_controls': {'final_passed':13,'provider_alias_refusal_cases':48,'original_pre_review_passed':12},
    'provider_ci_controls':9,'host_environment_controls':20,'child_budget_controls':2,
    'runtime_receipts_and_raw_log_digests_verified':True,
    'same_openssl_implementation_in_rust_and_python':True,
    'independent_cryptographic_implementation_claim':False,
    'complete_authorization_migration':False,'whole_chain_quantum_security':False,
    'hosted_candidate_qualification':False,'production_activation':False})
shutil.copy2(__file__, OUT / Path(__file__).name)
print(json.dumps({'out':str(OUT),'updated_pins':len(rows),'new_pins':len(added)}))
