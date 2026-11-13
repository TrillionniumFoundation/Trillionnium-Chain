#!/usr/bin/env python3
"""Fail-closed evidence-gate and heuristic source inventory for PQ claims.

This is an evidence-completeness validator, NOT cryptographic verification or an
independent certification. Works with Python >=3.10 and the standard library.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

EXCLUDED_DIRS = {'.git', 'target', 'node_modules', '.venv', 'venv', 'dist', 'build', '__pycache__'}
SOURCE_SUFFIXES = {'.rs', '.go', '.ts', '.tsx', '.js', '.sol', '.c', '.h', '.cc', '.cpp', '.hpp', '.proto'}
CLASSIC_RE = re.compile(r'(?i)(?<![a-z0-9])(?:ed25519|ecdsa|secp256k1|secp256r1|p256|schnorr|rsa(?:_pss)?|groth16|bn254)(?![a-z0-9])')
AUTH_RE = re.compile(r'(?i)\b(?:verify|verification|authorize|authorization|admission|handoff|governance|provider|identity|nonce|signer|signature|recovery|upgrade|validator|finality|consensus|transaction|account|authenticate)\b')
CRITICAL_ROUTES = ('transaction', 'account-rotation', 'task-auth', 'node-ingress', 'hepta-handoff',
                   'provider-discovery', 'model-release', 'task-evaluation', 'reward-settlement',
                   'signer-registration', 'emergency-upgrade', 'validator-finality',
                   'governance-upgrade', 'recovery', 'cross-chain')
ACCEPTED_MODES = {'pq-only', 'hybrid-and', 'inactive'}
VALID_SHA = re.compile(r'^[a-fA-F0-9]{40}$')


def load_json(path: Path):
    with path.open('r', encoding='utf-8') as f:
        return json.load(f)


def report_check(checks, name, ok, description, severity='BLOCKER'):
    checks.append({'id': name, 'status': 'PASS' if ok else severity, 'description': description})


def inside_repo(repo: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError('artifact path must be nonempty and relative')
    p = (repo / relative).resolve()
    if not p.is_relative_to(repo.resolve()):
        raise ValueError('artifact escapes repository root')
    return p


def check_artifacts(repo: Path, references, artifacts, checks, label: str) -> bool:
    if not isinstance(references, list) or not references:
        report_check(checks, label, False, 'no artifact identifiers declared')
        return False
    seen = set()
    valid = True
    for ident in references:
        if not isinstance(ident, str) or ident in seen:
            report_check(checks, label, False, 'invalid or repeated artifact identifier')
            valid = False
            continue
        seen.add(ident)
        entry = artifacts.get(ident) if isinstance(artifacts, dict) else None
        if not isinstance(entry, dict):
            report_check(checks, label + ':' + ident, False, 'missing artifact metadata')
            valid = False
            continue
        try:
            path = inside_repo(repo, entry['path'])
            digest = entry['sha256']
            if not re.fullmatch(r'[a-fA-F0-9]{64}', digest):
                raise ValueError('invalid SHA-256')
            if not path.is_file() or path.stat().st_size > 50_000_000:
                raise ValueError('artifact missing or exceeds 50 MB limit')
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != digest.lower():
                raise ValueError('artifact digest mismatch')
            report_check(checks, label + ':' + ident, True, 'artifact SHA-256 matched: ' + entry['path'])
        except (ValueError, KeyError, OSError, TypeError) as exc:
            report_check(checks, label + ':' + ident, False, str(exc))
            valid = False
    return valid


def git_revision(repo: Path):
    try:
        sha = subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'], capture_output=True,
                             text=True, timeout=10, check=True).stdout.strip()
        dirty = subprocess.run(['git', '-C', str(repo), 'status', '--porcelain', '--untracked-files=all'],
                               capture_output=True, text=True, timeout=10, check=True).stdout.strip()
        return sha, bool(dirty)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None, None


def scan_source(repo: Path, limit=1500):
    """Review leads only: classic signature presence does NOT prove live authority."""
    hits = []
    files_examined = 0
    for folder, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS and not (Path(folder) / d).is_symlink())
        for filename in sorted(files):
            p = Path(folder) / filename
            if p.suffix.lower() not in SOURCE_SUFFIXES or p.is_symlink():
                continue
            try:
                if p.stat().st_size > 3_000_000:
                    continue
                files_examined += 1
                rel = p.relative_to(repo).as_posix()
                with p.open('r', encoding='utf-8', errors='replace') as f:
                    for ln, line in enumerate(f, 1):
                        pattern = CLASSIC_RE.search(line)
                        if pattern:
                            fingerprint = hashlib.sha256((rel + '\0' + str(ln) + '\0' + line.rstrip('\n')).encode('utf-8')).hexdigest()[:24]
                            hits.append({'fingerprint': fingerprint, 'path': rel, 'line': ln, 'algorithm': pattern.group(0),
                                         'authority_hint_on_line': bool(AUTH_RE.search(line)),
                                         'excerpt': line.strip()[:220], 'review_status': 'UNREVIEWED'})
                            if len(hits) >= limit:
                                return {'files_examined': files_examined, 'truncated': True, 'hits': hits}
            except (UnicodeError, OSError):
                continue
    return {'files_examined': files_examined, 'truncated': False, 'hits': hits}


def check_authority(policy, evidence, repo, artifacts, checks):
    inventory = evidence.get('inventory', {})
    report_check(checks, 'authority:inventory-reviewed', inventory.get('entrypoints_enumerated') is True,
                 'all live authorization entrypoints must be enumerated and reviewed')
    check_artifacts(repo, inventory.get('artifacts'), artifacts, checks, 'authority:inventory-evidence')
    routes = evidence.get('routes', {})
    policy_routes = policy.get('critical_routes', [])
    config_ids = [x.get('id') for x in policy_routes if isinstance(x, dict)]
    report_check(checks, 'authority:critical-route-coverage',
                 len(config_ids) == len(set(config_ids)) and set(CRITICAL_ROUTES).issubset(set(config_ids)),
                 'policy must include every predefined critical route, without duplicate IDs')
    for route in policy_routes:
        rid = route.get('id', 'unknown')
        record = routes.get(rid, {}) if isinstance(routes, dict) else {}
        mode = record.get('mode', 'unknown')
        report_check(checks, f'authority:{rid}:mode', mode in ACCEPTED_MODES,
                     'allowed only pq-only, hybrid-and, or proven inactive; hybrid-or and unknown are forbidden')
        fields = ('role_and_chain_bound', 'nonce_replay_rejected', 'signature_stripping_rejected',
                  'epoch_and_version_bound', 'rollback_rejected', 'classical_only_rejected')
        if mode != 'inactive':
            for field in fields:
                report_check(checks, f'authority:{rid}:{field}', record.get(field) is True,
                             'required negative-test evidence for active authority')
        else:
            report_check(checks, f'authority:{rid}:non-authoritative',
                         record.get('no_live_authority') is True,
                         'inactive or historical formats must not grant live authority')
        check_artifacts(repo, record.get('artifacts'), artifacts, checks, f'authority:{rid}:evidence')
    ownership = evidence.get('migration', {})
    for field in ('pq_owner_bound_before_classic_break', 'no_classical_fallback_post_cutover',
                  'key_rotation_and_reorg_tested', 'unknown_algorithm_rejected'):
        report_check(checks, 'migration:' + field, ownership.get(field) is True,
                     'fail-closed migration or cutover requirement')
    check_artifacts(repo, ownership.get('artifacts'), artifacts, checks, 'migration:evidence')


def check_proof(policy, evidence, repo, artifacts, checks):
    cfg = policy.get('proof', {})
    manifest_rel = cfg.get('candidate_manifest_path', '')
    try:
        manifest = load_json(inside_repo(repo, manifest_rel))
        qualified = manifest.get('pq_128_security_qualified') is True
        activated = manifest.get('production_consensus_activation') is True
        report_check(checks, 'w1-candidate:manifest-pq128', qualified,
                     'candidate W1 manifest: not qualified for PQ-128 activation', 'WARNING')
        report_check(checks, 'w1-candidate:activation-safe', not (activated and not qualified),
                     'unqualified W1 must never be active in production consensus')
    except (ValueError, KeyError, FileNotFoundError, json.JSONDecodeError, TypeError, OSError) as exc:
        report_check(checks, 'w1-candidate:manifest', False, 'cannot inspect candidate manifest: ' + str(exc), 'WARNING')
    live = evidence.get('live_consensus_proof', {})
    report_check(checks, 'live-proof:backend-known', bool(live.get('backend') and live['backend'] != 'unknown'),
                 'name and freeze the actual *live* consensus proof backend (may differ from W1 candidate)')
    report_check(checks, 'live-proof:pq128-bound',
                 isinstance(live.get('conservative_quantum_soundness_bits'), int) and
                 live['conservative_quantum_soundness_bits'] >= policy.get('minimum_quantum_security_bits', 128),
                 'requires independent, concrete quantum soundness bounds across complete proof composition')
    for field in ('independent_crypto_review_passed', 'no_groth16_or_classical_proof_fallback',
                  'guest_verifier_transcript_parameter_bound', 'real_invalid_receipts_rejected',
                  'rollback_and_reorg_proof_rejection_tested'):
        report_check(checks, 'live-proof:' + field, live.get(field) is True,
                     'live prover/verifier end-to-end acceptance boundary')
    check_artifacts(repo, live.get('artifacts'), artifacts, checks, 'live-proof:evidence')


def check_pow(policy, evidence, repo, artifacts, checks):
    pow_e = evidence.get('pon_quantum', {})
    for field in ('full_valid_w1_oracle_modeled', 'precomputation_amortized', 'resource_and_uncompute_costed',
                  'block_propagation_and_reorg_costed', 'quantum_difficulty_attack_bounded',
                  'cumulative_work_fork_choice_tested', 'independent_adversarial_review_passed'):
        report_check(checks, 'pon:' + field, pow_e.get(field) is True,
                     'quantum cost model and executable adversarial validation required')
    cases = pow_e.get('solver_cases', {})
    for case in policy.get('required_solver_cases', []):
        report_check(checks, 'pon:solver:' + case, cases.get(case) == 'tested',
                     'solver class must be compared under equivalent constraints')
    check_artifacts(repo, pow_e.get('artifacts'), artifacts, checks, 'pon:evidence')


def check_recovery_and_capacity(policy, evidence, repo, artifacts, checks):
    recovery = evidence.get('recovery', {})
    for field in ('external_monotonic_anchor', 'internal_snapshot_replay_rejected',
                  'key_revocation_survives_reorg', 'power_loss_recovery_verified',
                  'downgrade_on_restore_rejected'):
        report_check(checks, 'recovery:' + field, recovery.get(field) is True,
                     'restore / rollback / key lifetime invariant')
    check_artifacts(repo, recovery.get('artifacts'), artifacts, checks, 'recovery:evidence')
    cap = evidence.get('capacity', {})
    for field in ('ml_dsa_size_budget', 'invalid_signature_cpu_budget', 'invalid_proof_cpu_budget',
                  'network_propagation_p99_budget', 'peer_malformed_input_bounded', 'persistent_storage_budget'):
        report_check(checks, 'capacity:' + field, cap.get(field) is True,
                     'real-node worst-case resource and rejection-cost measurement')
    check_artifacts(repo, cap.get('artifacts'), artifacts, checks, 'capacity:evidence')


def perform_audit(repo: Path, policy: dict, evidence: dict, mode='scan', include_scan=True):
    repo = repo.resolve()
    checks = []
    sha, dirty = git_revision(repo) if repo.exists() else (None, None)
    report_check(checks, 'policy:schema', policy.get('schema_version') == 1 and evidence.get('schema_version') == 1,
                 'expected v1 policy and evidence schemas')
    report_check(checks, 'repo:exists', repo.is_dir(), 'repository directory must exist')
    if mode == 'release':
        report_check(checks, 'git:head', bool(sha and VALID_SHA.fullmatch(sha)), 'release gate requires a Git commit')
        report_check(checks, 'git:clean', dirty is False, 'tracked source changes must be committed')
        report_check(checks, 'git:evidence-bound',
                     bool(sha and sha == evidence.get('source_commit')),
                     'evidence must bind to exact current HEAD SHA')
    else:
        report_check(checks, 'git:head-discovery', bool(sha), 'source HEAD unavailable', 'WARNING')
    artifacts = evidence.get('artifacts', {})
    if mode == 'release' and isinstance(artifacts, dict) and sha:
        for ident, entry in artifacts.items():
            try:
                rel = inside_repo(repo, entry['path']).relative_to(repo).as_posix()
                tracked = subprocess.run(['git', '-C', str(repo), 'ls-files', '--error-unmatch', '--', rel],
                                         capture_output=True, timeout=10).returncode == 0
            except (ValueError, KeyError, OSError, TypeError, subprocess.TimeoutExpired):
                tracked = False
            report_check(checks, 'artifact-tracked:' + str(ident), tracked,
                         'release evidence artifacts must be tracked by the frozen source commit')
    check_authority(policy, evidence, repo, artifacts, checks)
    check_proof(policy, evidence, repo, artifacts, checks)
    check_pow(policy, evidence, repo, artifacts, checks)
    check_recovery_and_capacity(policy, evidence, repo, artifacts, checks)
    hits = scan_source(repo) if include_scan and repo.is_dir() else {'files_examined': 0, 'truncated': False, 'hits': []}
    if mode == 'release':
        report_check(checks, 'scan:enabled', include_scan, 'release must scan classic-cryptography and proof usages')
        reviewed = evidence.get('classic_usage_dispositions', {})
        for finding in hits['hits']:
            fp = finding['fingerprint']
            entry = reviewed.get(fp, {}) if isinstance(reviewed, dict) else {}
            accepted = {'non_authoritative', 'historical_readonly', 'test_only', 'pq_guarded'}
            report_check(checks, 'classic-use:' + fp + ':disposition', entry.get('disposition') in accepted,
                         'each classic signature/proof site must be traced and explicitly reviewed; presence alone is not vulnerability')
            check_artifacts(repo, entry.get('artifacts'), artifacts, checks,
                            'classic-use:' + fp + ':evidence')
    report_check(checks, 'scan:complete', not hits['truncated'], 'source heuristic inventory must not be truncated')
    blockers = [x for x in checks if x['status'] == 'BLOCKER']
    return {
        'claim': 'Whole-chain PQ-128 (evidence completeness only)',
        'verdict': 'BLOCKED' if blockers else 'METADATA_READY_INDEPENDENT_SECURITY_REVIEW_STILL_REQUIRED',
        'scope': 'Does NOT independently prove cryptographic safety, exhaustive authority coverage or quantum lower bounds',
        'mode': mode, 'source': {'root': str(repo), 'head': sha, 'tracked_dirty': dirty},
        'check_counts': {s: sum(x['status'] == s for x in checks) for s in ('PASS','WARNING','BLOCKER')},
        'checks': checks, 'classic_crypto_review_leads': hits,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo', required=True, help='path to Trillionnium-Chain git checkout')
    ap.add_argument('--policy', required=True, help='reviewed route/required-cases policy JSON')
    ap.add_argument('--evidence', required=True, help='commit-bound evidence JSON')
    ap.add_argument('--mode', choices=['scan', 'release'], default='scan')
    ap.add_argument('--out', help='write JSON report to this path')
    ap.add_argument('--no-code-scan', action='store_true')
    args = ap.parse_args(argv)
    try:
        result = perform_audit(Path(args.repo), load_json(Path(args.policy)), load_json(Path(args.evidence)),
                               args.mode, not args.no_code_scan)
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        print(json.dumps({'verdict':'BLOCKED', 'error':str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    serialized = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(serialized + '\n', encoding='utf-8')
    print(json.dumps({'verdict': result['verdict'], 'source': result['source'],
                      'check_counts': result['check_counts'],
                      'classic_crypto_leads': len(result['classic_crypto_review_leads']['hits'])}, ensure_ascii=False))
    return 1 if result['verdict'] == 'BLOCKED' else 0

if __name__ == '__main__':
    sys.exit(main())
