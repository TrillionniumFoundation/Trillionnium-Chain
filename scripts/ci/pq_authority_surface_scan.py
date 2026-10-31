#!/usr/bin/env python3
"""Source-only inventory of Rust authorization cryptography, never PQ qualification.

All unknown/classical surfaces remain review obligations. A source hit does not
prove the code is active, grants permission, or has an exploitable path. Indirect
crypto, other languages, dynamic policy and externally stored roots are unseen.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
CRITICAL = {
    'trillionnium/crates/trnm-types/src/transfer.rs': 'classic-transfer-authorization',
    'trillionnium/crates/trnm-service-settlement/src/engine.rs': 'classic-settlement-signatures',
    'trillionnium/crates/trnm-research-protocol/src/command.rs': 'classic-research-command',
    'trillionnium/crates/trnm-research-protocol/src/hepta_handoff.rs': 'classic-hepta-v1',
    'trillionnium/crates/trnm-data-availability/src/cell/discovery.rs': 'classic-cell-discovery-v1',
    'trillionnium/crates/trnm-pon-node/src/ingress.rs': 'mixed-classic-and-pq-profile-boundary',
    'trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs': 'pq-crypto-only-no-authority',
    'trillionnium/crates/trnm-research-protocol/src/hepta_handoff/pq.rs': 'pq-hepta-v2-not-final-use',
    'trillionnium/crates/trnm-data-availability/src/cell/discovery/pq.rs': 'pq-cell-discovery-v2',
    'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/application_v6.rs': 'pq-application-v6-research',
}
# Recognize crypto entry primitives, not generic 'signature' comments.
CLASSIC = re.compile(r'\bed25519\b|ed25519_dalek|verify_strict\s*\(|verify_hex_strict\s*\(|SIGNATURE_SCHEME_ED25519|\b(?:ecdsa|secp256k1|schnorr|bls12_381)\b|\b(?:p256|k256)::ecdsa\b|\b(?:rsa::pss|ring::signature|openssl::sign::Verifier)\b', re.I)
PQ = re.compile(r'\bml_dsa\b|ML_DSA_65|PqNativeVerifier|PqNativeSigningKey|verify_tpq1\s*\(|\bpqcrypto_mldsa\b|\bdilithium\b|\bsphincs(?:plus)?\b|\bslh_dsa\b', re.I)
MAX_SOURCE_BYTES = 1024 * 1024
MAX_SOURCE_FILES = 20000


class AuditError(ValueError):
    pass


def sources(root: Path):
    base = root / 'trillionnium' / 'crates'
    if not base.is_dir() or base.is_symlink():
        raise AuditError('missing/symlink crate root')
    count = 0
    # Include all crate Rust, including build.rs, examples, tests and unusual\n    # directories. A selectable binary/feature may live outside src/.\n    # os.walk does not follow symlink dirs; refuse them rather than missing scope.
    for current, dirs, files in os.walk(base, followlinks=False):
        for dirname in dirs:
            if (Path(current) / dirname).is_symlink():
                raise AuditError('symlink directory in scan scope')
        dirs.sort()
        for filename in sorted(files):
            if not filename.endswith('.rs'):
                continue
            path = Path(current) / filename
            if path.is_symlink():
                raise AuditError('symlink source in scan scope')
            try:
                size = path.stat()
                if not stat.S_ISREG(size.st_mode) or size.st_size > MAX_SOURCE_BYTES:
                    raise AuditError('oversize/nonregular Rust source')
                data = path.read_bytes()
            except OSError as exc:
                raise AuditError('unreadable Rust source') from exc
            if len(data) != size.st_size:
                raise AuditError('source changed during scan')
            try:
                content = data.decode('utf-8')
            except UnicodeDecodeError as exc:
                raise AuditError('nonutf8 Rust source') from exc
            count += 1
            if count > MAX_SOURCE_FILES:
                raise AuditError('source file limit exceeded')
            yield path.relative_to(root).as_posix(), data, content


def inspect(root: Path) -> dict:
    all_paths = set()
    entries = []
    files_seen = 0
    for name, data, content in sources(root):
        files_seen += 1
        all_paths.add(name)
        classic_hits = []
        pq_hits = []
        for i, line in enumerate(content.splitlines(), 1):
            if CLASSIC.search(line):
                classic_hits.append(i)
            if PQ.search(line):
                pq_hits.append(i)
        if not classic_hits and not pq_hits and name not in CRITICAL:
            continue
        entries.append({'path': name,
                        'role_review_hint': CRITICAL.get(name, 'unreviewed-source-hit'),
                        'classical_indicator_lines': classic_hits[:24],
                        'pq_indicator_lines': pq_hits[:24],
                        'classical_indicator_count': len(classic_hits),
                        'pq_indicator_count': len(pq_hits),
                        'sha256': hashlib.sha256(data).hexdigest()})
    missing = sorted(set(CRITICAL) - all_paths)
    if missing:
        raise AuditError('critical source missing: ' + ', '.join(missing))
    return {'schema': 'trnm-pq-rust-source-authority-inventory-v1',
            'status': 'HOLD_INCOMPLETE_AUTHORITY_TRACING',
            'whole_chain_pq_qualified': False,
            'source_files_read': files_seen,
            'reviewed_roles_mapped': len(CRITICAL),
            'unreviewed_indicator_files': sum(e['role_review_hint'] == 'unreviewed-source-hit' for e in entries),
            'scope': 'All Rust files beneath trillionnium/crates, including build scripts, examples, tests and nonstandard directories; no reachability or runtime-effect proof',
            'findings': entries}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--summary-only', action='store_true')
    args = parser.parse_args()
    try:
        report = inspect(args.root)
    except AuditError as error:
        print(json.dumps({'status': 'REFUSE', 'reason': str(error)}), file=sys.stderr)
        return 2
    if args.summary_only:
        report.pop('findings')
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
