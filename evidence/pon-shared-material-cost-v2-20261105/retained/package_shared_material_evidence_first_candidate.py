#!/usr/bin/env python3
"""Package retained observations; keep repository source at its pinned Git commit."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--prior-algebra-inputs', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root = args.workspace.resolve()
    evidence = root / 'chain/evidence/pon-shared-material-cost-v2-20261105'
    payload = {}

    def add(path, name):
        assert not path.is_symlink(), path
        assert name not in payload and '..' not in Path(name).parts and not name.startswith('/'), name
        payload[name] = path.read_bytes()

    def add_tree(path, prefix, excluded=()):
        for child in sorted(path.rglob('*')):
            if child.is_file() and '__pycache__' not in child.parts:
                relative = child.relative_to(path).as_posix()
                if relative not in excluded:
                    add(child, prefix + '/' + relative)

    for name in ('campaign-v2', 'security-v2-t0', 'security-v2-t1', 'frozen-inputs',
                 'audit-notes', 'frozen-source-validation'):
        add_tree(root / name, name)
    add_tree(evidence, 'evidence', excluded=('archive.json', 'publication-validation.json'))
    for name in (
        'cost-v2-all-readback.json', 'cost-v2-all-readback-execution.json', 'cost-scenarios-v2.json',
        'security-v2-execution.json', 'security-v2-t0.stdout.log', 'security-v2-t0.stderr.log',
        'security-v2-t1.stdout.log', 'security-v2-t1.stderr.log',
        'initial-rust-test-build-cancelled.json', 'rust-shared-material-validation.json',
        'crypto-lib-tests.log', 'native-example-tests.log', 'native-release-build.log',
        'native-strict-clippy.log', 'workspace-fmt.log', 'consumer-tests-first.log',
        'consumer-tests-current.log', 'consumer-tests-final-candidate.log',
        'consumer-red-green-real.json', 'security-reader-red-green.json', 'security-tests-current.log',
        'cost-tests-current.log', 'cost-v1-four-current-readback.json', 'cost-v1-three-fixes-readback.json',
        'source-negative-tests.log', 'ci-contract-tests.log', 'repository-check-initial.log',
        'repository-check-second.log', 'final-candidate-pq-source.json', 'final-candidate-ci-contract.json',
        'concurrent-integration-explicit-base.json', 'concurrent-integration-preservation.json',
        'source-github-commit.json', 'final-source-github-commit.json', 'own-copy-space-recovery.json',
    ):
        add(root / name, 'development-and-commands/' + name)
    add(root / 'target/release/examples/pon_shared_material_v1', 'bin/pon_shared_material_v1')
    add(args.prior_algebra_inputs / 'manifest.json', 'prior-v1-algebra-inputs/manifest.json')
    for index in range(5):
        for name in ('material.bin', 'native.stdout.jsonl'):
            add(args.prior_algebra_inputs / f'tile-{index}' / name,
                f'prior-v1-algebra-inputs/tile-{index}/{name}')
    add(Path(__file__).resolve(), 'package_shared_material_evidence.py')
    payload['README.txt'] = (
        'Same-material W1 raw observations, 2026-11-05\n\n'
        'Measured source: eeedfe33f9c7cd27a1855b865e7faa458047dcd1\n'
        'Source repository: https://github.com/TrillionniumFoundation/Trillionnium-Chain\n'
        'Use evidence/REPRODUCE.md for commands and evidence/README.md for results.\n'
        'GitHub-relative links in those documents refer to the repository evidence directory.\n'
        'Source code stays at its pinned Git commit; source-files.json binds the measured files.\n'
        'The retained release binary is a local Linux observation, not a trusted distribution.\n'
        '30 complete observations and one genuine exhaustion are retained.\n'
        'One unique frozen material batch contains 64 requests; repetitions create no new demand.\n'
        'Shared host; full-system cost, net compute benefit and qualification remain unestablished.\n'
        'Archive metadata and later publication-only validation are outside this payload to avoid circular hashes.\n'
    ).encode()
    records = [{'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
               for name, data in sorted(payload.items())]
    manifest = {'schema': 'pon-shared-material-raw-archive-v2',
                'measured_source': 'eeedfe33f9c7cd27a1855b865e7faa458047dcd1',
                'file_count': len(records), 'payload_bytes': sum(row['bytes'] for row in records),
                'files': records, 'manifest_self_hash_excluded': True,
                'full_system_cost': None, 'net_compute_benefit': None,
                'qualification': False, 'production_activation': False}
    payload['payload-manifest.json'] = canonical(manifest)
    with args.out.open('xb') as file, zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(payload.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 5, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100755 if name == 'bin/pon_shared_material_v1' else 0o100644) << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    with zipfile.ZipFile(args.out) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist()) == len(payload)
        for row in records:
            data = archive.read(row['path'])
            assert len(data) == row['bytes']
            assert hashlib.sha256(data).hexdigest() == row['sha256']
    result = {'schema': 'pon-shared-material-archive-commitment-v2',
              'filename': args.out.name, 'bytes': args.out.stat().st_size,
              'sha256': hashlib.sha256(args.out.read_bytes()).hexdigest(),
              'zip_entries': len(payload), 'payload_files': len(records),
              'uncompressed_payload_bytes': manifest['payload_bytes'],
              'payload_manifest_sha256': hashlib.sha256(payload['payload-manifest.json']).hexdigest(),
              'crc_and_every_payload_sha256_verified': True,
              'measured_source': manifest['measured_source'],
              'excluded_from_payload': ['archive.json', 'publication-validation.json'],
              'qualification': False}
    (evidence / 'archive.json').write_bytes(canonical(result))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
