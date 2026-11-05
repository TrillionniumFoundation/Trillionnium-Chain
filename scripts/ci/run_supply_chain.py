#!/usr/bin/env python3
"""Check actual locked graphs; retain the fetched advisory tree and every failure."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from ci_observation import ROOT, checked, digest, finish, receipt_root, run, tool_root, tool_versions

MANIFESTS = ['trillionnium/Cargo.toml', 'tests/fuzz/Cargo.toml']


def main() -> int:
    versions = tool_versions()
    output = receipt_root('supply-chain')
    observations: list[dict] = []
    report = {'schema': 'trnm-supply-chain-v1', 'result': 'FAIL', 'tools': versions,
              'observations': observations, 'advisory_databases': [], 'acceptance_granted': False}
    binary = tool_root() / ('deny-' + versions['TRNM_CARGO_DENY_VERSION']) / 'bin/cargo-deny'
    try:
        checked([str(binary), '--version'], output / 'tool-version.log', observations)
        if (output / 'tool-version.log').read_text().strip() != 'cargo-deny ' + versions['TRNM_CARGO_DENY_VERSION']:
            raise ValueError('supply-chain tool version mismatch')
        report['cargo_deny_sha256'] = digest(binary)
        for index, manifest in enumerate(MANIFESTS):
            checked(['cargo', 'fetch', '--locked', '--manifest-path', manifest],
                    output / f'fetch-crates-{index}.log', observations)
        checked([str(binary), '--manifest-path', MANIFESTS[0], '--config', 'deny.toml',
                 '--locked', 'fetch', 'db'], output / 'fetch-advisories.log', observations)
        cargo_home = Path(os.environ['CARGO_HOME'])
        databases = sorted(p.parent for p in (cargo_home / 'advisory-dbs').glob('*/.git'))
        if len(databases) != 1:
            raise ValueError('expected exactly one isolated RustSec advisory database')
        for index, database in enumerate(databases):
            git = lambda *args: subprocess.check_output(['git', '-C', str(database), *args], text=True).strip()
            commit, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
            origin = git('remote', 'get-url', 'origin')
            if origin.lower().removesuffix('.git') != 'https://github.com/rustsec/advisory-db':
                raise ValueError('unexpected advisory database source')
            if git('status', '--porcelain'):
                raise ValueError('advisory database has uncommitted modifications')
            archive = output / f'advisories-{index}-{commit}.tar.gz'
            checked(['git', '-C', str(database), 'archive', '--format=tar.gz',
                     '--output=' + str(archive), commit], output / f'archive-{index}.log', observations)
            report['advisory_databases'].append({'origin': origin, 'commit': commit, 'tree': tree,
                                                'commit_time': git('show', '-s', '--format=%cI', 'HEAD'),
                                                'archive': archive.name})
        failed = False
        # Frozen checks cannot silently refresh the recorded database or lockfiles.
        # All categories and both graphs execute even when a prior graph is denied.
        for index, manifest in enumerate(MANIFESTS):
            result = run([str(binary), '--manifest-path', manifest, '--config', 'deny.toml',
                          '--all-features', '--frozen', '--format', 'json',
                          'check', 'advisories', 'licenses', 'bans', 'sources'],
                         output / f'check-{index}.jsonl', timeout=900)
            observations.append(result)
            failed |= result['exit_code'] != 0
        if failed:
            raise RuntimeError('dependency policy refused one or more graphs; inspect retained diagnostics')
        report['result'] = 'PASS'
    except (OSError, KeyError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        report['error'] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        finish(output, report, ['deny.toml', 'trillionnium/Cargo.lock', 'tests/fuzz/Cargo.lock',
                              'scripts/ci/tool-versions.env', 'scripts/ci/run_supply_chain.py'])
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
