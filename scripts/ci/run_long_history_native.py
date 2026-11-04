#!/usr/bin/env python3
"""Run the original 4105-block/public-page test as an owned unprivileged child.

The existing source-pinned fixed parent must already be provisioned. Compilation
stays outside this process envelope; construction, server and verifier all enter
the same original parent before the held native ELF can execute.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from check_required_native_test import validate
from from_zero_native_host import HISTORY_TEST, HISTORY_TIMEOUT_SECONDS, ROOT, run_host_child, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--host-owner', required=True)
    args = parser.parse_args()
    binary = args.binary
    if not binary.is_absolute() or binary.is_symlink() or binary.resolve(strict=True) != binary:
        raise ValueError('LONG_HISTORY_ORIGINAL_BINARY')
    args.out.mkdir(exist_ok=False)
    source = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    digest = sha(binary.read_bytes())
    result = run_host_child(
        [str(binary), HISTORY_TEST, '--exact', '--ignored', '--show-output', '--test-threads=1'],
        args.out / 'native', HISTORY_TIMEOUT_SECONDS, run_owner=args.host_owner,
        source=source, binary_sha256=digest,
    )
    # Retain both streams as emitted and expose the original pretty libtest log
    # to the existing workflow's exact-name and native summary checks.
    stdout = (args.out / 'native/stdout').read_bytes()
    stderr = (args.out / 'native/stderr').read_bytes()
    for raw in (stdout, stderr):
        if raw:
            sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    source_after = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    record = {'schema': 'native-long-history-host-process-v1', 'source': source,
              'binary_sha256': digest, 'source_unchanged': source_after == source,
              'binary_unchanged': sha(binary.read_bytes()) == digest,
              'actual_process': result, 'named_test': None, 'complete': False}
    try:
        record['named_test'] = validate(stdout.decode('utf-8').splitlines(), HISTORY_TEST)
        record['complete'] = (record['source_unchanged'] and record['binary_unchanged']
                              and result['host_scope']['complete'])
    except (UnicodeError, ValueError) as error:
        record['error'] = str(error)
    (args.out / 'summary.json').write_text(json.dumps(record, indent=2) + '\n')
    return 0 if record['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
