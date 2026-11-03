#!/usr/bin/env python3
"""Preserve Cargo argv; give only the complete architecture target its fixed Host."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys

import run_architecture_delivery_native as architecture
from replay_pinned_native import require


def is_architecture_target(binary: str) -> bool:
    return re.fullmatch(architecture.TARGET + r'-[0-9a-f]{16}', Path(binary).name) is not None


def main(argv: list[str]) -> int:
    require(bool(argv), 'CARGO_TEST_BINARY_REQUIRED')
    if not is_architecture_target(argv[0]):
        # All other workspace targets retain their exact executable, args,
        # environment, uid, current directory and ordinary process placement.
        os.execv(argv[0], argv)
    require(len(argv) == 1, 'ARCHITECTURE_ORIGINAL_UNFILTERED_ARGV_REQUIRED')
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('CI') == 'true'
            and os.getuid() != 0, 'ARCHITECTURE_HOSTED_UNPRIVILEGED_RUNNER_ONLY')
    native_cwd = Path.cwd().resolve()
    require(native_cwd == architecture.NATIVE_CWD, 'ARCHITECTURE_ORIGINAL_WORKING_DIRECTORY')
    binary = architecture.binary_path(argv[0])
    out = Path(os.environ['TRNM_CI_RECEIPT_DIR']) / 'architecture-native'
    architecture.prepare(binary, out, native_cwd)
    import run_from_zero_host as host
    # Cargo executes each test from its package directory. The existing Host
    # controller runs from the checkout root; the native child restores the
    # exact original package cwd recorded in preparation.
    os.chdir(architecture.ROOT)
    status = host.outer(['python3', architecture.SCRIPT, '--out', str(out)])
    log = out / 'native.log'
    if log.is_file():
        with log.open('rb') as stream:
            while chunk := stream.read(65536):
                sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
    if status == 0:
        architecture.require_controller_success(out)
    return status


if __name__ == '__main__':
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
