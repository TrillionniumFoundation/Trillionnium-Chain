#!/usr/bin/env python3
"""Offline bounded ingestion of an owner-pinned model operations package.

No downloads, training, signatures, chain changes or independent acceptance.
The package directory and every input are descriptor-pinned for one ingestion:
path validation is never separated from the file actually read.
"""
from __future__ import annotations
import argparse
import contextlib
import json
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract_wire import unique
from llm_adapter_contract import verify_target_contract, verify_run_plan, require
from model_acceptance import verify_acceptance

MAX_JSON = 2*1024*1024
MAX_MATERIAL = 16*1024*1024


def _descriptor_flags():
    require(
        os.name == 'posix'
        and hasattr(os, 'O_NOFOLLOW')
        and hasattr(os, 'O_DIRECTORY')
        and hasattr(os, 'O_NONBLOCK')
        and os.open in os.supports_dir_fd,
        'ACCEPTANCE_DESCRIPTOR_UNAVAILABLE')
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, 'O_CLOEXEC', 0)


def _open_relative(name, flags, parent):
    try:
        return os.open(name, flags, dir_fd=parent)
    except OSError as error:
        raise ValueError('ACCEPTANCE_INPUT_PATH') from error


@contextlib.contextmanager
def _pinned_package(folder):
    """Open every absolute package path component without following symlinks."""
    flags = _descriptor_flags() | os.O_DIRECTORY
    path = Path(os.path.abspath(folder))
    current = _open_relative(path.anchor, flags, None)
    try:
        for part in path.parts[1:]:
            successor = _open_relative(part, flags, current)
            previous, current = current, successor
            os.close(previous)
        yield current
    finally:
        os.close(current)


def _file_identity(info):
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns)


def _bounded_file_at(root, name, limit):
    require(
        type(name) is str
        and name
        and '\x00' not in name
        and '\\' not in name
        and not Path(name).is_absolute()
        and all(part not in ('', '.', '..') for part in name.split('/')),
        'ACCEPTANCE_INPUT_PATH')
    require(type(limit) is int and 0 <= limit <= MAX_MATERIAL, 'ACCEPTANCE_INPUT_LIMIT')
    flags = _descriptor_flags()
    parts = name.split('/')
    parent = os.dup(root)
    try:
        for part in parts[:-1]:
            successor = _open_relative(part, flags | os.O_DIRECTORY, parent)
            previous, parent = parent, successor
            os.close(previous)
        descriptor = _open_relative(parts[-1], flags, parent)
        try:
            before = os.fstat(descriptor)
            require(
                stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                'ACCEPTANCE_INPUT_PATH')
            require(before.st_size <= limit, 'ACCEPTANCE_INPUT_LIMIT')
            raw = bytearray()
            while len(raw) <= limit:
                chunk = os.read(descriptor, min(65536, limit + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            after = os.fstat(descriptor)
            require(len(raw) <= limit, 'ACCEPTANCE_INPUT_LIMIT')
            require(
                _file_identity(before) == _file_identity(after)
                and len(raw) == after.st_size,
                'ACCEPTANCE_INPUT_CHANGED')
            return bytes(raw)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def bounded_file(root, name, limit):
    """Compatibility helper: one descriptor-pinned read of an owner-selected root."""
    with _pinned_package(root) as descriptor:
        return _bounded_file_at(descriptor, name, limit)


def load_json(raw):
    return json.loads(
        raw,
        object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('ACCEPTANCE_NONFINITE')))


def ingest(folder, *, preregistration_hash, plan_hash, contract_hash,
           backbone_root, tokenizer_root, owner_record):
    with _pinned_package(folder) as root:
        contract = verify_target_contract(
            _bounded_file_at(root, 'contract.json', MAX_JSON), contract_hash,
            expected_backbone_root=backbone_root, expected_tokenizer_root=tokenizer_root)
        plan = verify_run_plan(
            _bounded_file_at(root, 'plan.json', MAX_JSON), plan_hash, contract, contract_hash,
            expected_owner_record=owner_record)
        index = load_json(_bounded_file_at(root, 'material-index.json', MAX_JSON))
        require(type(index) is dict and 1 <= len(index) <= 65536, 'ACCEPTANCE_MATERIAL_INDEX')
        remaining = MAX_MATERIAL
        material = {}
        for key, name in index.items():
            raw = _bounded_file_at(root, name, remaining)
            remaining -= len(raw)
            material[key] = raw
        return verify_acceptance(
            _bounded_file_at(root, 'preregistration.json', MAX_JSON), preregistration_hash,
            plan, plan_hash, load_json(_bounded_file_at(root, 'run-record.json', MAX_JSON)),
            load_json(_bounded_file_at(root, 'receipt.json', MAX_JSON)), material)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument(
        '--require-reported-gates',
        action='store_true',
        help='Print assessment then exit 2 for a failed reported gate; does not grant acceptance')
    for name in (
        'preregistration-hash', 'plan-hash', 'contract-hash',
        'backbone-root', 'tokenizer-root', 'owner-record'):
        parser.add_argument('--'+name, required=True)
    args = vars(parser.parse_args())
    folder = args.pop('input')
    required = args.pop('require_reported_gates')
    report = ingest(folder, **args)
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    if required and not report['reported_gates_passed']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()