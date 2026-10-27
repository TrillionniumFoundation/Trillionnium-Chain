#!/usr/bin/env python3
"""Freeze/execute one explicit PN1 supplement; preparation never runs pressure.

The operator supplies a new owned resource scope. This collector only observes
its limits; it does not create services, change cgroups, or cancel historical
runs. The outer collection budget cannot extend any native stage deadline.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import ctypes
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time

sys.dont_write_bytecode = True
from run_pon_w1_native_campaign import (ROOT, require, resource_observation, run_step,
    sha, source_snapshot, validate_build_environment, validate_resources, validate_source, write_new)
from run_pon_root_supplement import exact_source
from bounded_process import ProcessFailure, run_bounded

TARGET = 'public_v3_identity_campaign'
SELECTOR = 'separate_process_identity_capacity_and_signed_confirmation_supplement'
PLAN = dict(actors=24, prefix_calls_per_actor=192, pressure_calls_per_actor=288,
    prefix_seconds=1800, pressure_seconds=30, readiness_seconds=180, cleanup_seconds=5,
    call_seconds=2, actor_total_call_cap=480, honest_submission_cap=128,
    honest_history_cap=64, rounds=3, pressure_schedule='closed-loop-one-in-flight-per-actor', qualification=True)
ACCEPTANCE = dict(prefix_paid_unique_min=4096, post_capacity_fresh_min=1,
    round_depletion_coverage_numerator=9, round_depletion_coverage_denominator=10,
    maximum_unproven_gap_ns=1_000_000_000, confirmation_depth=6, business_blocks=21)
MIB = 1024**2
EVIDENCE_CAPS_V2 = dict(schema='native-public-v3-identity-evidence-limits-v2', artifact_total_bytes=8192*MIB,
    actor_prefix_bytes=64*MIB, actor_fresh_pressure_bytes=96*MIB, actor_replay_pressure_bytes=8*MIB,
    construction_bytes=8*MIB, actor_working_data_bytes=32*MIB, actor_vm_bytes=512*MIB,
    parent_vm_bytes=3072*MIB, parent_file_bytes=16*MIB, actor_file_bytes=8*MIB,
    node_roots=['honest-miner', 'honest-only/receiver', 'honest-only/independent-client',
        'replay-only/receiver', 'replay-only/independent-client',
        'fresh-identities/receiver', 'fresh-identities/independent-client'],
    node_database_bytes_each=16*MIB, node_database_total_bytes=336*MIB, node_metadata_total_bytes=MIB,
    node_file_names={'native.sqlite':16*MIB, 'native.sqlite-wal':16*MIB, 'native.sqlite-shm':16*MIB,
        'owner.lock':0, 'initializing.json':1024},
    sample_chunk_bytes=8*MIB, sample_chunks_per_phase=12, sample_total_bytes=288*MIB,
    frozen_binary_bytes=192*MIB, phase_report_bytes_each=16*MIB, phase_report_total_bytes=48*MIB,
    actor_metadata_bytes_each=MIB//2, actor_metadata_total_bytes=36*MIB,
    actor_log_bytes_each=64*1024, actor_log_total_bytes=9*MIB//2,
    outer_outputs_total_bytes=128*MIB, preparation_bytes=8*MIB, root_outputs_total_bytes=32*MIB,
    raw_root_outputs_bytes=MIB, inventory_bytes=31*MIB,
    reserved_total_bytes=16355*MIB//2, unassigned_bytes=29*MIB//2,
    bucket_members=dict(actor_stage='started, construction, call and retained partial files under prefix/pressure',
        actor_metadata='actor-root job, ready, prefix-finished, report, process-limits and stage-terminal JSON, including partials',
        actor_log='actor.log only; combined stdout/stderr must be bounded by its owner',
        phase='phase report, prefix-start, pressure-start and terminal JSON, including partials',
        samples='only the exact report sample_files chunks; summed sample_count preserves every row',
        root='artifact-files.json and raw top-level plan, report, process-limits and node-files JSON',
        outer='all other frozen/source/resource/native streams/results; excludes the single frozen binary',
        partial_policy='retain and charge the matching bucket; any partial or initializing marker prevents qualification',
        honest_only_pressure='must remain empty'),
    namespace_rules=dict(raw_root_json=['plan.json', 'report.json', 'process-limits.json', 'node-files.json', 'cap-terminal.json'],
        actor_metadata_json=['job.json', 'ready.json', 'prefix-finished.json', 'report.json', 'process-limits.json', 'stage-terminal.json'],
        phase_metadata_json=['report.json', 'prefix-start.json', 'pressure-start.json', 'terminal.json'],
        sample_name_pattern='samples-[0-9][0-9].jsonl', sample_indices='00..11',
        strict_success_forbidden=['*.partial.json', '*.tmp.json', 'initializing.json', 'cap-terminal.json', 'stage-terminal.json', 'terminal.json']),
    all_cap_hits='FAIL; preserve partial and terminal; never increase caps or retry as qualification',
    scope='stricter local evidence limits; original 4CPU/16GiB cgroup and workload limits remain')
# The descriptor is frozen independently from completion of its native owners.
# No full v2 selector may run until every writer/pipe/chunk enforces this ledger.
V2_FULL_IO_BOUNDARY_IMPLEMENTED = False
LINK_SCHEMA = 'pon-identity-prepared-execution-link-v1'
CLAIM_SCHEMA = 'pon-identity-one-shot-claim-v1'
CLAIM_TERMINAL_SCHEMA = 'pon-identity-one-shot-terminal-v1'
CLAIM_DOMAIN = 'trnm-pon-identity-one-shot-claim-v1'
FD_DISPATCH_SCHEMA = 'pon-identity-first-exec-fd-dispatch-v1'
CLAIM_DOCUMENT_BYTES = 16 * 1024
CLAIM_PAIR_RESERVATION_BYTES = 4 * CLAIM_DOCUMENT_BYTES
VIRTUAL_INPUT_NAMESPACES = ('input-prepared', 'external-claim')


def held_directory(path):
    """Open every absolute component without following links; caller owns the FD."""
    path = Path(path)
    require(path.is_absolute() and os.path.abspath(path) == str(path), 'CANONICAL_ABSOLUTE_DIRECTORY_REQUIRED')
    current = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def identity(info):
    return dict(device=info.st_dev, inode=info.st_ino)


class PreparedInput:
    """A complete, held original preparation; never an alias for its frozen copy."""
    def __init__(self, prepared, prepared_sha256, inventory_sha256, head, tree):
        sys.path.insert(0, str(ROOT / 'scripts/ci'))
        from check_pon_identity_churn import IdentityBundle, strict_json
        self.root = Path(prepared).parent
        require(not self.root.is_relative_to(ROOT), 'PREPARATION_OUTSIDE_SOURCE_REQUIRED')
        require(Path(prepared).name == 'prepared.json', 'FIXED_PREPARED_DOCUMENT_REQUIRED')
        self.parent_fd = held_directory(self.root.parent)
        self.bundle = None
        self.binary_fd = None
        directory = None
        try:
            directory = os.open(self.root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=self.parent_fd)
            self.bundle = IdentityBundle(self.root, inventory_sha256, version='v2', directory_fd=directory)
            raw = self.bundle.raw('prepared.json', 16*MIB)
            require(hashlib.sha256(raw).hexdigest() == prepared_sha256, 'EXACT_PREPARED_DOCUMENT_REQUIRED')
            self.value = strict_json(raw)
            expected = profile('v2')
            require(self.value['schema'] == expected['prepared_schema'] and self.value['prepared'] is True
                    and self.value['selector_executed'] is False and self.value['plan'] == PLAN
                    and self.value['acceptance'] == ACCEPTANCE and self.value['head'] == head
                    and self.value['tree'] == tree and self.value['evidence_caps'] == expected['evidence_caps']
                    and self.value['runner_sha256'] == sha(__file__)
                    and type(self.value['collector_seconds']) is int and 0 < self.value['collector_seconds'] <= 86400,
                    'BOUND_COMPLETE_PREPARATION_REQUIRED')
            files = self.value['files']
            require(set(files) | {'prepared.json'} == set(self.bundle.files), 'COMPLETE_ORIGINAL_PREPARATION_REQUIRED')
            require(all(not any(p in VIRTUAL_INPUT_NAMESPACES for p in Path(name).parts)
                        and Path(name).parts[0] != 'raw' for name in self.bundle.files),
                    'RESERVED_OR_NATIVE_PREPARATION_NAMESPACE')
            for name, pin in files.items():
                require(pin == {k:self.bundle.files[name][k] for k in ('bytes', 'sha256')},
                        'PREPARED_MEMBER_PIN_CHANGED')
            binary = self.value['binary']
            require(Path(binary['path']) == self.root / (TARGET + '.bin')
                    and binary['sha256'] == self.bundle.files[TARGET + '.bin']['sha256']
                    and binary['bytes'] == self.bundle.files[TARGET + '.bin']['bytes'],
                    'ORIGINAL_BINARY_BINDING_REQUIRED')
            self.binary_fd = os.open(TARGET + '.bin', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.bundle.fd)
            info = os.fstat(self.binary_fd)
            require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o222 == 0, 'READONLY_ORIGINAL_BINARY_REQUIRED')
            self.binding = dict(head=head, tree=tree, prepared_sha256=prepared_sha256,
                inventory_sha256=inventory_sha256, binary_sha256=binary['sha256'], binary_bytes=binary['bytes'],
                prepared_root=str(self.root), prepared_identity=identity(os.fstat(self.bundle.fd)),
                parent_identity=identity(os.fstat(self.parent_fd)), binary_identity=identity(info))
            self.recheck()
        except BaseException:
            self.close()
            raise
        finally:
            if directory is not None:
                os.close(directory)

    def recheck(self):
        require(identity(os.stat(self.root.name, dir_fd=self.parent_fd, follow_symlinks=False))
                == self.binding['prepared_identity'], 'ORIGINAL_PREPARATION_DIRECTORY_REPLACED')
        require(identity(os.stat(TARGET + '.bin', dir_fd=self.bundle.fd, follow_symlinks=False))
                == self.binding['binary_identity'], 'ORIGINAL_BINARY_REPLACED')
        for name, pin in self.bundle.files.items():
            self.bundle._read(name, 256*MIB, retain=False, expected=pin)
        digest = hashlib.sha256()
        os.lseek(self.binary_fd, 0, os.SEEK_SET)
        while chunk := os.read(self.binary_fd, 65536):
            digest.update(chunk)
        require(digest.hexdigest() == self.binding['binary_sha256']
                and os.fstat(self.binary_fd).st_size == self.binding['binary_bytes'], 'ORIGINAL_BINARY_CHANGED')
        require(hashlib.sha256(self.bundle.raw('prepared.json', 16*MIB)).hexdigest()
                == self.binding['prepared_sha256'], 'ORIGINAL_PREPARED_DOCUMENT_CHANGED')
        require(hashlib.sha256(self.bundle._read('artifact-files.json', 31*MIB)).hexdigest()
                == self.binding['inventory_sha256'], 'ORIGINAL_INVENTORY_CHANGED')

    def close(self):
        if self.binary_fd is not None:
            os.close(self.binary_fd)
            self.binary_fd = None
        if self.bundle is not None:
            self.bundle.close()
            self.bundle = None
        if self.parent_fd is not None:
            os.close(self.parent_fd)
            self.parent_fd = None


def held_file_names(directory_fd):
    """Inventory the held tree, never a re-resolved absolute ancestor chain."""
    names = []
    def failed(error):
        raise error
    for parent, directories, files, fd in os.fwalk('.', dir_fd=directory_fd,
            follow_symlinks=False, onerror=failed):
        directories.sort()
        for name in directories:
            require(stat.S_ISDIR(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode),
                    'NO_SYMLINK_OR_SPECIAL_ARTIFACTS')
        for name in sorted(files):
            require(stat.S_ISREG(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode),
                    'NO_SYMLINK_OR_SPECIAL_ARTIFACTS')
            names.append((Path(parent)/name).as_posix())
            require(len(names) <= 200_001, 'V2_ARTIFACT_FILE_COUNT_CAP')
    return sorted(names)


def checked_member(directory_fd, name, pin=None, *, retain=False, limit=256*MIB):
    """Recheck a held-root regular member against an already frozen pin."""
    from read_original_native_campaign import Bundle
    parts = Bundle.path_parts(name)
    current = os.dup(directory_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        with os.fdopen(os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                               dir_fd=current), 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_size <= limit
                    and (pin is None or before.st_size == pin['bytes']), 'BOUND_MEMBER_LENGTH_CHANGED')
            digest, size, chunks = hashlib.sha256(), 0, []
            while chunk := stream.read(min(65536, before.st_size-size+1)):
                size += len(chunk)
                require(size <= before.st_size, 'BOUND_MEMBER_GREW')
                digest.update(chunk)
                if retain: chunks.append(chunk)
            after = os.fstat(stream.fileno())
            fields = lambda s: (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            value = dict(bytes=size, sha256=digest.hexdigest())
            require(fields(before) == fields(after) and size == before.st_size
                    and (pin is None or value == {k:pin[k] for k in value}), 'BOUND_MEMBER_SHA_OR_IDENTITY_CHANGED')
            return value, b''.join(chunks) if retain else None
    finally:
        os.close(current)


def claim_basename(source):
    return source.root.name + '.execution-claim-v1'


def require_unclaimed(source):
    try:
        os.stat(claim_basename(source), dir_fd=source.parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise FileExistsError(errno.EEXIST, 'preparation already claimed; any retained state blocks retry')


def plan_linked_preparation(io, source):
    """Reserve both actual copies inside the unchanged shared caps before copying."""
    from check_pon_identity_churn import evidence_ledger_v2, linked_evidence_ledger_v2
    require(io.writer is not None and not any(io.writer.used.values()) and not any(io.writer.held.values()),
            'FRESH_V2_LINKED_OUTPUT_OWNER_REQUIRED')
    require(not os.listdir(io.writer.fd), 'FRESH_LINKED_OUTPUT_DIRECTORY_REQUIRED')
    require(not io.output.is_relative_to(source.root) and not source.root.is_relative_to(io.output),
            'DISJOINT_PREPARATION_EXECUTION_ROOTS_REQUIRED')
    source.recheck()
    require_unclaimed(source)
    pins = dict(source.bundle.files)
    pins['artifact-files.json'] = dict(bytes=os.stat('artifact-files.json', dir_fd=source.bundle.fd,
                                                   follow_symlinks=False).st_size,
                                      sha256=source.binding['inventory_sha256'])
    planned = {'frozen/'+name:pin for name,pin in pins.items()}
    caps = profile('v2')['evidence_caps']
    linked_evidence_ledger_v2(planned, 0, pins, {}, caps, strict=False)
    imported = evidence_ledger_v2(source.bundle.files, pins['artifact-files.json']['bytes'],
                                  caps, strict=False, preparation_only=True)
    io.writer.used.update(outer=imported['bucket_bytes'].get('outer',0),
                          binary=imported['bucket_bytes'].get('binary',0),
                          inventory=pins['artifact-files.json']['bytes'])
    require(io.writer.used['outer'] + CLAIM_PAIR_RESERVATION_BYTES <= io.writer.limits['outer'],
            'LINKED_CLAIM_AND_OUTER_TERMINAL_MUST_FIT_ORIGINAL_OUTER')
    return pins


def capture_linked_preparation(io, source, pins):
    for name, pin in pins.items():
        require('/' not in name, 'FLAT_ORIGINAL_PREPARATION_REQUIRED')
        bucket = 'binary' if name == TARGET+'.bin' else 'inventory' if name == 'artifact-files.json' else 'outer'
        io.writer.copy('frozen/'+name, name, bucket=bucket, expected=pin['sha256'], source_directory_fd=source.bundle.fd)
        if bucket == 'binary':
            directory, leaf = io.writer.parent('frozen/'+name)
            try: os.chmod(leaf, 0o500, dir_fd=directory, follow_symlinks=False)
            finally: os.close(directory)


class ClaimOwner:
    """One retained sibling claim; no protection against an administrator deleting it."""
    def __init__(self, io, source):
        self.io, self.source, self.frozen_pins = io, source, None
        self.fd, self.tokens, self.claim_pin, self.execution_parent_fd = None, [], None, None
        self.executable_fd = self.cwd_fd = None
        self.ran, self.attempted, self.terminal_attempted = False, False, False
        require(io.writer is not None, 'V2_CLAIM_WRITER_REQUIRED')
        try:
            self.execution_parent_fd = held_directory(io.output.parent)
            self.frozen_pins = plan_linked_preparation(io, source)
            io.linked_source = source
            self.tokens = [io.writer.reserve('outer', CLAIM_DOCUMENT_BYTES)]
            for _ in range(3): self.tokens.append(io.writer.reserve('outer', CLAIM_DOCUMENT_BYTES))
            os.mkdir(claim_basename(source), 0o700, dir_fd=source.parent_fd)
            self.fd = os.open(claim_basename(source), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=source.parent_fd)
            with os.fdopen(os.open('owner.lock', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                  0o600, dir_fd=self.fd), 'wb'): pass
            capture_linked_preparation(io, source, self.frozen_pins)
            directory, leaf = io.writer.parent('frozen/'+TARGET+'.bin')
            try:
                self.executable_fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            finally:
                os.close(directory)
            self.cwd_fd = held_directory(ROOT)
            io.bound_cwd_fd = self.cwd_fd
            self.executable_identity = identity(os.fstat(self.executable_fd))
            self.check_inputs()
            self.value = dict(schema=CLAIM_SCHEMA, domain=CLAIM_DOMAIN, binding=source.binding,
                execution_root=str(io.output), execution_identity=identity(os.fstat(io.writer.fd)),
                claim_identity=identity(os.fstat(self.fd)), created_utc=now(), qualification=False,
                administrator_deletion_resistance=False)
            self.claim_pin = self.external_json('claim.json', self.value, self.tokens[0])
            io.writer.json('claim-observed.json', self.value, reservation=self.tokens[1])
            link = dict(schema=LINK_SCHEMA, domain=CLAIM_DOMAIN,
                input_prepared=dict(canonical_root=str(source.root), prepared_sha256=source.binding['prepared_sha256'],
                                    inventory_sha256=source.binding['inventory_sha256']),
                execution_root=str(io.output), binding=source.binding,
                claim=dict(canonical_root=str(source.root.with_name(claim_basename(source))),
                           path='claim.json', **self.claim_pin), observed_copy='claim-observed.json',
                terminal_copy='claim-terminal-observed.json', qualification=False)
            size = io.json(io.output/'prepared-claim-link.json', link)
            self.link_pin = dict(bytes=size, sha256=hashlib.sha256(b''.join(json_chunks(link))).hexdigest())
        except (OSError, ValueError, KeyError, TypeError) as error:
            io.writer.poison(error)
            if self.fd is not None: self.finish(False, error=str(error))
            self.close()
            raise

    def check_inputs(self):
        self.source.recheck()
        require(identity(os.stat(self.io.output.name, dir_fd=self.execution_parent_fd, follow_symlinks=False))
                == identity(os.fstat(self.io.writer.fd)), 'HELD_EXECUTION_DIRECTORY_REPLACED')
        for name, pin in self.frozen_pins.items():
            checked_member(self.io.writer.fd, 'frozen/'+name, pin)
        if self.executable_fd is not None:
            require(identity(os.fstat(self.executable_fd)) == self.executable_identity,
                    'HELD_EXECUTABLE_IDENTITY_CHANGED')
            require(identity(os.stat('frozen/'+TARGET+'.bin', dir_fd=self.io.writer.fd,
                    follow_symlinks=False)) == self.executable_identity, 'HELD_EXECUTABLE_REPLACED')

    def external_json(self, name, value, token, *, terminal=False):
        size = sum(len(part) for part in json_chunks(value))
        require(size <= CLAIM_DOCUMENT_BYTES, 'CLAIM_DOCUMENT_16_KIB_CAP')
        directory = os.dup(self.fd)
        try:
            descriptor = os.open(name+'.partial.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
        except BaseException:
            os.close(directory)
            raise
        opened = [directory, name, descriptor]
        self.io.writer.chunks('external-claim/'+name, json_chunks(value), token, exact_bytes=size,
                              opened=opened, terminal=terminal)
        return dict(bytes=size, sha256=hashlib.sha256(b''.join(json_chunks(value))).hexdigest())

    def run_once(self, command, env, *, timeout):
        require(not self.attempted and self.claim_pin is not None, 'ONE_SHOT_NATIVE_OWNER_REQUIRED')
        self.attempted = True
        require(self.io.writer.failure is None, 'POISONED_CLAIM_OWNER')
        self.check_inputs()
        require(command and command[0] == str(self.io.output/'frozen'/ (TARGET+'.bin')), 'EXACT_CLAIMED_EXECUTABLE_REQUIRED')
        require(identity(os.stat(claim_basename(self.source), dir_fd=self.source.parent_fd, follow_symlinks=False))
                == self.value['claim_identity'], 'HELD_CLAIM_DIRECTORY_REPLACED')
        checked_member(self.fd, 'claim.json', self.claim_pin)
        checked_member(self.io.writer.fd, 'claim-observed.json', self.claim_pin)
        checked_member(self.io.writer.fd, 'prepared-claim-link.json', self.link_pin)
        root_path = '/proc/self/fd/'+str(self.io.writer.fd)
        actual = [command[0]]
        for argument in command[1:]:
            path = Path(argument)
            actual.append(root_path+'/'+path.relative_to(self.io.output).as_posix()
                          if path.is_absolute() and path.is_relative_to(self.io.output) else argument)
        bound_env = dict(env, TRNM_IDENTITY_CAMPAIGN_DIR=root_path+'/raw')
        dispatch = dict(schema=FD_DISPATCH_SCHEMA, qualification=False,
            executable_fd=self.executable_fd, executable_identity=self.executable_identity,
            executable_sha256=self.source.binding['binary_sha256'], executable_bytes=self.source.binding['binary_bytes'],
            execution_directory_fd=self.io.writer.fd, execution_identity=identity(os.fstat(self.io.writer.fd)),
            cwd_directory_fd=self.cwd_fd, cwd_identity=identity(os.fstat(self.cwd_fd)),
            actual_command=actual, actual_executable='/proc/self/fd/'+str(self.executable_fd),
            actual_cwd='/proc/self/fd/'+str(self.cwd_fd), actual_raw_root=bound_env['TRNM_IDENTITY_CAMPAIGN_DIR'],
            inherited_fds=sorted({self.executable_fd,self.io.writer.fd,self.cwd_fd}),
            native_descendant_path_binding_complete=False,
            scope='First exec and collector output FD binding only; Rust current_exe descendant dispatch remains unqualified')
        self.ran = True
        return self.io.step('campaign', command, bound_env, timeout=timeout,
                            fd_dispatch=dispatch)

    def finish(self, passed, *, returncode=None, error=None):
        require(not self.terminal_attempted, 'CLAIM_TERMINAL_ALREADY_ATTEMPTED')
        self.terminal_attempted = True
        value = dict(schema=CLAIM_TERMINAL_SCHEMA, domain=CLAIM_DOMAIN, binding=self.source.binding,
            claim_sha256=None if self.claim_pin is None else self.claim_pin['sha256'],
            dispatch_attempted=self.attempted, child_owner_called=self.ran,
            child_exit_observed=returncode is not None, native_owner_success=bool(passed), returncode=returncode,
            error=None if error is None else str(error)[:2048], qualification=False,
            scope='native owner finish; final bundle sealing and qualification remain separate')
        for external, name, token in [(True,'terminal.json',self.tokens[2]),
                                      (False,'claim-terminal-observed.json',self.tokens[3])]:
            try:
                if external: self.external_json(name, value, token, terminal=True)
                else: self.io.writer.json(name, value, reservation=token, terminal=True)
            except (OSError, ValueError, TypeError) as error:
                self.io.writer.poison(error)

    def close(self):
        for token in self.tokens: self.io.writer.cancel(token)
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.execution_parent_fd is not None:
            os.close(self.execution_parent_fd)
            self.execution_parent_fd = None
        for field in ('executable_fd','cwd_fd'):
            descriptor = getattr(self,field)
            if descriptor is not None:
                if field == 'cwd_fd' and self.io.bound_cwd_fd == descriptor:
                    self.io.bound_cwd_fd = None
                os.close(descriptor)
                setattr(self,field,None)


def publish_new(directory_fd, temporary, destination):
    """One Linux NOREPLACE operation; unsupported backends fail without fallback."""
    require(sys.platform.startswith('linux'), 'V2_LINUX_PUBLICATION_REQUIRED')
    library = ctypes.CDLL(None, use_errno=True)
    try:
        operation = library.renameat2
    except AttributeError as error:
        raise OSError(errno.ENOSYS, 'renameat2 unavailable') from error
    operation.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    operation.restype = ctypes.c_int
    if operation(directory_fd, os.fsencode(temporary), directory_fd, os.fsencode(destination), 1):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), destination)


def json_chunks(value):
    encoder = json.JSONEncoder(indent=2, sort_keys=True, allow_nan=False)
    for text in encoder.iterencode(value):
        for offset in range(0, len(text), 65536):
            yield text[offset:offset + 65536].encode('utf-8')
    yield b'\n'


class V2Writer:
    """An owned outer ledger, not the missing SQLite whole-I/O boundary.

    Reservations precede opens/children. No fsync is added to the old Python
    collector's zero-sync policy; this does not claim crash durability. Terminal
    bytes are reserved inside outer128MiB, not guaranteed against physical ENOSPC.
    The caller must retain this single owner until all native writers stop.
    """
    TERMINAL_BYTES = 65536

    def __init__(self, root, *, limits=None):
        self.root = Path(root)
        self.limits = dict(outer=128*MIB-self.TERMINAL_BYTES, terminal=self.TERMINAL_BYTES,
                           binary=192*MIB, inventory=31*MIB)
        if limits is not None:  # Only narrower component controls may be selected.
            require(set(limits) == set(self.limits) and all(type(n) is int and 0 <= n <= self.limits[k]
                    for k, n in limits.items()), 'V2_COMPONENT_LIMITS_CANNOT_EXPAND_PROFILE')
            self.limits = dict(limits)
        self.used = dict.fromkeys(self.limits, 0)
        self.held = dict.fromkeys(self.limits, 0)
        self.failure = None
        self.failure_context = None
        self.terminal_attempted = False
        self.fd = held_directory(self.root)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def poison(self, error):
        if self.failure is None:
            self.failure = str(error)[:2048]

    def reserve(self, bucket, amount, *, terminal=False):
        try:
            require(terminal or self.failure is None, 'V2_WRITER_POISONED')
            require(type(amount) is int and 0 <= amount <= self.limits[bucket]
                    and self.used[bucket] + self.held[bucket] + amount <= self.limits[bucket],
                    'V2_WRITE_BUCKET_CAP:' + bucket)
            self.held[bucket] += amount
            return [bucket, amount, True]
        except (OSError, ValueError, KeyError) as error:
            self.poison(error)
            raise

    def cancel(self, reservation):
        if reservation[2]:
            self.held[reservation[0]] -= reservation[1]
            reservation[2] = False

    def parent(self, name):
        parts = Path(name).parts
        require(parts and not Path(name).is_absolute() and all(p not in ('.', '..') for p in parts)
                and Path(*parts).as_posix() == name, 'V2_OWNED_OUTPUT_PATH_REQUIRED')
        current = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                try:
                    os.mkdir(part, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                os.close(current)
                current = child
            return current, parts[-1]
        except BaseException:
            os.close(current)
            raise

    def open_reserved(self, name, *, reject_existing_final=False):
        directory, leaf = self.parent(name)
        try:
            if reject_existing_final:
                try:
                    os.stat(leaf, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise FileExistsError(errno.EEXIST, 'final output already exists', leaf)
            descriptor = os.open(leaf + '.partial.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            return [directory, leaf, descriptor]
        except BaseException:
            os.close(directory)
            raise

    def chunks(self, name, pieces, reservation, *, exact_bytes=None, terminal=False, opened=None):
        bucket, amount, active = reservation
        directory, written = None, 0
        try:
            require(active and (terminal or self.failure is None), 'V2_WRITER_POISONED_OR_UNRESERVED')
            opened = opened or self.open_reserved(name)
            directory, leaf, descriptor = opened
            temporary = leaf + '.partial.json'
            opened[2] = None
            with os.fdopen(descriptor, 'wb', buffering=0) as stream:
                for piece in pieces:
                    require(isinstance(piece, bytes) and written + len(piece) <= amount,
                            'V2_RESERVED_STREAM_SIZE_EXCEEDED')
                    view = memoryview(piece)
                    while view:
                        count = stream.write(view)
                        require(count is not None and count > 0, 'V2_SHORT_WRITE_WITHOUT_PROGRESS')
                        written += count
                        view = view[count:]
                require(exact_bytes is None or written == exact_bytes, 'V2_SOURCE_LENGTH_CHANGED')
            publish_new(directory, temporary, leaf)
            return written
        except (OSError, ValueError, TypeError) as error:
            self.poison(error)
            raise
        finally:
            self.cancel(reservation)
            self.used[bucket] += written  # A failed partial remains charged and retained.
            if directory is not None:
                os.close(directory)
                opened[0] = None

    def json(self, name, value, *, bucket='outer', terminal=False, reservation=None):
        try:
            require(terminal or self.failure is None, 'V2_WRITER_POISONED')
            size = 0
            ceiling = min(self.limits[bucket], 16*MIB if bucket == 'outer' else self.limits[bucket])
            if reservation is not None: ceiling = min(ceiling, reservation[1])
            for piece in json_chunks(value):
                size += len(piece)
                require(size <= ceiling, 'V2_JSON_FILE_CAP:' + bucket)
            token = reservation or self.reserve(bucket, size, terminal=terminal)
            require(size <= token[1], 'V2_JSON_RESERVATION_EXCEEDED')
            return self.chunks(name, json_chunks(value), token, exact_bytes=size, terminal=terminal)
        except (OSError, ValueError, TypeError) as error:
            self.poison(error)
            raise

    def copy(self, name, source, *, bucket='outer', expected=None, source_directory_fd=None):
        try:
            with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_directory_fd), 'rb') as stream:
                before = os.fstat(stream.fileno())
                require(stat.S_ISREG(before.st_mode), 'V2_REGULAR_SOURCE_REQUIRED')
                ceiling = 16*MIB if bucket == 'outer' else self.limits[bucket]
                require(before.st_size <= ceiling, 'V2_COPY_FILE_CAP:' + bucket)
                token = self.reserve(bucket, before.st_size)
                fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                def pieces():
                    digest = hashlib.sha256()
                    for data in iter(lambda: stream.read(65536), b''):
                        digest.update(data)
                        yield data
                    require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before),
                            'V2_SOURCE_CHANGED_DURING_COPY')
                    require(expected is None or digest.hexdigest() == expected, 'V2_COPY_SHA_MISMATCH')
                return self.chunks(name, pieces(), token, exact_bytes=before.st_size)
        except (OSError, ValueError, TypeError) as error:
            self.poison(error)
            raise

    def terminal(self, phase, error):
        self.poison(error)
        require(not self.terminal_attempted, 'V2_TERMINAL_ALREADY_ATTEMPTED')
        self.terminal_attempted = True
        return self.json('outer-terminal.json', dict(schema='pon-identity-outer-terminal-v2',
            phase=str(phase)[:128], first_error=self.failure, qualification=False,
            observed_step=self.failure_context,
            used_bytes=dict(self.used), reserved_bytes=dict(self.held), limits=dict(self.limits),
            physical_enospc_terminal_guaranteed=False, sync_calls_added=0), bucket='terminal', terminal=True)


class CollectorIO:
    """Keep v1 calls unchanged; own every new v2 collector output."""
    def __init__(self, output, version):
        self.output, self.version = output, version
        self.linked_source = None
        self.bound_cwd_fd = None
        self.writer = V2Writer(output) if version == 'v2' else None

    def json(self, path, value):
        if self.writer is None:
            return write_new(path, value)
        return self.writer.json(path.relative_to(self.output).as_posix(), value)

    def copy(self, source, destination, *, expected=None):
        if self.writer is None:
            with source.open('rb') as original, destination.open('xb') as target:
                shutil.copyfileobj(original, target)
            return
        name = destination.relative_to(self.output).as_posix()
        bucket = 'binary' if name in (TARGET + '.bin', 'frozen/' + TARGET + '.bin') else 'outer'
        return self.writer.copy(name, source, bucket=bucket, expected=expected)

    def step(self, name, command, env, *, timeout, stdout_limit=16*MIB, stderr_limit=4*MIB,
             fd_dispatch=None):
        if self.writer is None:
            return run_step(self.output, name, command, env, timeout=timeout,
                            stdout_limit=stdout_limit, stderr_limit=stderr_limit)
        tokens, opened = [], []
        start = time.monotonic_ns()
        row = dict(name=name, command=command, cwd=str(ROOT), outer_stage_timeout_seconds=timeout,
            returncode=None, error=None, stdout=name + '.stdout.log', stderr=name + '.stderr.log',
            stdout_truncated=False, stderr_truncated=False)
        if fd_dispatch is not None:
            row['fd_dispatch'] = fd_dispatch
        stdout = stderr = b''
        try:
            require(0 <= stdout_limit <= 16*MIB and 0 <= stderr_limit <= 4*MIB,
                    'V2_ORIGINAL_STREAM_CAPS_REQUIRED')
            tokens = [self.writer.reserve('outer', stdout_limit)]
            tokens.append(self.writer.reserve('outer', stderr_limit))
            tokens.append(self.writer.reserve('outer', 65536))
            opened.append(self.writer.open_reserved(row['stdout'], reject_existing_final=True))
            opened.append(self.writer.open_reserved(row['stderr'], reject_existing_final=True))
            try:
                options = (dict(cwd='/proc/self/fd/'+str(self.bound_cwd_fd), pass_fds=(self.bound_cwd_fd,))
                           if self.bound_cwd_fd is not None else dict(cwd=ROOT))
                actual = command
                if fd_dispatch is not None:
                    require(fd_dispatch['schema'] == FD_DISPATCH_SCHEMA
                            and fd_dispatch['execution_identity'] == identity(os.fstat(self.writer.fd))
                            and fd_dispatch['actual_raw_root'] == env['TRNM_IDENTITY_CAMPAIGN_DIR'],
                            'BOUND_FIRST_EXEC_DISPATCH_REQUIRED')
                    actual = fd_dispatch['actual_command']
                    options = dict(cwd=fd_dispatch['actual_cwd'], executable_fd=fd_dispatch['executable_fd'],
                                   pass_fds=tuple(fd_dispatch['inherited_fds']))
                captured = run_bounded(actual, b'', timeout=timeout, stdout_limit=stdout_limit,
                                       stderr_limit=stderr_limit, env=env, **options)
                row['returncode'], stdout, stderr = captured.returncode, captured.stdout, captured.stderr
            except ProcessFailure as error:
                row.update(returncode=error.returncode, error=str(error),
                    stdout_truncated=error.stdout_truncated, stderr_truncated=error.stderr_truncated)
                stdout, stderr = error.stdout, error.stderr
            except (OSError, ValueError) as error:
                row['error'] = str(error)
            self.writer.chunks(row['stdout'], [stdout], tokens[0], exact_bytes=len(stdout), opened=opened[0])
            self.writer.chunks(row['stderr'], [stderr], tokens[1], exact_bytes=len(stderr), opened=opened[1])
            stdout_pin, _ = checked_member(self.writer.fd, row['stdout'], limit=stdout_limit)
            stderr_pin, _ = checked_member(self.writer.fd, row['stderr'], limit=stderr_limit)
            row.update(elapsed_ns=time.monotonic_ns()-start, stdout_bytes=len(stdout), stderr_bytes=len(stderr),
                       stdout_sha256=stdout_pin['sha256'], stderr_sha256=stderr_pin['sha256'])
            row['elapsed_seconds'] = row['elapsed_ns'] / 1_000_000_000
            row['complete_success'] = row['returncode'] == 0 and row['error'] is None
            self.writer.json(name + '.step.json', row, reservation=tokens[2])
            if not row['complete_success']:
                self.writer.poison(row['error'] or 'V2_CHILD_NONZERO_EXIT')
            return row
        except (OSError, ValueError, TypeError) as error:
            if self.writer.failure_context is None:
                self.writer.failure_context = dict(name=str(name)[:128], returncode=row['returncode'],
                    child_error=None if row['error'] is None else str(row['error'])[:2048],
                    timeout_seconds=str(timeout)[:64], elapsed_ns=time.monotonic_ns()-start,
                    stdout_truncated=row['stdout_truncated'], stderr_truncated=row['stderr_truncated'],
                    observed_stdout_bytes=len(stdout), observed_stderr_bytes=len(stderr),
                    observed_stdout_sha256=hashlib.sha256(stdout).hexdigest(),
                    observed_stderr_sha256=hashlib.sha256(stderr).hexdigest(), raw_preservation_complete=False)
            self.writer.poison(error)
            raise
        finally:
            for directory, _, descriptor in opened:
                if descriptor is not None:
                    os.close(descriptor)
                if directory is not None:
                    os.close(directory)
            for token in tokens:
                self.writer.cancel(token)

    def source(self, label, env, head, tree):
        if self.writer is None:
            return exact_source(self.output, label, env, head, tree)
        validate_source(source_snapshot(), head, tree)
        row = self.step(label, [sys.executable, 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                               '--expected-head', head], env, timeout=120)
        require(row['complete_success'], 'RAW_SOURCE_IDENTITY_FAILED')
        value = json.loads(checked_member(self.writer.fd, row['stdout'], retain=True, limit=16*MIB)[1])
        require(value['tested_commit'] == head and value['tested_tree'] == tree
                and value['tracked_worktree_verified'] is True, 'RAW_SOURCE_STDOUT_IDENTITY_FAILED')
        self.json(self.output / (label + '.json'), value)
        return row

    def finish(self, name, result, passed, *, preparation_only=False):
        if self.writer is None:
            write_new(self.output / name, result)
            inventory(self.output, version='v1', preparation_only=preparation_only)
            return passed
        try:
            try:
                self.json(self.output / name, result)
                if not passed:
                    self.writer.poison(result.get('failure') or 'V2_COLLECTION_FAILED')
                if self.writer.failure is None:
                    inventory(self.output, version='v2', preparation_only=preparation_only,
                              writer=self.writer, linked_source=self.linked_source)
            except (OSError, ValueError, TypeError) as error:
                self.writer.poison(error)
            if self.writer.failure is not None:
                try:
                    self.writer.terminal(name, self.writer.failure)
                except (OSError, ValueError, TypeError) as error:
                    print(json.dumps(dict(outer_terminal_write_failed=str(error)[:2048],
                        qualification=False, physical_enospc_terminal_guaranteed=False)), file=sys.stderr)
                return False
            return passed
        finally:
            self.writer.close()


def profile(version):
    require(version in ('v1', 'v2'), 'EXPLICIT_SUPPORTED_EVIDENCE_PROFILE_REQUIRED')
    return dict(version=version, plan=dict(PLAN),
        campaign_schema='native-public-v3-identity-churn-supplement-' + version,
        construction_schema='public-v3-real-identity-prefix-' + version,
        job_schema='native-public-v3-identity-actor-job-' + version,
        prepared_schema='pon-identity-churn-prepared-' + version,
        execution_schema=('pon-identity-churn-execution-v1' if version == 'v1'
                          else 'pon-identity-churn-execution-v2-one-shot-v1'),
        inventory_schema='pon-identity-artifact-files-' + version,
        selector=SELECTOR if version == 'v1' else SELECTOR + '_v2',
        evidence_caps=None if version == 'v1' else deepcopy(EVIDENCE_CAPS_V2),
        execution_enabled=version == 'v1' or V2_FULL_IO_BOUNDARY_IMPLEMENTED)


def now():
    return datetime.now(timezone.utc).isoformat()


def environment():
    validate_build_environment(os.environ)
    return {key: value for key, value in os.environ.items() if not key.startswith('TRNM_')}


def inventory(output, *, version='v1', preparation_only=False, writer=None, linked_source=None):
    if version == 'v2' and writer is None:
        owner = V2Writer(output)
        try:
            return inventory(output, version=version, preparation_only=preparation_only,
                             writer=owner, linked_source=linked_source)
        finally:
            owner.close()
    rows = []
    if version == 'v1':
        for path in sorted(output.rglob('*')):
            require(not path.is_symlink(), 'NO_SYMLINK_ARTIFACTS')
            relative = path.relative_to(output).as_posix()
            if path.is_file() and relative != 'artifact-files.json':
                rows.append(dict(path=relative, bytes=path.stat().st_size, sha256=sha(path)))
    else:
        directory = os.dup(writer.fd) if writer is not None else held_directory(output)
        try:
            for name in held_file_names(directory):
                if name != 'artifact-files.json':
                    rows.append(dict(path=name, **checked_member(directory, name)[0]))
                    require(len(rows) <= 200_000, 'V2_ARTIFACT_FILE_COUNT_CAP')
        finally:
            os.close(directory)
    selected = profile(version)
    value = dict(schema=selected['inventory_schema'], files=rows)
    if version == 'v1':
        write_new(output / 'artifact-files.json', value)
        return
    size = 0
    for piece in json_chunks(value):
        size += len(piece)
        require(size <= 31 * MIB, 'V2_INVENTORY_31_MIB_CAP')
    require(sum(row['bytes'] for row in rows) + size <= 8192 * MIB,
            'V2_ORIGINAL_ARTIFACT_AND_INVENTORY_CAP')
    if selected['evidence_caps'] is not None:
        sys.path.insert(0, str(ROOT / 'scripts/ci'))
        from check_pon_identity_churn import evidence_ledger_v2, linked_evidence_ledger_v2, claim_inventory
        files = {row['path']: row for row in rows}
        require('prepared-claim-link.json' not in files or linked_source is not None,
                'HELD_ORIGINAL_PREPARATION_REQUIRED_FOR_LINKED_INVENTORY')
        if linked_source is None:
            evidence_ledger_v2(files, size, selected['evidence_caps'], strict=False, preparation_only=preparation_only)
        else:
            linked_source.recheck()
            original = dict(linked_source.bundle.files)
            original['artifact-files.json'] = dict(bytes=os.stat('artifact-files.json', dir_fd=linked_source.bundle.fd,
                    follow_symlinks=False).st_size, sha256=linked_source.binding['inventory_sha256'])
            linked_evidence_ledger_v2(files, size, original, claim_inventory(linked_source)[1],
                                      selected['evidence_caps'], strict=False)
    owned = writer is None
    writer = writer or V2Writer(output)
    try:
        writer.json('artifact-files.json', value, bucket='inventory')
    finally:
        if owned:
            writer.close()



def prepare(args, output):
    selected = profile(getattr(args, 'profile', 'v1'))
    target = args.target_dir.resolve()
    require(not target.is_relative_to(ROOT) and not target.is_relative_to(output)
            and not output.is_relative_to(target), 'ISOLATED_BUILD_TARGET_REQUIRED')
    env = environment()
    io = CollectorIO(output, selected['version'])
    env.update(CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS='2', CARGO_NET_OFFLINE='true',
               RUSTUP_TOOLCHAIN='1.95.0', PYTHONDONTWRITEBYTECODE='1')
    result = dict(schema=selected['prepared_schema'], head=args.expected_head, tree=args.expected_tree,
        created_utc=now(), prepared=False, failure=None, steps=[], plan=PLAN,
        collector_seconds=args.collection_seconds, selector_executed=False, runner_sha256=sha(__file__),
        acceptance=ACCEPTANCE)
    try:
        require(selected['version'] == 'v1' or selected['evidence_caps'] is not None,
                'V2_COMPLETE_BYTE_LEDGER_NOT_FROZEN')
        require(selected['execution_enabled'], 'V2_FULL_IO_BOUNDARY_NOT_IMPLEMENTED')
        if selected['version'] == 'v2':
            result['evidence_caps'] = selected['evidence_caps']
        require(type(args.collection_seconds) is int and 0 < args.collection_seconds <= 86400,
                'EXPLICIT_FINITE_COLLECTION_SECONDS_REQUIRED')
        result['steps'].append(io.source('source-before', env, args.expected_head, args.expected_tree))
        command = [str(args.cargo.resolve()), '+1.95.0', 'test', '--locked', '--offline', '--release',
            '--jobs', '2', '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-pon-node',
            '--test', TARGET, '--no-run', '--message-format=json']
        build = io.step('build', command, env, timeout=1800)
        result['steps'].append(build)
        require(build['complete_success'], 'NATIVE_BUILD_FAILED')
        artifacts = [json.loads(line) for line in (output / build['stdout']).read_bytes().splitlines()]
        artifacts = [row for row in artifacts if row.get('reason') == 'compiler-artifact'
            and row.get('target', {}).get('name') == TARGET and row.get('executable')]
        require(len(artifacts) == 1, 'ONE_EXACT_TEST_BINARY_REQUIRED')
        artifact = Path(artifacts[0]['executable']).resolve()
        require(artifact.is_relative_to(target) and artifacts[0]['profile'] == dict(debug_assertions=False,
            debuginfo=0, opt_level='3', overflow_checks=False, test=True), 'EXACT_RELEASE_PROFILE_REQUIRED')
        binary = output / (TARGET + '.bin')
        io.copy(artifact, binary)
        binary.chmod(0o500)
        require(sha(binary) == sha(artifact), 'BINARY_CHANGED_DURING_CAPTURE')
        result['binary'] = dict(path=str(binary), sha256=sha(binary), bytes=binary.stat().st_size,
                                compiler_profile=artifacts[0]['profile'])
        result['steps'].append(io.source('source-after', env, args.expected_head, args.expected_tree))
        result['prepared'] = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['failure'] = str(error)
    result['completed_utc'] = now()
    result['files'] = {p.relative_to(output).as_posix(): dict(bytes=p.stat().st_size, sha256=sha(p))
                      for p in sorted(output.rglob('*')) if p.is_file() and not p.is_symlink()}
    return io.finish('prepared.json', result, result['prepared'], preparation_only=True)


def execute(args, output):
    selected = profile(getattr(args, 'profile', 'v1'))
    env = environment()
    io = CollectorIO(output, selected['version'])
    result = dict(schema=selected['execution_schema'], head=args.expected_head, tree=args.expected_tree,
        started_utc=now(), complete_success=False, selector_executed=False, failure=None,
        prepared_sha256=args.prepared_sha256, plan=PLAN, post_observations={})
    prepared = binary = resources = linked_source = claim_owner = None
    try:
        require(selected['version'] == 'v1' or selected['evidence_caps'] is not None,
                'V2_COMPLETE_BYTE_LEDGER_NOT_FROZEN')
        require(selected['execution_enabled'], 'V2_FULL_IO_BOUNDARY_NOT_IMPLEMENTED')
        if selected['version'] == 'v2':
            require(getattr(args, 'prepared_inventory_sha256', None), 'EXPLICIT_PREPARED_INVENTORY_SHA_REQUIRED')
            linked_source = PreparedInput(args.prepared.absolute(), args.prepared_sha256,
                args.prepared_inventory_sha256, args.expected_head, args.expected_tree)
            prepared = linked_source.value
            require(prepared['binary']['compiler_profile'] == dict(debug_assertions=False, debuginfo=0,
                opt_level='3', overflow_checks=False, test=True), 'EXACT_RELEASE_PROFILE_REQUIRED')
            claim_owner = ClaimOwner(io, linked_source)
            frozen = output / 'frozen'
            result['evidence_caps'] = selected['evidence_caps']
        else:
            require(sha(args.prepared) == args.prepared_sha256, 'EXACT_PREPARED_MANIFEST_SHA_REQUIRED')
            prepared = json.loads(args.prepared.read_text())
            require(prepared['schema'] == selected['prepared_schema'] and prepared['prepared'] is True
                and prepared['selector_executed'] is False and prepared['plan'] == PLAN
                and prepared['acceptance'] == ACCEPTANCE
                and prepared['runner_sha256'] == sha(__file__)
                and prepared['head'] == args.expected_head and prepared['tree'] == args.expected_tree,
                'FROZEN_EXACT_SOURCE_PREPARATION_REQUIRED')
            if selected['version'] == 'v2':
                require(prepared['evidence_caps'] == selected['evidence_caps'], 'FROZEN_V2_BYTE_LEDGER_REQUIRED')
                result['evidence_caps'] = selected['evidence_caps']
            binary = Path(prepared['binary']['path'])
            require(binary == args.prepared.resolve().parent / (TARGET + '.bin') and not binary.is_symlink()
                and binary.stat().st_mode & 0o222 == 0 and sha(binary) == prepared['binary']['sha256'],
                'FROZEN_BINARY_REQUIRED')
            frozen = output / 'frozen'
            frozen.mkdir()
            for name, pin in prepared['files'].items():
                parts = Path(name)
                require(not parts.is_absolute() and parts.as_posix() == name and '..' not in parts.parts,
                        'FROZEN_MEMBER_PATH_REQUIRED')
                origin, destination = args.prepared.resolve().parent / parts, frozen / parts
                require(all(not p.is_symlink() for p in (origin, *origin.parents))
                        and origin.is_file() and origin.stat().st_size == pin['bytes']
                        and sha(origin) == pin['sha256'], 'PREPARATION_MEMBER_CHANGED')
                destination.parent.mkdir(parents=True, exist_ok=True)
                io.copy(origin, destination, expected=pin['sha256'])
                require(sha(destination) == pin['sha256'], 'FROZEN_COPY_CHANGED')
            io.copy(args.prepared, frozen / 'prepared.json', expected=args.prepared_sha256)
            require(sha(frozen / 'prepared.json') == args.prepared_sha256, 'PREPARED_CHANGED_DURING_CAPTURE')
        binary = frozen / (TARGET + '.bin')
        if claim_owner is None: binary.chmod(0o500)
        else: os.fchmod(claim_owner.executable_fd, 0o500)
        result['binary'] = dict(prepared['binary'], path=str(binary))
        result['collector_seconds'] = prepared['collector_seconds']
        resources = resource_observation()
        io.json(output / 'resource-before.json', resources)
        validate_resources(resources, 10)
        result['source_before'] = io.source('source-before', env, args.expected_head, args.expected_tree)
        if claim_owner is None:
            write_new(args.prepared.resolve().parent / 'execute-claimed.json',
                dict(out=str(output), started_utc=now(), prepared_sha256=args.prepared_sha256))
        env.update(TRNM_IDENTITY_CAMPAIGN_DIR=str(output / 'raw'), TRNM_IDENTITY_SOURCE_HEAD=args.expected_head,
                   TRNM_IDENTITY_SOURCE_TREE=args.expected_tree)
        result['selector_executed'] = True
        command = [str(binary), '--exact', selected['selector'], '--ignored', '--nocapture', '--test-threads=1']
        result['step'] = (io.step('campaign', command, env, timeout=prepared['collector_seconds'])
            if claim_owner is None else claim_owner.run_once(command, env, timeout=prepared['collector_seconds']))
        require(result['step']['complete_success'], 'NATIVE_SUPPLEMENT_FAILED')
        result['complete_success'] = True  # Native exit only; the strict reader is separate.
    except (OSError, ValueError, KeyError, TypeError) as error:
        result['failure'] = str(error)
    finally:
        if result['selector_executed']:
            for label in ('binary', 'source', 'resources'):
                row = dict(complete_success=False, failure=None)
                try:
                    if label == 'binary':
                        if claim_owner is None:
                            require(sha(binary) == prepared['binary']['sha256'], 'FROZEN_BINARY_CHANGED')
                        else:
                            claim_owner.check_inputs()
                    elif label == 'source':
                        io.source('source-after', env, args.expected_head, args.expected_tree)
                    else:
                        after = resource_observation()
                        io.json(output / 'resource-after.json', after)
                        validate_resources(after, 10)
                        require(after['cgroup'] == resources['cgroup'], 'RESOURCE_SCOPE_CHANGED')
                    row['complete_success'] = True
                except (OSError, ValueError, KeyError, TypeError) as error:
                    row['failure'] = str(error)
                    result['complete_success'] = False
                result['post_observations'][label] = row
    result['completed_utc'] = now()
    try:
        if claim_owner is not None:
            claim_owner.finish(result['complete_success'], returncode=result.get('step', {}).get('returncode'),
                               error=result['failure'])
            claim_owner.close()
        return io.finish('results.json', result, result['complete_success'])
    finally:
        if claim_owner is not None: claim_owner.close()
        if linked_source is not None: linked_source.close()
        if io.writer is not None: io.writer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'execute'))
    for name in ('out', 'target-dir', 'cargo', 'prepared'):
        parser.add_argument('--' + name, type=Path, required=name == 'out')
    for name in ('expected-head', 'expected-tree'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--prepared-sha256')
    parser.add_argument('--prepared-inventory-sha256')
    parser.add_argument('--collection-seconds', type=int)
    parser.add_argument('--profile', choices=('v1', 'v2'), default='v1')
    args = parser.parse_args()
    validate_source(source_snapshot(), args.expected_head, args.expected_tree)
    output = args.out.resolve()
    require(not output.is_relative_to(ROOT), 'OUTPUT_OUTSIDE_SOURCE_REQUIRED')
    require((args.target_dir and args.cargo and args.collection_seconds) if args.mode == 'prepare'
            else (args.prepared and args.prepared_sha256), 'MODE_ARGUMENTS_REQUIRED')
    output.mkdir(parents=True, exist_ok=False)
    passed = prepare(args, output) if args.mode == 'prepare' else execute(args, output)
    print(json.dumps(dict(out=str(output), mode=args.mode, native_collection_success=passed,
                         campaign_reader_qualified=False)))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
