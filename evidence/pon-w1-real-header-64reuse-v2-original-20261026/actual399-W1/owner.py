#!/usr/bin/env python3
"""One NOT-YET-RUN incremental W1 release build; no native W1 execution.

The trusted local launcher must own a fresh absolute-Nice10, CPU4/16GiB
control-group unit and accept only its real terminal within the remaining280s.
The receipt is a component observation, never a prepared/native qualification.
"""
import time
START = time.monotonic()
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
WORKSPACE = Path('/home/qian-qi/Documents/Codex/2026-10-25/github-trillionnium-chain-https-github-com')
HERE = Path(__file__).resolve().parent
PREVIOUS = WORKSPACE / 'work/ci-follow/pn1-v3-clean-source-public-qualification-20261026-001'
SOURCE, TARGET = PREVIOUS / 'ownedsource', PREVIOUS / 'target'
OUTPUT = HERE / 'execution-001'
HEAD = '399dd82608df72c71c502b8bda0aa95898794080'
TREE = '66ceec03cd2b67ae88a5662cf75e4ba80292cd2b'
BRANCH = 'docs/chain-audit-remediation-20261022'
ORIGIN = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
EXAMPLE = 'pon_w1_real_header_reuse_v1'
EXAMPLE_PATH = 'trillionnium/crates/trnm-pon-node/examples/' + EXAMPLE + '.rs'
EXAMPLE_SHA = '414ce8909db072f7fe511f69337735be2fe4b0b1c575e5cbfac56216c1d40748'
PROFILE = dict(debug_assertions=False, debuginfo=0, opt_level='3', overflow_checks=False, test=False)
DOMAIN = 'pn1-w1-clean399-incremental-normal-release-build-owner-v1'
PREVIOUS_CHARGED, ORIGINAL_BUILD_SECONDS, MAX_OWNER_SECONDS = 320, 600, 280
DEADLINE, FINAL_RESERVE = START + MAX_OWNER_SECONDS, 35
TARGET_ID = dict(device=2050, inode=54057931)
MIB = 1024**2
PINS = {
    'scripts/run_pon_native_io_component.py': 'c5e8d582d2b53411b15114c6c7fd03b618f5ce3c79ee25bc198dd372857bbc65',
    'scripts/run_pon_identity_churn.py': '177bdbdf505299693618e4060cb65a4c8a46cf1ec5c85414a38d04accdd139cf',
    'scripts/run_pon_w1_native_campaign.py': 'eff0930837331f08882a0d69a6909e8f8dda2b23dad58cf0e6bc60d175f0a431',
    'scripts/read_original_native_campaign.py': '9f7b088084f089e298e8bb66e07009c7cc844a4197bc06b33d7bf33f86ba93ff',
    'formal/pon-nakamoto-v1/bounded_process.py': 'da175430a6b669d3e7d40fe7ec0e7bc00fe6e992cc2d4d443af07209b4013815',
    'scripts/ci/check_pon_identity_churn.py': '7000380737367657292f2e7cc6f779dde8ce64eaaebf5c196de733caf9ffbe71',
}
OLD_PREPARED_SHA = '924fd7428cdf079c2b91a6cdb4af9aabd9896e732e870420a0c3b4929b61a0ac'
OLD_INVENTORY_SHA = '49945617a5911c49bc402bd74f008ab9e023aa35286613de26464d5fcefba12a'
OLD_ELF_SHA = '38f34d7464fd808ceae92699d0dbaaba0b928c34d9498819e10f477cf8628a51'
OLD_ELF_REL = 'release/deps/public_v3_identity_campaign-19bfac7fcfb49be1'
OLD_TERMINAL_SHA = '7561230b5f1d971d5c2cc25e8c1a1f484309c7697e28c6de23381505b404aefe'
FLAGS = dict.fromkeys(('qualifying_execution_receipt', 'source_binary_attestation',
    'native_W1_64_reuse_executed', 'independent_relation_reader_passed',
    'all_13_kernels_cost_audited', 'minimum_known_cost_qualified', 'hardware_fairness_qualified',
    'original_three_FD_caller_qualified', 'full_W1_4097_qualified',
    'whole_writer_qualified', 'full_guard_enabled', 'task_complete', 'merge_ready'), False)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hash_file(path):
    require(not path.is_symlink() and path.is_file(), 'REGULAR_PINNED_INPUT_REQUIRED')
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def remaining(reserve=FINAL_RESERVE):
    value = DEADLINE - time.monotonic() - reserve
    require(value > 0, 'W1_REMAINING_BUILD_BUDGET_EXHAUSTED')
    return value


def load_low_levels():
    for name, pin in PINS.items():
        require(hash_file(SOURCE / name) == pin, 'PINNED_LOW_LEVEL_SOURCE_CHANGED:' + name)
    require(hash_file(SOURCE / EXAMPLE_PATH) == EXAMPLE_SHA, 'W1_EXAMPLE_SOURCE_CHANGED')
    sys.path[:0] = [str(SOURCE / 'scripts'), str(SOURCE / 'scripts/ci'),
                    str(SOURCE / 'formal/pon-nakamoto-v1')]
    spec = importlib.util.spec_from_file_location('w1_pinned_component_low_levels',
        SOURCE / 'scripts/run_pon_native_io_component.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run():
    require(PREVIOUS_CHARGED + MAX_OWNER_SECONDS == ORIGINAL_BUILD_SECONDS,
            'ORIGINAL_W1_BUILD_LEDGER_CHANGED')
    require(HERE == WORKSPACE / 'work/ci-follow/W1-clean399-normal-release-actual-build-20261026-001',
            'PINNED_NEW_OWNER_LOCATION_REQUIRED')
    n = load_low_levels()
    # No thread exists here. F_DUPFD_CLOEXEC allocates a free FD atomically;
    # an occupied6 is refused, never closed or overwritten to imitate old output.
    try:
        os.fstat(6)
    except OSError as error:
        require(error.errno == errno.EBADF, 'FD6_STATE_UNKNOWN')
    else:
        raise ValueError('FD6_ALREADY_OCCUPIED_NO_REBIND')
    held = n.held_directory(TARGET)
    if held != 6:
        try:
            copied = fcntl.fcntl(held, fcntl.F_DUPFD_CLOEXEC, 6)
            if copied != 6:
                os.close(copied)
                raise ValueError('FD6_UNAVAILABLE_NO_REBIND')
        finally:
            os.close(held)
    target_fd = 6
    parent_fd = source_fd = output_parent = ancestor_fd = None
    io = monitor = None
    row = dict(schema=DOMAIN, head=HEAD, tree=TREE, source=str(SOURCE),
        target=str(TARGET), output=str(OUTPUT), started_utc=n.now(),
        owner_sha256=hash_file(Path(__file__)), previous_conservative_charge_seconds=PREVIOUS_CHARGED,
        original_build_seconds=ORIGINAL_BUILD_SECONDS, remaining_owner_seconds=MAX_OWNER_SECONDS,
        original_formal_build_absolute_window_previously_started=False,
        target_reuse='sequential-incremental-cache-reuse-not-fresh-independent-build',
        target_exclusivity='trusted-operator-serialization-not-enforced-against-unrelated-processes',
        low_level_sources=PINS, source_example_sha256=EXAMPLE_SHA,
        borrowed_low_level_schemas_are_not_W1_qualification=True,
        build_candidate_success_before_final_io=False, failure=None, observations=[],
        outer_durable_terminal_and_elapsed_acceptance_required=True, **FLAGS)

    def fail(stage, error):
        text = str(error)[:2048]
        if row['failure'] is None:
            row['failure'] = text
        row['observations'].append(dict(stage=stage, error=text))
        row['build_candidate_success_before_final_io'] = False

    try:
        parent_fd = n.held_directory(PREVIOUS)
        source_fd = n.held_directory(SOURCE)
        output_parent = n.held_directory(HERE)
        ancestor_fd = n.held_directory(PREVIOUS.parent)
        parent_id, source_id = n.identity(os.fstat(parent_fd)), n.identity(os.fstat(source_fd))
        output_parent_id = n.identity(os.fstat(output_parent))
        ancestor_id = n.identity(os.fstat(ancestor_fd))
        require(n.owned_directory(target_fd) == TARGET_ID, 'ORIGINAL_TARGET_IDENTITY_CHANGED')
        require(n.identity(os.stat(PREVIOUS.name, dir_fd=ancestor_fd, follow_symlinks=False)) == parent_id
            and n.identity(os.stat(HERE.name, dir_fd=ancestor_fd, follow_symlinks=False)) == output_parent_id,
            'PINNED_SOURCE_TARGET_OUTPUT_ANCESTOR_BINDING_REQUIRED')
        require(n.identity(os.stat('target', dir_fd=parent_fd, follow_symlinks=False)) == TARGET_ID,
                'ORIGINAL_TARGET_NAME_CHANGED')
        require(n.identity(os.stat('ownedsource', dir_fd=parent_fd, follow_symlinks=False)) == source_id,
                'HELD_SOURCE_BINDING_CHANGED')
        os.mkdir(OUTPUT.name, 0o700, dir_fd=output_parent)

        class BuildIO(n.ComponentIO):
            def build_step(self, command, env, held_target):
                require(held_target == 6 and env['CARGO_TARGET_DIR'] == '/proc/self/fd/6',
                        'W1_HELD_FD6_BUILD_BINDING_REQUIRED')
                return self.owned_step('w1-normal-release-cargo', command, env, remaining(),
                    dict(cwd=SOURCE, pass_fds=(held_target,)))

        io = BuildIO(OUTPUT)
        row['held_binding'] = dict(parent=parent_id, source=source_id, target=TARGET_ID,
            target_fd=6, actual_target='/proc/self/fd/6',
            ancestor=ancestor_id, output_parent=output_parent_id, output=n.identity(os.fstat(io.writer.fd)))
        before = n.resources()
        require(set(range(4)).issubset(os.sched_getaffinity(0)), 'PINNED_FOUR_BUILD_CPUS_UNAVAILABLE')
        io.json(OUTPUT / 'resources-before.json', before)
        # Reject ambient build overrides before constructing the explicit child
        # whitelist. No value from an undeclared CARGO_/RUST* variable is forwarded.
        n.validate_build_environment(os.environ)
        require(os.environ.get('HOME') == '/home/qian-qi', 'TRUSTED_INSTALLED_HOME_REQUIRED')
        env = dict(HOME=os.environ['HOME'], PATH='/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin',
            LANG='C.UTF-8', LC_ALL='C.UTF-8', CARGO_TARGET_DIR='/proc/self/fd/6',
            CARGO_BUILD_JOBS='2', CARGO_NET_OFFLINE='true', RUSTUP_TOOLCHAIN='1.95.0',
            PYTHONDONTWRITEBYTECODE='1', GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0')
        row['child_environment_whitelist'] = env

        def step(name, command, cap=10):
            value = io.owned_step(name, command, env, min(cap, remaining()), dict(cwd=SOURCE))
            require(value['complete_success'], 'W1_CHECK_FAILED:' + name)
            return n.checked_member(io.writer.fd, value['stdout'], retain=True, limit=16*MIB)[1]

        def source_check(label):
            values = {}
            for key, args in [('head', ['rev-parse', 'HEAD']), ('tree', ['rev-parse', 'HEAD^{tree}']),
                    ('status', ['status', '--porcelain=v1', '--untracked-files=all']),
                    ('branch', ['branch', '--show-current']), ('origin', ['remote', 'get-url', 'origin'])]:
                values[key] = step(label + '-' + key, ['git', '-c', 'core.hooksPath=/dev/null',
                    '-c', 'core.fsmonitor=false', *args]).decode().strip()
            require(values == dict(head=HEAD, tree=TREE, status='', branch=BRANCH, origin=ORIGIN),
                    'W1_CLEAN_EXACT_COMMITTED_SOURCE_REQUIRED')
            proof = n.strict_json(step(label + '-tracked-bytes', ['/usr/bin/python3', '-B',
                'scripts/ci/verify_ci_source.py', '--kind', 'head', '--expected-head', HEAD], 25))
            require(proof['tested_commit'] == HEAD and proof['tested_tree'] == TREE
                and proof['tracked_worktree_verified'] is True, 'W1_TRACKED_SOURCE_BYTES_NOT_VERIFIED')
            require(n.identity(os.fstat(parent_fd)) == parent_id
                and n.identity(os.fstat(source_fd)) == source_id
                and n.identity(os.fstat(ancestor_fd)) == ancestor_id
                and n.identity(os.stat(PREVIOUS.name, dir_fd=ancestor_fd, follow_symlinks=False)) == parent_id
                and n.identity(os.stat('ownedsource', dir_fd=parent_fd, follow_symlinks=False)) == source_id,
                'W1_SOURCE_OR_ANCESTOR_REPLACED')
            for name, pin in PINS.items():
                require(n.checked_member(source_fd, name)[0]['sha256'] == pin, 'W1_LOW_LEVEL_CHANGED')
            require(n.checked_member(source_fd, EXAMPLE_PATH)[0]['sha256'] == EXAMPLE_SHA,
                    'W1_EXAMPLE_CHANGED')
            return values

        def old_package_check():
            fd = n.held_directory(PREVIOUS / 'prepared')
            try:
                require(n.checked_member(fd, 'prepared.json')[0]['sha256'] == OLD_PREPARED_SHA,
                        'OLD_PN1_PREPARED_CHANGED')
                pin, raw = n.checked_member(fd, 'artifact-files.json', retain=True)
                require(pin['sha256'] == OLD_INVENTORY_SHA, 'OLD_PN1_INVENTORY_CHANGED')
                inventory = n.strict_json(raw)
                names = set()
                for member in inventory['files']:
                    require(member['path'] not in names, 'OLD_PN1_DUPLICATE_MEMBER')
                    names.add(member['path'])
                    n.checked_member(fd, member['path'], dict(bytes=member['bytes'], sha256=member['sha256']))
                require(set(n.held_file_names(fd)) == names | {'artifact-files.json'},
                        'OLD_PN1_PACKAGE_MEMBERS_CHANGED')
                frozen = n.checked_member(fd, 'public_v3_identity_campaign.bin')[0]
                require(frozen['sha256'] == OLD_ELF_SHA, 'OLD_PN1_FROZEN_ELF_CHANGED')
            finally:
                os.close(fd)
            old = n.checked_member(target_fd, OLD_ELF_REL)[0]
            require(old['sha256'] == OLD_ELF_SHA, 'OLD_PN1_TARGET_ELF_CHANGED')
            terminal = PREVIOUS / 'execution-owned-001/durable-terminal-original.json'
            require(hash_file(terminal) == OLD_TERMINAL_SHA, 'OLD_PN1_TERMINAL_CHANGED')
            status = n.strict_json(n.strict_json(terminal.read_bytes())['content'][0]['text'])
            require(status['job_id'] == '1a17864a6fe-96a-1231' and status['state'] == 'failed'
                and type(status['exit_code']) is int and status['exit_code'] == 1
                and status['timed_out'] is False and status['output_complete'] is True,
                'OLD_PN1_JOB_NOT_KNOWN_TERMINAL')
            return dict(prepared_sha256=OLD_PREPARED_SHA, inventory_sha256=OLD_INVENTORY_SHA,
                prior_binary=frozen, prior_target_binary=old, terminal_sha256=OLD_TERMINAL_SHA,
                consumed_original_claim_preserved_not_reused=True)

        row['source_before'] = source_check('source-before')
        row['previous_package_before'] = old_package_check()
        step('preflight', ['bash', 'scripts/project-preflight.sh', '--dev'], 25)
        command = ['taskset', '--cpu-list', '0,1,2,3', 'prlimit', '--as=3221225472', '--',
            '/home/qian-qi/.cargo/bin/cargo', '+1.95.0', 'build', '--locked', '--offline',
            '--release', '--jobs', '2', '--manifest-path', 'trillionnium/Cargo.toml',
            '-p', 'trnm-pon-node', '--example', EXAMPLE, '--message-format=json']
        row['build_command'] = command
        monitor = n.BuildStop(target_fd, parent_fd, 'target', io)
        row['target_logical_bytes_before'] = monitor.measure()
        build = monitor.run(command, env)
        row['build'] = build
        require(build['complete_success'], 'W1_ACTUAL_NORMAL_RELEASE_BUILD_FAILED')
        raw = n.checked_member(io.writer.fd, build['stdout'], retain=True, limit=16*MIB)[1]
        events = [n.strict_json(line) for line in raw.splitlines()]
        require(all(type(event) is dict for event in events), 'W1_CARGO_JSON_OBJECTS_REQUIRED')
        finishes = [event for event in events if event.get('reason') == 'build-finished']
        require(len(finishes) == 1 and finishes[0].get('success') is True, 'W1_CARGO_SUCCESS_EVENT_REQUIRED')
        artifacts = [event for event in events if event.get('reason') == 'compiler-artifact'
            and event.get('target', {}).get('name') == EXAMPLE and event.get('executable')]
        require(len(artifacts) == 1, 'W1_UNIQUE_ACTUAL_EXAMPLE_EXECUTABLE_REQUIRED')
        artifact = artifacts[0]
        require(artifact['package_id'] == 'path+file://' + str(SOURCE / 'trillionnium/crates/trnm-pon-node') + '#0.1.0'
            and artifact['target']['src_path'] == str(SOURCE / EXAMPLE_PATH)
            and artifact['target']['kind'] == ['example'] and artifact['target']['crate_types'] == ['bin']
            and type(artifact['fresh']) is bool, 'W1_EXACT_PACKAGE_EXAMPLE_REQUIRED')
        n.typed(artifact['profile'], PROFILE)
        row['actual_compiler_artifact'] = artifact
        # A cached build-script event remains labelled reused evidence. Its
        # literal FD6 OUT_DIR must still bind this real held target; do not edit it.
        binding = dict(identity=TARGET_ID, passed_fd=6, actual_target='/proc/self/fd/6', declared_path=str(TARGET))
        row['cached_or_rerun_native_abi_event'] = n.native_abi_build(events, binding)
        row['native_abi_event_is_not_proof_of_fresh_C_compilation'] = True
        advertised = Path(artifact['executable'])
        roots = (Path('/proc/self/fd/6'), TARGET)
        relative = next((advertised.relative_to(root) for root in roots if advertised.is_relative_to(root)), None)
        require(relative is not None and relative.parts[0] == 'release'
            and relative.as_posix().startswith('release/examples/'), 'W1_ARTIFACT_OUTSIDE_HELD_RELEASE_EXAMPLES')
        # Reuse only the held-file copy primitive; never reopen the advertised
        # ambient/proc path, strip a binary, or substitute the old test ELF.
        binary_pin = n.checked_member(target_fd, relative.as_posix())[0]
        require(0 < 2 * binary_pin['bytes'] <= 192*MIB, 'W1_ORIGINAL_TWIN_BINARY_CAP')
        io.writer.copy(EXAMPLE + '.bin', relative.as_posix(), bucket='binary',
            expected=binary_pin['sha256'], source_directory_fd=target_fd)
        captured, prefix = n.checked_member(io.writer.fd, EXAMPLE + '.bin', retain=True, limit=96*MIB)
        require(captured == binary_pin and prefix[:4] == b'\x7fELF', 'W1_ACTUAL_ELF_CAPTURE_REQUIRED')
        os.chmod(EXAMPLE + '.bin', 0o500, dir_fd=io.writer.fd, follow_symlinks=False)
        row['actual_binary'] = dict(file=EXAMPLE + '.bin', target_relative_path=relative.as_posix(),
            **captured, compiler_profile=artifact['profile'], artifact_fresh=artifact['fresh'])
        monitor.measure()
        row['source_after'] = source_check('source-after')
        row['previous_package_after'] = old_package_check()
        after = n.resources()
        require(after['cgroup'] == before['cgroup'], 'W1_RESOURCE_SCOPE_CHANGED')
        io.json(OUTPUT / 'resources-after.json', after)
        require(monitor.error is None and monitor.child is None
            and not monitor.pending and not monitor.watch_thread.is_alive(), 'W1_BUILD_MONITOR_TERMINAL_UNKNOWN')
        require(n.identity(os.fstat(parent_fd)) == parent_id
            and n.identity(os.stat('target', dir_fd=parent_fd, follow_symlinks=False)) == TARGET_ID
            and n.identity(os.stat(HERE.name, dir_fd=ancestor_fd, follow_symlinks=False)) == output_parent_id
            and n.identity(os.stat(OUTPUT.name, dir_fd=output_parent, follow_symlinks=False)) == n.identity(os.fstat(io.writer.fd)),
            'W1_TARGET_ANCESTOR_CHANGED')
        row['build_candidate_success_before_final_io'] = True
    except BaseException as error:
        fail('build-owner', error)
    finally:
        if monitor is not None:
            row['build_monitor'] = monitor.monitor_observation()
        row['completed_utc'] = n.now()
        row['elapsed_seconds_before_final_result_publication'] = time.monotonic() - START
        row['charged_seconds_before_final_result_publication'] = PREVIOUS_CHARGED + time.monotonic() - START
        if time.monotonic() > DEADLINE:
            fail('deadline-before-seal', 'W1_ORIGINAL_REMAINING_BUILD_BUDGET_EXCEEDED')
        if io is not None:
            try:
                # Terminal reservation includes the result even after a poisoned
                # child/raw writer; every partial file remains in the inventory.
                io.writer.json('w1-build-owner-result.json', row, bucket='terminal', terminal=True)
                members = n.files_at(io.writer.fd)
                require(len(members) <= 126, 'W1_BOUNDED_BUILD_MEMBER_COUNT')
                manifest = dict(schema='pn1-w1-normal-release-build-inventory-v1', profile=DOMAIN,
                    files=[dict(path=name, **pin) for name, pin in sorted(members.items())], **FLAGS)
                io.writer.json('artifact-files.json', manifest, bucket='inventory', terminal=True)
                # Include all actual writes, fsyncs, file closes and stdout flush
                # before the final deadline gate; JSON timing alone is not proof.
                for name in n.held_file_names(io.writer.fd):
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=io.writer.fd)
                    try:
                        require(stat.S_ISREG(os.fstat(fd).st_mode), 'W1_FINAL_REGULAR_OUTPUT_REQUIRED')
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                os.fsync(io.writer.fd)
            except BaseException as error:
                fail('final-publication', error)
            finally:
                io.writer.close()
        for fd in (output_parent, source_fd, parent_fd, ancestor_fd, target_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError as error:
                    fail('close-held-directory', error)
    print(json.dumps(dict(schema=DOMAIN, output=str(OUTPUT), failure=row['failure'],
        build_candidate_success_before_final_io=row['build_candidate_success_before_final_io'],
        elapsed_seconds_before_stdout_flush=time.monotonic()-START,
        outer_durable_terminal_and_elapsed_acceptance_required=True, **FLAGS), sort_keys=True), flush=True)
    elapsed = time.monotonic() - START
    require(elapsed <= MAX_OWNER_SECONDS and PREVIOUS_CHARGED + elapsed <= ORIGINAL_BUILD_SECONDS,
            'W1_ACTUAL_CUMULATIVE_BUILD_BUDGET_EXCEEDED')
    return 0 if row['failure'] is None and row['build_candidate_success_before_final_io'] else 1


if __name__ == '__main__':
    try:
        code = run()
    except BaseException as error:
        print(json.dumps(dict(schema=DOMAIN, failure=str(error)[:2048],
            elapsed_seconds_before_stdout_flush=time.monotonic()-START, **FLAGS)), flush=True)
        code = 1
    sys.exit(code)
