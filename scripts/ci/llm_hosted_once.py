#!/usr/bin/env python3
"""One published, cooperating Git campaign; never a new trial authority.

Register on a clean source commit S using an already-created empty SQLite
authority. Freeze S on the dedicated execution branch; the existing PR remains
the integration path. Publish one intent commit I whose sole parent is S and whose sole
change is that registration. Publication spends the opportunity even if setup
or the runner fails. The job never initializes, repairs, refunds or resumes an
authority. The original CPU/4-thread/10-step strict-v1 pilot owns all phases.
The existing hash-locked small-control dependency closure is reused unchanged;
that lock's prior purpose is not evidence of pretrained execution or efficacy.

This guard covers the fetched heads/tags of the cooperating repository and the
platform's first run attempt. Deleted/force-erased unreachable history, malicious
repository administrators and duplicate platform delivery are not independent
custody. No release, adoption, reward or statistical qualification is granted.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request


SCHEMA = 'trnm-smollm-hosted-intent-v1'
SCOPE = 'one-cooperating-git-campaign-no-independent-custody'
CAMPAIGN = 'model-owner-completion-20261104-once-v1'
REPOSITORY = 'TrillionniumFoundation/Trillionnium-Chain'
REF = 'refs/heads/fix/chain-model-owner-hosted-once-20261105'
WORKFLOW = '.github/workflows/pon-smollm-hosted-once.yml'
INTENTS = 'config/pon/hosted-model-intents-v1'
DRIVER = 'scripts/ci/llm_hosted_once.py'
LOCK = 'scripts/ci/model-runtime-cpu-requirements.txt'
FAMILY = 'config/pon/model-family-smollm2-135m-v1.json'
RELATED_IDENTITY = 'cooperating-git-campaign:' + CAMPAIGN
MANIFEST_SHA256 = '6e6a76d478f28906566c1cc8db9ef767922b7a215c9f795da8d845e965c59f0c'
MAX_INTENT = 256 * 1024
MAX_EMPTY_LEDGER = 64 * 1024
MAX_MANIFEST = 64 * 1024
MAX_SOURCE = 8 * 1024 * 1024
MAX_EVIDENCE_FILE = 8 * 1024 * 1024
MAX_EVIDENCE_TOTAL = 64 * 1024 * 1024
QUALIFICATIONS = ('public_network_ready', 'authenticated_inference_accepted',
                  'independent_accepted', 'prospective_accepted', 'public_reward_eligible')
FALSE_QUALIFICATIONS = {name: False for name in QUALIFICATIONS}
INTENT_KEYS = ('schema scope campaign repository ref source_commit source_hashes '
               'policy policy_id trial_id initial_checkpoint related_identity '
               'empty_ledger material_manifest plan plan_id qualifications').split()
HISTORY_SCOPE = ('all fetched heads and tags; full reachable ancestry; excludes '
                 'deleted/force-erased unreachable history and GitHub pull-only refs')


class Refused(ValueError):
    pass


def require(value, code):
    if not value:
        raise Refused('HOSTED_' + code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'NONFINITE_JSON'))


def hex_value(value, length=64):
    require(type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value), 'DIGEST')
    return value


def closed(value, keys):
    require(type(value) is dict and set(value) == set(keys), 'FIELDS')


def read_regular(path, maximum, *, allow_empty=False):
    path = Path(path)
    require(path.absolute() == path.resolve(), 'SYMLINK')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                (0 if allow_empty else 1) <= before.st_size <= maximum, 'REGULAR_BOUND')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read(maximum + 1)
        after = os.fstat(fd)
        require(len(raw) == before.st_size and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'FILE_CHANGED')
        return raw
    finally:
        os.close(fd)


def write_once(path, raw):
    require(Path(path).absolute() == Path(path).resolve(), 'OUTPUT_SYMLINK')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as handle:
            handle.write(raw)
            handle.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def json_once(path, value):
    write_once(path, canonical(value) + b'\n')


def git(repo, *args, check=True):
    # No hooks, replace objects, global configuration, textconv or lazy network
    # fetch. Arguments are code constants or previously checked hex identities.
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
               GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1', LC_ALL='C')
    command = ['git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null',
               '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false',
               '-c', 'core.attributesFile=/dev/null',
               '--literal-pathspecs', '-C', str(repo), *args]
    result = subprocess.run(command, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=60, check=False)
    require(not check or result.returncode == 0, 'GIT:' + args[0])
    require(len(result.stdout) <= 32 * 1024 * 1024, 'GIT_OUTPUT_BOUND')
    return result.stdout if check else result


def clean_source(repo, commit):
    hex_value(commit, 40)
    require(Path(repo).absolute() == Path(repo).resolve(), 'REPOSITORY_SYMLINK')
    require(git(repo, 'rev-parse', '--show-toplevel').decode().strip() == str(Path(repo).resolve()),
            'REPOSITORY_ROOT')
    require(git(repo, 'rev-parse', 'HEAD').decode().strip() == commit, 'CHECKOUT')
    require(git(repo, 'rev-parse', '--is-shallow-repository').strip() == b'false', 'SHALLOW')
    require(not git(repo, 'for-each-ref', '--format=%(refname)', 'refs/replace'), 'REPLACE_REFS')
    for name in ('info/grafts', 'objects/info/alternates', 'shallow'):
        path = Path(git(repo, 'rev-parse', '--git-path', name).decode().strip())
        if not path.is_absolute():
            path = Path(repo) / path
        require(not os.path.lexists(path), 'GIT_ALTERNATE_HISTORY')
    for name in ('extensions.partialclone', 'remote.origin.promisor'):
        result = git(repo, 'config', '--local', '--get', name, check=False)
        require(result.returncode == 1, 'PARTIAL_CLONE')
    executable_config = git(repo, 'config', '--local', '--no-includes', '--get-regexp',
        r'^(filter\.|include\.|includeif\.|diff\.)', check=False)
    require(executable_config.returncode == 1, 'EXECUTABLE_GIT_CONFIG')
    flags = git(repo, 'ls-files', '-v', '-z').split(b'\0')
    require(all(not row or row.startswith(b'H ') for row in flags), 'INDEX_FLAGS')
    status = git(repo, 'status', '--porcelain=v1', '--untracked-files=all', '--ignored=matching')
    require(not status, 'DIRTY_OR_SHADOW')


def source_hashes(repo, commit):
    # The entire script/formal source trees are bounded, not a caller-selected
    # list of convenient imports. The commit additionally binds the whole tree.
    output = git(repo, 'ls-tree', '-r', '-z', commit, '--', 'scripts',
                 'formal/pon-nakamoto-v1', FAMILY, WORKFLOW)
    result, total = {}, 0
    for row in output.split(b'\0'):
        if not row:
            continue
        metadata, encoded_path = row.split(b'\t', 1)
        mode, kind, oid = metadata.decode('ascii').split()
        path = encoded_path.decode('ascii')
        require(mode in ('100644', '100755') and kind == 'blob' and
                not path.startswith('/') and '..' not in Path(path).parts, 'SOURCE_MEMBER')
        raw = read_regular(Path(repo) / path, MAX_SOURCE, allow_empty=True)
        object_id = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        require(object_id == oid, 'SOURCE_BYTES')
        result[path] = digest(raw)
        total += len(raw)
    require(1 <= len(result) <= 2048 and total <= 64 * 1024 * 1024 and
            all(name in result for name in (DRIVER, LOCK, FAMILY, WORKFLOW,
                'scripts/llm_runtime_pilot.py', 'scripts/llm_runtime_trial_ledger.py',
                'scripts/llm_runtime_assessment.py', 'scripts/llm_base_material.py')),
            'SOURCE_CLOSURE')
    return result


def modules(repo):
    # Caller has checked all source bytes, tracked state AND ignored shadows.
    scripts = str(Path(repo) / 'scripts')
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    names = ('llm_runtime_pilot', 'llm_runtime_trial_ledger')
    loaded = []
    for name in names:
        module = importlib.import_module(name)
        require(Path(module.__file__).resolve() == Path(scripts) / (name + '.py'), 'IMPORT_ORIGIN')
        loaded.append(module)
    return tuple(loaded)


def packed(raw):
    return dict(size=len(raw), sha256=digest(raw), base64=base64.b64encode(raw).decode('ascii'))


def unpacked(value, maximum):
    closed(value, ('size', 'sha256', 'base64'))
    require(type(value['size']) is int and 0 < value['size'] <= maximum and
            type(value['base64']) is str and len(value['base64']) <= 4 * ((maximum + 2) // 3),
            'PACKED_BOUND')
    hex_value(value['sha256'])
    try:
        raw = base64.b64decode(value['base64'], validate=True)
    except (ValueError, TypeError) as error:
        raise Refused('HOSTED_BASE64') from error
    require(packed(raw) == value, 'PACKED_BYTES')
    return raw


def no_sidecars(path):
    require(not list(Path(path).parent.glob(Path(path).name + '-*')), 'LEDGER_SIDECAR_UNKNOWN')


def ledger_readback(raw, policy_id, ledger_module):
    """Read only a detached byte snapshot; never open a live DB for recovery."""
    require(raw.startswith(b'SQLite format 3\0') and len(raw) >= 100 and
            raw[18:20] == b'\x01\x01', 'LEDGER_FORMAT')
    with tempfile.TemporaryDirectory(prefix='trnm-hosted-ledger-read-') as temporary:
        path = Path(temporary) / 'snapshot.sqlite3'
        write_once(path, raw)
        uri = 'file:' + urllib.parse.quote(str(path), safe='/') + '?mode=ro&immutable=1'
        db = sqlite3.connect(uri, uri=True, timeout=0, isolation_level=None)
        try:
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA query_only=ON')
            require(db.execute('PRAGMA quick_check').fetchall() == [('ok',)], 'LEDGER_INTEGRITY')
            policy, checkpoint, attempts, count = ledger_module.TrialLedger(path, policy_id)._read(db)
        finally:
            db.close()
        require(read_regular(path, len(raw)) == raw, 'READ_ONLY_LEDGER_CHANGED')
        no_sidecars(path)
    return dict(policy=policy, policy_id=policy_id, checkpoint=checkpoint,
                spent=len(attempts), attempts=attempts, events=count, scope=ledger_module.SCOPE)


def manifest_value(raw, runtime):
    require(digest(raw) == MANIFEST_SHA256, 'ORIGINAL_MANIFEST')
    value = decode(raw)
    closed(value, ('model', 'revision', 'files'))
    require(value['model'] == runtime.MODEL and value['revision'] == runtime.REVISION and
            type(value['files']) is dict and set(value['files']) == set(runtime.PUBLIC_FILES),
            'MATERIAL_ROSTER')
    for name, (size, sha) in runtime.PUBLIC_FILES.items():
        closed(value['files'][name], ('revision', 'size', 'sha256'))
        require(value['files'][name] == dict(revision=runtime.REVISION, size=size, sha256=sha),
                'MATERIAL_PIN')
    return value


def validate_payload(value, repo, source):
    closed(value, INTENT_KEYS)
    for key, expected in (('schema', SCHEMA), ('scope', SCOPE), ('campaign', CAMPAIGN),
                          ('repository', REPOSITORY), ('ref', REF), ('source_commit', source),
                          ('related_identity', RELATED_IDENTITY), ('qualifications', FALSE_QUALIFICATIONS)):
        require(value[key] == expected, 'CONTEXT:' + key)
    require(all(item is False for item in value['qualifications'].values()), 'QUALIFICATION')
    for key in ('policy_id', 'trial_id', 'initial_checkpoint', 'plan_id'):
        hex_value(value[key])
    require(value['source_hashes'] == source_hashes(repo, source), 'SOURCE_HASHES')
    database = unpacked(value['empty_ledger'], MAX_EMPTY_LEDGER)
    manifest_raw = unpacked(value['material_manifest'], MAX_MANIFEST)
    runtime, ledger = modules(repo)
    state = ledger_readback(database, value['policy_id'], ledger)
    require(canonical(state['policy']) == canonical(value['policy']) and
            state['checkpoint'] == value['initial_checkpoint']
            and state['spent'] == 0 and state['attempts'] == {} and state['events'] == 0 and
            state['policy']['max_attempts'] == 1 and state['policy']['family_alpha'] == [1, 20],
            'EMPTY_ORIGINAL_AUTHORITY')
    manifest = manifest_value(manifest_raw, runtime)
    runtime.verify_family(runtime.read_json(runtime.FAMILY_PATH))
    plan = runtime.registered_plan(runtime.experiment_plan(manifest, backend='cpu', threads=4,
        steps=10, exit_observation='strict-v1'), value['policy_id'], value['trial_id'])
    runtime.validate_plan(plan)
    require(canonical(value['plan']) == canonical(plan) and
            value['plan_id'] == digest(canonical(plan)), 'EXACT_PLAN')
    return state


def event_context(event, env):
    require(env.get('GITHUB_ACTIONS') == 'true' and env.get('GITHUB_EVENT_NAME') == 'push' and
            env.get('GITHUB_REPOSITORY') == REPOSITORY and env.get('GITHUB_REF') == REF and
            env.get('GITHUB_RUN_ATTEMPT') == '1', 'EVENT_CONTEXT')
    require(type(env.get('GITHUB_RUN_ID')) is str and
            re.fullmatch('[1-9][0-9]{0,23}', env['GITHUB_RUN_ID']), 'RUN_ID')
    require(type(event) is dict and event.get('repository', {}).get('full_name') == REPOSITORY and
            event.get('ref') == REF and all(event.get(k) is False for k in ('created', 'deleted', 'forced')),
            'PUSH_CONTEXT')
    before, after = hex_value(event.get('before'), 40), hex_value(event.get('after'), 40)
    require(before != '0' * 40 and env.get('GITHUB_SHA') == after and
            env.get('GITHUB_WORKFLOW_SHA') == after and
            env.get('GITHUB_WORKFLOW_REF') == REPOSITORY + '/' + WORKFLOW + '@' + REF and
            event.get('head_commit', {}).get('id') == after, 'EVENT_SHA')
    return before, after


def history_gate(repo, intent_commit):
    # Conservatively burn this single-campaign namespace after ANY prior touch,
    # including malformed intents, other filenames, deletion, rename and merges.
    commits = git(repo, 'rev-list', '--all', '--full-history', '--', INTENTS).decode().splitlines()
    require(commits == [intent_commit], 'PRIOR_PUBLISHED_INTENT')


def validate(repo, event, env):
    before, after = event_context(event, env)
    clean_source(repo, after)
    parents = git(repo, 'show', '-s', '--format=%P', after).decode().strip().split()
    require(len(parents) == 1, 'INTENT_SINGLE_PARENT')
    source = hex_value(parents[0], 40)
    require(git(repo, 'merge-base', '--is-ancestor', before, source, check=False).returncode == 0,
            'BEFORE_NOT_SOURCE_ANCESTOR')
    changes = git(repo, 'diff-tree', '--no-commit-id', '--name-status', '--no-renames',
                  '-r', '-z', source, after).split(b'\0')
    require(len(changes) == 3 and changes[0] == b'A' and changes[-1] == b'', 'INTENT_ONLY_ADDITION')
    path = changes[1].decode('ascii')
    require(re.fullmatch(re.escape(INTENTS) + '/[0-9a-f]{64}\\.json', path), 'INTENT_PATH')
    raw = read_regular(Path(repo) / path, MAX_INTENT)
    require(raw == git(repo, 'show', after + ':' + path), 'INTENT_BYTES')
    value = decode(raw)
    closed(value, INTENT_KEYS)
    require(path == INTENTS + '/' + hex_value(value['trial_id']) + '.json', 'INTENT_PATH_TRIAL')
    history_gate(repo, after)
    state = validate_payload(value, repo, source)
    return value, dict(schema='trnm-smollm-hosted-admission-v1', scope=SCOPE,
        campaign=CAMPAIGN, run_id=env['GITHUB_RUN_ID'], run_attempt=1,
        before=before, source_commit=source, intent_commit=after,
        intent_path=path, intent_sha256=digest(raw), plan_id=value['plan_id'],
        policy_id=value['policy_id'], trial_id=value['trial_id'],
        initial_checkpoint=state['checkpoint'], git_intent_spent=True,
        history_scope=HISTORY_SCOPE, qualifications=FALSE_QUALIFICATIONS)


def register(repo, source, ledger_path, manifest_path, trial):
    """Offline only: consume existing bytes, never bootstrap or run a trial."""
    hex_value(source, 40)
    hex_value(trial)
    clean_source(repo, source)
    require(not git(repo, 'rev-list', '--all', '--full-history', '--', INTENTS), 'PRIOR_PUBLISHED_INTENT')
    hashes = source_hashes(repo, source)
    no_sidecars(ledger_path)
    database = read_regular(ledger_path, MAX_EMPTY_LEDGER)
    no_sidecars(ledger_path)
    manifest_raw = read_regular(manifest_path, MAX_MANIFEST)
    runtime, ledger = modules(repo)
    # Read the one canonical policy row, then let the original owner recheck the
    # complete schema/journal/checkpoint. No caller-selected SQL is executed.
    with tempfile.TemporaryDirectory(prefix='trnm-hosted-policy-read-') as temporary:
        path = Path(temporary) / 'snapshot.sqlite3'
        write_once(path, database)
        uri = 'file:' + urllib.parse.quote(str(path), safe='/') + '?mode=ro&immutable=1'
        db = sqlite3.connect(uri, uri=True, timeout=0)
        try:
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA query_only=ON')
            require(db.execute('SELECT type, name, tbl_name, sql FROM sqlite_master '
                'ORDER BY name').fetchall() == [('table', 'events', 'events', ledger.EVENTS_SQL),
                ('table', 'policy', 'policy', ledger.POLICY_SQL)], 'LEDGER_SCHEMA')
            rows = db.execute('SELECT identity FROM policy WHERE singleton=1').fetchall()
        finally:
            db.close()
        require(len(rows) == 1, 'POLICY_ROW')
        policy_id = hex_value(rows[0][0])
    state = ledger_readback(database, policy_id, ledger)
    manifest = manifest_value(manifest_raw, runtime)
    plan = runtime.registered_plan(runtime.experiment_plan(manifest, backend='cpu', threads=4,
        steps=10, exit_observation='strict-v1'), policy_id, trial)
    value = dict(schema=SCHEMA, scope=SCOPE, campaign=CAMPAIGN, repository=REPOSITORY, ref=REF,
        source_commit=source, source_hashes=hashes, policy=state['policy'], policy_id=policy_id,
        trial_id=trial, initial_checkpoint=state['checkpoint'], related_identity=RELATED_IDENTITY,
        empty_ledger=packed(database), material_manifest=packed(manifest_raw),
        plan=plan, plan_id=digest(canonical(plan)), qualifications=FALSE_QUALIFICATIONS)
    validate_payload(value, repo, source)
    raw = canonical(value) + b'\n'
    require(len(raw) <= MAX_INTENT, 'INTENT_BOUND')
    path = Path(repo) / INTENTS / (trial + '.json')
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    write_once(path, raw)
    return dict(registration=str(path), source_commit=source, trial_id=trial,
                policy_id=policy_id, initial_checkpoint=state['checkpoint'],
                plan_id=value['plan_id'], sha256=digest(raw), size=len(raw),
                scope=SCOPE, publication_spends_opportunity=True)


def work_root(env, repo):
    base = Path(env.get('RUNNER_TEMP', ''))
    require(base.is_absolute() and base == base.resolve() and base.is_dir() and
            not base.is_relative_to(Path(repo).resolve()), 'RUNNER_TEMP')
    root = base / 'pon-smollm-hosted-once-v1'
    root.mkdir(mode=0o700, exist_ok=True)
    require(root == root.resolve() and root.stat().st_uid == os.getuid(), 'WORK_DIRECTORY')
    evidence = root / 'evidence'
    evidence.mkdir(mode=0o700, exist_ok=True)
    require(evidence == evidence.resolve(), 'EVIDENCE_DIRECTORY')
    return root


def record(root, value):
    raw = canonical(dict(utc_ns=time.time_ns(), **value)) + b'\n'
    path = root / 'stages.jsonl'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    try:
        require(os.fstat(fd).st_size < 1024 * 1024, 'STAGE_LOG_BOUND')
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)


def stage(root, name, function):
    start = time.monotonic_ns()
    record(root, dict(stage=name, state='started'))
    try:
        value = function()
    except BaseException as error:
        record(root, dict(stage=name, state='failed', duration_ns=time.monotonic_ns() - start,
                         error_type=type(error).__name__, error=str(error)[:2048]))
        raise
    record(root, dict(stage=name, state='succeeded', duration_ns=time.monotonic_ns() - start))
    return value


def child_env(root):
    # Do not inherit user Python, pip, HuggingFace, proxy or credential overrides.
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR')
           if key in os.environ}
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', TOKENIZERS_PARALLELISM='false',
        HF_HOME=str(root / 'huggingface-cache'), HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1',
        HF_HUB_DISABLE_TELEMETRY='1', DO_NOT_TRACK='1',
        PIP_CONFIG_FILE='/dev/null', PIP_DISABLE_PIP_VERSION_CHECK='1',
        OMP_NUM_THREADS='4', MKL_NUM_THREADS='4', OPENBLAS_NUM_THREADS='4')
    return env


def command(root, name, argv, repo, timeout):
    path = root / (name + '.log')
    with path.open('xb') as output:
        result = subprocess.run(argv, cwd=repo, env=child_env(root), stdout=output,
                                stderr=subprocess.STDOUT, timeout=timeout, check=False)
    json_once(root / (name + '-exit.json'), dict(command=argv, returncode=result.returncode))
    require(result.returncode == 0, 'COMMAND_EXIT:' + name + ':' + str(result.returncode))
    return result.returncode


def download_materials(root, runtime, manifest_raw):
    directory = root / 'materials'
    directory.mkdir(mode=0o700, exist_ok=False)
    started = time.monotonic()
    for name, (size, expected) in runtime.PUBLIC_FILES.items():
        require(time.monotonic() - started < 1800, 'DOWNLOAD_DEADLINE')
        url = ('https://huggingface.co/' + runtime.MODEL + '/resolve/' + runtime.REVISION + '/' + name)
        h, count = hashlib.sha256(), 0
        with urllib.request.urlopen(url, timeout=120) as response, (directory / name).open('xb') as output:
            require(urllib.parse.urlsplit(response.url).scheme == 'https', 'DOWNLOAD_SCHEME')
            while True:
                require(time.monotonic() - started < 1800, 'DOWNLOAD_DEADLINE')
                chunk = response.read(min(1024 * 1024, size + 1 - count))
                if not chunk:
                    break
                count += len(chunk)
                require(count <= size, 'DOWNLOAD_SIZE')
                output.write(chunk)
                h.update(chunk)
        require(count == size and h.hexdigest() == expected, 'DOWNLOAD_HASH')
        record(root, dict(stage='material:' + name, state='verified', size=count, sha256=expected))
    write_once(directory / 'material-manifest.json', manifest_raw)
    runtime.verify_materials(directory)


def environment_record():
    result = dict(schema='trnm-smollm-hosted-environment-v1', python=sys.version,
        executable=sys.executable, platform=platform.platform(), machine=platform.machine(),
        cpu_count=os.cpu_count(), qualifications=FALSE_QUALIFICATIONS)
    try:
        result['affinity'] = sorted(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        result['affinity'] = None
    for name in ('cpu.max', 'memory.max', 'memory.current', 'memory.stat'):
        path = Path('/sys/fs/cgroup') / name
        try:
            result[name] = path.read_text()[:32768]
        except OSError:
            result[name] = None
    return result


def execute(repo, event, env):
    value, admitted = validate(repo, event, env)
    root = work_root(env, repo)
    # The marker is created before venv/pip/download or any trial subprocess.
    # Every failure leaves it behind. It is a same-job guard, not global custody.
    json_once(root / 'launch-intent.json', admitted)
    json_once(root / 'environment.json', environment_record())
    runtime, _ = modules(repo)
    pilot_started, pilot_returned = False, False
    try:
        stage(root, 'python-profile', lambda: require(sys.implementation.name == 'cpython' and
            sys.version_info[:3] == (3, 12, 3), 'PYTHON_PROFILE'))
        stage(root, 'venv', lambda: command(root, 'venv',
            [sys.executable, '-I', '-B', '-m', 'venv', str(root / 'venv')], repo, 300))
        python = str(root / 'venv/bin/python')
        stage(root, 'dependencies', lambda: command(root, 'dependencies',
            [python, '-I', '-B', '-m', 'pip', 'install', '--isolated', '--require-hashes',
             '--only-binary=:all:', '--no-cache-dir', '--progress-bar', 'off', '--retries', '0',
             '--timeout', '120', '--index-url', 'https://pypi.org/simple', '-r', str(Path(repo) / LOCK)],
            repo, 1800))
        metadata_code = ('import importlib.metadata,json; print(json.dumps(dict(sorted('
                         '(d.metadata["Name"],d.version) for d in importlib.metadata.distributions()))))')
        stage(root, 'installed-metadata', lambda: command(root, 'installed-metadata',
            [python, '-I', '-B', '-c', metadata_code], repo, 60))
        manifest_raw = unpacked(value['material_manifest'], MAX_MANIFEST)
        stage(root, 'materials', lambda: download_materials(root, runtime, manifest_raw))
        # Setup may be slow. Recheck source/intent/plan immediately before the
        # original runner, without resetting or initializing any authority.
        stage(root, 'before-trial-revalidation', lambda: validate(repo, event, env))
        write_once(root / 'ledger.sqlite3', unpacked(value['empty_ledger'], MAX_EMPTY_LEDGER))
        argv = [python, '-B', str(Path(repo) / 'scripts/llm_runtime_pilot.py'), 'run',
            '--materials', str(root / 'materials'), '--output', str(root / 'run'),
            '--trial-ledger', str(root / 'ledger.sqlite3'), '--trial-policy', value['policy_id'],
            '--trial-checkpoint', value['initial_checkpoint'], '--trial-id', value['trial_id'],
            '--related-identity', RELATED_IDENTITY, '--backend', 'cpu', '--threads', '4',
            '--steps', '10', '--exit-observation-profile', 'strict-v1']
        pilot_started = True
        # The original supervisor owns every phase deadline. subprocess.run's
        # timeout kills only its direct child, so imposing another parent-only
        # timeout here could orphan a model process. The GitHub whole-job owner
        # supplies the separate 300-minute bound; interrupted cleanup stays unknown.
        stage(root, 'original-pilot', lambda: command(root, 'original-pilot', argv, repo, None))
        pilot_returned = True
    except BaseException as error:
        # A recorded subprocess return code proves return even when it was
        # nonzero. Timeout/runner interruption has no invented terminal record.
        pilot_returned = (root / 'original-pilot-exit.json').is_file()
        json_once(root / 'execution-terminal.json', dict(outcome='failed',
            error_type=type(error).__name__, error=str(error)[:2048],
            pilot_started=pilot_started, pilot_returned=pilot_returned,
            git_intent_spent=True, automatic_retry_allowed=False, qualifications=FALSE_QUALIFICATIONS))
        raise
    json_once(root / 'execution-terminal.json', dict(outcome='returned-unqualified',
        pilot_started=pilot_started, pilot_returned=pilot_returned, git_intent_spent=True,
        automatic_retry_allowed=False, qualifications=FALSE_QUALIFICATIONS))


ROOT_RECORDS = ('validation.json', 'launch-intent.json', 'environment.json', 'stages.jsonl',
    'execution-terminal.json', 'venv.log', 'venv-exit.json', 'dependencies.log',
    'dependencies-exit.json', 'installed-metadata.log', 'installed-metadata-exit.json',
    'original-pilot.log', 'original-pilot-exit.json')
RUN_RECORDS = ('experiment-plan.json', 'experiment-freeze.json', 'trial-checkpoint.json',
               'phase-outcomes.json', 'evaluation-roster.json', 'assessment.json', 'abort.json',
               'loader-1thread-plan.json')
PHASE_RECORDS = ('actual-receipt.json', 'supervisor.json', 'target-contract.json',
                 'predictions.json', 'artifact.json', 'wrapped-adapter.json', 'process.log')


def collect(repo, event, env, *, event_error=None):
    root = work_root(env, repo)
    target = root / 'evidence'
    report = dict(schema='trnm-smollm-hosted-collection-v1', scope=SCOPE,
        campaign=CAMPAIGN, git_publication_spends_opportunity=True,
        automatic_retry_allowed=False, qualifications=FALSE_QUALIFICATIONS,
        files=[], missing=[], omitted=[], ledger=dict(state='UNKNOWN'), history_scope=HISTORY_SCOPE)
    report['excluded_payloads'] = ['materials/', 'venv/', 'huggingface-cache/',
        'run/*/artifact.safetensors', 'large profiler payloads and non-allowlisted files']
    report['workflow_steps'] = {name: env.get('HOSTED_' + name.upper() + '_OUTCOME', 'unknown')
        for name in ('checkout', 'admission', 'python_setup', 'execution')}
    report['environment'] = environment_record()
    if event_error is not None:
        report['event_error'] = event_error
    value = None
    try:
        value, admitted = validate(repo, event, env)
        report['admission'] = admitted
    except BaseException as error:
        report['validation_error'] = dict(type=type(error).__name__, message=str(error)[:2048])
    phase_names = ['loader-1thread', 'loader-reference']
    roles = ['candidate', 'current-backbone', 'fresh-budget-matched-lora',
             'budget-matched-full-tune', 'randomized-rank-matched-lora']
    phase_names += [kind + '-' + role for kind in ('train', 'evaluate') for role in roles]
    names = list(ROOT_RECORDS) + ['run/' + name for name in RUN_RECORDS]
    names += ['run/' + phase + '/' + name for phase in phase_names for name in PHASE_RECORDS]
    total = 0
    for name in names:
        path = root / name
        if not os.path.lexists(path):
            report['missing'].append(name)
            continue
        size = None
        try:
            size = path.lstat().st_size
            require(size <= MAX_EVIDENCE_FILE and total + size <= MAX_EVIDENCE_TOTAL,
                    'EVIDENCE_BOUND')
            raw = read_regular(path, MAX_EVIDENCE_FILE, allow_empty=True)
            destination = target / name
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_once(destination, raw)
            total += len(raw)
            report['files'].append(dict(path=name, size=len(raw), sha256=digest(raw)))
        except (OSError, ValueError) as error:
            report['omitted'].append(dict(path=name, reason=str(error)[:512], size=size,
                sha256=None, hash_status='not-computed-for-rejected-or-out-of-bound-file'))
    # Never use inspect(): it begins a writable transaction and can recover a
    # journal. No readback at all after an unobserved pilot exit or hot sidecar.
    try:
        require(value is not None, 'UNADMITTED_READBACK')
        terminal = decode(read_regular(root / 'execution-terminal.json', MAX_MANIFEST))
        require(terminal.get('pilot_started') is False or terminal.get('pilot_returned') is True,
                'PILOT_TERMINAL_UNKNOWN')
        path = root / 'ledger.sqlite3'
        if not path.exists():
            require(terminal.get('pilot_started') is False, 'MISSING_SPENT_LEDGER')
            report['ledger'] = dict(state='NOT_CREATED', git_intent_spent=True)
        else:
            no_sidecars(path)
            raw = read_regular(path, MAX_EVIDENCE_FILE)
            no_sidecars(path)
            _, ledger = modules(repo)
            readback = ledger_readback(raw, value['policy_id'], ledger)
            no_sidecars(path)
            report['ledger'] = dict(state='READ_ONLY_SNAPSHOT', size=len(raw), sha256=digest(raw),
                                    readback=readback, git_intent_spent=True)
            write_once(target / 'ledger.sqlite3', raw)
    except (OSError, ValueError, sqlite3.Error) as error:
        report['ledger'] = dict(state='UNKNOWN', error_type=type(error).__name__,
                               reason=str(error)[:2048], git_intent_spent=True)
    json_once(target / 'collection.json', report)
    return report


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    registration = commands.add_parser('register', help='offline: use existing authority bytes; never run')
    registration.add_argument('--source-commit', required=True)
    registration.add_argument('--ledger', required=True)
    registration.add_argument('--manifest', required=True)
    registration.add_argument('--trial-id', required=True)
    for name in ('validate', 'execute', 'collect'):
        commands.add_parser(name)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    if args.command == 'register':
        print(json.dumps(register(repo, args.source_commit, args.ledger, args.manifest, args.trial_id)))
        return
    if args.command == 'collect':
        event_error = None
        try:
            event = decode(read_regular(os.environ.get('GITHUB_EVENT_PATH', ''), 4 * 1024 * 1024))
        except (OSError, ValueError) as error:
            # Missing/corrupt event bytes remain an explicit refusal. Collection
            # can retain failure metadata without admitting or running anything.
            event = {}
            event_error = dict(type=type(error).__name__, message=str(error)[:2048])
        report = collect(repo, event, os.environ, event_error=event_error)
        print(json.dumps(dict(ledger=report['ledger']['state'], files=len(report['files']),
                              omitted=len(report['omitted']), qualifications=FALSE_QUALIFICATIONS)))
        return
    if args.command == 'execute':
        event = decode(read_regular(os.environ.get('GITHUB_EVENT_PATH', ''), 4 * 1024 * 1024))
        execute(repo, event, os.environ)
        return
    root = work_root(os.environ, repo)
    try:
        event = decode(read_regular(os.environ.get('GITHUB_EVENT_PATH', ''), 4 * 1024 * 1024))
        _, admitted = validate(repo, event, os.environ)
    except BaseException as error:
        json_once(root / 'validation.json', dict(outcome='refused', error_type=type(error).__name__,
                  error=str(error)[:2048], automatic_retry_allowed=False,
                  qualifications=FALSE_QUALIFICATIONS))
        raise
    json_once(root / 'validation.json', dict(outcome='admitted', **admitted))
    print(json.dumps(admitted))


if __name__ == '__main__':
    main()
