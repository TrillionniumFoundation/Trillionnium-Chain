"""Qualification-only source and command contract for the public PQ owner."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[4]
PREFIX = 'hia/platform/pq_auth/'
SCHEMA = 'trnm.hia.pq-public-qualification.v2'
COMPILER = '87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54'
REVISION = 'f33d8da316de8fdf27b504371f1a5310997ff548'
LIMITS = {'whole_chain_native': False, 'whole_crypto_crate_ported': False,
          'openssl_owned_provider_ported': False, 'tuf_ported': False,
          'constant_time_qualified': False, 'foreign_arbitrary_pointer_gate_qualified': False,
          'register_stack_secret_erasure_qualified': False, 'production_activation': False,
          'live_pointer_const_and_exclusive_budget_contract_required': True}
UNITS = (
    ('auth', 'hia/src/crypto/pq_auth_owner.hepta', 'trnm_pq_auth_private'),
    ('verify', 'hia/src/crypto/pq_auth_verify.hepta', 'trnm_pq_verify_private'),
    ('profile', 'hia/src/crypto/pq_profile_auth.hepta', 'trnm_pq_profile_private'),
    ('owned-emitter', PREFIX + 'owned_emitter.hepta', None),
)
PLATFORM_FILES = ('build_owned.py', 'emit_owned.py', 'owned_emitter.hepta', 'owned.map',
                  'owned_exports.json', 'pq_auth.h', 'README.md', 'qualify.py', 'readback.py',
                  'qualification/contract.py', 'qualification/integrity.py',
                  'qualification/api.py', 'qualification/native_cases.py',
                  'qualification/allocations.py', 'qualification/lifetimes.py',
                  'qualification/cases.json.xz', 'qualification/allocator_observer.c',
                  'qualification/abi_client.c', 'qualification/supervision.py',
                  'qualification/supervision_controls.py')
SHARED = ('hia/components.json', 'hia/toolchain.lock.json', 'hia/qualification/compiler-binding.json',
          'hia/tools/ml_dsa_original.py', 'hia/tools/qualify_ml_dsa.py', 'hia/tools/toolchain.py',
          'hia/tools/qualify.py', 'hia/tools/component_partition.py', 'hia/tests/native_support.py',
          'hia/tests/rust_ml_dsa_reference.rs', 'hia/tests/rust_pq_auth_reference.rs',
          'hia/tests/rust_pq_profile_reference.rs')
ORIGINAL_ROOTS = ('trillionnium/crates/trnm-crypto-primitives', 'trillionnium/crates/trnm-protocol',
                  'trillionnium/Cargo.toml', 'trillionnium/Cargo.lock', 'rust-toolchain.toml',
                  'scripts/project-preflight.sh', 'scripts/ci/prepare_pq_provider.sh', 'AGENTS.md',
                  'config/pon/work-profile-v1.json',
                  'trillionnium/crates/trnm-pon-node/examples/support/w1_from_zero.rs',
                  'tests/fixtures/cpq1-content-v1/vectors.json')
ADAPTERS = {'auth': 'hia/tests/rust_pq_auth_reference.rs', 'profile': 'hia/tests/rust_pq_profile_reference.rs'}
LIBRARIES = ('hex', 'serde_json', 'zeroize', 'trnm_crypto_primitives', 'trnm_protocol')
PLATFORM_GUARD = {'policy': 'reject-unbound-native-tool-overrides-v1', 'overrides': []}
PARTITIONS = (
    ('methods', 'methods', 0, 1480),
    ('extended-small', 'extended', 0, 116),
    ('extended-max-sign', 'extended', 116, 117),
    ('extended-max-frame', 'extended', 117, 118),
    ('extended-max-tpq1', 'extended', 118, 119),
    ('extended-tail', 'extended', 119, 129),
)


def partition_cases(corpus, name):
    need(len(corpus) == 1609 and len({row['label'] for row in corpus}) == 1609,
         'complete native roster required before partitioning')
    selected = [row for row in PARTITIONS if row[0] == name]
    need(len(selected) == 1, 'unknown native partition')
    _, suite, begin, end = selected[0]
    rows = [row for row in corpus if row['suite'] == suite]
    need(len(rows) == (1480 if suite == 'methods' else 129), 'changed native suite size')
    if suite == 'extended':
        need([row['label'] for row in rows[116:119]] == ['maximum-8', 'maximum-7', 'maximum-13']
             and all(row['original'].get('generated_payload_bytes') == 67108864 for row in rows[116:119]),
             'large-message partition identities changed')
    return rows[begin:end]


def check_platform_environment(environment):
    forbidden = ('CC', 'CXX', 'AR', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'ARFLAGS',
                 'LIBRARY_PATH', 'COMPILER_PATH', 'GCC_EXEC_PREFIX', 'CPATH', 'C_INCLUDE_PATH',
                 'CPLUS_INCLUDE_PATH', 'COLLECT_GCC_OPTIONS', 'LD_RUN_PATH',
                 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', 'DYLD_FRAMEWORK_PATH')
    for name in forbidden:
        need(not environment.get(name), 'unbound platform override: ' + name)
    for name in ('ld', 'cc', 'git', 'bash', 'objcopy', 'objdump', 'nm'):
        found = shutil.which(name, path=environment.get('PATH'))
        need(found is not None and Path(found).resolve(strict=True) == Path('/usr/bin', name).resolve(strict=True),
             'shadowed platform executable: ' + name)
    return dict(PLATFORM_GUARD)


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def same(left, right):
    return canonical(left) == canonical(right)


def relative(name):
    need(type(name) is str and name and '\\' not in name and '\0' not in name
         and not Path(name).is_absolute() and '..' not in Path(name).parts
         and Path(name).as_posix() == name and name != '.', 'noncanonical relative path')
    return name


def regular(path, directory=False):
    path = Path(path).absolute()
    for current in (path, *path.parents):
        need(not current.is_symlink(), 'symlinked qualification path')
    value = path.stat()
    need(stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode), 'nonregular qualification path')
    if not directory:
        need(value.st_nlink == 1, 'hardlinked qualification input')
    return path


def read(root, name):
    return regular(regular(root, directory=True) / relative(name)).read_bytes()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def document(raw):
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda name: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def identity(path):
    raw = regular(path).read_bytes()
    return {'bytes': len(raw), 'sha256': sha(raw)}


def input_map(root, *, git_original=True):
    from hia.tools.ml_dsa_original import boundary_inputs
    roots = (*ORIGINAL_ROOTS, *boundary_inputs(root))
    if git_original:
        raw = subprocess.check_output(['git', 'ls-tree', '-rz', 'HEAD', '--', *roots], cwd=root)
        names = [entry.split(b'\t', 1)[1].decode() for entry in raw.split(b'\0') if entry]
    else:
        names = []
        for prefix in roots:
            path = Path(root) / prefix
            names.extend(item.relative_to(root).as_posix() for item in path.rglob('*') if item.is_file()) if path.is_dir() else names.append(prefix)
    need(names, 'empty original source roster')
    names = set(names) | set(SHARED) | {PREFIX + name for name in PLATFORM_FILES}
    manifest = document(read(root, 'hia/components.json'))
    need(set(manifest) == {'schema', 'includes'} and manifest['schema'] == 'trnm.hia.component-includes.v1', 'component schema')
    def visit(name, ancestry=()):
        need(name not in ancestry, 'cyclic component source')
        relative(name)
        need(name.startswith(('src/', 'platform/', 'storage/')) and name.endswith('.hepta'), 'component path')
        names.add('hia/' + name)
        for row in manifest['includes'].get(name, []):
            need(type(row) is dict and set(row) == {'source', 'functions'} and type(row['functions']) is list
                 and row['functions'] and len(set(row['functions'])) == len(row['functions']), 'component functions')
            visit(row['source'], (*ancestry, name))
    for _, source, _ in UNITS:
        visit(source[4:])
    return {name: sha(read(root, name)) for name in sorted(names)}


def compose(root, entry):
    """Rebuild exact text selection without running the compiler or emitter."""
    manifest = document(read(root, 'hia/components.json'))
    captured = {}
    def functions(name):
        raw = read(root, 'hia/' + name)
        captured[name] = sha(raw)
        matches = list(re.finditer(rb'(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)', raw))
        found = {match.group(1).decode(): match.group(0) for match in matches}
        need(len(matches) == len(found), 'duplicate HIA function')
        return raw, found
    def visit(name, ancestry=()):
        need(name not in ancestry, 'cyclic HIA composition')
        raw, own = functions(name)
        names, result = set(own), [raw.rstrip() + b'\n']
        for row in manifest['includes'].get(name, []):
            _, available = visit(row['source'], (*ancestry, name))
            for name_ in row['functions']:
                need(name_ in available and name_ not in names, 'invalid HIA include')
                names.add(name_)
                result.append(available[name_].rstrip() + b'\n')
        return b''.join(result), own
    result, _ = visit(entry[4:])
    return result, captured


def adapter_command(rust, repository, original, prefix, graph, family, target):
    argv = [Path(rust) / 'rustc', '--edition=2021', '-D', 'warnings', Path(repository) / ADAPTERS[family],
            '-L', 'dependency=' + str(Path(original) / 'target/debug/deps'), '-L', 'native=' + prefix + '/lib']
    for name in LIBRARIES:
        argv += ['--extern', name + '=' + graph[name]['path']]
    return list(map(str, [*argv, '-o', target]))


def normalize(family, value):
    if family == 'auth' and value['code'] != 0:
        result = {'code': value['code']}
        if 'frame' in value:
            result['frame'] = {'code': value['frame']['code']}
        return result
    return value


def inventory(root):
    result = {}
    for path in sorted(Path(root).rglob('*')):
        name = path.relative_to(root).as_posix()
        if name == 'report.json' or name.startswith('original/target/'):
            continue
        need(not path.is_symlink(), 'symlinked artifact inventory')
        if path.is_file():
            result[name] = identity(path)
    return result
