"""Compare actual native HIA sampling with complete unchanged original Rust.

Only an existing cfg(test) include receives a private child declaration. The
production Host file and every other original file retain their exact bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]
sys.path.insert(0, str(REPOSITORY))
from hia.platform.host_resource.build import source_manifest
from hia.platform.host_resource.qualify import qualify
from hia.platform.host_resource.cases import corpus_bytes
from hia.platform.transport_request.rust_oracle import command
from hia.platform.build import source_manifest as platform_source_manifest

HOST = 'trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs'
RESOURCE = 'trillionnium/crates/trnm-pon-node/src/host_kernel_parent_resource_tests.rs'
HOOK = 'hia_host_resource_oracle.rs'
DECLARATION = (b'\n#[cfg(test)]\nmod hia_host_resource_oracle {\n'
               b'    include!("hia_host_resource_oracle.rs");\n}\n')
TEST = 'host_kernel_parent::kernel_parent::resource_tests::hia_host_resource_oracle::evaluate'
MARKER = 'HIA_HOST_RESOURCE_ORACLE:'
SKIP = {'target', '__pycache__', '.pytest_cache'}
REQUIRED_TESTS = (
    'host_kernel_parent::kernel_parent::resource_tests::counter_reader_keeps_exact_bounds_short_reads_interrupts_and_real_eof',
    'host_kernel_parent::kernel_parent::resource_tests::counter_reader_refuses_invalid_utf8_and_errors_after_valid_prefixes',
    'host_kernel_parent::kernel_parent::resource_tests::resource_sampling_reopens_every_counter_and_preserves_parser_bounds',
    'host_kernel_parent::kernel_parent::resource_tests::resource_sampling_refuses_symlink_missing_and_nonreadable_counter_children',
    'host_kernel_parent::kernel_parent::resource_tests::resource_sampling_refuses_a_real_fifo_without_waiting_for_a_writer',
    'host_kernel_parent::kernel_parent::resource_tests::resource_sampling_keeps_both_current_checks_and_original_error_precedence',
    'host_kernel_parent::kernel_parent::resource_tests::resource_sampling_final_check_refuses_replacement_permissions_and_limit_changes',
    'host_kernel_parent::kernel_parent::tests::read_kernel_membership_from_current_os_thread_not_process_leader',
    'host_kernel_parent::kernel_parent::relative_tests::held_parent_production_final_fence_observes_change_after_actual_fifth_open',
)


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink() and path.resolve(strict=True) == path,
            'Missing, symlinked or noncanonical source: ' + str(path))
    result = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        while raw := stream.read(1 << 20):
            result.update(raw)
            size += len(raw)
    return {'bytes': size, 'sha256': result.hexdigest()}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def complete_source_manifest() -> dict:
    require(__debug__, 'Resource source binding refuses optimized Python')
    return {**{'hia/' + path: value for path, value in platform_source_manifest().items()},
            **source_manifest()}


def validate_source_bindings(native: dict) -> dict:
    """Require the entire declared input set, including the current oracle.

    Checking only keys supplied by a bundle permits an omitted input to escape
    its native-generation binding. Equality with both the builder receipt and
    the locally declared complete set is therefore mandatory before copying or
    executing any original source, and is repeated at every source fence.
    """
    require(type(native) is dict and type(native.get('build')) is dict,
            'Missing native build/source binding')
    sources = native.get('source_inputs')
    built = native['build'].get('source_inputs')
    require(type(sources) is dict and type(built) is dict and sources == built,
            'Native top-level and build source maps differ')
    expected = complete_source_manifest()
    require(sources == expected, 'Native bundle omits, adds or changes a mandatory source input')
    return expected


def original_manifest(repository: Path) -> dict:
    require(__debug__, 'Original resource validation refuses optimized Python')
    rows = {}
    for directory in ('trillionnium', 'config', 'formal'):
        for path in sorted((repository / directory).rglob('*')):
            relative = path.relative_to(repository)
            if any(part in SKIP for part in relative.parts):
                continue
            require(not path.is_symlink(), 'Symlinked original input: ' + str(relative))
            if path.is_file():
                rows[relative.as_posix()] = identity(path)
    require(all(path in rows for path in (HOST, RESOURCE, 'trillionnium/Cargo.toml', 'trillionnium/Cargo.lock')),
            'Incomplete original Host/Cargo source set')
    return rows


def native_comparison(repository: Path, output: Path) -> dict:
    original = original_manifest(repository)
    native = qualify(output / 'physical')
    sources = native['build']['source_inputs']
    require(sources == complete_source_manifest(), 'Native build omitted a mandatory source input')
    raw_corpus = (output / 'physical/cases.jsonl').read_bytes()
    require(raw_corpus == corpus_bytes(), 'Native executable corpus changed')
    (output / 'corpus.jsonl').write_bytes(raw_corpus)
    controls = []
    for physical in native['semantic']:
        # These values are read from the actual native receipt, not reconstructed
        # from case expectations or supplied by an external sampler.
        controls.append({'name': physical['name'], 'image_sha256': physical['native_image_sha256'],
                         'comparison': [{k: row[k] for k in ('error', 'values', 'delta', 'checks')}
                                        for row in physical['comparison']]})
    require(original_manifest(repository) == original, 'Original source changed during native sampling')
    require(all(identity(repository / path) == value for path, value in sources.items()),
            'Bound native/original source changed')
    result = {'schema': 'trnm.hia.host-resource-native-input.v1',
        'status': 'NATIVE_PASS_ORIGINAL_NOT_RUN', 'build': native['build'],
        'source_inputs': sources, 'original_sources': original,
        'original_source_set_sha256': digest(json.dumps(original, sort_keys=True, separators=(',', ':')).encode()),
        'corpus': identity(output / 'corpus.jsonl'), 'cases': controls,
        'native_physical_observations': native['semantic'],
        'native_protocol_controls': native['controls'], 'native_trace': native['trace'],
        'production_parent_authority': False, 'original_execution': 'NOT_RUN'}
    write_json(output / 'native-comparison.json', result)
    return result


def original_comparison(repository: Path, bundle: Path, output: Path, target: Path | None) -> dict:
    stages = []
    report = {'schema': 'trnm.hia.host-resource-original-differential.v1', 'status': 'FAIL',
        'stages': stages, 'production_parent_authority': False,
        'production_fixed_parent_positive_qualified': False, 'whole_node_qualified': False,
        'original_4s_16_service_budget_qualified': False, 'runtime_rust_dependency': False,
        'scope': 'original sample_counters, readers/parser, cpu_delta_since and explicit private mutation sequences'}
    try:
        missing = [tool for tool in ('cargo', 'rustc') if shutil.which(tool) is None]
        if missing:
            report.update(status='NOT_RUN', missing_tools=missing)
            write_json(output / 'report.json', report)
            return report
        comparison_raw = (bundle / 'native-comparison.json').read_bytes()
        native = json.loads(comparison_raw)
        require(native['status'] == 'NATIVE_PASS_ORIGINAL_NOT_RUN' and native['build']['status'] == 'PASS',
                'Native physical sampler did not qualify')
        sources = validate_source_bindings(native)
        original = original_manifest(repository)
        require(original == native['original_sources'], 'Original sources differ from actual native binding')
        for path, value in sources.items():
            require(identity(repository / path) == value, 'Native-bound source differs: ' + path)
        raw_corpus = (bundle / 'corpus.jsonl').read_bytes()
        corpus = output / 'corpus.jsonl'
        corpus.write_bytes(raw_corpus)
        require(identity(corpus) == native['corpus'] and raw_corpus == corpus_bytes(), 'Native exact corpus differs')
        definitions = [json.loads(line) for line in raw_corpus.splitlines()]
        require([r['name'] for r in definitions] == [r['name'] for r in native['cases']],
                'Native case order differs')
        require(len(definitions) == len(native['native_physical_observations']), 'Native physical rows missing')
        for semantic, physical in zip(native['cases'], native['native_physical_observations'], strict=True):
            require(physical['status'] == 'PASS' and physical['name'] == semantic['name'], 'Native physical failure')
            reduced = [{k: row[k] for k in ('error', 'values', 'delta', 'checks')}
                       for row in physical['comparison']]
            require(semantic['comparison'] == reduced, 'Native semantic row differs from physical comparison')
            require(semantic['image_sha256'] == physical['native_image_sha256']
                    == native['build']['fixture_executable']['sha256'], 'Native image identity differs')
            receipts = physical['receipts'][1:]
            require(len(receipts) == len(reduced), 'Native receipt extent differs')
            before = physical['receipts'][0]['complete_checks']
            for receipt, comparison in zip(receipts, reduced, strict=True):
                require(receipt['error'] == comparison['error']
                        and [receipt[k] for k in ('cpu_usage_usec', 'cpu_nr_periods', 'cpu_nr_throttled',
                             'cpu_throttled_usec', 'memory_current_bytes', 'pids_current')] == comparison['values']
                        and [receipt[k] for k in ('delta_usage_usec', 'delta_nr_periods',
                             'delta_nr_throttled', 'delta_throttled_usec')] == comparison['delta']
                        and receipt['complete_checks'] - before == comparison['checks'],
                        'Comparison not bound to actual native receipt')
                before = receipt['complete_checks']
        isolated = output / 'isolated-source'
        isolated.mkdir(mode=0o700)
        for relative, value in original.items():
            source = repository / relative
            require(identity(source) == value, 'Original source changed before copy: ' + relative)
            destination = isolated / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        include = isolated / RESOURCE
        prefix = include.read_bytes()
        require(b'mod hia_host_resource_oracle' not in prefix, 'Original already has the private oracle')
        hook = (HERE / 'rust_reference.rs').read_bytes()
        hook_path = include.parent / HOOK
        require(not hook_path.exists(), 'Private hook path collision')
        hook_path.write_bytes(hook)
        include.write_bytes(prefix + DECLARATION)
        def check_sources(binary=None, binary_identity=None):
            require((bundle / 'native-comparison.json').read_bytes() == comparison_raw
                    and (bundle / 'corpus.jsonl').read_bytes() == raw_corpus, 'Native evidence changed')
            require(validate_source_bindings(native) == sources, 'Complete native source binding changed')
            require(original_manifest(repository) == original, 'Original repository changed')
            for relative, value in original.items():
                if relative == RESOURCE:
                    require((isolated / relative).read_bytes() == prefix + DECLARATION,
                            'Original resource test prefix changed')
                else:
                    require(identity(isolated / relative) == value, 'Original production/input changed: ' + relative)
            require(hook_path.read_bytes() == hook == (HERE / 'rust_reference.rs').read_bytes(), 'Private oracle changed')
            require(identity(corpus) == native['corpus'], 'Original corpus changed')
            require(all(identity(repository / path) == value for path, value in sources.items()), 'Bound source changed')
            if binary is not None:
                require(identity(binary) == binary_identity, 'Original executable changed')
        check_sources()
        version, row = command(['rustc', '-Vv'], isolated, output, 'rustc-version', timeout=10)
        stages.append(row)
        target = target.resolve() if target else output / 'cargo-target'
        require(target != repository and repository not in target.parents and target != isolated
                and isolated not in target.parents, 'Cargo target must be outside source')
        argv = ['cargo', 'test', '--locked', '--manifest-path', str(isolated / 'trillionnium/Cargo.toml'),
                '-p', 'trnm-pon-node', '--lib', '--no-run', '--message-format=json', '--target-dir', str(target)]
        raw, row = command(argv, isolated, output, 'cargo-original-test-build', timeout=900)
        stages.append(row)
        events = [json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
        binaries = [item for item in events if item.get('reason') == 'compiler-artifact'
                    and item['target']['name'] == 'trnm_pon_node' and item.get('executable')
                    and item['profile'].get('test')]
        require(len(binaries) == 1, 'Expected exactly one actual original Node test executable')
        binary = Path(binaries[0]['executable'])
        binary_identity = identity(binary)
        check_sources(binary, binary_identity)
        listed, row = command([str(binary), '--list'], isolated, output, 'list-original-tests', timeout=20)
        stages.append(row)
        names = {line.removesuffix(': test') for line in listed.decode().splitlines() if line.endswith(': test')}
        require(set((TEST, *REQUIRED_TESTS)) <= names, 'Required original Host/resource tests were not linked')
        retained, row = command([str(binary), 'host_kernel_parent::', '--skip', 'hia_host_resource_oracle',
                                 '--nocapture', '--test-threads=1'], isolated, output,
                                'retained-original-host-tests', timeout=240)
        stages.append(row)
        for name in REQUIRED_TESTS:
            require('test ' + name + ' ... ok' in retained.decode(), 'Original test did not execute: ' + name)
        environment = dict(os.environ, TRNM_HIA_HOST_RESOURCE_CORPUS=str(corpus))
        raw, row = command([str(binary), '--exact', TEST, '--nocapture', '--test-threads=1'],
                           isolated, output, 'actual-original-resource-corpus', env=environment, timeout=240)
        stages.append(row)
        check_sources(binary, binary_identity)
        observed = [json.loads(line.split(MARKER, 1)[1]) for line in raw.decode().splitlines() if MARKER in line]
        require([r['name'] for r in observed] == [r['name'] for r in native['cases']],
                'Actual original resource rows missing, reordered or extra')
        controls = []
        for expected, actual in zip(native['cases'], observed, strict=True):
            same = expected['name'] == actual['name'] and expected['comparison'] == actual['comparison']
            controls.append({'name': expected['name'], 'status': 'PASS' if same else 'FAIL',
                             'native': expected, 'original': actual})
        write_json(output / 'comparison.json', {'controls': controls})
        require(all(row['status'] == 'PASS' for row in controls), 'Actual original resource differential failed')
        summary = [line for line in retained.decode().splitlines() if line.startswith('test result:')]
        report.update(status='PASS', controls=len(controls), operations=sum(len(r['comparison']) for r in observed),
            failed=0, compiler=version.decode(), executable=binary_identity, original_sources=original,
            native_image=native['build']['fixture_executable'], native_comparison_sha256=digest(comparison_raw),
            exact_corpus=native['corpus'], source_inputs=sources, source_inputs_stable=True,
            original_production_file_unchanged=original[HOST], original_test_file_prefix_unchanged=original[RESOURCE],
            appended_test_child_hex=DECLARATION.hex(), private_adapter_sha256=digest(hook),
            required_original_tests=list(REQUIRED_TESTS), retained_original_summary=summary,
            original_sample_counters_cases=sum(all(method == 'original sample_counters' for method in r['methods'])
                                                for r in observed),
            actual_original_primitives=['sample_counters', 'ScopedParentDirectory::read_counters',
                'ScopedParentDirectory::read_counter', 'read_counter_text', 'resource_sample',
                'KernelResourceSample::cpu_delta_since', 'read_context', 'cgroup_within_parent',
                'open_current_parent', 'ScopedParentDirectory::from_file', 'ScopedParentDirectory::read_limits',
                'ScopedParentDirectory::verify_limits', 'ScopedParentDirectory::verify_path'],
            fixed_production_KernelBudget_open_and_checked_parent_executed=False,
            per_counter_syscall_counts_compared_to_original=False)
        write_json(output / 'report.json', report)
        return report
    except BaseException as error:
        report['failure'] = repr(error)
        write_json(output / 'report.json', report)
        raise


def main() -> int:
    if not __debug__:
        raise RuntimeError('Original resource qualification refuses optimized Python')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, default=REPOSITORY)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--native-only', action='store_true')
    parser.add_argument('--target-dir', type=Path)
    args = parser.parse_args()
    repository = args.repository.resolve(strict=True)
    require(repository == REPOSITORY, 'Run the exact resource oracle from the selected repository')
    require(not (args.native_only and args.bundle), 'Native-only cannot reuse a prior observation')
    output = args.output.absolute()
    require(not output.exists() and not output.is_symlink(), 'Use a fresh original resource output')
    output.mkdir(mode=0o700, parents=True)
    if args.bundle:
        bundle = args.bundle.resolve(strict=True)
    else:
        bundle = output / 'native'
        bundle.mkdir(mode=0o700)
        native = native_comparison(repository, bundle)
        if args.native_only:
            print(json.dumps({'status': native['status'], 'cases': len(native['cases']),
                              'report': str(bundle / 'native-comparison.json')}))
            return 0
    original = output / 'original'
    original.mkdir(mode=0o700)
    report = original_comparison(repository, bundle, original, args.target_dir)
    print(json.dumps({'status': report['status'], 'cases': report.get('controls', 0),
                      'report': str(original / 'report.json')}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
