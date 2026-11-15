#!/usr/bin/env python3
"""Run new checks on the direct docs/evidence/corpus child of native source 165d.

No campaign result or earlier test success is inherited. Importing this helper
has no write, environment or process effect; only main() performs validation.
The original failed observations stay intact. All output is create-only and
outside the checkout. The provider helper is imported from verified bytes and
its main() is never called.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import types
from urllib.parse import unquote, urlsplit

ROOT = Path('/home/qian-qi/work/chain-w1-baseline-20261111-9082')
WORK = ROOT.parent
PARENT = '165d286b687e0a73d7fe68148d2179274fc0c0b8'
BRANCH = 'fix/chain-w1-baseline-20261111-9082'
ORIGINAL = WORK / 'w1-baseline-9082-validation-165d'
TARGET = WORK / 'w1-baseline-9082-target-165d'
PUBLICATION = WORK / 'w1-baseline-9082-evidence-publication/publication-result.json'
PROVIDER_HELPER = ORIGINAL / 'supplemental-provider-clippy/helpers/supplemental-provider-clippy-165d.py'
PROVIDER_HELPER_SHA256 = '363fa66725ddedf2a6fa1e34b785b31c2e8ddeaa767f058766b2037c0f4ea492'
PROVIDER_HELPER_BYTES = 18226
EVIDENCE = 'evidence/pon-w1-zero-paired-lazy-20261112/'
CORPUS = 'config/pon/pq-cross-branch-corpus-v1.json'
FULL_MARKDOWN = (EVIDENCE + 'README.md', EVIDENCE + 'cost-results.md',
                 'docs/research/PON_W1_ZERO_PAIRED_LAZY_V1.md')
ADDED_MARKDOWN = ('docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md',
                  'docs/protocol/pon-nakamoto-v1/details/W1_IMPLEMENTATION_COMPARISON.md')
METADATA_COMMAND = ['cargo', 'metadata', '--locked', '--offline', '--format-version', '1',
                    '--manifest-path', 'trillionnium/Cargo.toml']


def require(value, message):
    if not value:
        raise ValueError(message)


def write_json(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_regular(path, maximum=32 * 1024 * 1024):
    for item in (path, *path.parents):
        require(not item.is_symlink(), 'linked control input: ' + str(item))
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'nonregular or oversized control input')
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    require(len(data) == before.st_size and fingerprint(before) == fingerprint(after)
            == fingerprint(path.stat(follow_symlinks=False)), 'control input changed during complete read')
    return data


def retain(source, destination):
    data = read_regular(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    require(read_regular(source) == data and read_regular(destination) == data, 'retained input readback differs')
    return {'source': str(source), 'retained': str(destination), 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}, data


def git(*arguments):
    return subprocess.check_output(['git', *arguments], cwd=ROOT, timeout=30,
                                   env={**os.environ, 'GIT_NO_LAZY_FETCH': '1'})


def child_scope(publication):
    child = publication['evidence_child']
    require(type(child) is str and re.fullmatch(r'[0-9a-f]{40}', child), 'invalid evidence child identity')
    require(publication['result'] == 'EVIDENCE_CHILD_COMMITTED_AND_SOURCE_VERIFIED'
            and publication['native_execution_source'] == PARENT
            and publication['native_results_reassigned'] is False, 'publication source or outcome differs')
    require(git('rev-parse', 'HEAD').decode().strip() == child, 'checkout HEAD is not the published evidence child')
    require(git('branch', '--show-current').decode().strip() == BRANCH, 'wrong task branch')
    require(git('rev-list', '--parents', '-n', '1', child).decode().split() == [child, PARENT],
            'child must have exactly one parent, the executed 165d source')
    tree = git('rev-parse', child + '^{tree}').decode().strip()
    require(publication['evidence_tree'] == tree, 'publication tree differs')
    raw = git('diff', '--no-ext-diff', '--no-renames', '--name-status', '-z', PARENT, child, '--').split(b'\0')
    require(raw[-1] == b'', 'incomplete Git difference framing')
    raw.pop()
    require(len(raw) % 2 == 0, 'unexpected renamed/copied difference record')
    changes = []
    for index in range(0, len(raw), 2):
        status, path = raw[index].decode(), raw[index + 1].decode('utf-8')
        require(status in {'A', 'M', 'D', 'T'}, 'unsupported difference status')
        require(path.startswith('docs/') or path.startswith('evidence/') or path == CORPUS,
                'child changed code, lockfile, graph or another undeclared path: ' + path)
        changes.append({'status': status, 'path': path})
    require(changes, 'empty publication child')
    require(sorted(row['path'] for row in changes) == sorted(publication['changed_paths']),
            'publication path roster differs from Git')
    require(git('diff', '--no-ext-diff', '--name-only', PARENT, child, '--',
                'trillionnium', 'scripts', 'formal', '.cargo', 'Cargo.toml', 'Cargo.lock',
                'rust-toolchain', 'rust-toolchain.toml') == b'', 'implementation or Cargo source changed')
    return {'child': child, 'parent': PARENT, 'tree': tree, 'changes': changes,
            'single_parent_verified': True, 'only_docs_evidence_and_named_corpus_changed': True,
            'code_and_lockfile_changes': [], 'cargo_manifest_source_changes': []}


def normalized_graph(metadata):
    """Normalize graph sets, while retaining all package/dependency/target fields."""
    def canonical(value):
        if isinstance(value, dict):
            return {key: canonical(item) for key, item in sorted(value.items())}
        if isinstance(value, list):
            return sorted((canonical(item) for item in value),
                          key=lambda item: json.dumps(item, sort_keys=True, separators=(',', ':')))
        return value
    return canonical({key: metadata[key] for key in ('packages', 'workspace_members',
                      'workspace_default_members', 'resolve', 'workspace_root', 'target_directory', 'version')})


def added_lines(path, child):
    patch = git('diff', '--no-ext-diff', '--unified=0', PARENT, child, '--', path).decode('utf-8')
    selected = set()
    line_number = None
    for line in patch.splitlines():
        if line.startswith('@@ '):
            match = re.match(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@', line)
            require(match is not None, 'unrecognized Markdown hunk')
            line_number = int(match.group(1))
        elif line_number is not None and line.startswith('+') and not line.startswith('+++'):
            selected.add(line_number)
            line_number += 1
        elif line_number is not None and line.startswith(' '):
            line_number += 1
    return selected


def markdown_report(child):
    rows, failures = [], []
    for relative in (*FULL_MARKDOWN, *ADDED_MARKDOWN):
        text = read_regular(ROOT / relative).decode('utf-8')
        selected = None if relative in FULL_MARKDOWN else added_lines(relative, child)
        # Keep line numbers while ignoring fenced code, as the existing checker does.
        masked = re.sub(r'(?ms)^```[^\n]*\n.*?^```[^\n]*$',
                        lambda match: '\n' * match.group(0).count('\n'), text)
        definitions = {}
        for match in re.finditer(r'(?m)^\s{0,3}\[([^\]]+)\]:\s*<?([^\s>]+)>?', masked):
            definitions[' '.join(match.group(1).split()).casefold()] = match.group(2)
        destinations = []
        for match in re.finditer(r'!?\[[^\]\n]*\]\(\s*(?:<([^>]+)>|([^\s)]+))(?:\s+[^)]*)?\)', masked):
            destinations.append((match.start(), match.group(1) or match.group(2)))
        for match in re.finditer(r'!?\[([^\]\n]+)\]\[([^\]\n]*)\]', masked):
            line_number = masked.count('\n', 0, match.start()) + 1
            if selected is not None and line_number not in selected:
                continue
            label = ' '.join((match.group(2) or match.group(1)).split()).casefold()
            if label in definitions:
                destinations.append((match.start(), definitions[label]))
            else:
                failures.append({'file': relative, 'reason': 'unresolved reference label', 'label': label})
        # Definitions themselves cover reference and shortcut destinations.
        for match in re.finditer(r'(?m)^\s{0,3}\[([^\]]+)\]:\s*<?([^\s>]+)>?', masked):
            destinations.append((match.start(), match.group(2)))
        for offset, destination in destinations:
            line_number = masked.count('\n', 0, offset) + 1
            if selected is not None and line_number not in selected:
                continue
            parsed = urlsplit(destination.strip('<>'))
            row = {'file': relative, 'line': line_number, 'destination': destination}
            if parsed.scheme or parsed.netloc:
                row['scope'] = 'external-URL-not-fetched'
            else:
                resolved = (ROOT / relative).parent / unquote(parsed.path) if parsed.path else ROOT / relative
                resolved = resolved.resolve()
                row.update(scope='local-path-existence', target=str(resolved),
                           exists=resolved.is_relative_to(ROOT.resolve()) and resolved.exists())
                if not row['exists']:
                    failures.append(row)
            rows.append(row)
    return {'schema': 'TRNM-W1-FINAL-CHILD-MARKDOWN1', 'child': child,
            'full_documents': FULL_MARKDOWN, 'added_lines_only_documents': ADDED_MARKDOWN,
            'local_link_paths_checked': True, 'fragments_checked': False, 'external_URLs_fetched': False,
            'links': rows, 'failures': failures, 'result': 'PASS' if not failures else 'FAIL'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publication-result', type=Path, default=PUBLICATION)
    parser.add_argument('--provider-helper', type=Path, default=PROVIDER_HELPER)
    parser.add_argument('--output', type=Path, default=WORK / 'w1-baseline-9082-final-child-validation')
    args = parser.parse_args()
    output = args.output.absolute()
    require(output == output.resolve(strict=False) and output.parent.is_dir(), 'noncanonical output')
    require(not any(output.is_relative_to(path) for path in (ROOT, TARGET, ORIGINAL)), 'output must be outside source/target/original records')
    require(not output.exists() and not output.is_symlink(), 'final output is create-only')
    output.mkdir()
    os.chdir(ROOT)
    os.environ['PATH'] = '/home/qian-qi/.cargo/bin:' + os.environ['PATH']
    os.environ['CARGO_TARGET_DIR'] = str(TARGET)
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    sys.dont_write_bytecode = True
    provider_bytes = read_regular(args.provider_helper)
    require(len(provider_bytes) == PROVIDER_HELPER_BYTES
            and hashlib.sha256(provider_bytes).hexdigest() == PROVIDER_HELPER_SHA256,
            'provider helper differs from reviewed frozen bytes')
    provider = types.ModuleType('w1_final_provider_controls')
    provider.__file__ = str(args.provider_helper)
    environment_before_import = dict(os.environ)
    exec(compile(provider_bytes, str(args.provider_helper), 'exec'), provider.__dict__)
    require(dict(os.environ) == environment_before_import, 'provider import changed the environment')
    sys.path.insert(0, str(ROOT / 'scripts/ci'))
    from run_w1_rank_batch_v5 import (capture, discover_tool, digest, build_environment_overrides,
                                    cargo_configuration_snapshot, require_cargo_configuration)
    report = {'schema': 'TRNM-W1-FINAL-EVIDENCE-CHILD-VALIDATION1', 'result': 'HOLD',
              'native_measurement_source': PARENT, 'native_measurements_reassigned': False,
              'native_campaign_executed_by_this_validator': False, 'previous_success_inherited': False,
              'production_activation': False, 'security_qualified': False, 'commands': [],
              'validation_errors': [], 'final_errors': [], 'original_inputs': [],
              'process_usage_scope': 'wait4; unreaped-descendant costs may be missing',
              'rss_scope': 'kernel ru_maxrss; not sum or global simultaneous peak', 'started_unix': time.time()}
    child = None
    prerequisites_passed = False

    def run(command, stem, timeout):
        print(json.dumps({'command_started': stem, 'command': command, 'timeout_seconds': timeout}), flush=True)
        observed = capture(command, output, stem, timeout=timeout)
        observed['finished_unix'] = time.time()
        report['commands'].append(observed)
        write_json(output / (stem + '.json'), observed)
        with (output / 'commands.jsonl').open('a') as stream:
            stream.write(json.dumps(observed, sort_keys=True) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps({'command_finished': stem, 'exit_code': observed['exit_code'],
                          'timed_out': observed['timed_out'], 'elapsed_ns': observed['elapsed_ns']}), flush=True)
        return observed

    def ok(observed):
        return observed['exit_code'] == 0 and observed['timed_out'] is False

    def checked(command, stem, timeout):
        observed = run(command, stem, timeout)
        require(ok(observed), 'prerequisite command failed: ' + stem)
        return observed

    def source(stem):
        target = output / (stem + '-identity.json')
        require(not target.exists() and not target.is_symlink(), 'source receipt already exists')
        checked(['/usr/bin/python3', '-B', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                 '--expected-head', child, '--output', str(target)], stem, 600)
        return json.loads(read_regular(target))

    try:
        actual_helper, _ = retain(Path(__file__).absolute(), output / 'helpers/final-evidence-validator.py')
        report['executed_helper'] = actual_helper
        controls, _ = retain(args.provider_helper, output / 'helpers/provider-controls.py')
        report['provider_helper'] = controls
        publication_identity, raw = retain(args.publication_result, output / 'publication-result.json')
        report['original_inputs'].append(publication_identity)
        publication = json.loads(raw)
        child = publication['evidence_child']
        report['child_scope'] = child_scope(publication)
        report['child'] = child
        report['source_before'] = source('source-before')
        checked(['bash', 'scripts/project-preflight.sh', '--dev'], 'preflight', 120)
        report['provider_before'] = provider.provider_identity()
        write_json(output / 'provider-before.json', report['provider_before'])
        require(report['provider_before']['all_five_match'], 'five current provider pins do not match')
        selection = provider.check_inherited_environment(dict(os.environ))
        report['provider_selection'] = selection
        write_json(output / 'provider-environment-selection.json', selection)
        require(selection['compatible'], 'conflicting inherited OpenSSL selection; not overwritten')
        os.environ.update(provider.expected_environment())
        report['effective_seven_key_environment'] = {key: os.environ[key] for key in provider.expected_environment()}
        report['build_environment_overrides'] = build_environment_overrides(dict(os.environ))
        require(not report['build_environment_overrides'], 'unreviewed compiler/Cargo override')
        report['cargo_configuration_before'] = cargo_configuration_snapshot(ROOT, dict(os.environ))
        require_cargo_configuration(report['cargo_configuration_before'])
        tools = {name: discover_tool(name) for name in ('rustc', 'cargo')}
        report['toolchain'] = {name: {'path': str(path), 'resolved_launcher': str(path.resolve(strict=True)),
                                    'launcher_sha256': digest(path)} for name, path in tools.items()}
        checked([str(tools['rustc']), '-vV'], 'rustc', 30)
        checked([str(tools['cargo']), '--version'], 'cargo', 30)
        compiler = (output / 'rustc.stdout').read_text()
        require('\nrelease: 1.95.0\n' in compiler and '\nhost: x86_64-unknown-linux-gnu\n' in compiler,
                'original Rust 1.95.0 x86_64 contract differs')
        require((output / 'cargo.stdout').read_text().startswith('cargo 1.95.0 '), 'original Cargo version differs')
        checked([str(provider.PREFIX / 'bin/openssl'), 'version', '-a'], 'provider-version', 30)
        require((output / 'provider-version.stdout').read_text().splitlines()[0]
                == 'OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL 3.5.9 29 Sep 2026)', 'provider version differs')
        for name in ('workspace-strict-clippy.json', 'workspace-strict-clippy.stdout',
                     'workspace-strict-clippy.stderr', 'checks-phase.json', 'cargo-metadata.json',
                     'cargo-metadata.stdout', 'campaign-source-before-identity.json'):
            retained, _ = retain(ORIGINAL / name, output / 'prior-observations' / name)
            report['original_inputs'].append(retained)
        # Retain original supplemental failures as observations, with no PASS precondition.
        for directory in sorted(ORIGINAL.glob('supplemental-provider-clippy*')):
            require(directory.is_dir() and not directory.is_symlink(), 'linked original supplemental directory')
            for path in sorted(directory.rglob('*')):
                if path.is_file() or path.is_symlink():
                    retained, _ = retain(path, output / 'prior-observations' / directory.name / path.relative_to(directory))
                    report['original_inputs'].append(retained)
        original_metadata = json.loads(read_regular(output / 'prior-observations/cargo-metadata.json'))
        require(original_metadata['command'] == METADATA_COMMAND and original_metadata['exit_code'] == 0
                and original_metadata['timed_out'] is False, 'original metadata observation is not the declared successful graph command')
        original_identity = json.loads(read_regular(output / 'prior-observations/campaign-source-before-identity.json'))
        require(original_identity['tested_commit'] == PARENT and original_identity['tracked_worktree_verified'] is True,
                'original graph source identity differs')
        qrom = output / 'qrom-current'
        qrom.mkdir()
        prerequisites_passed = True
        commands = [
            ('cargo-metadata', METADATA_COMMAND, 300, None),
            ('crypto-lib-tests', ['cargo', 'test', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-crypto-primitives', '--lib'], 1800, ('rust', 199)),
            ('workspace-fmt', ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check'], 300, None),
            ('zero-paired-lazy-reader', ['/usr/bin/python3', '-B', 'scripts/ci/test_pon_w1_zero_paired_lazy_v1.py'], 300, ('python', 21)),
            ('v5-runner-controls', ['/usr/bin/python3', '-B', 'scripts/ci/test_run_w1_rank_batch_v5.py'], 300, ('python', 6)),
            ('source-integrity-negatives', ['/usr/bin/python3', '-B', 'scripts/ci/test_ci_source_integrity.py'], 600, ('python', 43)),
            ('qrom-current-controls', ['/usr/bin/python3', '-B', 'scripts/ci/w1_qrom_supplemental_controls.py', '--suite', 'current', '--repo-root', str(ROOT), '--output-dir', str(qrom)], 300, ('python', 14)),
            ('qrom-current-map', ['/usr/bin/python3', '-B', 'scripts/w1_qrom_current_implementation_audit.py', '--repo-root', str(ROOT), '--output', str(qrom / 'implementation-current.json')], 300, None),
            ('pq-corpus-guard', ['/usr/bin/python3', '-B', 'scripts/ci/check_pq_research_integration.py'], 600, None),
            ('pq-corpus-tests', ['/usr/bin/python3', '-B', 'scripts/ci/test_pq_research_integration.py'], 600, ('python', 60)),
            ('ci-contract', ['/usr/bin/python3', '-B', 'scripts/ci/check_ci_contract.py'], 300, None),
            ('distributed-inventory', ['/usr/bin/python3', '-B', 'scripts/refresh_distributed_source_inventory.py', '--check'], 300, None),
            ('root-dependency-checker', ['/usr/bin/python3', '-B', 'scripts/ci/pq_root_dependency_register.py', '--root', str(ROOT), '--manifest', 'config/pon/pq-root-dependency-register-v3.json'], 300, None),
            ('root-dependency-controls', ['/usr/bin/python3', '-B', 'scripts/ci/test_pq_root_dependency_register.py'], 300, ('python', 43)),
            ('crypto-strict-clippy', ['cargo', 'clippy', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-crypto-primitives', '--all-targets', '--', '-D', 'warnings'], 1800, None),
            ('workspace-strict-clippy', ['cargo', 'clippy', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'], 3600, None),
        ]
        for stem, command, timeout, count in commands:
            observed = run(command, stem, timeout)
            try:
                if count is not None:
                    text = (output / observed['stdout']).read_text(errors='replace') + '\n' + (output / observed['stderr']).read_text(errors='replace')
                    if count[0] == 'python':
                        counts = [int(value) for value in re.findall(r'(?m)^Ran (\d+) tests? in ', text)]
                        complete = counts == [count[1]] and re.search(r'(?m)^OK\s*$', text) is not None
                    else:
                        counts = [tuple(map(int, row)) for row in re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', text)]
                        complete = counts == [(count[1], 0, 0, 0, 0)]
                    completion = {'expected_tests': count[1], 'observed_counts': counts,
                                  'expected_test_count_no_skip_and_exit_verified': bool(complete and ok(observed))}
                    write_json(output / (stem + '-completion.json'), completion)
                    require(completion['expected_test_count_no_skip_and_exit_verified'], 'test completion count/skip/exit differs')
                if stem == 'cargo-metadata':
                    require(ok(observed), 'new locked/offline metadata failed')
                    before = normalized_graph(json.loads(read_regular(output / 'prior-observations/cargo-metadata.stdout')))
                    after = normalized_graph(json.loads(read_regular(output / observed['stdout'])))
                    graph = {'unchanged': before == after, 'original_source': PARENT, 'current_child': child,
                             'original_graph_sha256': hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
                             'current_graph_sha256': hashlib.sha256(json.dumps(after, sort_keys=True).encode()).hexdigest()}
                    write_json(output / 'cargo-graph-comparison.json', graph)
                    report['cargo_graph_comparison'] = graph
                    require(graph['unchanged'], 'locked Cargo graph differs from the executed source')
            except (OSError, ValueError, KeyError, TypeError) as error:
                report['validation_errors'].append({'stem': stem, 'error': type(error).__name__ + ': ' + str(error)})
        try:
            markdown = markdown_report(child)
            write_json(output / 'markdown-links.json', markdown)
            report['markdown_links_passed'] = markdown['result'] == 'PASS'
        except (OSError, ValueError, KeyError, TypeError) as error:
            report['markdown_links_passed'] = False
            report['validation_errors'].append({'stem': 'markdown', 'error': type(error).__name__ + ': ' + str(error)})
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError) as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        report['prerequisites_passed'] = prerequisites_passed
        try:
            report['provider_after'] = provider.provider_identity()
            write_json(output / 'provider-after.json', report['provider_after'])
            require(report['provider_after']['all_five_match']
                    and report.get('provider_before') == report['provider_after'], 'provider identity absent or changed')
        except (OSError, ValueError, KeyError, TypeError) as error:
            report['final_errors'].append(type(error).__name__ + ': ' + str(error))
        try:
            if type(child) is str and re.fullmatch(r'[0-9a-f]{40}', child):
                report['source_after'] = source('source-after')
                require(report.get('source_before') == report['source_after'], 'source identity absent or changed')
            else:
                raise ValueError('no verified child identity for final source check')
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            report['final_errors'].append(type(error).__name__ + ': ' + str(error))
        try:
            report['cargo_configuration_after'] = cargo_configuration_snapshot(ROOT, dict(os.environ))
            require_cargo_configuration(report['cargo_configuration_after'])
            require(report.get('cargo_configuration_before') == report['cargo_configuration_after'], 'Cargo configuration absent or changed')
            require(report.get('effective_seven_key_environment') == provider.expected_environment()
                    == {key: os.environ.get(key) for key in provider.expected_environment()}, 'provider environment changed')
        except (OSError, ValueError, KeyError, TypeError) as error:
            report['final_errors'].append(type(error).__name__ + ': ' + str(error))
        try:
            for item in report['original_inputs']:
                data = read_regular(Path(item['source']))
                require(len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256'],
                        'original input changed: ' + item['source'])
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            report['final_errors'].append(type(error).__name__ + ': ' + str(error))
        report['failed_commands'] = sum(not ok(row) for row in report['commands'])
        if (prerequisites_passed and not report.get('error') and not report['final_errors']
                and not report['validation_errors'] and report['failed_commands'] == 0
                and report.get('markdown_links_passed') is True
                and report.get('cargo_graph_comparison', {}).get('unchanged') is True):
            report['result'] = 'FINAL_CHILD_CHECKS_PASSED'
        report['finished_unix'] = time.time()
        report['artifact_files'] = [provider.regular_identity(path) for path in sorted(output.rglob('*')) if path.is_file()]
        write_json(output / 'final-validation.json', report)
    print(json.dumps({'result': report['result'], 'child': child,
                      'receipt': str(output / 'final-validation.json')}), flush=True)
    return 0 if report['result'] == 'FINAL_CHILD_CHECKS_PASSED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
