#!/usr/bin/env python3
"""Read-only documentation integrity gate; never semantic or independent acceptance."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tomllib
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = 'config/documentation-contracts-v1.json'
GUIDE = 'docs/modules/TRNM_MODULE_IMPLEMENTATION_GUIDE_V1.md'
AUTHORITY = 'docs/architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md'
REVIEW = 'docs/modules/TRNM_INDEPENDENT_REVIEW_V1.md'
PLAN = 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
REFERENCE = 'docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md'
MANIFEST = 'docs/development/plan-manifest-v1.toml'
COVERAGE = 'config/module-coverage-v1.toml'
SELF = 'scripts/ci/check_documentation_contracts_v1.py'
TEST = 'scripts/ci/test_documentation_contracts_v1.py'
MODULES = [f'M{i:02d}' for i in range(18)]
PROFILES = {
    'bft-v0': 'frozen-implementation-target-not-activation',
    'pcc1': 'candidate-contract-not-wire-version',
    'ai-v1': 'draft-protocol-v1-not-activated',
    'legacy-ledger-observation': 'historical-local-stage-vocabulary-not-publication-authority',
}
_V0 = 'docs/protocol/poco-bft-v0/'
V0_IMPORTS = {
    _V0+'01-system-model-and-threat-model.md': '9b7791addf496d0b88f84bb37592d099ad525eec',
    _V0+'02-chained-qc-consensus.md': '6f5d6a88e15b3682ffe7d28137032d69f86edb9b',
    _V0+'03-wire-crypto-and-domain-separation.md': 'd0f79ed79f044eeb09f04224000754ae24d3b23b',
    _V0+'04-epochs-validator-sets-and-upgrades.md': 'c08f835d295d1ca7c747ccf3c3bd1af7ae7f767c',
    _V0+'05-poco-weights-bond-and-slashing.md': 'd8005598471dff3bae229eda6d129b5a1a14b066',
    _V0+'06-light-client.md': '42609bc8e36e990f4bad64b86d687f333ac3b58b',
    _V0+'07-invariants-and-conformance.md': '4b9c425acc9588ba36d188fc0ea5616ac4f61f5d',
}
REQUIRED_DOMAINS = [
    {'consensus', 'cryptography'}, {'cryptography', 'application-security'},
    {'consensus'}, {'storage-recovery', 'cryptography'},
    {'network-security', 'storage-recovery'}, {'application-security', 'storage-recovery'},
    {'execution', 'storage-recovery'}, {'storage-recovery', 'execution', 'client-proofs'},
    {'consensus', 'storage-recovery'}, {'network-security', 'storage-recovery'},
    {'application-security', 'execution', 'economics'}, {'cryptography', 'application-security'},
    {'economics', 'application-security', 'storage-recovery'},
    {'client-proofs', 'consensus', 'cryptography', 'storage-recovery'},
    {'client-proofs', 'application-security'}, {'release-supply-chain', 'storage-recovery'},
    {'application-security', 'execution', 'release-supply-chain'}, {'release-supply-chain'},
]
DOMAIN_IDS = set().union(*REQUIRED_DOMAINS)
TOP_FIELDS = {
    'schema', 'plan_id', 'authority_contract', 'implementation_guide', 'review_policy',
    'coverage_manifest', 'production_authority', 'semantic_design_accepted',
    'implementation_accepted', 'profile_status', 'pcc1_v0_imports',
    'independent_review_assignments', 'integration_observation', 'modules', 'auxiliary_trace',
}
ROW_FIELDS = {
    'id', 'guide_ref', 'profiles', 'primary_crates', 'normative_refs',
    'implementation_refs', 'regression_refs', 'regression_scope', 'requirement_ids',
    'review_domains', 'implementation_owner_scope', 'independent_review_status',
    'semantic_acceptance', 'implementation_acceptance', 'operation_trace',
}
PIN_FIELDS = {
    'documentation_authority_git_blob': AUTHORITY,
    'module_implementation_guide_git_blob': GUIDE,
    'independent_review_policy_git_blob': REVIEW,
    'documentation_contract_registry_git_blob': REGISTRY,
    'documentation_contract_gate_git_blob': SELF,
    'documentation_contract_test_git_blob': TEST,
}


class DocumentationError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(f'{code}: {detail}')
        self.code = code
        self.detail = detail


def require(value: bool, code: str, detail: str) -> None:
    if not value:
        raise DocumentationError(code, detail)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, 'DOC-JSON-DUPLICATE', key)
        result[key] = value
    return result


def strings(value: Any, where: str) -> list[str]:
    require(isinstance(value, list) and bool(value), 'DOC-LIST', where)
    require(all(isinstance(x, str) and bool(x.strip()) for x in value), 'DOC-LIST', where)
    require(len(set(value)) == len(value), 'DOC-DUPLICATE', where)
    return value


def file_ref(root: Path, value: str) -> tuple[Path, str]:
    require(isinstance(value, str) and bool(value), 'DOC-PATH', repr(value))
    parts = value.split('#')
    require(len(parts) <= 2, 'DOC-PATH', value)
    path = parts[0]
    require(path and not path.startswith('/') and '\\' not in path and ':' not in path,
            'DOC-PATH', value)
    require(all(p not in {'', '.', '..'} for p in path.split('/')), 'DOC-PATH', value)
    require(not any(p.startswith('-') for p in path.split('/')), 'DOC-PATH', value)
    local = root.joinpath(*PurePosixPath(path).parts)
    require(local.resolve().is_relative_to(root.resolve()), 'DOC-PATH-ESCAPE', value)
    require(local.is_file(), 'DOC-MISSING-FILE', value)
    if len(parts) == 2:
        require(bool(parts[1]), 'DOC-ANCHOR', value)
        require(f'<a id="{parts[1]}"></a>' in local.read_text(encoding='utf-8'),
                'DOC-ANCHOR', value)
    return local, path


def blob_id(content: bytes) -> str:
    return hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()


def check_pin(path: Path, expected: str) -> None:
    require(blob_id(path.read_bytes()) == expected, 'DOC-PIN', str(path))


def validate_structure(data: dict[str, Any], coverage: dict[str, Any]) -> None:
    require(isinstance(data, dict) and set(data) == TOP_FIELDS, 'DOC-SCHEMA', 'top-level fields')
    require(data['schema'] == 'trnm-documentation-contracts-v1', 'DOC-SCHEMA', 'schema')
    require(data['plan_id'] == 'trnm-chain-development-plan-v2', 'DOC-PLAN', 'plan ID')
    for field, expected in [('authority_contract', AUTHORITY), ('implementation_guide', GUIDE),
                            ('review_policy', REVIEW), ('coverage_manifest', COVERAGE)]:
        require(data[field] == expected, 'DOC-BINDING', field)
    for field in ['production_authority', 'semantic_design_accepted', 'implementation_accepted']:
        require(data[field] is False, 'DOC-PROMOTION', field)
    require(data['profile_status'] == PROFILES, 'DOC-PROFILE', 'profile meaning/activation drift')
    require(data['pcc1_v0_imports'] == V0_IMPORTS, 'DOC-IMPORT', 'frozen import repin')
    require(data['independent_review_assignments'] == [], 'DOC-SELF-ACCEPTANCE',
            'appointments/findings require external authenticated evidence, not this local index')
    obs = data['integration_observation']
    require(isinstance(obs, dict) and set(obs) == {'observed_source', 'selected_successor_pr', 'stack', 'current_identity'},
            'DOC-LINEAGE', 'observation fields')
    require(isinstance(obs['observed_source'], str) and re.fullmatch(r'[0-9a-f]{40}', obs['observed_source']) is not None,
            'DOC-LINEAGE', 'observed source')
    require(type(obs['selected_successor_pr']) is int and obs['selected_successor_pr'] == 62,
            'DOC-LINEAGE', 'selected integration successor')
    require(obs['current_identity'] == 'derive-head-tree-base-and-prospective-merge-at-verification-time',
            'DOC-LINEAGE', 'mutable current identity must not be pinned as an observation')
    expected_stack = [
        {'pr': 62, 'base_ref': 'main', 'head_ref': 'work/plan-v2-full-gap-closure-20260902'},
        {'pr': 85, 'base_ref': 'work/plan-v2-full-gap-closure-20260902', 'head_ref': 'work/poco-authority-ai-convergence-20260907'},
        {'pr': 86, 'base_ref': 'work/poco-authority-ai-convergence-20260907', 'head_ref': 'fix/chain-pcc1-runtime-integration'},
    ]
    require(obs['stack'] == expected_stack, 'DOC-LINEAGE', 'observed stack differs; re-observe/review explicitly')
    rows = data['modules']
    require(isinstance(rows, list) and all(isinstance(x, dict) for x in rows), 'DOC-MODULES', 'rows')
    require([x.get('id') for x in rows] == MODULES, 'DOC-MODULES', 'exact ordered M00-M17 inventory')
    coverage_rows = coverage.get('module_coverage', [])
    require(isinstance(coverage_rows, list) and all(isinstance(x, dict) for x in coverage_rows),
            'DOC-COVERAGE', 'coverage rows')
    require([x.get('id') for x in coverage_rows] == MODULES, 'DOC-COVERAGE', 'module inventory')
    all_crates: list[str] = []
    all_requirements: list[str] = []
    for index, (row, covered) in enumerate(zip(rows, coverage_rows)):
        mid = MODULES[index]
        require(set(row) == ROW_FIELDS, 'DOC-SCHEMA', mid)
        require(row['guide_ref'] == f'{GUIDE}#{mid.lower()}', 'DOC-BINDING', mid)
        profiles = strings(row['profiles'], mid+' profiles')
        require(set(profiles) <= set(PROFILES), 'DOC-PROFILE', mid)
        crates = strings(row['primary_crates'], mid+' crates')
        require(crates == covered.get('primary_crates'), 'DOC-OWNERSHIP', mid)
        all_crates.extend(crates)
        for field in ['normative_refs', 'implementation_refs', 'regression_refs']:
            strings(row[field], mid+' '+field)
        require(row['regression_scope'] == 'existing-review-input-not-independent-golden-acceptance',
                'DOC-VECTOR-CLAIM', mid)
        requirements = strings(row['requirement_ids'], mid+' requirements')
        require(len(requirements) >= 5 and all(re.fullmatch(mid+r'-[A-Z][A-Z0-9-]*', x) for x in requirements),
                'DOC-REQUIREMENTS', mid)
        all_requirements.extend(requirements)
        trace = row['operation_trace']
        trace_fields = {'requirement_id', 'profile', 'implementation_path', 'implementation_symbol',
                        'error_path', 'error_symbol_or_literal', 'regression_path', 'regression_symbol',
                        'scope', 'limitation'}
        require(isinstance(trace, dict) and set(trace) == trace_fields, 'DOC-TRACE', mid+' fields')
        require(all(isinstance(x, str) and bool(x.strip()) for x in trace.values()), 'DOC-TRACE', mid+' values')
        require(trace['requirement_id'] in requirements and trace['profile'] in profiles,
                'DOC-TRACE', mid+' applicability')
        require(trace['scope'] == 'representative-source-regression-not-complete-module-acceptance',
                'DOC-TRACE', mid+' scope')
        require(trace['implementation_path'] in row['implementation_refs']
                and trace['error_path'] in row['implementation_refs']
                and trace['regression_path'] in row['regression_refs'], 'DOC-TRACE', mid+' references')
        for key in ['implementation_symbol', 'regression_symbol']:
            require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', trace[key]) is not None,
                    'DOC-TRACE', mid+' symbol spelling')
        domains = set(strings(row['review_domains'], mid+' domains'))
        require(REQUIRED_DOMAINS[index] <= domains <= DOMAIN_IDS, 'DOC-REVIEW-DOMAIN', mid)
        require(row['implementation_owner_scope'] == 'repository-maintainer-routing-only', 'DOC-OWNER-ROLE', mid)
        require(row['independent_review_status'] == 'vacant', 'DOC-SELF-ACCEPTANCE', mid)
        require(row['semantic_acceptance'] == row['implementation_acceptance'] == 'not-assessed',
                'DOC-PROMOTION', mid)
    require(len(all_crates) == len(set(all_crates)), 'DOC-OWNERSHIP', 'duplicate primary crate')
    require(len(all_requirements) == len(set(all_requirements)), 'DOC-REQUIREMENTS', 'duplicate ID')
    auxiliary = data['auxiliary_trace']
    expected_aux = coverage.get('auxiliary_units', [])
    require(isinstance(auxiliary, list) and all(isinstance(x, dict) for x in auxiliary), 'DOC-AUXILIARY', 'rows')
    require(isinstance(expected_aux, list) and bool(expected_aux), 'DOC-AUXILIARY', 'coverage')
    require(len(auxiliary) == len(expected_aux), 'DOC-AUXILIARY', 'count')
    require(len({x.get('id') for x in auxiliary}) == len(auxiliary), 'DOC-AUXILIARY', 'duplicates')
    require({(x.get('id'), x.get('primary_module')) for x in auxiliary}
            == {(x.get('id'), x.get('primary_module')) for x in expected_aux}, 'DOC-AUXILIARY', 'ownership')
    for row in auxiliary:
        require(set(row) == {'id', 'primary_module', 'guide_ref'}, 'DOC-SCHEMA', 'auxiliary')
        require(row['primary_module'] in MODULES and row['guide_ref'] == f"{GUIDE}#{row['primary_module'].lower()}",
                'DOC-AUXILIARY', row['id'])


def guide_sections(text: str) -> dict[str, str]:
    matches = list(re.finditer(r'^## (M\d{2}) — ', text, re.MULTILINE))
    require([m[1] for m in matches] == MODULES, 'DOC-GUIDE', 'ordered module headings')
    return {m[1]: text[m.start():matches[i+1].start() if i+1 < len(matches) else len(text)]
            for i, m in enumerate(matches)}


def validate_guide(data: dict[str, Any], text: str) -> None:
    sections = guide_sections(text)
    for row in data['modules']:
        section = sections[row['id']]
        for marker in ['**Applicability and inputs.**', '**State/admission algorithm.**',
                       '**Error and recovery semantics.**', '**Conformance requirements.**',
                       '**Implementation and consumers.**']:
            require(marker in section, 'DOC-GUIDE', row['id']+' '+marker)
        declared = set(row['requirement_ids'])
        found = set(re.findall(r'`('+row['id']+r'-[A-Z][A-Z0-9-]*)`', section))
        require(declared == found, 'DOC-REQUIREMENTS', row['id']+' guide/index mismatch')
    m08 = sections['M08']
    for text_rule in ['Validated -> IntentDurable -> SignatureRecorded -> VotePublished',
                      'FinalityVerified -> CommitIntentDurable -> ApplicationApplied -> CommitRecorded -> CheckpointConfirmed -> ReceiptPublished',
                      'does not wait']:
        require(text_rule in m08, 'DOC-LIFECYCLE', text_rule)


def has_function_definition(text: str, symbol: str) -> bool:
    """Lexical navigation check only; never an AST or behavioral equivalence proof."""
    return re.search(r'(?m)^\s*(?:(?:pub(?:\([^)]*\))?|async|const|unsafe)\s+)*(?:fn|def)\s+'
                     + re.escape(symbol) + r'\s*(?:[<(])', text) is not None


def validate_trace_symbols(root: Path, trace: dict[str, str]) -> None:
    for path_key, symbol_key in [('implementation_path', 'implementation_symbol'),
                                 ('regression_path', 'regression_symbol')]:
        path, _ = file_ref(root, trace[path_key])
        require(has_function_definition(path.read_text(encoding='utf-8'), trace[symbol_key]),
                'DOC-SYMBOL', trace[path_key]+'::'+trace[symbol_key])
    path, _ = file_ref(root, trace['error_path'])
    require(trace['error_symbol_or_literal'] in path.read_text(encoding='utf-8'),
            'DOC-SYMBOL', trace['error_path']+' error definition/literal')


def git(root: Path, *args: str) -> str:
    return subprocess.run(['git', *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()


def source_identity(root: Path, expected: str | None = None) -> tuple[str, str]:
    head, tree = git(root, 'rev-parse', 'HEAD'), git(root, 'rev-parse', 'HEAD^{tree}')
    require(re.fullmatch(r'[0-9a-f]{40}', head) is not None and re.fullmatch(r'[0-9a-f]{40}', tree) is not None,
            'DOC-SOURCE', 'full source/tree identities required')
    if expected:
        require(expected == head, 'DOC-SOURCE', 'event source does not match HEAD')
    require(not git(root, 'status', '--porcelain', '--untracked-files=all'), 'DOC-DIRTY', 'exact checkout must be clean')
    return head, tree


def validate_files(root: Path, data: dict[str, Any], manifest: dict[str, Any]) -> dict[str, dict[str, str]]:
    refs = {REGISTRY, GUIDE, AUTHORITY, REVIEW, PLAN, REFERENCE, MANIFEST, COVERAGE, SELF, TEST}
    refs.update(data['pcc1_v0_imports'])
    for row in data['modules']:
        refs.add(row['guide_ref'])
        for field in ['normative_refs', 'implementation_refs', 'regression_refs']:
            refs.update(row[field])
        for crate in row['primary_crates']:
            base = f'trillionnium/crates/{crate}'
            refs.add(base+'/Cargo.toml')
            entries = [base+'/src/'+name for name in ['lib.rs', 'main.rs'] if (root/base/'src'/name).is_file()]
            require(bool(entries), 'DOC-IMPLEMENTATION', crate+' has no declared standard entry point')
            refs.update(entries)
    bindings: dict[str, dict[str, str]] = {}
    for ref in sorted(refs):
        path, relative = file_ref(root, ref)
        content = path.read_bytes()
        actual = blob_id(content)
        # A working-tree byte match to HEAD is required, not a directory count.
        require(git(root, 'rev-parse', 'HEAD:'+relative) == actual, 'DOC-SOURCE', relative)
        bindings[relative] = {'git_blob': actual, 'sha256': hashlib.sha256(content).hexdigest()}
    for row in data['modules']:
        validate_trace_symbols(root, row['operation_trace'])
    for path, expected in data['pcc1_v0_imports'].items():
        check_pin(root/path, expected)
    for field, path in PIN_FIELDS.items():
        require(manifest.get(field) == bindings[path]['git_blob'], 'DOC-PIN', field)
    validate_guide(data, (root/GUIDE).read_text(encoding='utf-8'))
    plan = (root/PLAN).read_text(encoding='utf-8')
    reference = (root/REFERENCE).read_text(encoding='utf-8')
    for path in [AUTHORITY, GUIDE, REVIEW, REGISTRY]:
        require(path in plan, 'DOC-ENTRYPOINT', path+' missing from sole plan')
    for text in [plan, reference]:
        require('legacy-ledger-observation' in text and 'VotePublished' in text and 'ReceiptPublished' in text,
                'DOC-LIFECYCLE', 'plan/reference must distinguish legacy stages and the two PCC1 publications')
    return bindings


def main() -> int:
    import os
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Optional report outside the repository; not an acceptance attestation')
    args = parser.parse_args()
    if args.output:
        require(not args.output.resolve().is_relative_to(ROOT), 'DOC-OUTPUT', 'report must be outside the source checkout')
    head, tree = source_identity(ROOT, os.environ.get('TRNM_EXPECTED_SOURCE_SHA'))
    data = json.loads((ROOT/REGISTRY).read_text(encoding='utf-8'), object_pairs_hook=strict_object)
    coverage = tomllib.loads((ROOT/COVERAGE).read_text(encoding='utf-8'))
    manifest = tomllib.loads((ROOT/MANIFEST).read_text(encoding='utf-8'))
    validate_structure(data, coverage)
    require(manifest.get('selected_successor_pull_request') == data['integration_observation']['selected_successor_pr'],
            'DOC-LINEAGE', 'plan manifest successor mismatch')
    require(subprocess.run(['git', 'merge-base', '--is-ancestor', data['integration_observation']['observed_source'], 'HEAD'],
                           cwd=ROOT, capture_output=True).returncode == 0, 'DOC-LINEAGE', 'observed source is not an ancestor')
    bindings = validate_files(ROOT, data, manifest)
    canonical = json.dumps(bindings, sort_keys=True, separators=(',', ':')).encode()
    report = {
        'schema': 'trnm-documentation-integrity-report-v1', 'source_commit': head, 'source_tree': tree,
        'module_count': len(data['modules']), 'primary_crate_count': sum(len(x['primary_crates']) for x in data['modules']),
        'auxiliary_count': len(data['auxiliary_trace']), 'requirement_count': sum(len(x['requirement_ids']) for x in data['modules']),
        'representative_operation_trace_count': len(data['modules']),
        'symbol_check_scope': 'lexical-source-definition-not-behavioral-equivalence',
        'input_count': len(bindings), 'input_set_sha256': hashlib.sha256(canonical).hexdigest(),
        'scope': 'version-reference-requirement-source-integrity-only', 'result': 'PASS',
        'semantic_design_acceptance': 'not-assessed', 'implementation_acceptance': 'not-assessed',
        'independent_acceptance': 'absent-from-local-index-requires-authenticated-external-evidence',
        'vacant_review_domains': sorted(DOMAIN_IDS), 'production_authority': False,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({**report, 'inputs': bindings}, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (DocumentationError, OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(json.dumps({'result': 'FAIL', 'code': getattr(error, 'code', 'DOC-INPUT'), 'detail': str(error),
                          'semantic_design_acceptance': 'not-assessed', 'production_authority': False}), file=sys.stderr)
        raise SystemExit(2)
