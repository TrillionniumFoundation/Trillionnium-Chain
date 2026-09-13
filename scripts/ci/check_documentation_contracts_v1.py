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
OPERATIONS = 'config/documentation-operations-v1.json'
OPERATION_GUIDE = 'docs/modules/TRNM_FOUNDATION_OPERATION_CONTRACTS_V1.md'
REQUIRED_FOUNDATION_OPERATIONS = {
    'M02-OP-VOTE-BARRIER', 'M02-OP-TIMEOUT-BARRIER', 'M03-OP-SIGN-EXACT',
    'M04-OP-PERSIST-INGRESS', 'M04-OP-ACK-PREPARED', 'M08-OP-COMMIT-STRICT',
    'M08-OP-READ-STRICT', 'M15-OP-RECOVER-SESSION', 'M15-OP-ADVANCE-VERIFIED-FACT',
    'M02-OP-TC-ADVANCE', 'M08-OP-RECOVER-EXPECTED-LEDGER', 'M08-OP-APPEND-EXACT-LEDGER',
    'M15-OP-NATIVE-SIGNED-VOTE-REPLAY-V1',
}
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
    _V0+'02-chained-qc-consensus.md': '52deb69f59cb048563b023e82b8ff927f4fb1aac',
    _V0+'03-wire-crypto-and-domain-separation.md': '57d85f30c9d6ed85d081ffbf63f57d2e5dc6e2ce',
    _V0+'04-epochs-validator-sets-and-upgrades.md': 'c08f835d295d1ca7c747ccf3c3bd1af7ae7f767c',
    _V0+'05-poco-weights-bond-and-slashing.md': '103c899bd5c60995429feee2848991540cf6e831',
    _V0+'06-light-client.md': '42609bc8e36e990f4bad64b86d687f333ac3b58b',
    _V0+'07-invariants-and-conformance.md': '608dc2486885e162822cbb4344b6424a827fd064',
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


def operation_object(value: Any, fields: set[str], where: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == fields, 'DOC-OP-SCHEMA', where)
    return value


def operation_text(value: Any, where: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), 'DOC-OP-TEXT', where)
    return value


def operation_reference(root: Path, value: Any, refs: set[str]) -> None:
    reference = operation_object(value, {'path', 'selector'}, 'source reference')
    path, relative = file_ref(root, reference['path'])
    selector = operation_text(reference['selector'], relative)
    require(selector in path.read_text(encoding='utf-8'), 'DOC-OP-SELECTOR', relative+': '+selector)
    refs.add(relative)


def operation_features(root: Path, package: str, features: Any, refs: set[str]) -> None:
    require(isinstance(features, list) and all(isinstance(x, str) for x in features),
            'DOC-OP-FEATURE', package)
    require(len(features) == len(set(features)), 'DOC-OP-FEATURE', package+' duplicate')
    path, relative = file_ref(root, f'trillionnium/crates/{package}/Cargo.toml')
    manifest = tomllib.loads(path.read_text(encoding='utf-8'))
    require(manifest.get('package', {}).get('name') == package, 'DOC-OP-PACKAGE', package)
    require(set(features) <= set(manifest.get('features', {})), 'DOC-OP-FEATURE', package)
    refs.add(relative)


def operation_case_command(case: dict[str, Any]) -> list[str]:
    """Describe a bounded replay; never execute registry-controlled commands."""
    command = ['cargo', 'test', '--locked', '--offline', '-p', case['package']]
    if case['features']:
        command += ['--features', ','.join(case['features'])]
    if case['target'] == 'lib':
        command += ['--lib']
    elif case['target'].startswith('bin:'):
        command += ['--bin', case['target'].removeprefix('bin:')]
    else:
        command += ['--test', case['target']]
    return command + [case['test_filter'], '--', '--exact']


def operation_target_features(manifest: dict[str, Any], target: dict[str, Any],
                              selected: list[str], where: str) -> None:
    """Resolve named local features and default edges, not dependency cfgs."""
    graph = manifest.get('features', {})
    required = target.get('required-features', [])
    require(isinstance(required, list) and all(isinstance(x, str) for x in required),
            'DOC-OP-FEATURE', where+' required-features')
    require(set(required) <= set(graph), 'DOC-OP-FEATURE', where+' unsupported target feature')
    enabled = set(selected)
    if 'default' in graph:
        enabled.add('default')
    pending = list(enabled)
    while pending:
        feature = pending.pop()
        for edge in graph.get(feature, []):
            if edge in graph and edge not in enabled:
                enabled.add(edge)
                pending.append(edge)
    require(set(required) <= enabled, 'DOC-OP-FEATURE', where+' missing required target feature')


def operation_test_region(text: str, symbol: str, features: list[str] | None = None) -> str:
    """Lexical Rust test region, including inline tests; not an AST or execution."""
    match = re.search(r'(?m)^(?P<indent>[ \t]*)fn '+re.escape(symbol)+r'\s*\(', text)
    require(match is not None, 'DOC-OP-TEST', symbol)
    attributes = []
    for line in reversed(text[:match.start()].rstrip().splitlines()):
        if not line.strip().startswith('#['):
            break
        attributes.append(line.strip())
    require('#[test]' in attributes, 'DOC-OP-TEST', symbol+' is not an attributed test')
    require(not any(re.match(r'#\[ignore(?:\s|\])', item) for item in attributes),
            'DOC-OP-TEST', symbol+' is ignored by the generated replay command')
    if features is not None:
        for attribute in attributes:
            if attribute.startswith('#[cfg(') and attribute != '#[cfg(test)]':
                gate = re.fullmatch(r'#\[cfg\(feature\s*=\s*"([^"]+)"\)\]', attribute)
                require(gate is not None and gate[1] in features,
                        'DOC-OP-FEATURE', symbol+' unselected or unsupported direct test cfg')
    remaining = text[match.end():]
    following = re.search(r'(?m)^'+re.escape(match['indent'])+r'fn [A-Za-z_][A-Za-z0-9_]*\s*\(', remaining)
    return text[match.start():match.end()+(following.start() if following else len(remaining))]


def validate_operations(root: Path, data: Any, registry: dict[str, Any],
                        coverage: dict[str, Any]) -> tuple[dict[str, Any], set[str]]:
    """Validate explicit operation records without upgrading any acceptance axis."""
    operation_object(data, {'schema', 'plan_id', 'primary_module', 'source_observation', 'scope',
                           'module_ids', 'operation_catalog_complete', 'production_authority',
                           'semantic_acceptance', 'implementation_acceptance', 'operations'}, 'catalog')
    require(data['schema'] == 'trnm-documentation-operations-v1', 'DOC-OP-SCHEMA', 'catalog schema')
    require(data['plan_id'] == registry['plan_id'] and data['primary_module'] == 'M17',
            'DOC-OP-SCHEMA', 'plan/owner')
    require(data['scope'] == 'bounded-foundation-operations-not-all-enabled-operations',
            'DOC-OP-SCOPE', 'scope')
    require(data['operation_catalog_complete'] is False and data['production_authority'] is False,
            'DOC-OP-PROMOTION', 'catalog cannot establish completeness or activation')
    for field in ['semantic_acceptance', 'implementation_acceptance']:
        require(data[field] == 'not-assessed', 'DOC-OP-PROMOTION', field)
    require(isinstance(data['source_observation'], str)
            and re.fullmatch(r'[0-9a-f]{40}', data['source_observation']) is not None,
            'DOC-OP-SOURCE', 'historical source observation')
    modules = strings(data['module_ids'], 'operation modules')
    require(set(modules) == {'M02', 'M03', 'M04', 'M08', 'M15'}, 'DOC-OP-SCOPE', 'foundation modules')
    rows = data['operations']
    require(isinstance(rows, list) and bool(rows), 'DOC-OP-SCHEMA', 'operations')
    module_rows = {row['id']: row for row in registry['modules']}
    package_owners = {package: row['id'] for row in coverage['module_coverage']
                      for package in row['primary_crates']}
    refs = {OPERATIONS, OPERATION_GUIDE}
    identities: set[str] = set()
    case_ids: set[str] = set()
    seen_modules: set[str] = set()
    commands: list[dict[str, Any]] = []
    state_fields = {'authenticated_inputs', 'preconditions', 'accepted_effects', 'rejected_effects',
                    'uncertain_recovery', 'publication'}
    for row in rows:
        operation_object(row, {'id', 'module_id', 'requirement_ids', 'profile', 'implementation',
                               'normative_clauses', 'schema_refs', 'domain_refs', 'limit_refs',
                               'state', 'errors', 'producer_modules', 'consumer_modules', 'cases',
                               'independent_vectors', 'open_requirements'}, 'operation')
        mid, oid = row['module_id'], row['id']
        require(isinstance(mid, str) and mid in modules, 'DOC-OP-MODULE', str(mid))
        require(isinstance(oid, str) and re.fullmatch(mid+r'-OP-[A-Z][A-Z0-9-]*', oid) is not None,
                'DOC-OP-ID', str(oid))
        require(oid not in identities, 'DOC-OP-DUPLICATE', oid)
        identities.add(oid)
        seen_modules.add(mid)
        requirements = strings(row['requirement_ids'], oid+' requirements')
        require(set(requirements) <= set(module_rows[mid]['requirement_ids']), 'DOC-OP-REQUIREMENT', oid)
        require(row['profile'] in module_rows[mid]['profiles'], 'DOC-OP-PROFILE', oid)
        impl = operation_object(row['implementation'], {'package', 'path', 'symbol', 'features'}, oid+' implementation')
        require(impl['package'] in package_owners, 'DOC-OP-PACKAGE', oid)
        require(isinstance(impl['path'], str)
                and impl['path'].startswith(f"trillionnium/crates/{impl['package']}/src/"),
                'DOC-OP-PACKAGE', oid+' implementation path')
        path, relative = file_ref(root, impl['path'])
        symbol = operation_text(impl['symbol'], oid+' symbol')
        require(has_function_definition(path.read_text(encoding='utf-8'), symbol), 'DOC-OP-SYMBOL', oid)
        refs.add(relative)
        operation_features(root, impl['package'], impl['features'], refs)
        clauses = row['normative_clauses']
        require(isinstance(clauses, list) and bool(clauses), 'DOC-OP-CLAUSE', oid)
        for clause in clauses:
            operation_object(clause, {'path', 'heading', 'rule'}, oid+' clause')
            path, relative = file_ref(root, clause['path'])
            require(operation_text(clause['heading'], oid) in path.read_text(encoding='utf-8').splitlines(),
                    'DOC-OP-CLAUSE', oid+' exact heading')
            operation_text(clause['rule'], oid+' rule')
            refs.add(relative)
        for field in ['schema_refs', 'domain_refs', 'limit_refs']:
            require(isinstance(row[field], list) and bool(row[field]), 'DOC-OP-SCHEMA', oid+' '+field)
            for reference in row[field]:
                operation_reference(root, reference, refs)
        state = operation_object(row['state'], state_fields, oid+' state')
        for field in state_fields:
            strings(state[field], oid+' '+field)
        errors = row['errors']
        require(isinstance(errors, list) and bool(errors), 'DOC-OP-ERROR', oid)
        for error in errors:
            operation_object(error, {'class', 'reference', 'meaning'}, oid+' error')
            require(error['class'] in {'reject', 'unavailable', 'uncertain', 'halt'}, 'DOC-OP-ERROR', oid)
            operation_reference(root, error['reference'], refs)
            operation_text(error['meaning'], oid+' error meaning')
        for field in ['producer_modules', 'consumer_modules']:
            require(set(strings(row[field], oid+' '+field)) <= set(MODULES), 'DOC-OP-MODULE', oid)
        vectors = operation_object(row['independent_vectors'], {'status', 'reason'}, oid+' independent vectors')
        require(vectors['status'] == 'open', 'DOC-OP-VECTOR-CLAIM', oid)
        operation_text(vectors['reason'], oid+' vector gap')
        strings(row['open_requirements'], oid+' open requirements')
        require(isinstance(row['cases'], list) and bool(row['cases']), 'DOC-OP-TEST', oid)
        kinds: set[str] = set()
        for case in row['cases']:
            operation_object(case, {'id', 'kind', 'provenance', 'package', 'source_path', 'symbol',
                                    'target', 'test_filter', 'features', 'expected_outcome',
                                    'assertion_fragments', 'replay_status'}, oid+' case')
            cid = operation_text(case['id'], oid+' case id')
            require(cid.startswith(oid+'-') and cid not in case_ids, 'DOC-OP-DUPLICATE', cid)
            case_ids.add(cid)
            require(case['kind'] in {'positive', 'negative', 'recovery'}, 'DOC-OP-TEST', cid)
            kinds.add(case['kind'])
            require(case['provenance'] == 'source-regression-not-independent-golden', 'DOC-OP-VECTOR-CLAIM', cid)
            require(case['replay_status'] == 'not-run-by-documentation-checker', 'DOC-OP-REPLAY-CLAIM', cid)
            operation_text(case['expected_outcome'], cid+' outcome')
            require(case['package'] in package_owners, 'DOC-OP-PACKAGE', cid)
            operation_features(root, case['package'], case['features'], refs)
            path, relative = file_ref(root, case['source_path'])
            base = f"trillionnium/crates/{case['package']}/"
            symbol = operation_text(case['symbol'], cid+' symbol')
            target = operation_text(case['target'], cid+' target')
            source_text = path.read_text(encoding='utf-8')
            if target == 'lib' or target.startswith('bin:'):
                require(relative.startswith(base+'src/') and relative.endswith('.rs'), 'DOC-OP-TEST', cid)
                if target.startswith('bin:'):
                    manifest = tomllib.loads((root/base/'Cargo.toml').read_text(encoding='utf-8'))
                    binaries = {entry['name']: entry for entry in manifest.get('bin', [])}
                    name = target.removeprefix('bin:')
                    require(name in binaries, 'DOC-OP-TEST', cid+' binary target')
                    operation_target_features(manifest, binaries[name], case['features'], cid)
                    binary_path, binary_relative = file_ref(root, base+binaries[name].get('path', 'src/main.rs'))
                    require(binary_path.suffix == '.rs', 'DOC-OP-TEST', cid+' binary source')
                    refs.add(binary_relative)
                module = relative.removeprefix(base+'src/').removesuffix('.rs').replace('/', '::')
                expected_filter = (module+'::' if module not in {'lib', 'main'} else '')
                inline = re.search(r'(?m)^    fn '+re.escape(symbol)+r'\s*\(', source_text)
                if inline:
                    require(re.search(r'(?m)^mod tests\s*\{', source_text[:inline.start()]) is not None,
                            'DOC-OP-FILTER', cid+' unsupported inline test module')
                    expected_filter += 'tests::'
                expected_filter += symbol
            else:
                require(relative == base+'tests/'+case['target']+'.rs', 'DOC-OP-TEST', cid)
                manifest = tomllib.loads((root/base/'Cargo.toml').read_text(encoding='utf-8'))
                tests = {entry['name']: entry for entry in manifest.get('test', [])}
                if target in tests:
                    require(base+tests[target].get('path', 'tests/'+target+'.rs') == relative,
                            'DOC-OP-TEST', cid+' declared integration source')
                    operation_target_features(manifest, tests[target], case['features'], cid)
                expected_filter = symbol
            require(case['test_filter'] == expected_filter, 'DOC-OP-FILTER', cid)
            region = operation_test_region(source_text, symbol, case['features'])
            for fragment in strings(case['assertion_fragments'], cid+' assertions'):
                require(fragment in region, 'DOC-OP-ASSERTION', cid+': '+fragment)
            refs.add(relative)
            commands.append({'operation_id': oid, 'case_id': cid, 'cwd': 'trillionnium',
                             'argv': operation_case_command(case), 'result': case['replay_status']})
        require('positive' in kinds and 'negative' in kinds, 'DOC-OP-TEST', oid+' positive/negative coverage')
    require(seen_modules == set(modules), 'DOC-OP-SCOPE', 'each declared foundation module needs operations')
    require(REQUIRED_FOUNDATION_OPERATIONS <= identities, 'DOC-OP-SCOPE', 'retained foundation operation removed')
    return {'operation_count': len(rows), 'source_regression_case_count': len(case_ids),
            'operations_with_open_requirements': len(rows), 'independent_golden_vector_count': 0,
            'operation_catalog_complete': False, 'semantic_acceptance': 'not-assessed',
            'implementation_acceptance': 'not-assessed', 'production_authority': False,
            'reference_check_scope': 'lexical-source-and-case-binding-not-behavioral-equivalence',
            'replay_commands': commands}, refs


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


def validate_files(root: Path, data: dict[str, Any], manifest: dict[str, Any],
                   operation_refs: set[str] | None = None) -> dict[str, dict[str, str]]:
    refs = {REGISTRY, GUIDE, AUTHORITY, REVIEW, PLAN, REFERENCE, MANIFEST, COVERAGE, SELF, TEST}
    refs.update(operation_refs or set())
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
    operations = json.loads((ROOT/OPERATIONS).read_text(encoding='utf-8'), object_pairs_hook=strict_object)
    operation_report, operation_refs = validate_operations(ROOT, operations, data, coverage)
    require(manifest.get('selected_successor_pull_request') == data['integration_observation']['selected_successor_pr'],
            'DOC-LINEAGE', 'plan manifest successor mismatch')
    require(subprocess.run(['git', 'merge-base', '--is-ancestor', data['integration_observation']['observed_source'], 'HEAD'],
                           cwd=ROOT, capture_output=True).returncode == 0, 'DOC-LINEAGE', 'observed source is not an ancestor')
    require(subprocess.run(['git', 'merge-base', '--is-ancestor', operations['source_observation'], 'HEAD'],
                           cwd=ROOT, capture_output=True).returncode == 0,
            'DOC-OP-SOURCE', 'operation source observation is not an ancestor')
    bindings = validate_files(ROOT, data, manifest, operation_refs)
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
        'operation_catalog': {key: value for key, value in operation_report.items() if key != 'replay_commands'},
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({**report, 'inputs': bindings, 'operation_catalog': operation_report},
                                        indent=2, sort_keys=True)+'\n', encoding='utf-8')
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (DocumentationError, OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(json.dumps({'result': 'FAIL', 'code': getattr(error, 'code', 'DOC-INPUT'), 'detail': str(error),
                          'semantic_design_acceptance': 'not-assessed', 'production_authority': False}), file=sys.stderr)
        raise SystemExit(2)
