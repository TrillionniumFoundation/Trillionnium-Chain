#!/usr/bin/env python3
"""Verify source-bound engineering observations; never confer public-network authority."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch
from report_module_evidence import rust_code, rust_group_end

ROOT = Path(__file__).resolve().parents[2]
FLAGS = ('public_network_ready', 'production_activation', 'independent_accepted',
         'future_window_accepted', 'work_profile_qualified', 'physical_power_loss',
         'native_execution_authenticated')
CASES = (('hot', 'legacy'), ('hot', 'protected'), ('disjoint4', 'protected'), ('growth', 'protected'))
TESTS = ('test_model_attribution', 'test_work_utility', 'test_public_evaluation_lifecycle', 'test_llm_adapter_contract')
SOCKET_RUN = 'transport-sustained-paid-unpaid'
NEGATIVE_RUN = 'public-readiness-evidence-negative-tests'
SOURCE_NEGATIVE_RUN = 'evidence-source-negative-tests'
SOURCE_PREPARATION_RUN = 'evidence-source-preparation'
PIPELINE_BINARY_LIMIT = 512 * 1024 * 1024
PIPELINE_OBSERVATION_SCOPE = 'software-file-snapshots-and-launcher-exit-not-execution-attestation'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def load(path):
    def constant(value):
        raise ValueError('noncanonical JSON constant '+value)
    return json.loads(path.read_text(), object_pairs_hook=unique, parse_constant=constant)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hash_file(path, *, limit=None):
    fingerprint, size = hashlib.sha256(), 0
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and (limit is None or 0 < info.st_size <= limit),
                'artifact bounded regular file')
        while chunk := stream.read(65536 if limit is None else min(65536, limit - size + 1)):
            size += len(chunk)
            require(limit is None or size <= limit, 'artifact file limit')
            fingerprint.update(chunk)
    return fingerprint.hexdigest(), size


def integer(value, minimum=0, maximum=None):
    require(type(value) is int and value >= minimum and (maximum is None or value <= maximum), 'invalid integer')
    return value


def digest(value, length=64):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{'+str(length)+'}', value), 'digest shape')
    return value


def scope_flags(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FLAGS:
                require(item is False, 'artifact unsupported authority '+key)
            scope_flags(item)
    elif isinstance(value, list):
        for item in value: scope_flags(item)


def safe(folder, relative):
    """No symlink component, normalization alias, traversal or implicit file substitution."""
    require(isinstance(relative, str) and relative and all(c not in relative for c in ('\\','\x00','\n','\r','\t')), 'unsafe artifact path')
    item = Path(relative)
    require(not item.is_absolute() and item.as_posix() == relative and all(p not in ('.', '..') for p in item.parts), 'unsafe artifact path')
    path = Path(folder)
    require(all(not ancestor.is_symlink() for ancestor in (path,*path.parents)), 'symlink evidence root/ancestor')
    for part in item.parts:
        path = path / part
        require(not path.is_symlink(), 'symlink artifact')
    require(path.is_file(), 'missing artifact '+relative)
    return path


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root, text=True).strip()


def relevant(path):
    return ((path.startswith(('trillionnium/', 'formal/pon-nakamoto-v1/', 'scripts/'))
             and not path.endswith('.md')) or path.startswith(('config/pon/', '.github/workflows/')))


def source_inventory(root, commit):
    inventory = {}
    for row in git(root, 'ls-tree', '-r', commit).splitlines():
        metadata, path = row.split('\t', 1)
        if relevant(path):
            mode, kind, oid = metadata.split()
            require(mode in ('100644', '100755') and kind == 'blob', 'source symlink or non-file')
            raw = subprocess.check_output(['git', 'cat-file', 'blob', oid], cwd=root)
            inventory[path] = sha(raw)
    return inventory


def validate_source(root, report, manifest, *, current=True):
    commit, tree = digest(report['source_commit'], 40), digest(report['source_tree'], 40)
    require(commit == manifest['implementation_commit'] and tree == manifest['implementation_tree'], 'source identity')
    require(git(root, 'rev-parse', commit+'^{tree}') == tree, 'source tree')
    expected = source_inventory(root, commit)
    require(report['source_files_sha256'] == expected and expected, 'source inventory/hash mismatch')
    if current:
        paths = set(git(root, 'ls-files').splitlines()) | set(git(root, 'ls-files', '--others', '--exclude-standard').splitlines())
        require({p for p in paths if relevant(p)} == set(expected), 'current source inventory changed')
        for name, fingerprint in expected.items():
            require(sha(safe(root, name).read_bytes()) == fingerprint, 'current source bytes changed '+name)
    return commit


def validate_artifacts(root, folder, manifest, *, tracked=True):
    files = manifest['files']
    require(isinstance(files, dict) and 'qualification.json' in files, 'artifact inventory')
    observed = set()
    for path in folder.rglob('*'):
        require(not path.is_symlink(), 'symlink artifact')
        if path.is_file() and path != folder/'manifest.json':
            observed.add(path.relative_to(folder).as_posix())
    require(set(files) == observed, 'artifact inventory mismatch')
    for name, fingerprint in files.items():
        limit = PIPELINE_BINARY_LIMIT if name == 'binaries/continuous_pipeline' else None
        observed_sha, _ = hash_file(safe(folder, name), limit=limit)
        require(observed_sha == digest(fingerprint), 'artifact bytes changed '+name)
        if name.endswith('.json'):
            scope_flags(load(safe(folder,name)))
    if tracked and folder.is_relative_to(root):
        index = set(git(root, 'ls-files').splitlines())
        prefix = folder.relative_to(root)
        required = {(prefix/'manifest.json').as_posix()} | {(prefix/p).as_posix() for p in files}
        require(required <= index, 'untracked published evidence')


def validate_source_preparation(root, text, commit):
    prepared=json.loads(text.splitlines()[-1],object_pairs_hook=unique)
    from prepare_evidence_sources import declarations
    expected=declarations(root,source=commit)
    require(prepared['verified_object_trees'] == expected
            and prepared['branch_refs_changed'] is False
            and prepared['acceptance_granted'] is False, 'source-preparation scope')
    return expected


def validate_environment(root, report, baseline):
    requirements=safe(root,'formal/pon-nakamoto-v1/requirements.txt').read_text()
    environment=report['environment'];reference=baseline['environment']
    for package in ('numpy','cryptography'):
        pins=re.findall(r'(?m)^'+package+r'==([0-9]+\.[0-9]+\.[0-9]+)[ \t]*$',requirements)
        require(len(pins) == 1, 'missing or ambiguous environment pin '+package)
        require(environment.get(package) == reference.get(package) == pins[0], 'environment dependency pin '+package)
    python=environment.get('python')
    require(isinstance(python,str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',python)
            and python == reference.get('python'), 'environment Python/baseline mismatch')
    # These are observer records, not remote package or hardware attestations.
    for package in ('cryptography_openssl','cffi'):
        value=environment.get(package)
        require(isinstance(value,str) and value.strip(), 'missing environment runtime record '+package)
    for observer in (environment,reference):
        child=observer.get('child_python3')
        require(isinstance(child,dict), 'missing child Python environment')
        require(isinstance(child.get('executable'),str) and Path(child['executable']).is_absolute(),
                'child Python executable')
        for package in ('python','numpy','cryptography'):
            require(child.get(package) == observer.get(package), 'child Python runtime mismatch '+package)
    require(environment['child_python3'] == reference['child_python3'], 'child Python/baseline mismatch')


def quantiles(values):
    ordered = sorted(values)
    def rank(percent):
        return ordered[max(0, math.ceil(len(ordered)*percent/100)-1)]
    return {'count':len(ordered), 'p50_ns':rank(50) if ordered else None,
            'p95_ns':rank(95) if len(ordered) >= 20 else None,
            'p99_ns':rank(99) if len(ordered) >= 100 else None,
            'tail_rule':'empirical block sample quantiles only;20 samples for p95 resolution,100 for p99; correlation and confidence are not established'}


def validate_tails(summary):
    records = summary['records'][:integer(summary['requested_blocks'], 20, 4096)]
    for field, metric in [('intake_to_inclusion_ns','inclusion_latency_block_samples'),
                          ('intake_to_confirmation_ns','confirmation_latency_block_samples')]:
        values = [integer(row[field], 1) for row in records]
        require(summary[metric] == quantiles(values), 'unobserved/miscomputed latency tails')


def decode_packet(raw):
    require(len(raw) >= 318+2+49188 and len(raw) <= 1048576, 'packet length')
    require(raw[:6] == b'PNH1\x01\x00', 'header version')
    count = int.from_bytes(raw[318:320], 'little')
    require(count <= 256, 'packet transaction limit')
    pos, txs = 320, []
    for _ in range(count):
        require(pos+2 <= len(raw), 'transaction framing')
        size = int.from_bytes(raw[pos:pos+2], 'little'); pos += 2
        require(159 <= size <= 2048 and pos+size <= len(raw), 'transaction framing')
        txs.append(raw[pos:pos+size]); pos += size
    require(len(raw)-pos == 49188, 'work length/trailing bytes')
    return raw[:318], txs, raw[pos:]


def native_durable_schema(root):
    """Extract the legacy evidence schema from one explicitly supported contract.

    Historical literal V1, inline composed V2 and the explicitly selected V2
    backend are supported. Authenticated, permanent-account growth and PQ
    network storage are different evidence scopes; recognizing their exact mappings
    must never append their tables or return their domains in this legacy result.
    This is not a Rust evaluator. Unknown bodies/literals fail closed. The shared
    Rust lexical mask excludes comment/string decoys without changing literals
    whose exact bytes are checked separately below.
    """
    source = safe(root,'trillionnium/crates/trnm-pon-node/src/store.rs').read_text()
    def direct(code, position):
        prefix = code[:position]
        return all(prefix.count(left) == prefix.count(right) for left,right in ('{}','()','[]'))
    def bodies(text, kind, name):
        code = rust_code(text)
        found = []
        for match in re.finditer(r'\b'+kind+r'\s+'+re.escape(name)+r'\b',code):
            # Only direct items of this source/owner, not nested modules, macros
            # or local declarations that happen to have the same spelling.
            if not direct(code,match.start()):
                continue
            require(re.match(r'\s*'+(r'\(' if kind == 'fn' else r'\{'),code[match.end():]),
                    'durable source header '+name)
            start = code.find('{',match.end())
            require(start >= 0, 'durable source body '+name)
            end = rust_group_end(code,start)
            require(end is not None, 'durable source body '+name)
            found.append(text[start+1:end-1])
        return found
    def body(text, kind, name):
        found = bodies(text,kind,name)
        require(len(found) == 1, 'durable source body '+name)
        return found[0]
    def layout(actual, expected, message):
        # String payloads are not compared by whitespace normalization. Each
        # schema-affecting literal is also checked, byte for byte, with value().
        normalize = lambda text: re.sub(r'\s+','',rust_code(text))
        require(normalize(actual) == normalize(expected),message)
    def closed_header(text, kind, name, expected):
        code = rust_code(text)
        found = [m for m in re.finditer(r'\b'+kind+r'\s+'+re.escape(name)+r'\b',code)
                 if direct(code,m.start())]
        message = 'durable backend selected header '+name
        require(len(found) == 1,message)
        match = found[0]
        # Current supported items have no attributes or modifiers. In
        # particular, a cfg-disabled declaration cannot authorize extraction.
        prefix = code[:match.start()].rstrip()
        require(not prefix or prefix[-1] in '{};',message)
        end = code.find('{',match.end())
        require(end >= 0,message)
        layout(text[match.start():end],expected,message)
    def value(text, prefix):
        matches = list(re.finditer(prefix,rust_code(text)))
        require(len(matches) == 1, 'durable schema literal prefix')
        literal = re.match(r'\s*"([^"\\]*)"',text[matches[0].end():],re.S)
        require(literal is not None, 'durable schema string literal')
        return literal[1]
    def literal(text, name):
        code = rust_code(text)
        matches = [match for match in re.finditer(r'\bconst\s+'+name+r'\s*:\s*&str\s*=',code)
                   if direct(code,match.start())]
        require(len(matches) == 1, 'durable schema literal '+name)
        parsed = re.match(r'\s*"([^"\\]*)"\s*;',text[matches[0].end():],re.S)
        require(parsed is not None, 'durable schema literal '+name)
        return parsed[1]
    def legacy(ddl, domain):
        # Source binding does not authorize widening this evidence contract.
        # These tables have their own full-state/commitment/node verification.
        require(not re.search(r'\b(?:archive_nodes|native_state_commitments|growth_states|pq_network_[a-z0-9_]+|pq_witness_[a-z0-9_]+)\b',ddl,re.I),
                'authenticated tables in legacy durable schema')
        return ddl,domain
    code = rust_code(source)
    if re.search(r'\bconst\s+BASE_DDL\b',code):
        base = literal(source,'BASE_DDL')
        composed = body(source,'fn','ddl')
        layout(composed,'format!("{}{}", BASE_DDL, crate::ancestry_index::DDL)', 'durable V2 schema composition')
        require(value(composed,r'\bformat!\s*\(') == '{}{}', 'durable V2 schema composition')
        require(not re.search(r'\bconst\s+DDL\b',code), 'ambiguous durable schema')
        if re.search(r'\bStateBackend\b',code):
            # Select this branch first. A bad current mapping cannot fall back
            # to a historical inline hash elsewhere in the same source file.
            # These are closed source contracts, not a retry after failure.
            # Scan all code tokens (without evaluating cfg) so a removed enum
            # arm cannot hide a remaining PQ implementation, module or owner.
            witness_pq = re.search(r'\b(?:PqWitnessV4|pq_witness|pq_rollback_witness)\b',code) is not None
            canonical_pq = witness_pq or re.search(r'\b(?:PqNetworkV2|PqContinuousV3)\b',code) is not None
            old_pq = re.search(r'\bPqNetworkV1\b',code) is not None
            require(not (canonical_pq and old_pq), 'durable backend mixed PQ generations')
            has_pq = canonical_pq or old_pq or re.search(r'\bpq_network\b',code) is not None
            pq_variants, pq_ddl, pq_domains, pq_formats = '', '', [], []
            if canonical_pq:
                pq_variants = 'PqNetworkV2, PqContinuousV3,'
                pq_ddl = 'Self::PqNetworkV2 | Self::PqContinuousV3 => format!("{}{}", ddl(), pq_network::DDL),'
                pq_domains = [('PqNetworkV2','native-pq-network-owner-schema-v2'),
                              ('PqContinuousV3','native-pq-continuous-owner-schema-v3')]
                pq_formats = [r'PqNetworkV2\s*\|\s*Self::PqContinuousV3']
                if witness_pq:
                    # This is a closed mapping of the new native namespace,
                    # never evidence that the witness protects legacy tables or
                    # that the system has qualified for production/whole PQ.
                    pq_variants += 'PqWitnessV4,'
                    pq_ddl += '''Self::PqWitnessV4 => {
                        format!("{}{}{}", ddl(), pq_network::DDL, pq_rollback_witness::DDL)
                    }'''
                    pq_domains.append(('PqWitnessV4','native-pq-network-witness-schema-v4'))
            elif has_pq:
                pq_variants = '#[cfg(feature = "pq-native-openssl")] PqNetworkV1,'
                pq_ddl = '#[cfg(feature = "pq-native-openssl")] Self::PqNetworkV1 => format!("{}{}", ddl(), pq_network::DDL),'
                pq_domains = [('PqNetworkV1','native-pq-network-owner-schema-v1')]
                pq_formats = ['PqNetworkV1']
            pq_domain_arms = ''.join(
                ('' if canonical_pq else '#[cfg(feature = "pq-native-openssl")]')+
                'Self::'+variant+' => b"'+expected+'",' for variant,expected in pq_domains)
            variants = body(source,'enum','StateBackend')
            layout(variants,'Legacy, AuthenticatedV1, PermanentAccountGrowthV2,'+pq_variants,
                   'durable backend variants')
            implementation = body(source,'impl','StateBackend')
            layout(implementation, '''
                fn ddl(self) -> String {
                    match self {
                        Self::Legacy => ddl(),
                        Self::AuthenticatedV1 => format!("{}{}", ddl(), native_authenticated::DDL),
                        Self::PermanentAccountGrowthV2 => format!("{}{}", ddl(), growth::DDL),
            '''+pq_ddl+'''
                    }
                }
                fn selected_schema_id(self, settings: &Settings) -> Hash {
                    if growth_profile_v2::enabled(&settings.app) {
                        hash(
                            b"native-growth-reference-branch-schema-v2",
                            &[self.ddl().as_bytes()],
                        )
                    } else {
                        self.schema_id()
                    }
                }
                fn schema_id(self) -> Hash {
                    let domain: &[u8] = match self {
                        Self::Legacy => b"native-branch-schema-v2",
                        Self::AuthenticatedV1 => b"native-authenticated-branch-schema-v1",
                        Self::PermanentAccountGrowthV2 => b"native-permanent-account-growth-schema-v2",
            '''+pq_domain_arms+'''
                    };
                    hash(domain, &[self.ddl().as_bytes()])
                }
            ''', 'durable backend composition/domain')
            backend_ddl = body(implementation,'fn','ddl')
            selected_domain = body(implementation,'fn','selected_schema_id')
            domain = body(implementation,'fn','schema_id')
            # rust_code masks literal payloads. Layout alone therefore cannot
            # authenticate which feature guards each optional PQ item.
            if has_pq and not canonical_pq:
                for name, section in [('variants',variants), ('ddl',backend_ddl), ('domain',domain)]:
                    require(value(section,r'#\s*\[\s*cfg\s*\(\s*feature\s*=') == 'pq-native-openssl',
                            'durable backend feature '+name)
            for variant in ['AuthenticatedV1', 'PermanentAccountGrowthV2']+pq_formats:
                require(value(backend_ddl,r'\bSelf::'+variant+r'\s*=>\s*format!\s*\(') == '{}{}',
                        'durable backend composition '+variant)
            if witness_pq:
                require(value(backend_ddl,r'\bSelf::PqWitnessV4\s*=>\s*\{\s*format!\s*\(') == '{}{}{}',
                        'durable backend composition PqWitnessV4')
            require(value(selected_domain,r'\bhash\s*\(\s*b') == 'native-growth-reference-branch-schema-v2',
                    'durable growth schema domain')
            for variant, expected in [('Legacy','native-branch-schema-v2'),
                                      ('AuthenticatedV1','native-authenticated-branch-schema-v1'),
                                      ('PermanentAccountGrowthV2','native-permanent-account-growth-schema-v2')]+pq_domains:
                require(value(domain,r'\bSelf::'+variant+r'\s*=>\s*b') == expected,
                        'durable backend domain '+variant)
            node = body(source,'impl','Node')
            selections = {
                'open':'Self::open_with_fault(path, settings, workers, None)',
                'open_with_fault':'''ensure(!owner_marker_present(path)?, "OWNER_TASK_POLICY_REQUIRED")?;
                    Self::open_inner(path, settings, workers, hook, None, None, None)''',
                'open_inner':'''Self::open_selected(path, settings, workers, hook,
                    NativeOwners { policy: owner_policy, mining: mining_owner, continuous: continuous_owner, pq_network: None, },
                    StateBackend::Legacy, false,)''',
                'open_with_authenticated_state':'''Self::open_with_authenticated_state_and_fault(path, settings, workers, None)''',
                'open_with_authenticated_state_and_fault':'''ensure(!owner_marker_present(path)?, "OWNER_TASK_POLICY_REQUIRED")?;
                    Self::open_selected(path, settings, workers, hook,
                        NativeOwners { policy: None, mining: None, continuous: None, pq_network: None, }, StateBackend::AuthenticatedV1, false,)''',
            }
            for name, expected in selections.items():
                if witness_pq:
                    expected = expected.replace('pq_network: None,','pq_network: None, pq_witness: None,')
                if not has_pq:
                    # Only the trusted expected template changes. Source bytes
                    # must match the complete pre-PQ owner contract verbatim.
                    expected = expected.replace('pq_network: None,','')
                layout(body(node,'fn',name),expected,'durable backend opener '+name)
            selected_body = body(node,'fn','open_selected')
            split_selected = re.search(r'\b(?:SelectedOpen|open_selected_mode)\b',code) is not None
            if split_selected:
                # Existing-owner open is a new closed source contract. Check
                # the complete ordinary delegation before following its schema
                # bindings; never retry the old body after a malformed split.
                selected_modes = body(source,'enum','SelectedOpen')
                observation_field = ('observation_only' if re.search(
                    r'\bobservation_only\b',rust_code(selected_modes))
                    else 'growth_observation_only')
                # The broader read-only observer renamed this field. Select
                # its separately reviewed complete implementation before any
                # validation; a failure never retries another source contract.
                observation_member = observation_field + (
                    ',' if observation_field == 'growth_observation_only' else '')
                layout(selected_modes, '''
                    InitializeOrRecover { OBSERVATION_FIELD: bool },
                    ExistingPqOwner,
                '''.replace('OBSERVATION_FIELD',observation_field),
                       'durable backend selected modes')
                layout(selected_body, '''Self::open_selected_mode(
                    path, settings, workers, hook, owners, state_backend,
                    SelectedOpen::InitializeOrRecover { OBSERVATION_MEMBER },
                )'''.replace('OBSERVATION_MEMBER',observation_member),
                       'durable backend selected delegation')
                selected_body = body(node,'fn','open_selected_mode')
                selected_code = rust_code(selected_body)
                mode = re.search(r'\blet\s*\(\s*'+observation_field+r'\s*,\s*existing_owner_only\s*\)\s*=\s*match\s+selection\s*\{',selected_code)
                require(mode is not None and direct(selected_code,mode.start()),
                        'durable backend selected mode binding')
                mode_end = rust_group_end(selected_code,selected_code.index('{',mode.start()))
                require(mode_end is not None, 'durable backend selected mode binding')
                layout(selected_body[mode.start():mode_end], '''
                    let (OBSERVATION_FIELD, existing_owner_only) = match selection {
                        SelectedOpen::InitializeOrRecover { OBSERVATION_MEMBER }
                            => (OBSERVATION_FIELD, false),
                        SelectedOpen::ExistingPqOwner => (false, true),
                    }
                '''.replace('OBSERVATION_MEMBER',observation_member)
                   .replace('OBSERVATION_FIELD',observation_field),
                       'durable backend selected mode binding')
                mode_remaining = selected_code[:mode.start()]+selected_code[mode_end:]
                mode_names = r'\b(?:selection|'+observation_field+r'|existing_owner_only)\b'
                require(not re.search(r'\blet\s+[^;=]*'+mode_names+r'[^;=]*=',mode_remaining)
                        and not re.search(mode_names+r'\s*=(?!=)',mode_remaining)
                        and not re.search(r'&\s*mut\s*\(*\s*'+mode_names,mode_remaining),
                        'durable backend selected mode rebound')
            selected = rust_code(selected_body)
            bindings = list(re.finditer(r'\blet\s+ddl\s*=\s*state_backend\.ddl\(\)\s*;\s*let\s+schema_id\s*=\s*state_backend\.selected_schema_id\(\s*&\s*settings\s*\)\s*;',selected))
            require(len(bindings) == 1 and direct(selected,bindings[0].start()),
                    'durable backend selected schema')
            remaining = selected[:bindings[0].start()]+selected[bindings[0].end():]
            names = r'\b(?:state_backend|settings|ddl|schema_id)\b'
            places = names+r'(?:\s*\.\s*[A-Za-z_]\w*|\s*\[[^\]]*\])*'
            require(not re.search(r'\blet\s+[^;=]*'+names+r'[^;=]*=',remaining)
                    and not re.search(places+r'\s*[+*/%&|^\-]?=(?!=)',remaining)
                    and not re.search(r'&\s*mut\s*\(*\s*'+names,remaining),
                    'durable backend selected schema rebound')
            if split_selected:
                closed_header(source,'enum','SelectedOpen','enum SelectedOpen')
                closed_header(source,'impl','Node','impl Node')
                closed_header(node,'fn','open_selected', '''fn open_selected(
                    path: &Path, settings: Settings, workers: usize,
                    hook: Option<&mut Hook<'_>>, owners: NativeOwners,
                    state_backend: StateBackend, OBSERVATION_FIELD: bool,
                ) -> Result<Self>'''.replace('OBSERVATION_FIELD',observation_field))
                closed_header(node,'fn','open_selected_mode', '''fn open_selected_mode(
                    path: &Path, settings: Settings, workers: usize,
                    mut hook: Option<&mut Hook<'_>>, owners: NativeOwners,
                    state_backend: StateBackend, selection: SelectedOpen,
                ) -> Result<Self>''')
                # Bind the complete reviewed implementation, including literal
                # bytes. The local binding checks above cannot prove arbitrary
                # Rust control flow: an early return into another opener can
                # leave every recognized schema assignment intact. New bodies
                # require explicit review; no historical fallback is allowed.
                reviewed_bodies = {
                    'growth_observation_only': '63905b7095fe69d6036775847e604eae33faedbbfca5d8997664a68a5f889671',
                    'observation_only': '088b58a4072271bb60772bfacab6cf06ec4052700cef46f92708453d8b9a07be',
                }
                require(sha(selected_body.encode()) == reviewed_bodies[observation_field],
                        'durable backend selected implementation')
        else:
            matches = [match for match in re.finditer(r'\bhash\(\s*b"native-branch-schema-v2"\s*,\s*&\[\s*ddl\.as_bytes\(\)\s*\]\s*\)',source)
                       if code[match.start():match.start()+4] == 'hash']
            require(len(matches) == 1, 'durable V2 schema domain')
        index = safe(root,'trillionnium/crates/trnm-pon-node/src/ancestry_index.rs').read_text()
        return legacy(base+literal(index,'DDL'), 'native-branch-schema-v2')
    ddl = literal(source,'DDL')
    matches = [match for match in re.finditer(r'\bhash\(\s*b"native-branch-schema-v1"\s*,\s*&\[\s*DDL\.as_bytes\(\)\s*\]\s*\)',source)
               if code[match.start():match.start()+4] == 'hash']
    require(len(matches) == 1 and not re.search(r'\bStateBackend\b',code), 'durable V1 schema domain')
    return legacy(ddl, 'native-branch-schema-v1')


def validate_native_ancestry(database, summary, rows, H):
    """Full finite evidence-dump integrity check, not a keyed/independent certificate.

    The native runtime validates visited rows lazily. Here every retained block's
    derived rows are recomputed from the already replay-bound blocks; neither
    scope resists an owner rewriting all authoritative inputs and resealing them.
    """
    context = tuple(bytes.fromhex(summary[key]) for key in ('network','parameters','genesis'))
    require(all(len(v) == 32 for v in context), 'ancestry context')
    metadata = {}
    for block,parent,height,_,packet,state_root in rows:
        require(isinstance(block,bytes) and len(block) == 32 and len(state_root) == 32
                and type(height) is int and 0 <= height < 2**63, 'ancestry block metadata')
        if block == context[2]:
            require(height == 0 and parent is None and packet is None, 'ancestry genesis metadata')
        else:
            require(isinstance(parent,bytes) and len(parent) == 32 and height > 0
                    and isinstance(packet,bytes) and len(packet) <= 1048576, 'ancestry packet metadata')
            header,_,proof = decode_packet(packet)
            require(header[6:38] == context[0] and header[38:70] == context[1]
                    and header[70:102] == parent and int.from_bytes(header[102:110],'little') == height
                    and header[214:246] == state_root and H('block',header,proof[-32:]) == block,
                    'ancestry header context/identity')
        require(block not in metadata, 'duplicate ancestry block')
        metadata[block] = (parent,height)
    require(context[2] in metadata, 'ancestry genesis missing')
    expected = {}; zero = bytes(32)
    for block,parent,height,_,_,_ in rows:
        if not height: continue
        require(parent in metadata and metadata[parent][1]+1 == height, 'ancestry parent height')
        for level in range(height.bit_length()):
            if level == 0:
                ancestor,ancestor_height,left_seal,right_seal = parent,height-1,zero,zero
            else:
                left = expected.get((block,level-1))
                require(left is not None, 'ancestry left half missing')
                right = expected.get((left[0],level-1))
                require(right is not None, 'ancestry right half missing')
                ancestor,ancestor_height,left_seal,right_seal = right[0],right[1],left[4],right[4]
            require(ancestor in metadata and metadata[ancestor][1] == height-(1<<level)
                    and ancestor_height == height-(1<<level), 'ancestry ancestor height')
            seal = H('native-derived-ancestry-row-v1',*context,block,parent,height.to_bytes(8,'little'),
                     bytes([level]),ancestor,ancestor_height.to_bytes(8,'little'),left_seal,right_seal)
            expected[(block,level)] = (ancestor,ancestor_height,left_seal,right_seal,seal)
    require(database.execute('SELECT count(*) FROM ancestry_jump').fetchone()[0] == len(expected),
            'ancestry derived row count')
    actual = {}
    for block,level,ancestor,height,left,right,seal in database.execute('SELECT block,level,ancestor,ancestor_height,left_seal,right_seal,seal FROM ancestry_jump'):
        key = (block,level)
        require(key not in actual, 'duplicate ancestry derived row')
        actual[key] = (ancestor,height,left,right,seal)
    require(actual == expected, 'ancestry derived row/half-link/seal differs')


def validate_durable_store(root, folder, summary, packets, roots, cumulative, state, canonical, H):
    ddl, schema_domain = native_durable_schema(root)
    schema_names = set(re.findall(r'CREATE (?:TABLE|INDEX) (\w+)',ddl))
    expected_sql = {match[1]:' '.join(match[0][:-1].split())
                    for match in re.finditer(r'CREATE (?:TABLE|INDEX) (\w+).*?;',ddl,re.S)}
    actual_ledger_bytes = sum(path.stat().st_size for owner in ('producer','validator')
                              for path in (folder/owner).rglob('*') if path.is_file())
    require(integer(summary['ledger_disk_bytes'],1) == actual_ledger_bytes, 'actual ledger disk denominator')
    for owner in ('producer','validator'):
        path = safe(folder,owner+'/native.sqlite')
        require(not path.with_name(path.name+'-wal').exists(), 'uncheckpointed durable evidence')
        with sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True) as database:
            database.execute('PRAGMA trusted_schema=OFF')
            require(database.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'durable SQLite integrity')
            schema = dict(database.execute("SELECT name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"))
            require(set(schema) == schema_names and {name:' '.join(sql.split()) for name,sql in schema.items()} == expected_sql, 'durable schema additions/omissions/changes')
            metadata = dict(database.execute('SELECT key,value FROM metadata'))
            require(metadata == {'schema':H(schema_domain,ddl.encode()),
                                  'parameters':bytes.fromhex(summary['parameters']),
                                  'genesis':bytes.fromhex(summary['genesis'])}, 'durable metadata/context')
            tip,generation,slot = database.execute('SELECT tip,generation,state_slot FROM active WHERE singleton=1').fetchone()
            require(tip.hex() == summary['producer_final_state']['tip'] and generation == len(packets) and slot in (0,1), 'durable active state')
            values = {key:json.loads(bytes(raw),object_pairs_hook=unique) for key,raw in database.execute('SELECT key,value FROM kv WHERE slot=?',(slot,))}
            require(canonical(values) == canonical(state), 'durable published state differs from replay')
            require(database.execute('SELECT count(*) FROM blocks').fetchone()[0] == len(packets)+1, 'durable block denominator')
            rows = list(database.execute('SELECT id,parent,height,chainwork,packet,state_root FROM blocks ORDER BY height'))
            genesis = rows[0]
            require(genesis == (bytes.fromhex(summary['genesis']),None,0,bytes(64),None,roots[0]), 'durable genesis state')
            for index,(actual,raw) in enumerate(zip(rows[1:],packets),1):
                block,parent,height,work,packet,root = actual
                previous = bytes.fromhex(summary['genesis']) if index == 1 else rows[index-1][0]
                require(block.hex() == summary['records'][index-1]['block'] and parent == previous
                        and height == index and work == cumulative[index].to_bytes(64,'big')
                        and packet == raw and root == roots[index], 'durable packet/state/work differs from replay')
            if schema_domain == 'native-branch-schema-v2':
                validate_native_ancestry(database,summary,rows,H)


def validate_observations(batch, row, tx_ids, summary, headers, cumulative, *, confirmed):
    observations = batch['observations']
    require(isinstance(observations, list) and len(observations) == len(tx_ids), 'confirmation count')
    require([o['transaction'] for o in observations] == tx_ids, 'confirmation membership')
    for fact in observations:
        for key in ('network', 'parameters', 'genesis'):
            require(fact[key] == summary[key], 'confirmation context')
        require(fact['included_block'] == row['block'] and fact['included_height'] == row['height'], 'confirmation inclusion')
        observed = integer(fact['observed_height'], row['height'], len(headers))
        if not confirmed:
            require(observed == row['height'], 'initial membership observation height')
        require(fact['observed_tip'] == headers[observed-1]['id'], 'confirmation observed tip')
        depth = observed-row['height']
        require(fact['depth'] == depth and fact['active_generation'] == observed, 'confirmation depth/generation')
        require(fact['reorged'] is False and fact['finalized'] is False and fact['execution_authority'] is False, 'confirmation authority')
        require(fact['policy'] == 'installed-depth-and-required-work', 'confirmation policy')
        work = cumulative[observed]-cumulative[row['height']]
        threshold = (2**256//(headers[row['height']-1]['target']+1))*6
        require(fact['work_delta'] == work.to_bytes(64,'big').hex()
                and fact['required_work_delta'] == threshold.to_bytes(64,'big').hex(), 'confirmation work')
        expected = depth >= 6 and work >= threshold
        require(fact['confirmed'] is expected and expected is confirmed, 'confirmation truth')
        require(integer(fact['observed_now'], 1)+120 >= headers[observed-1]['timestamp'], 'future observation')


def validate_pipeline(root, folder, pattern, profile, command):
    sys.path.insert(0, str(root/'formal/pon-nakamoto-v1'))
    import contract_wire as wire
    import ledger
    import work_oracle
    from reference import retarget
    summary = load(safe(folder, 'summary.json'))
    require(summary['schema'] == 'trnm-continuous-native-pipeline-v1' and summary['pattern'] == pattern, 'pipeline schema/case')
    require(summary['campaign_passed'] is True and summary['producer_validator_heads_agree'] is True
            and summary['campaign_error'] is None and summary['final_head_error'] is None, 'failed pipeline campaign')
    require(summary['logical_pacing'] is False and summary['admission_profile'] == ('connection-work-v1' if profile == 'protected' else 'legacy-development'), 'live pipeline profile')
    blocks = integer(summary['requested_blocks'], 20, 4096)
    batch = integer(summary['transactions_per_block'], 1, 256)
    pace = integer(summary['pace_ms'], 1000, 60000)
    require(command[-5:] == [str(blocks),str(batch),str(pace),pattern,profile], 'pipeline command parameters')
    require(summary['transaction_type'] == 'signed PNX1 transfer tag1 only', 'pipeline transaction class')
    require(summary['funded_senders'] == (1 if pattern == 'hot' else 4), 'pipeline sender denominator')
    require(summary['accepted_transactions'] == summary['confirmed_transactions'] == blocks*batch and summary['pending_confirmation_blocks'] == 0, 'pipeline actual totals')
    require(summary['gpu_used'] is False and summary['gpu_device'] is None and summary['vram_bytes'] is None and summary['mempool_latency'] is None, 'pipeline unmeasured claim')
    params = wire.development_parameters('closed-round-all-eligible-min-v1')
    genesis_time = integer(summary['genesis_timestamp'], 1)
    params['genesis_timestamp'] = genesis_time
    params['chain_label'] = 'trnm-pon-native-wall-devnet-4-closed-round-all-eligible-min-v1-'+str(genesis_time)
    network = wire.H('network',params['chain_label'].encode())
    parameters = wire.H('parameters',wire.canonical(params),wire.canonical(wire.SCHEMA),wire.canonical(wire.WORK_PROFILE),wire.canonical(wire.MODEL_FAMILY))
    require(summary['network'] == network.hex() and summary['parameters'] == parameters.hex(), 'pipeline parameter/source binding')
    with patch.multiple(wire, PARAMS=params, NETWORK=network, PARAMETER_HASH=parameters), patch.multiple(ledger, PARAMS=params, NETWORK=network, PARAMETER_HASH=parameters):
        state = ledger.genesis_state()
        genesis = wire.H('genesis',network,parameters,wire.state_root(state),wire.u64(genesis_time)).hex()
        require(summary['genesis'] == genesis, 'pipeline genesis')
        records = summary['records']
        require(len(records) == blocks+6, 'pipeline confirmation drain blocks')
        headers, tx_sets, cumulative, parent = [], [], [0], genesis
        packets, roots = [], [wire.state_root(state)]
        history = [{'timestamp':genesis_time,'target':int(params['initial_target_hex'],16)}]
        for index, row in enumerate(records):
            raw = safe(folder, f'block-{index:04}.bin').read_bytes()
            packets.append(raw)
            hb, txs, proof = decode_packet(raw)
            header = wire.header_decode(hb)
            require(header['miner'] == ledger.public(ledger.key(3)), 'pipeline actual miner')
            require(header['parent'].hex() == parent and header['network'] == network and header['parameters'] == parameters and header['height'] == index+1, 'packet parent/context/height')
            require(row['height'] == index+1 and row['packet_bytes'] == len(raw) and row['transaction_count'] == len(txs) == (batch if index < blocks else 0), 'packet/transfer denominator')
            require(header['timestamp'] == row['timestamp'] and header['timestamp'] > history[-1]['timestamp'], 'packet live timestamp')
            target = history[-1]['target']
            if (index+1)%params['retarget_interval'] == 0:
                target = retarget(target,history[-params['retarget_interval']]['timestamp'],history[-1]['timestamp'],params['retarget_interval'],params['target_spacing_seconds'],int(params['pow_limit_hex'],16))
            require(int.from_bytes(header['target'],'big') == target and row['attempts'] == header['nonce']+1 <= 4096, 'packet target/attempts')
            require(header['transactions'] == wire.sequence_root('transactions',txs), 'packet body commitment')
            ids = []
            for offset, tx in enumerate(txs):
                decoded = wire.tx_decode(tx)
                require(decoded['tag'] == 1 and decoded['network'] == network and decoded['fields']['amount'] == 1, 'actual signed transfer')
                sender_index = 0 if pattern == 'hot' else offset%4
                require(decoded['sender'] == ledger.public(ledger.key(sender_index)), 'actual funded sender')
                receiver = wire.H('pipeline-growth-receiver-v1',wire.u64(index),wire.u64(offset)) if pattern == 'growth' else wire.H('pipeline-receiver-v1',wire.u64(sender_index))
                require(decoded['fields']['recipient'] == receiver, 'actual conflict/growth pattern')
                ids.append(wire.H('tx-id',tx).hex())
            work_oracle.verify(wire.H('challenge',hb),header['work_task'],header['target'],proof)
            require(header['work_task'] == ledger.MAINTENANCE, 'pipeline work task')
            state, receipts = ledger.execute_reference(state,txs,index+1,header['miner'],header['parent'])
            roots.append(wire.state_root(state))
            require(header['state'] == wire.state_root(state) and header['receipts'] == wire.sequence_root('receipts',receipts), 'pipeline state/receipt replay')
            require(integer(row['producer_state_keys'],1) == len(state), 'pipeline actual state growth')
            for metric in ('scheduled_lateness_ns','construct_sign_ns','execute_and_mine_ns',
                           'producer_full_verify_and_store_ns','producer_activate_ns',
                           'socket_admission_verify_store_activate_ns','membership_query_ns',
                           'intake_to_inclusion_ns','disk_bytes_before','disk_bytes_after',
                           'ledger_disk_bytes_before','ledger_disk_bytes_after'):
                integer(row[metric])
            require(row['ledger_disk_bytes_before'] <= row['disk_bytes_before']
                    and row['ledger_disk_bytes_after'] <= row['disk_bytes_after'], 'ledger bytes include packet/log artifacts')
            block_id = wire.H('block',hb,proof[-32:]).hex()
            require(row['block'] == block_id, 'actual block identity')
            parent = block_id
            headers.append({'id':block_id,'target':target,'timestamp':header['timestamp']})
            tx_sets.append(ids)
            cumulative.append(cumulative[-1]+2**256//(target+1))
            history.append(headers[-1])
        for row, ids in zip(records[:blocks],tx_sets[:blocks]):
            validate_observations(row['initial_membership'],row,ids,summary,headers,cumulative,confirmed=False)
            validate_observations(row['confirmation'],row,ids,summary,headers,cumulative,confirmed=True)
            require(integer(row['intake_to_confirmation_ns'],1) >= integer(row['intake_to_inclusion_ns'],1), 'confirmation timing')
        final = summary['producer_final_state']
        require(final['tip'] == parent and final['height'] == blocks+6 and final['state_root'] == wire.state_root(state).hex(), 'pipeline final state')
        require(final['chainwork_hex'] == cumulative[-1].to_bytes(64,'big').hex(), 'pipeline final chainwork')
        for field in ('tip','height','state_root','chainwork_hex'):
            require(summary['validator_final_head'][field] == final[field], 'validator/producer divergence')
        validate_durable_store(root,folder,summary,packets,roots,cumulative,state,wire.canonical,wire.H)
    validate_tails(summary)
    seconds = summary['inclusion_window_seconds']
    require(type(seconds) in (int,float) and math.isfinite(seconds) and seconds >= (blocks-1)*pace/1000, 'live pacing denominator')
    require(math.isclose(summary['measured_inclusion_transactions_per_second'],blocks*batch/seconds,rel_tol=1e-12), 'pipeline rate denominator')
    whole = summary['whole_campaign_seconds']
    integer(summary['producer_close_ns'])
    require(type(whole) in (int,float) and math.isfinite(whole) and whole >= seconds, 'pipeline campaign denominator')
    require(math.isclose(summary['whole_campaign_confirmed_transactions_per_second'],blocks*batch/whole,rel_tol=1e-12), 'pipeline confirmed rate denominator')
    return blocks*batch


def validate_socket_log(text):
    rows = []
    for line in text.splitlines():
        start = line.find('{')
        if start >= 0:
            value = json.loads(line[start:], object_pairs_hook=unique)
            if value.get('schema') == 'transport-admission-sustained-cost-v2':
                rows.append(value)
    require([r['phase'] for r in rows] == ['baseline','unpaid_false_transcript','paid_false_transcript','slow_hello_occupancy'], 'socket phase coverage')
    require(re.search(r'\btest sustained_protected_socket_cost_campaign \.\.\.',text)
            and re.search(r'test result: ok\. 1 passed; 0 failed;',text)
            and 'panicked at' not in text and 'test result: FAILED' not in text, 'socket actual test outcome')
    for row in rows:
        for field in ['attack_connections','paid_full_work_rejections','cheap_rejections','busy_rejections',
                      'slow_preface_connections','slow_partial_hello_connections','slow_body_hello_connections',
                      'request_template_bytes','attacker_body_bytes_successfully_written',
                      'attacker_body_write_success_count','attacker_body_write_outcome_unknown_count',
                      'attacker_body_not_started_count','attack_transport_error_count','forged_ticket_hash_trials',
                      'admission_hash_trials','attacker_admission_solve_ns']:
            integer(row[field])
        # The harness records the serialized first-request template size in every
        # phase, including baseline; this is not total attacker-submitted bytes.
        require('submitted_wire_bytes' not in row
                and integer(row['request_template_bytes'],1) == rows[0]['request_template_bytes'], 'socket request template size')
        require(row['bits'] == 16 and row['ttl_ms'] == 2000 and row['requested_attack_duration_ns'] == 10_000_000_000, 'socket cost context')
        integer(row['observed_wall_ns'],1)
        require(row['attack_connections'] == row['paid_full_work_rejections']+row['cheap_rejections']+row['busy_rejections']+row['slow_preface_connections']+row['attack_transport_error_count'], 'socket attack denominator')
        require(row['slow_preface_connections'] == row['slow_partial_hello_connections']+row['slow_body_hello_connections'], 'slow initial/body occupancy denominator')
        require(len(row['attack_transport_errors']) == row['attack_transport_error_count']
                and all(isinstance(error,str) and error for error in row['attack_transport_errors']), 'socket transport failure denominator')
        for prefix in ('honest_submit','honest_head'):
            attempts = integer(row[prefix+'_attempts'],1)
            samples, errors = row[prefix+'_ns'], row[prefix+'_errors']
            require(attempts == len(samples)+len(errors), 'honest outcome denominator')
            for sample in samples: integer(sample,1)
            for error in errors:
                integer(error['elapsed_ns'],1); require(isinstance(error['error'],str) and error['error'], 'honest error outcome')
        require(row['honest_valid_blocks'] == len(row['honest_submit_ns']), 'honest acceptance count')
        metrics = row['metrics']
        for value in metrics.values(): integer(value)
        require(row['paid_full_work_rejections']+row['honest_valid_blocks'] <= metrics['work_verifications'] <= row['paid_full_work_rejections']+row['honest_submit_attempts'], 'socket verifier denominator')
        require(metrics['admission_rejected_before_work'] == row['cheap_rejections'] and metrics['admission_accepted'] >= row['paid_full_work_rejections']+row['busy_rejections']+row['honest_valid_blocks'], 'socket cost accounting')
        baseline = row['phase'] == 'baseline'
        slow = row['phase'] == 'slow_hello_occupancy'
        body_fields = ('attacker_body_bytes_successfully_written','attacker_body_write_success_count',
                       'attacker_body_write_outcome_unknown_count','attacker_body_not_started_count')
        if baseline or slow:
            require(all(row[field] == 0 for field in body_fields), 'unexpected attacker body write')
        else:
            # A failed opaque write helper can fail before or during the body.
            # It contributes an unknown outcome, never invented partial bytes.
            success, unknown, not_started = (row[field] for field in body_fields[1:])
            require(success+unknown+not_started == row['attack_connections'], 'attacker body outcome denominator')
            require(row['attacker_body_bytes_successfully_written'] == success*row['request_template_bytes'], 'attacker body byte denominator')
            require(success >= row['paid_full_work_rejections']+row['cheap_rejections']+row['busy_rejections']
                    and unknown+not_started <= row['attack_transport_error_count'], 'attacker body outcome accounting')
        if not slow:
            require(row['slow_preface_connections'] == row['slow_partial_hello_connections']
                    == row['slow_body_hello_connections'] == 0, 'unexpected slow-Hello phase')
        require(row['attacker_streams'] == (0 if baseline else (3 if slow else 2)) and len(row['attacker_observed_ns']) == row['attacker_streams'], 'attacker identity denominator')
        for elapsed in row['attacker_observed_ns']: integer(elapsed,9_000_000_000)
        if baseline:
            require(all(row[field] == 0 for field in
                ('attack_connections','paid_full_work_rejections','cheap_rejections','busy_rejections',
                 'slow_preface_connections','slow_partial_hello_connections','slow_body_hello_connections',
                 'attack_transport_error_count','forged_ticket_hash_trials','admission_hash_trials',
                 'attacker_admission_solve_ns')), 'baseline attack contamination')
        elif row['phase'] == 'unpaid_false_transcript':
            require(row['attack_connections'] > 0 and row['paid_full_work_rejections'] == row['admission_hash_trials'] == row['attacker_admission_solve_ns'] == 0, 'unpaid work reached verifier')
        elif slow:
            require(row['slow_partial_hello_connections'] > 0 and row['slow_body_hello_connections'] > 0
                and row['request_template_bytes'] > 0 and all(row[field] == 0 for field in
                ('forged_ticket_hash_trials','admission_hash_trials','attacker_admission_solve_ns','paid_full_work_rejections','cheap_rejections','busy_rejections')), 'slow-preface cost/outcome class')
        else:
            require(row['paid_full_work_rejections'] > 0 and row['admission_hash_trials'] >= row['paid_full_work_rejections']+row['busy_rejections'] and row['attacker_admission_solve_ns'] > 0, 'paid attack cost absent')
    return rows


def validate_attribution(root, folder, command, commit):
    sys.path.insert(0,str(root/'formal/pon-nakamoto-v1'))
    from contract_wire import H, canonical
    from evaluation_bundle import artifact_id, verify_bundle
    from model_attribution import verify_attribution_result
    report = load(safe(folder,'report.json'))
    require(report['schema'] == 'pon-bounded-model-attribution-campaign-v1'
            and report['source_commit'] == commit and report['source_clean'] is True, 'attribution source')
    for flag in ('prospective_accepted','independent_accepted','ordinary_hepta_entry','llm_runtime_executed','public_reward_eligible'):
        require(report[flag] is False, 'attribution authority '+flag)
    require(command[0].endswith('python3') and command[1] == 'formal/pon-nakamoto-v1/experiments/model_attribution_campaign.py', 'attribution invocation')
    require(command[command.index('--bundle-hash')+1] == report['bundle'], 'attribution owner bundle')
    inputs = root/'evidence/pon-native-node-v1/model-current/model'
    for name,fingerprint in report['input_files_sha256'].items():
        require(name in {'evaluation-bundle.json','train.json','evaluation_a.json','evaluation_b.json'}, 'attribution input inventory')
        raw = safe(inputs,name).read_bytes()
        original = subprocess.check_output(['git','show',commit+':'+(inputs.relative_to(root)/name).as_posix()],cwd=root)
        require(raw == original and sha(raw) == digest(fingerprint), 'attribution actual input bytes')
    require(set(report['input_files_sha256']) == {'evaluation-bundle.json','train.json','evaluation_a.json','evaluation_b.json'}, 'attribution complete inputs')
    for name,fingerprint in report['source_files_sha256'].items():
        require(relevant(name) and sha(safe(root,name).read_bytes()) == digest(fingerprint), 'attribution source bytes')
    bundle = verify_bundle(safe(inputs,'evaluation-bundle.json').read_bytes(),report['bundle'])
    parent = bundle['controls']['current']
    cases = [('evaluation_a','evaluation_a','evaluation_a'),('evaluation_b','evaluation_b','evaluation_b'),
             ('evaluation_b_repeated_A_content','evaluation_a','evaluation_a'),('stale_retry_A','evaluation_a','evaluation_a'),
             ('reexecuted_A','evaluation_a','evaluation_a')]
    for result_name,plan_name,partition in cases:
        raw = safe(folder,plan_name+'-plan.json').read_bytes()
        verify_attribution_result(raw,H('bounded-model-attribution-plan-v1',raw).hex(),
            load(safe(inputs,partition+'.json')),load(safe(folder,result_name+'-result.json')),
            expected_parent=artifact_id(parent),expected_bundle=report['bundle'])
    synthetic = copy.deepcopy(parent)
    synthetic['source'] = 'controlled-complementarity-attack-fixture'
    synthetic['base'] = [[0]*257 for _ in range(3)]; synthetic['base'][0][-1] = 1
    synthetic['router'] = [[0]*257 for _ in range(3)]
    synthetic['deltas'] = [[[0]*257 for _ in range(3)] for _ in range(3)]
    identity = lambda value: H('attribution-campaign-identity-v1',value.encode()).hex()
    tasks = [dict(id=identity('controlled-task-'+str(i)),file='controlled-attack/'+str(i)+'.rs',label=1,
                  source_content_sha256=identity('controlled-content-'+str(i)),x=[1,1]+[0]*254+[8]) for i in range(24)]
    raw = safe(folder,'complementarity-plan.json').read_bytes()
    require(canonical(load(safe(folder,'controlled_complementarity-consumer-tasks.json'))) == canonical(tasks), 'synthetic attack tasks')
    verified = verify_attribution_result(raw,H('bounded-model-attribution-plan-v1',raw).hex(),tasks,
        load(safe(folder,'controlled_complementarity-result.json')),
        expected_parent=artifact_id(synthetic),expected_bundle=identity('controlled-attack-bundle'))
    require(report['controlled_complementarity'] == load(folder/'controlled_complementarity-result.json')['complementarity'], 'controlled attack outcome')
    return verified


def validate_pipeline_executable(folder, report, by_name):
    """Bind retained bytes and observed launches, without authenticating execution."""
    binding = report.get('pipeline_executable')
    require(isinstance(binding, dict) and set(binding) == {
        'cargo_artifact', 'build_log', 'retained_path', 'initial', 'retained', 'observation_scope'},
        'pipeline executable binding required')
    require(binding['observation_scope'] == PIPELINE_OBSERVATION_SCOPE,
            'pipeline executable observation scope')
    environment = report.get('environment')
    require(isinstance(environment, dict), 'pipeline observer environment')
    observer = environment.get('resource_observer')
    require(isinstance(observer, dict) and set(observer) == {'executable', 'sha256', 'identity', 'observation'},
            'pipeline resource observer record')
    require(isinstance(observer['executable'], str) and Path(observer['executable']).is_absolute()
            and isinstance(observer['identity'], str) and re.match(r'^time \(GNU [Tt]ime\)', observer['identity'])
            and observer['observation'] == 'software-file-snapshot-not-execution-attestation',
            'pipeline resource observer scope')
    digest(observer['sha256'])
    build = by_name['pipeline-build']
    require(binding['build_log'] == build['log'] == 'logs/pipeline-build.log', 'pipeline build log binding')
    messages = []
    for line in safe(folder, build['log']).read_text().splitlines():
        try:
            message = json.loads(line, object_pairs_hook=unique)
        except json.JSONDecodeError:
            continue
        if isinstance(message, dict):
            messages.append(message)
    candidates = [message for message in messages if message.get('reason') == 'compiler-artifact'
                  and isinstance(message.get('target'), dict)
                  and message['target'].get('name') == 'continuous_pipeline']
    finished = [message for message in messages if message.get('reason') == 'build-finished']
    require(len(candidates) == 1 and len(finished) == 1 and finished[0].get('success') is True,
            'pipeline unique successful Cargo artifact')
    artifact = candidates[0]
    require(binding['cargo_artifact'] == artifact, 'pipeline Cargo artifact changed')
    manifest = artifact.get('manifest_path')
    suffix = '/trillionnium/crates/trnm-pon-node/Cargo.toml'
    require(isinstance(manifest, str) and manifest.endswith(suffix)
            and Path(manifest).is_absolute() and Path(manifest).as_posix() == manifest
            and '..' not in Path(manifest).parts, 'pipeline package manifest')
    target = artifact['target']
    profile = artifact.get('profile')
    require(target.get('src_path') == manifest[:-len(suffix)] +
            '/trillionnium/crates/trnm-pon-node/examples/continuous_pipeline.rs'
            and target.get('kind') == ['example'] and target.get('crate_types') == ['bin']
            and isinstance(profile, dict) and profile.get('opt_level') == '3'
            and profile.get('test') is False and type(artifact.get('fresh')) is bool,
            'pipeline compiled target/profile')
    for snapshot in (binding['initial'], binding['retained']):
        require(isinstance(snapshot, dict) and set(snapshot) == {
            'path', 'bytes', 'sha256', 'device', 'inode', 'mtime_ns', 'ctime_ns'},
            'pipeline file snapshot')
        path = snapshot['path']
        require(isinstance(path, str) and Path(path).is_absolute()
                and Path(path).as_posix() == path and '..' not in Path(path).parts,
                'pipeline absolute observed path')
        integer(snapshot['bytes'], 1, PIPELINE_BINARY_LIMIT)
        digest(snapshot['sha256'])
        for field in ('device', 'inode', 'mtime_ns', 'ctime_ns'):
            integer(snapshot[field])
    initial, retained = binding['initial'], binding['retained']
    filenames = artifact.get('filenames')
    require(artifact.get('executable') == initial['path'] and isinstance(filenames, list)
            and all(isinstance(path, str) for path in filenames)
            and initial['path'] in filenames, 'pipeline executable artifact path')
    require(binding['retained_path'] == 'binaries/continuous_pipeline', 'pipeline retained file binding')
    require((retained['bytes'], retained['sha256']) == (initial['bytes'], initial['sha256'])
            and report['pipeline_binary_sha256'] == initial['sha256'], 'pipeline retained hash/length binding')
    fingerprint, size = hash_file(safe(folder, binding['retained_path']), limit=PIPELINE_BINARY_LIMIT)
    require(size == retained['bytes'] and fingerprint == retained['sha256'],
            'pipeline retained executable bytes')
    original_out = Path(retained['path']).parent.parent
    require(Path(retained['path']) == original_out/binding['retained_path'], 'pipeline retained observed path')
    for pattern, profile_name in CASES:
        name = 'pipeline-'+pattern+'-'+profile_name
        row = by_name[name]
        require(row.get('resource_observer') == observer and 'resource_observer_error' not in row,
                'pipeline resource observer binding/failure')
        command = row['command']
        require(isinstance(command, list) and all(isinstance(value, str) for value in command)
                and len(command) == 7 and command[0] == initial['path']
                and command[1] == str(original_out/name), 'pipeline exact executable/output argv')
        execution = row.get('pipeline_execution')
        require(isinstance(execution, dict) and set(execution) == {
            'requested_argv', 'launched_argv', 'launcher_pid', 'before', 'after', 'observation_scope'},
            'pipeline complete execution observations')
        require(execution['requested_argv'] == command
                and execution['observation_scope'] == PIPELINE_OBSERVATION_SCOPE,
                'pipeline requested argv/scope')
        expected_launcher = [row['resource_observer']['executable'], '-f', '%M %U %S', '-o',
                             str(original_out/'logs'/(name+'.usage')), *command]
        require(execution['launched_argv'] == expected_launcher, 'pipeline actual launcher argv')
        integer(execution['launcher_pid'], 1)
        expected_snapshot = dict(source=initial, retained=retained)
        require(execution['before'] == execution['after'] == expected_snapshot,
                'pipeline before/after file binding')
        require(type(row['returncode']) is int and row['returncode'] == 0
                and row['timed_out'] is False, 'pipeline actual child outcome')
    return binding


def validate(root=ROOT, evidence=None, *, tracked=True):
    root = Path(root).resolve()
    folder = Path(evidence or root/'evidence/pon-public-readiness-v2').absolute()
    require(not folder.is_symlink(), 'symlink evidence root')
    manifest = load(safe(folder,'manifest.json'))
    require(manifest['schema'] == 'trnm-public-readiness-evidence-v2', 'manifest schema: current execution requires v2; retain v1 as historical')
    validate_artifacts(root,folder,manifest,tracked=tracked)
    report = load(safe(folder,'qualification.json'))
    require(report['schema'] == 'trnm-public-readiness-engineering-v2', 'qualification schema')
    for value in (manifest,report):
        require(value['source_clean'] is True and value['all_commands_passed'] is True, 'failed/dirty engineering run')
        for flag in FLAGS: require(value[flag] is False, 'unsupported authority '+flag)
    require(report['source_clean_after'] is True and 'error' not in report, 'incomplete run')
    commit = validate_source(root,report,manifest)
    validate_environment(root,report,load(safe(folder,'baseline/qualification.json')))
    records = report['results']
    required = {'full-native-reference-regression','pipeline-build','bounded-model-attribution',SOCKET_RUN,NEGATIVE_RUN,SOURCE_NEGATIVE_RUN,SOURCE_PREPARATION_RUN,*TESTS} | {'pipeline-'+p+'-'+a for p,a in CASES}
    require(len(records) == len(required) and {r['name'] for r in records} == required, 'command matrix')
    by_name = {r['name']:r for r in records}
    for row in records:
        require(type(row['returncode']) is int and row['returncode'] == 0 and row['timed_out'] is False, 'failed command')
        require('resource_observer_error' not in row, 'failed resource observer')
        integer(row['elapsed_ns'],1)
        require(row['vram_bytes'] is None and row['log'] in manifest['files'] and isinstance(row['command'],list) and row['command'], 'command evidence')
        if row['peak_rss_kib'] is not None: integer(row['peak_rss_kib'],1)
        text = safe(folder,row['log']).read_text()
        if row['name'] in TESTS:
            require(row['command'][0].endswith('python3') and row['command'][1:] == ['formal/pon-nakamoto-v1/'+row['name']+'.py'], 'Python invocation')
            require(re.search(r'(?m)^Ran [1-9]\d* tests?\b',text) and re.search(r'(?m)^OK\s*$',text), 'Python actual outcome')
        if row['name'] in (NEGATIVE_RUN,SOURCE_NEGATIVE_RUN):
            target = 'scripts/ci/test_public_readiness_evidence.py' if row['name'] == NEGATIVE_RUN else 'scripts/ci/test_evidence_sources.py'
            require(row['command'][0].endswith('python3') and row['command'][1:] == [target], 'negative-test invocation')
            require(re.search(r'(?m)^Ran [1-9]\d* tests?\b',text) and re.search(r'(?m)^OK\s*$',text), 'negative-test actual outcome')
        if row['name'] == SOURCE_PREPARATION_RUN:
            require(row['command'][0].endswith('python3') and row['command'][1:] == ['scripts/ci/prepare_evidence_sources.py'], 'source-preparation invocation')
            validate_source_preparation(root,text,commit)
    baseline_command = by_name['full-native-reference-regression']['command']
    require(baseline_command[0].endswith('python3') and baseline_command[1] == 'scripts/run_evaluation_qualification.py' and '--native-node' in baseline_command and baseline_command[baseline_command.index('--source')+1] == commit, 'baseline command/source')
    from check_client_confirmation_evidence import validate as baseline_validate
    baseline = baseline_validate(root=root,evidence=folder/'baseline')
    require(baseline['measured_commit'] == commit and baseline['runtime_matches'] is True and baseline['native_development_entry'] is True, 'baseline execution scope')
    build = by_name['pipeline-build']['command']
    require(build == ['cargo','build','--offline','--locked','--release','--manifest-path','trillionnium/Cargo.toml','-p','trnm-pon-node','--examples','--bins','--message-format=json-render-diagnostics'], 'pipeline actual build')
    validate_pipeline_executable(folder, report, by_name)
    transfers = 0
    for pattern, profile in CASES:
        name = 'pipeline-'+pattern+'-'+profile
        command = by_name[name]['command']
        require(len(command) == 7 and Path(command[0]).name == 'continuous_pipeline' and Path(command[1]).name == name, 'pipeline invocation')
        transfers += validate_pipeline(root,folder/name,pattern,profile,command)
        output = json.loads(safe(folder,by_name[name]['log']).read_text().splitlines()[-1],object_pairs_hook=unique)
        summary = load(folder/name/'summary.json')
        require(output['accepted_transactions'] == output['confirmed_transactions'] == summary['accepted_transactions'] and output['public_qualified'] is False, 'pipeline execution output')
    socket = by_name[SOCKET_RUN]
    require(socket['command'] == ['cargo','test','--offline','--locked','--release','--manifest-path','trillionnium/Cargo.toml',
            '-p','trnm-pon-node','--test','protected_ingress','sustained_protected_socket_cost_campaign',
            '--','--exact','--ignored','--nocapture','--test-threads=1'], 'socket exact invocation')
    validate_socket_log(safe(folder,socket['log']).read_text())
    validate_attribution(root,folder/'attribution',by_name['bounded-model-attribution']['command'],commit)
    require(report['environment']['cargo_jobs'] == 2 and report['environment']['test_threads'] == 1 and report['environment']['gpu_used'] is False and report['environment']['vram_bytes'] is None, 'environment scope')
    return {'measured_commit':commit,'current_source_qualified_by_this_check':True,'runtime_matches':True,
            'engineering_observations_verified':True,'pipeline_cases':4,'actual_confirmed_transfers':transfers,
            'pipeline_file_and_launcher_bindings_verified':True,
            'pipeline_observation_scope':PIPELINE_OBSERVATION_SCOPE,
            **{flag:False for flag in FLAGS}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT)
    parser.add_argument('--evidence',type=Path)
    parser.add_argument('--historical',action='store_true')
    args = parser.parse_args()
    folder = args.evidence or args.root/('evidence/pon-public-readiness-v1' if args.historical else 'evidence/pon-public-readiness-v2')
    if args.historical:
        from historical_evidence import measured_checkout
        validate_artifacts(args.root.resolve(),folder.absolute(),load(safe(folder,'manifest.json')))
        with measured_checkout(args.root,folder) as source:
            child = subprocess.run([sys.executable,'-B',str(source/'scripts/ci/check_public_readiness_evidence.py'),
                                    '--root',str(source),'--evidence',str(folder.absolute())],
                                   cwd=source,check=True,capture_output=True,text=True)
            original = json.loads(child.stdout.splitlines()[-1])
        result = dict(original,current_source_qualified_by_this_check=False,runtime_matches=False,
                      historical_semantics_verified=True,**{flag:False for flag in FLAGS})
    else:
        result = validate(args.root,folder)
    print(json.dumps(result,sort_keys=True))
