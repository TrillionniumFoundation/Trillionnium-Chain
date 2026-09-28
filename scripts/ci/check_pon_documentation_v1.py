#!/usr/bin/env python3
"""Read-only PoN target, retirement, module and reference integrity check.

No crypto, runtime, economic, model-efficacy or independent acceptance is granted.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from typing import Any
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = 'config/pon-nakamoto-v1.json'
PROFILE = 'pon-nakamoto-v1'
MODULES = [f'M{i:02d}' for i in range(18)]
SECTIONS = ['Authority','Interfaces','State machine','Persistence and recovery',
            'Resource bounds','Security','Verification and evidence','Source migration']
PROTOCOL_NAMES = {'README.md','CONSENSUS.md','NEURAL_WORK.md','MODEL_COMMONS.md',
                  'ECONOMICS.md','RECOVERY_MIGRATION.md','SECURITY_ACCEPTANCE.md','REFERENCES.md'}
TOP_FIELDS = {'schema','plan_id','selected_development_target','decision_date','consensus_family',
'poco_development_retired','fork_choice','confirmation','validator_voting','quality_weighted_chainwork',
'automatic_bft_fallback','automatic_hash_only_fallback','legacy_implementation','work_profile',
'implementation','production_candidate','production_consensus_activation','public_testnet_ready',
'release_ready','parameter_status','required_consensus_parameters','protocol_documents','module_targets',
'module_documents','existing_crate_documents','legacy_protocol_roots','legacy_frozen_inputs','legacy_rule',
'new_checks','reference_test_scope','required_real_evidence'}

class TargetError(ValueError): pass

def require(condition: bool, message: str) -> None:
    if not condition: raise TargetError(message)

def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON key: '+key)
        value[key] = item
    return value

def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=strict_object)
    require(isinstance(value, dict), 'JSON object required')
    return value

def validate_contract(data: dict[str, Any]) -> None:
    require(set(data) == TOP_FIELDS, 'contract fields must be closed')
    require(data['schema'] == 'trnm-pon-nakamoto-v1', 'schema mismatch')
    require(data['plan_id'] == 'trnm-chain-development-plan-v2', 'one stable plan required')
    require(data['selected_development_target'] == PROFILE, 'selected target mismatch')
    require(data['consensus_family'] == 'nakamoto-useful-neural-work', 'consensus family mismatch')
    require(data['poco_development_retired'] is True, 'PoCO development must be retired')
    require(data['fork_choice'] == 'maximum-fully-validated-cumulative-required-work', 'fork choice mismatch')
    require(data['confirmation'] == 'probabilistic-depth-and-work-policy', 'confirmation mismatch')
    for field in ['validator_voting','quality_weighted_chainwork','automatic_bft_fallback',
                  'automatic_hash_only_fallback','production_candidate','production_consensus_activation',
                  'public_testnet_ready','release_ready']:
        require(data[field] is False, 'forbidden activation/authority: '+field)
    expected_impl = {'runtime_implemented','work_profile_qualified','public_model_efficacy_measured',
                     'public_model_product_loop_accepted','reorg_external_effects_qualified',
                     'independent_security_accepted','independent_economics_accepted'}
    require(isinstance(data['implementation'], dict) and set(data['implementation']) == expected_impl,
            'implementation axes must be complete')
    require(all(v is False for v in data['implementation'].values()), 'documentation cannot grant implementation')
    work = data['work_profile']
    require(set(work) == {'status','primitive_direction','concrete_profile_id','canonical_codec_frozen',
                         'cost_hardness_accepted','independent_verifier','work_class_count',
                         'quality_is_work','historical_training_is_fresh_work'}, 'work profile fields')
    require(work['status'] == 'unqualified' and work['concrete_profile_id'] is None, 'no qualified primitive exists in this change')
    require(work['primitive_direction'] == 'challenge-bound-verifiable-neural-linear-algebra', 'work direction mismatch')
    require(type(work['work_class_count']) is int and work['work_class_count'] == 1, 'no uncalibrated work classes')
    for key in ['canonical_codec_frozen','cost_hardness_accepted','independent_verifier','quality_is_work','historical_training_is_fresh_work']:
        require(work[key] is False, 'unsupported work claim: '+key)
    rows = data['module_targets']
    require(isinstance(rows, list) and [r.get('id') for r in rows] == MODULES, 'exact 18 module targets required')
    for row in rows:
        require(set(row) == {'id','source_owner_registry','technical_spec','role','domain_contract','status'}, 'module row fields')
        require(row['source_owner_registry'] == 'config/module-coverage-v1.toml', 'one actual source registry')
        require(row['status'] == 'target-not-implemented-by-documentation', 'module implementation not granted')
        require(row['technical_spec'].startswith('docs/modules/'+row['id']+'_'), 'wrong module spec')
    require(len(set(r['technical_spec'] for r in rows)) == 18, 'duplicate specification')
    require({Path(p).name for p in data['protocol_documents']} == PROTOCOL_NAMES and len(data['protocol_documents']) == len(PROTOCOL_NAMES), 'incomplete protocol suite')
    for key in ['module_documents','existing_crate_documents','required_consensus_parameters','new_checks','required_real_evidence']:
        values = data[key]
        require(isinstance(values,list) and values and all(isinstance(x,str) and x for x in values), key+' must be nonempty')
        require(len(values) == len(set(values)), key+' has duplicates')
    require(data['legacy_protocol_roots'] == ['docs/protocol/poco-bft-v0','docs/protocol/poco-ai-native-v1','docs/protocol/poco-convergence-v1'], 'legacy scope drift')
    require(data['legacy_frozen_inputs'] and all(re.fullmatch('[0-9a-f]{64}',v) for v in data['legacy_frozen_inputs'].values()), 'legacy byte fingerprints missing')
    legacy=data['legacy_implementation']
    require(legacy['consensus_mainline']=='native-poco-bft' and legacy['protocol_target']=='poco-bft-v0'
            and legacy['source_runtime_changed'] is False, 'runtime identity falsely relabelled')
    require(data['parameter_status']=='reference-formulas-only-deployment-values-not-selected', 'unreviewed deployment parameters')
    require(data['reference_test_scope']=='arithmetic-fork-reorg-accounting-only-not-neural-work-or-runtime', 'reference claims strengthened')

def validate_spec(text: str, mid: str) -> None:
    require(text.startswith('# '+mid+' '), 'wrong module heading '+mid)
    require('Selected profile: `pon-nakamoto-v1`' in text, 'missing selected profile '+mid)
    cut='## Retired PoCO implementation reference'
    require(text.count(cut)==1, 'explicit legacy boundary required '+mid)
    primary=text.split(cut,1)[0]
    require('proposed contracts' in primary, 'API implementation boundary missing '+mid)
    for heading in SECTIONS:
        pattern=r'^## PoN '+re.escape(heading)+r'\n\n(.+?)(?=\n## |\Z)'
        matches=re.findall(pattern,primary,re.M|re.S)
        require(len(matches)==1 and len(matches[0].strip())>40, 'missing PoN section '+mid+': '+heading)
    require('PoCO is retired' in text.split(cut,1)[1], 'legacy target ambiguity '+mid)

def file_in(root: Path, relative: str) -> Path:
    path=Path(relative)
    require(not path.is_absolute() and '..' not in path.parts, 'noncanonical path '+relative)
    resolved=(root/path).resolve()
    require(resolved.is_relative_to(root.resolve()) and resolved.is_file(), 'missing/escaping file '+relative)
    return resolved

def check_links(root: Path, relative: str) -> int:
    document=file_in(root,relative); text=document.read_text(encoding='utf-8')
    text=re.sub(r'^```[^\n]*\n.*?^```[^\n]*$', '', text, flags=re.M|re.S)
    count=0
    for target in re.findall(r'\[[^\]]*\]\(([^\s)]+)\)',text):
        parsed=urlsplit(target.strip('<>'))
        if parsed.scheme or parsed.netloc or not parsed.path: continue
        target_path=(root/parsed.path.lstrip('/')) if parsed.path.startswith('/') else document.parent/unquote(parsed.path)
        require(target_path.resolve().is_relative_to(root.resolve()) and target_path.exists(), 'broken link '+relative+' -> '+target)
        count+=1
    return count

def validate_repository(root: Path) -> dict[str, Any]:
    data=read_json(root/CONTRACT);validate_contract(data)
    coverage=tomllib.loads((root/'config/module-coverage-v1.toml').read_text())
    require([r['id'] for r in coverage['module_coverage']]==MODULES, 'source owner inventory mismatch')
    require(coverage['development_target']==PROFILE, 'source registry lacks selected target')
    live=read_json(root/'config/consensus-mainline.json')
    require(live['development_target']==PROFILE and live['poco_development_retired'] is True, 'machine target mismatch')
    require(live['consensus_mainline']=='native-poco-bft' and live['protocol_target']=='poco-bft-v0', 'legacy implementation misrepresented')
    for flag in ['production_candidate','production_consensus_activation']:
        require(live[flag] is False, 'runtime activation changed')
    actual_specs={p.relative_to(root).as_posix() for p in (root/'docs/modules').glob('M[0-9]*.md')}
    require(actual_specs=={r['technical_spec'] for r in data['module_targets']}, 'primary spec inventory mismatch')
    actual_modules={p.relative_to(root).as_posix() for p in (root/'docs/modules').glob('*.md')}
    require(set(data['module_documents'])==actual_modules, 'all module documentation must be covered')
    actual_crates={p.relative_to(root).as_posix() for p in (root/'trillionnium/crates').rglob('*.md')}
    require(set(data['existing_crate_documents'])==actual_crates, 'all existing crate documentation must be covered')
    for row in data['module_targets']:
        validate_spec(file_in(root,row['technical_spec']).read_text(),row['id'])
        file_in(root,row['domain_contract'])
    for relative in data['module_documents']+data['existing_crate_documents']:
        require(PROFILE in file_in(root,relative).read_text(), 'document omitted target: '+relative)
    actual_legacy={p.relative_to(root).as_posix() for folder in data['legacy_protocol_roots'] for p in (root/folder).rglob('*') if p.is_file()}
    require(actual_legacy==set(data['legacy_frozen_inputs']), 'legacy input inventory changed')
    for relative,expected in data['legacy_frozen_inputs'].items():
        require(hashlib.sha256(file_in(root,relative).read_bytes()).hexdigest()==expected, 'legacy bytes altered: '+relative)
    for relative in data['new_checks']:file_in(root,relative)
    docs=data['protocol_documents']+data['module_documents']+data['existing_crate_documents']+['README.md','docs/README.md','docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md']
    links=sum(check_links(root,p) for p in docs)
    plan=(root/'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md').read_text()
    for phrase in ['RETired','PN0','PN1','PN2','PN3','PN4','PN5','PN6']:
        if phrase=='RETired':require('RETIRED AS DEVELOPMENT TARGET' in plan, 'plan does not retire PoCO')
        else:require(phrase in plan,'missing active phase '+phrase)
    return {'result':'PASS','modules':18,'module_documents':len(actual_modules),'crate_documents':len(actual_crates),
            'legacy_inputs_unchanged':len(actual_legacy),'local_links_checked':links,'selected_target':PROFILE,
            'crypto_security_accepted':False,'runtime_accepted':False,'model_efficacy_accepted':False,'activation':False}

def main() -> int:
    report=validate_repository(ROOT)
    report['head']=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    report['tree']=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True).strip()
    changes=subprocess.check_output(['git','status','--porcelain','--untracked-files=normal'],cwd=ROOT,text=True)
    report['source_state']='committed-clean' if not changes.strip() else 'working-tree-not-exact-head-evidence'
    print(json.dumps(report,sort_keys=True))
    return 0

if __name__=='__main__':
    try: raise SystemExit(main())
    except (TargetError,ValueError,KeyError,OSError,subprocess.CalledProcessError) as error:
        print('PoN documentation validation failed: '+str(error),file=sys.stderr);raise SystemExit(2)
