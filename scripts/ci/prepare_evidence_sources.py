#!/usr/bin/env python3
"""Fetch only missing declared Git objects; never move branches or accept evidence.

A squash merge does not make measured implementation commits ancestors of main.
Object presence is necessary for later byte/tree validation, not a passing result.
"""
from pathlib import Path
import json,re,subprocess
ROOT=Path(__file__).resolve().parents[2]
REMOTE='https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'

def identity(value):
    if not isinstance(value,str) or re.fullmatch('[0-9a-f]{40}',value)is None:
        raise ValueError('invalid measured Git identity')
    return value

def declarations(root):
    # v1 source bytes are also bound by the independently retained mainline archive.
    values={'5d59b9540268914794a62e8fa237caf999499314':'30ee65c0752693f4eecc90f924972279f00c0c73'}
    names=['pon-v3','pon-v4','pon-evaluation-bundle-v1']
    # The collector's original commit must remain retrievable after squash publication.
    for package in ['pon-contract-authority-v1', 'pon-client-confirmation-v1', 'pon-native-session-v1', 'pon-native-node-v1']:
        if (root/'evidence'/package/'manifest.json').is_file():
            names.append(package)
    for name in names:
        data=json.loads((root/'evidence'/name/'manifest.json').read_text())
        commit=identity(data['implementation_commit']);tree=identity(data['implementation_tree'])
        if commit in values and values[commit]!=tree:raise ValueError('conflicting source tree')
        values[commit]=tree
    # Cost collections may be newer than the enclosing runtime qualification.
    for package in ['pon-contract-authority-v1', 'pon-native-session-v1', 'pon-native-node-v1']:
        path = root/'evidence'/package/'work-cost/execution.json'
        if not path.is_file():
            continue
        data = json.loads(path.read_text())
        if data.get('schema') != 'pon-native-cost-execution-v1':
            raise ValueError('invalid cost execution schema')
        commit, tree = identity(data['source_commit']), identity(data['source_tree'])
        if commit in values and values[commit] != tree:
            raise ValueError('conflicting source tree')
        values[commit] = tree
    return values

def prepare(root=ROOT,run=subprocess.run):
    root=Path(root).resolve();fetched=[]
    declarations_map=declarations(root)
    for commit,tree in declarations_map.items():
        identity(commit);identity(tree)
        found=run(['git','cat-file','-e',commit+'^{commit}'],cwd=root,capture_output=True,text=True)
        if found.returncode:
            fetch=run(['git','fetch','--no-tags','--no-write-fetch-head',REMOTE,commit],cwd=root,capture_output=True,text=True,timeout=90)
            if fetch.returncode:raise ValueError('declared source fetch failed: '+commit)
            fetched.append(commit)
        actual=run(['git','rev-parse',commit+'^{tree}'],cwd=root,capture_output=True,text=True)
        if actual.returncode or actual.stdout.strip()!=tree:raise ValueError('measured tree unavailable or mismatched: '+commit)
    return {'verified_object_trees':declarations_map,'fetched':fetched,'branch_refs_changed':False,'acceptance_granted':False}
if __name__=='__main__':print(json.dumps(prepare(),sort_keys=True))
