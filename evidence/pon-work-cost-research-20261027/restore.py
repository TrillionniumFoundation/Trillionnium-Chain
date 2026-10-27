#!/usr/bin/env python3
"""Verify or restore a lossless historical W1 evidence bundle; executes no code."""
from pathlib import Path,PurePosixPath
import argparse,gzip,hashlib,io,json,shutil,tarfile

MAX_FILE=64*1024*1024
MAX_TOTAL=512*1024*1024
def require(condition,message):
    if not condition:raise ValueError(message)
def safe(name):
    p=PurePosixPath(name)
    require(not p.is_absolute()and p.parts and all(s not in ('','.','..')for s in p.parts),'unsafe archive path')
    require('\\'not in name,'noncanonical archive path')
    return Path(*p.parts)
def sha(data):return hashlib.sha256(data).hexdigest()
def uncompressed(path,expected):
    require(type(expected)is int and 0<=expected<=MAX_FILE,'declared file bound')
    with gzip.open(path,'rb')as stream:data=stream.read(expected+1)
    require(len(data)==expected,'decompressed length')
    return data
def restore(bundle,output=None,snapshot=None):
    manifest_bytes=(bundle/'manifest.json').read_bytes();m=json.loads(manifest_bytes)
    require(m['schema']=='trnm-w1-research-lossless-bundle-v1','schema')
    require(m['succinct_proof_generated']is False and m['node_service_qualified']is False,'unearned qualification')
    if output is not None:output.mkdir(parents=True,exist_ok=False)
    paths=set();objects={};total=0
    for e in m['evidence']:
        name=safe(e['path']);require(str(name)not in paths,'duplicate evidence path');paths.add(str(name))
        require(e['object']=='objects/'+e['sha256']+'.gz','object identity')
        compressed=(bundle/safe(e['object'])).read_bytes()
        require(len(compressed)==e['compressed_bytes']and sha(compressed)==e['compressed_sha256'],'compressed evidence changed')
        data=uncompressed(bundle/e['object'],e['bytes']);require(sha(data)==e['sha256'],'raw evidence changed')
        total+=len(data);require(total<=MAX_TOTAL,'total evidence bound')
        objects[e['object']]=e['sha256']
        if output is not None:
            target=output/'evidence'/name;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb')as f:f.write(data)
    source_files=0;archive_total=0
    for a in m['source_archives']:
        blob=(bundle/safe(a['path'])).read_bytes()
        require(len(blob)==a['bytes']and sha(blob)==a['sha256'],'source archive changed')
        seen=set()
        with tarfile.open(fileobj=io.BytesIO(blob),mode='r:gz')as tar:
            for member in tar:
                name=safe(member.name);require(member.isfile()and str(name)not in seen,'nonregular/duplicate archive member');seen.add(str(name))
                require(0<=member.size<=MAX_FILE,'archive member bound');archive_total+=member.size
                require(archive_total<=MAX_TOTAL,'source archive total bound')
                data=tar.extractfile(member).read(member.size+1);require(len(data)==member.size,'archive member length')
                source_files+=1
                if output is not None:
                    target=output/name;target.parent.mkdir(parents=True,exist_ok=True)
                    with target.open('xb')as f:f.write(data)
    if output is not None:
        if snapshot:
            source=output/'evidence'/snapshot;record=json.loads((source/'build.json').read_text())
            for entry in record['files']:
                name=safe(entry['path']);data=(source/name).read_bytes()
                require(sha(data)==entry['sha256'],'build input changed')
                target=output/'harness'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        # Preserve the historical absolute-path config; create a new explicit
        # replay config for the archived local sources. No registry is forged.
        lines=['# Relocated exact local research dependencies; not native workspace lock.', '[patch.crates-io]']
        import tomllib
        for path in sorted((output/'dependencies').iterdir()):
            package=tomllib.loads((path/'Cargo.toml').read_text())['package']['name']
            lines.append(package+' = { path = '+json.dumps(str(path.resolve()))+' }')
        (output/'harness/replay-local-paths.toml').write_text('\n'.join(lines)+'\n')
        (output/'harness/evidence').mkdir(exist_ok=True)
    return dict(result='PASS',manifest_sha256=sha(manifest_bytes),evidence_paths=len(paths),unique_objects=len(objects),
                raw_evidence_bytes=total,source_archive_files=source_files,source_archive_uncompressed_bytes=archive_total,
                restored=output is not None,selected_build_snapshot=snapshot,executed_code=False,
                timing_authenticated=False,hardness_proved=False,node_service_qualified=False,succinct_proof=False)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('bundle',type=Path);p.add_argument('--output',type=Path)
    p.add_argument('--snapshot',choices=['build-input-v1','build-input-v3'])
    a=p.parse_args();require(a.output is not None or a.snapshot is None,'snapshot requires output')
    print(json.dumps(restore(a.bundle,a.output,a.snapshot),indent=2))
