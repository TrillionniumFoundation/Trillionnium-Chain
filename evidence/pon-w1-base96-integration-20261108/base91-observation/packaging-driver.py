#!/usr/bin/env python3
"""Package already completed fixed-base91 observations; perform no new Git check."""
import gzip
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
from pathlib import Path

RAW = Path('/home/qian-qi/work/chain-w1-base91-impact-20261108-ec265b-01')
DEST = Path('/home/qian-qi/work/chain-w1-base91-publication-20261108-ec265b-01')
C7 = '40a3a45d6b8afc5c4706c5235fec47634f4aabbe'
TREE = '4b25e3194a0682adff40bb476f2e7c0a395639fe'
BASE = '91c1b7da0f0b1f41c088d9ac0b2ee160b550b80c'
CANONICAL = 'e8550e15374ce6a0cc60f435ccd4a0c401741930'

def sha(b):
    return hashlib.sha256(b).hexdigest()

def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        a = os.fstat(fd)
        assert stat.S_ISREG(a.st_mode) and a.st_size < 25*1024*1024
        b = b''
        while len(b) <= a.st_size:
            chunk = os.read(fd, min(1048576, a.st_size-len(b)+1))
            if not chunk:
                break
            b += chunk
        z = os.fstat(fd)
        fields = lambda x: (x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        assert fields(a) == fields(z) and len(b) == z.st_size
        b.decode('utf-8')
        return b
    finally:
        os.close(fd)

def dump(v):
    return (json.dumps(v, ensure_ascii=False, sort_keys=True, indent=2)+'\n').encode()

def write(p,b):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f:
        f.write(b)

inputs=json.loads(read(Path(sys.argv[1])))
readme=read(Path(sys.argv[2]))
DEST.mkdir()
raw={}
index=[]

def add(member,path,pin=None):
    b=read(path)
    if pin:
        assert sha(b)==pin['sha256'] and len(b)==pin['bytes']
    assert member not in raw and not member.startswith('/') and '..' not in Path(member).parts
    raw[member]=b
    index.append({'member':member,'original_path':str(path),'bytes':len(b),'sha256':sha(b)})
    return b

pins={Path(x['path']).name:x for x in inputs['raw_pins']}
for name,pin in pins.items():
    add(name,RAW/name,pin)
review=json.loads(raw['raw-review.json'])
canonical=json.loads(raw['isolated-canonical-review.json'])
inventory=json.loads(raw['inventory-static-consistency.json'])
assert review['source_commit']==canonical['source_commit']==inventory['source_commit']==C7
assert review['source_tree']==TREE and review['reviewed_base91']==canonical['base91']==BASE
assert review['complete'] is True and review['static_merge_exit']==0
assert review['static_tree']==canonical['isolated_canonical_merge_tree']==inventory['hypothetical_merge_tree']==CANONICAL
assert review['source_worktree_changes']==review['tests_executed']==review['new_operations']==review['full_proofs']==0
assert canonical['pin_count']==650 and canonical['required_count']==558
assert canonical['all_other_corpus_fields_and_required_order_preserved'] is True
assert canonical['c7_generated_inventory_pin_preserved'] is True
assert len(canonical['only_changed_pins'])==2
assert inventory['same_all_tracked_path_set'] is True and inventory['tracked_paths']==15390
assert inventory['inventory_registered_file_count']==1279 and inventory['inventory_same_bytes'] is True
assert inventory['generator_same_bytes'] is True and inventory['extra_generated_inventory_registration_fix_needed_for_this_delta'] is False
assert inventory['new_tree_check_command_executed'] is False and inventory['new_tree_compiled'] is False
assert inventory['new_tree_worktree_created'] is False and inventory['actual_merge_performed'] is False
commands=json.loads(raw['commands.json'])
if isinstance(commands,dict):
    commands=commands['commands']
assert commands==review['commands'] and len(commands)==18
for c in commands:
    assert c['exit']==0
    for stream in ('stdout','stderr'):
        name=c['label']+'.'+stream
        add('commands/'+name,RAW/name,{'sha256':c[stream+'_sha256'],'bytes':c[stream+'_bytes']})
for name,text in inputs['recorded_review_scripts'].items():
    b=text.encode()
    write(DEST/'recorded-review-scripts'/name,b)
for name,terminal_text in inputs['terminals'].items():
    t=json.loads(terminal_text)
    assert t['job_id']==inputs['job_ids'][name] and t['state']=='succeeded' and t['exit_code']==0
    assert t['output_complete'] is True and t['output_durable'] is True and t['timed_out'] is False
    write(DEST/'jobs'/(name+'.terminal.json'),terminal_text.encode())
    output=inputs['outputs'][name]
    for stream in ('stdout','stderr'):
        data=bytes.fromhex(output[stream]['bytes_hex'])
        assert len(data)==output[stream]['next_offset']
        write(DEST/'jobs'/(name+'.'+stream),data)
buf=io.BytesIO()
with gzip.GzipFile(fileobj=buf,mode='wb',mtime=0) as gz:
    with tarfile.open(fileobj=gz,mode='w') as tf:
        for member,b in sorted(raw.items()):
            ti=tarfile.TarInfo(member)
            ti.size,ti.mode,ti.mtime=len(b),0o644,0
            tf.addfile(ti,io.BytesIO(b))
archive=buf.getvalue()
with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tf:
    assert sorted(tf.getnames())==sorted(raw)
    for member,b in raw.items():
        assert tf.extractfile(member).read()==b
write(DEST/'raw-logs.tar.gz',archive)
write(DEST/'raw-output-index.json',dump({'archive':'raw-logs.tar.gz','archive_sha256':sha(archive),
    'members':index,'members_count':len(index),'all_original_bytes_and_tar_members_reverified':True}))
for original,target in [('raw-review.json','raw-review.original.json'),
                        ('isolated-canonical-review.json','isolated-canonical-review.original.json'),
                        ('inventory-static-consistency.json','inventory-static-consistency.original.json')]:
    write(DEST/target,raw[original])
write(DEST/'README.md',readme)
summary={'schema':'TRNM-W1-C7-BASE91-PUBLICATION1','frozen_source_commit':C7,'frozen_source_tree':TREE,
    'observed_base':BASE,'observed_base_parent':'96a241bf43f6a46d35dfb3d4ced9594ed8ceca75',
    'observed_base_tree':'cb9c954cf657b2e57c2f0c61badffdd6941abe6d',
    'base96_delta':{'paths':review['changed_paths'],'insertions':5,'deletions':3,
                   'scope':'History source.json self-label correction, two assertions inside an existing method, and two matching corpus blob pins'},
    'canonical_order':[BASE,C7],'canonical_static_tree':CANONICAL,
    'canonical_helper_sha256':canonical['helper_sha256'],'isolated_canonical_matches_ordinary_merge_tree':True,
    'source_pin_count':650,'required_path_count':558,'only_changed_pins':canonical['only_changed_pins'],
    'static_inventory':inventory,'production_rust_src_changes':False,'m12_or_w1_generation_changes':False,
    'ci_source_guard_or_event_context_changes':False,'actual_merge':False,'new_candidate_created':False,
    'tests_executed':0,'new_operations':0,'new_proofs':0,'source_worktree_writes':0,'pushes':0,
    'new_tree_source_qualification_established':False,'old_c7_elf_relabelled_as_new_tree':False,
    'full_history_4105_block_workload_executed':False,'documentation_is_posthoc':True,
    'raw_archive_members':len(raw),'raw_archive_sha256':sha(archive),
    'publication_state':'filesystem and archive verified; Git index/commit readback is the publishing owner responsibility'}
write(DEST/'summary.json',dump(summary))
write(DEST/'packaging-driver.py',read(Path(__file__)))
members=[]
for p in sorted(DEST.rglob('*')):
    if p.is_file():
        b=p.read_bytes()
        assert len(b)<25*1024*1024
        members.append({'path':p.relative_to(DEST).as_posix(),'bytes':len(b),'sha256':sha(b)})
write(DEST/'manifest.json',dump({'schema':'TRNM-W1-BASE91-PUBLICATION-MANIFEST1','members':members,
    'files_including_manifest':len(members)+1,'filesystem_verified':True,'git_index_or_commit_verified':False}))
for item in members:
    b=(DEST/item['path']).read_bytes()
    assert len(b)==item['bytes'] and sha(b)==item['sha256']
print(json.dumps({'directory':str(DEST),'files':len(members)+1,'raw_members':len(raw),
    'manifest_sha256':sha(read(DEST/'manifest.json')),'summary_sha256':sha(read(DEST/'summary.json')),
    'raw_archive_sha256':sha(archive),'bytes':len(archive)}),flush=True)
