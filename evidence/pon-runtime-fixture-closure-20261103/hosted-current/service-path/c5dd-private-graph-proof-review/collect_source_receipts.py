#!/usr/bin/env python3
"""Static source receipts only. Never runs SQLite or a native test."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tomllib

OUT=Path(__file__).resolve().parent
REPO=Path('/workspace/scratch/b5a148b09b11/chain-six-axis')
C5='c5dd7c7718925b951dc6e4d5ccc5a86ccfa8e3c1'
B4='b4bdf142f513081715ecc8d1f9674291e85302cc'
PATHS=[
 'trillionnium/crates/trnm-sqlite-io-boundary/src/transaction_scope.rs',
 'trillionnium/crates/trnm-sqlite-io-boundary/src/transaction_scope_tests.rs',
 'trillionnium/crates/trnm-sqlite-io-boundary/src/sql.rs',
 'trillionnium/crates/trnm-sqlite-io-boundary/src/owner.rs',
 'trillionnium/crates/trnm-sqlite-io-boundary/src/lib.rs',
 'trillionnium/crates/trnm-sqlite-io-boundary/Cargo.toml',
 'trillionnium/crates/trnm-pon-node/src/store.rs',
 'trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs',
 'trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs',
 'trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback/fence_tests.rs',
 'trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback/frontier_tests.rs',
 'trillionnium/crates/trnm-pon-node/src/store/reorg_readback_tests.rs',
 'trillionnium/crates/trnm-pon-node/src/store/reorg_cancellation.rs',
 'trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_scoped_readback.rs',
 'trillionnium/crates/trnm-pon-node/Cargo.toml',
 'docs/protocol/pon-nakamoto-v1/details/PERFORMANCE_ACCEPTANCE.md',
 'trillionnium/Cargo.lock',
]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(rev,path):return subprocess.check_output(['git','--no-replace-objects','show',rev+':'+path],cwd=REPO)
files=[]
for path in PATHS:
 identities=[]
 for rev in (C5,B4):
  raw=git(rev,path)
  identities.append(dict(commit=rev,bytes=len(raw),sha256=sha(raw),
   git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()))
 files.append(dict(path=path,identities=identities,bytes_equal=identities[0]['sha256']==identities[1]['sha256']))
assert all(f['bytes_equal'] for f in files)
lock=tomllib.loads(git(C5,'trillionnium/Cargo.lock').decode())
packages={p['name']:p for p in lock['package'] if p['name'] in ('libsqlite3-sys','rusqlite')}
registry=Path('/workspace/scratch/b5a148b09b11/toolchain/cargo/registry/src/index.crates.io-1949cf8c6b5b557f')
upstream=[]
for package,relative in [('libsqlite3-sys','sqlite3/sqlite3.c'),('rusqlite','src/trace.rs')]:
 root=registry/(package+'-'+packages[package]['version']);path=root/relative;raw=path.read_bytes()
 archive=registry.parent.parent/'cache'/registry.name/(root.name+'.crate')
 archive_raw=archive.read_bytes()
 assert sha(archive_raw)==packages[package]['checksum']
 with tarfile.open(archive,mode='r:gz') as tar:
  member=tar.extractfile(root.name+'/'+relative)
  assert member is not None
  assert member.read()==raw
 item=dict(package=package,version=packages[package]['version'],package_checksum=packages[package]['checksum'],
  path=str(path),bytes=len(raw),sha256=sha(raw),registry_archive=str(archive),
  archive_sha256=sha(archive_raw),archive_matches_cargo_lock=True,file_matches_archive_member=True)
 if package=='libsqlite3-sys':
  text=raw.decode();item['sqlite_version']=re.search(r'^#define SQLITE_VERSION\s+"([^"]+)"',text,re.M).group(1)
  item['sqlite_source_id']=re.search(r'^#define SQLITE_SOURCE_ID\s+"([^"]+)"',text,re.M).group(1)
  assert item['sqlite_version']=='3.51.3'
 upstream.append(item)
related=[]
for name in ['c5dd-graph-scope-review/review.json','c5dd-graph-internal-review/review.json','c5dd-baseline-critical-path/small-readback.json']:
 path=Path('/workspace/scratch/b5a148b09b11/next-validation/service-path-review')/name
 if path.exists():
  raw=path.read_bytes();related.append(dict(path=str(path),bytes=len(raw),sha256=sha(raw)))
result=dict(schema='cross-cursor-graph-proof-static-source-receipts-v1',
 observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
 measured_source=C5,followup_source=B4,files=files,pinned_dependency_sources=upstream,related_existing_readbacks=related,
 native_or_sqlite_executions=0,source_or_target_modifications=False,
 scope='Static source and retained evidence only; named test source is not a newly executed control.')
(OUT/'source-identities.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(dict(files=len(files),all_source_pairs_equal=True,sqlite_version=upstream[0]['sqlite_version'],
 sha256=sha((OUT/'source-identities.json').read_bytes()),native_executions=0)))
