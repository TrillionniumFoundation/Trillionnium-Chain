#!/usr/bin/env python3
"""Read every byte of the fixed D26 copy plan through its original Git view.

Only eight original SQLite gzip containers are archived. All 614 prepared
payloads, all 232 decoded gzip streams, both controls and the sealed copy plan
are verified. SQLite, Node, historical scripts and network fetches are never
invoked. No receipt or other evidence file is written by this checker.
"""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import zlib

import check_historical_archive as history


PACKAGE = 'evidence/pon-business-gates-readback-20261107/ci-d26'
INDEX_PATH = 'evidence/pon-business-gates-readback-20261107/D26_SQLITE_ARCHIVE.json'
COMMIT = '893210a45b44742edfe2510fea1d92e9974b5f95'
TREE = 'a2d04b29621bb78504244471aacac3be3bc78d1d'
ORIGINAL_FILES = 617
ORIGINAL_BYTES = 202448382
PAYLOAD_FILES = 614
PREPARED_BYTES = 201804106
ORIGINAL_PAYLOAD_BYTES = 1998818859
RAW_FILES = 382
RAW_BYTES = 5901434
GZIP_FILES = 232
GZIP_PREPARED_BYTES = 195902672
GZIP_RAW_BYTES = 1992917425
ARCHIVED_FILES = 8
ARCHIVED_BYTES = 176597049
SQLITE_RAW_BYTES = 1745207296
ENCODINGS = {'raw': 382, 'gzip-mtime-0': 67, 'gzip-mtime-0-no-filename': 165}
LANES = ('arm64-head', 'arm64-merge', 'x64-head', 'x64-merge')
SQLITE_PATHS = frozenset(
    f'history/{lane}/history-native/long-history/{owner}/native.sqlite.gz'
    for lane in LANES for owner in ('confirmer', 'validator'))
CONTROL_PINS = {
    'COPY_PLAN.json': {'bytes':629029, 'blob':'5c74b55e6e1a28b9af50a62952cdac28cb8383f5',
        'sha256':'91c7527b23e32262db6f5cbccf0066aff796d1efd525fa638df5ee851851ca67'},
    'GATE_CORE.json': {'bytes':12902, 'blob':'3d7339a6f3409ea5d4fc4459db0dfe8be2fb2e0f',
        'sha256':'62b53966b176f3a665ce77950d8be847284db1b78532dd2cff55d49098da5435'},
    'README.md': {'bytes':2345, 'blob':'bec67b4376717b0b5d6193ac31f5d04df2e37989',
        'sha256':'454828d86b5ace9feef4e66668d3b1e97407ea02f42e09e2d1e83d66f8e90358'},
}
CHUNK = 1024 * 1024
HEX = re.compile(r'[0-9a-f]{64}\Z')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def blob_digest(raw):
    return hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()


def document(raw):
    def bad_constant(value):
        raise history.Invalid('non-finite JSON constant: '+value)
    return json.loads(raw,object_pairs_hook=history.unique,parse_constant=bad_constant)


def natural(value, label):
    history.require(type(value) is int and value >= 0,'invalid nonnegative integer: '+label)
    return value


def hex_digest(value, label):
    history.require(isinstance(value,str) and HEX.fullmatch(value),'invalid SHA256: '+label)
    return value


def fixed_tree(root):
    history.git(root,'merge-base','--is-ancestor',COMMIT,'HEAD')
    history.require(history.git(root,'rev-parse',COMMIT+'^{tree}').decode().strip() == TREE,
                    'D26 original tree differs')
    rows = history.tree_rows(root,COMMIT,[PACKAGE])
    history.require(len(rows) == ORIGINAL_FILES and sum(row['bytes'] for row in rows.values()) == ORIGINAL_BYTES,
                    'D26 original complete file denominator differs')
    return rows


def original_bytes(root, row):
    raw = history.git(root,'cat-file','blob',row['blob'])
    history.require(len(raw) == row['bytes'] and blob_digest(raw) == row['blob'],
                    'D26 original Git blob differs: '+row['path'])
    return raw


def plan_rows(plan):
    history.require(plan['schema'] == 'trnm-d26-light-evidence-copy-plan-v2'
                    and plan['status'] == 'HOLD' and plan['native_gate_validated'] is False
                    and plan['later_files_will_not_be_added'] is True
                    and plan['all_encoded_original_bytes_read_back'] is True,
                    'original D26 seal or qualification fields differ')
    history.require(type(plan['files']) is list and len(plan['files']) == PAYLOAD_FILES,
                    'D26 complete payload roster differs')
    rows = {}
    for row in plan['files']:
        name = history.canonical(row['path'])
        history.require(name not in rows and name not in CONTROL_PINS,'duplicate or colliding D26 payload')
        natural(row['bytes'],name)
        natural(row['original_bytes'],name)
        hex_digest(row['sha256'],name)
        hex_digest(row['original_sha256'],name)
        history.require(row['encoding'] in ENCODINGS,'unknown D26 payload encoding')
        if row['encoding'] == 'raw':
            history.require(row['bytes'] == row['original_bytes'] and row['sha256'] == row['original_sha256'],
                            'raw D26 identity changed by preparation')
        else:
            history.require(name.endswith('.gz'),'gzip payload name differs')
        rows[name] = row
    history.require(dict(Counter(row['encoding'] for row in rows.values())) == ENCODINGS,
                    'D26 encoding denominator differs')
    totals = {'payload_file_count':PAYLOAD_FILES, 'payload_prepared_bytes':PREPARED_BYTES,
              'payload_original_bytes':ORIGINAL_PAYLOAD_BYTES}
    for name,value in totals.items():
        history.require(type(plan[name]) is int and plan[name] == value,'D26 total differs: '+name)
    history.require(sum(row['bytes'] for row in rows.values()) == PREPARED_BYTES
                    and sum(row['original_bytes'] for row in rows.values()) == ORIGINAL_PAYLOAD_BYTES,
                    'D26 payload sums differ')
    history.require(type(plan['control_files']) is list and len(plan['control_files']) == 2,
                    'D26 original controls missing')
    controls = {row['path']:row for row in plan['control_files']}
    history.require(set(controls) == {'GATE_CORE.json','README.md'} and len(controls) == 2,
                    'D26 control names differ')
    for name,row in controls.items():
        history.require(type(row['bytes']) is int and row['bytes'] == CONTROL_PINS[name]['bytes']
                        and row['sha256'] == CONTROL_PINS[name]['sha256'],
                        'D26 sealed control differs: '+name)
    return rows


def sqlite_rows(plan, rows):
    history.require(type(plan['sqlite']) is list and len(plan['sqlite']) == ARCHIVED_FILES,
                    'D26 eight original SQLite identities missing')
    found = set()
    for row in plan['sqlite']:
        path = history.canonical(row['portable_path'])
        history.require(path in SQLITE_PATHS and path not in found and path in rows,
                        'D26 SQLite portable path differs')
        found.add(path)
        payload = rows[path]
        for key in ('compressed_bytes','raw_bytes'):
            natural(row[key],path)
        history.require(payload['encoding'] == 'gzip-mtime-0-no-filename'
                        and row['compressed_bytes'] == payload['bytes']
                        and row['compressed_sha256'] == payload['sha256']
                        and row['raw_bytes'] == payload['original_bytes']
                        and row['raw_sha256'] == payload['original_sha256'],
                        'D26 SQLite raw/prepared binding differs')
        origin = payload['origin']
        history.require(origin['original_ci_database'] is True
                        and origin['artifact_id'] == row['artifact_id']
                        and origin['archive_member'] == row['archive_member']
                        and row['lane'] in LANES
                        and path == 'history/'+row['lane']+'/'+row['archive_member']+'.gz',
                        'D26 SQLite original artifact/member binding differs')
    history.require(found == SQLITE_PATHS
                    and sum(row['compressed_bytes'] for row in plan['sqlite']) == ARCHIVED_BYTES
                    and sum(row['raw_bytes'] for row in plan['sqlite']) == SQLITE_RAW_BYTES,
                    'D26 SQLite complete byte denominator differs')
    return {PACKAGE+'/'+path for path in found}


def contract(root, tree):
    originals = {}
    for name,pin in CONTROL_PINS.items():
        row = tree.get(PACKAGE+'/'+name)
        history.require(row is not None and row['blob'] == pin['blob'] and row['bytes'] == pin['bytes'],
                        'D26 fixed original control tree differs: '+name)
        raw = original_bytes(root,row)
        history.require(digest(raw) == pin['sha256'],'D26 fixed original control SHA differs: '+name)
        originals[name] = raw
    plan = document(originals['COPY_PLAN.json'])
    rows = plan_rows(plan)
    selected = sqlite_rows(plan,rows)
    history.require(set(tree) == {PACKAGE+'/'+name for name in rows} | {PACKAGE+'/'+name for name in CONTROL_PINS},
                    'D26 original 617-entry view differs from sealed plan')
    core = document(originals['GATE_CORE.json'])
    history.require(core['schema'] == 'trnm-d26-final-gate-core-v2'
                    and core['status'] == 'HOLD' and core['native_gate_validated'] is False,
                    'D26 original core promotes qualification')
    return plan,rows,selected,originals


def current_files(root):
    package = root/PACKAGE
    for ancestor in [package,*package.parents]:
        if ancestor == root:
            break
        history.require(not ancestor.is_symlink(),'symlink in D26 package path')
    history.require(package.is_dir(),'D26 package directory missing')
    found = set()
    for path in package.rglob('*'):
        history.require(not path.is_symlink(),'symlink in D26 retained tree')
        mode = path.lstat().st_mode
        if stat.S_ISREG(mode):
            found.add(path.relative_to(root).as_posix())
        else:
            history.require(stat.S_ISDIR(mode),'special file in D26 retained tree')
    return found


def index_rows(root, paths):
    result = {}
    for item in history.git(root,'ls-files','--stage','-z','--',*paths).split(b'\0'):
        if not item:
            continue
        metadata,path = item.split(b'\t',1)
        mode,oid,stage = metadata.decode('ascii').split()
        name = history.canonical(path.decode('utf-8'))
        history.require(stage == '0' and name not in result,'unmerged or duplicate D26 Git index entry')
        result[name] = (mode,oid)
    return result


def tracking(root, tree, selected, archived, index_raw=None):
    wanted = set(tree)-selected if archived else set(tree)
    history.require(current_files(root) == wanted,'D26 current namespace has missing or extra paths')
    indexed = index_rows(root,[PACKAGE])
    history.require(set(indexed) == wanted,'D26 retained roster is not exactly tracked')
    history.require(all(indexed[name] == (tree[name]['mode'],tree[name]['blob']) for name in wanted),
                    'D26 retained index bytes or mode differ from original')
    if archived:
        own = index_rows(root,[INDEX_PATH])
        history.require(own == {INDEX_PATH:('100644',blob_digest(index_raw))},
                        'D26 archive index is untracked or staged with different bytes')
        indexed.update(own)
    return wanted,indexed


@contextmanager
def current_reader(root, name):
    path = history.local_file(root,name)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path,flags)
    try:
        history.require(stat.S_ISREG(os.fstat(fd).st_mode),'D26 reader requires a regular file')
        with os.fdopen(fd,'rb',closefd=False) as stream:
            yield stream
    finally:
        os.close(fd)


@contextmanager
def view_reader(root, name, tree, selected):
    if name in selected:
        with io.BytesIO(original_bytes(root,tree[name])) as stream:
            yield stream
    else:
        with current_reader(root,name) as stream:
            yield stream


def hash_prepared(stream, row, original):
    total = 0
    sha = hashlib.sha256()
    oid = hashlib.sha1(b'blob '+str(original['bytes']).encode('ascii')+b'\0')
    while block := stream.read(CHUNK):
        total += len(block)
        history.require(total <= row['bytes'],'prepared D26 payload exceeds its bound')
        sha.update(block)
        oid.update(block)
    history.require(total == row['bytes'] == original['bytes']
                    and sha.hexdigest() == row['sha256'] and oid.hexdigest() == original['blob'],
                    'D26 prepared bytes/SHA/Git blob differ: '+row['path'])
    return total,sha.hexdigest()


def verify_payload(stream, row, original):
    prepared_size,prepared_sha = hash_prepared(stream,row,original)
    if row['encoding'] == 'raw':
        history.require(prepared_size == row['original_bytes'] and prepared_sha == row['original_sha256'],
                        'D26 raw original identity differs')
        raw_size,raw_sha = prepared_size,prepared_sha
    else:
        stream.seek(0)
        header = stream.read(10)
        history.require(len(header) == 10 and header[:3] == b'\x1f\x8b\x08'
                        and header[4:8] == b'\0'*4 and not header[3] & 0xe0,
                        'D26 deterministic gzip header differs')
        if row['encoding'] == 'gzip-mtime-0-no-filename':
            history.require(not header[3] & 8,'D26 no-filename gzip contains a filename')
        stream.seek(0)
        sha = hashlib.sha256()
        raw_size = 0
        with gzip.GzipFile(fileobj=stream,mode='rb') as decoded:
            while block := decoded.read(CHUNK):
                raw_size += len(block)
                history.require(raw_size <= row['original_bytes'],'D26 decoded payload exceeds its bound')
                sha.update(block)
        raw_sha = sha.hexdigest()
        history.require(raw_size == row['original_bytes'] and raw_sha == row['original_sha256'],
                        'D26 decoded original bytes or SHA differ: '+row['path'])
        # gzip.GzipFile consumed every member and its trailer before EOF.
        history.require(stream.read(1) == b'','D26 compressed stream has an unread tail')
    return {'path':row['path'],'prepared_bytes':prepared_size,'prepared_sha256':prepared_sha,
            'original_bytes':raw_size,'original_sha256':raw_sha,'encoding':row['encoding']}


def verify_view(root, tree, rows, selected, controls):
    observations = []
    hashes = {}
    for name,row in sorted(rows.items()):
        full = PACKAGE+'/'+name
        with view_reader(root,full,tree,selected) as stream:
            observation = verify_payload(stream,row,tree[full])
        observations.append(observation)
        hashes[full] = observation['prepared_sha256']
    for name,raw in controls.items():
        full = PACKAGE+'/'+name
        with current_reader(root,full) as stream:
            current = stream.read(len(raw)+1)
        history.require(current == raw,'sealed D26 control changed: '+name)
        hashes[full] = digest(current)
    gz = [row for row in observations if row['encoding'] != 'raw']
    direct = [row for row in observations if row['encoding'] == 'raw']
    history.require(len(observations) == PAYLOAD_FILES
                    and sum(row['prepared_bytes'] for row in observations) == PREPARED_BYTES
                    and sum(row['original_bytes'] for row in observations) == ORIGINAL_PAYLOAD_BYTES,
                    'D26 complete payload readback denominator differs')
    history.require(len(gz) == GZIP_FILES
                    and sum(row['prepared_bytes'] for row in gz) == GZIP_PREPARED_BYTES
                    and sum(row['original_bytes'] for row in gz) == GZIP_RAW_BYTES
                    and len(direct) == RAW_FILES
                    and sum(row['prepared_bytes'] for row in direct) == RAW_BYTES,
                    'D26 complete gzip/raw readback denominator differs')
    history.require(len(hashes) == ORIGINAL_FILES,'D26 full original view not verified')
    observation_bytes = json.dumps(observations,sort_keys=True,separators=(',',':')).encode()
    return hashes,digest(observation_bytes)


def archive_inputs(root,index,tree,selected):
    history.require(index.absolute() == root/INDEX_PATH,'D26 archive index outside fixed parent package')
    raw = history.local_file(root,INDEX_PATH).read_bytes()
    data = document(raw)
    history.require(data['source_commit'] == COMMIT and data['source_tree'] == TREE,
                    'D26 archive snapshot differs')
    scopes = sorted(name.rsplit('/',1)[0] for name in selected)
    history.require(data['scopes'] == scopes,'D26 archive must cover exactly eight complete leaf scopes')
    files = {row['path'] for row in data['files']}
    history.require(files == selected and len(data['files']) == ARCHIVED_FILES
                    and type(data['file_count']) is int and data['file_count'] == ARCHIVED_FILES
                    and type(data['total_bytes']) is int and data['total_bytes'] == ARCHIVED_BYTES,
                    'D26 selected archive denominator differs')
    manifests = [row['path'] for row in data['historical_manifests']]
    history.require(len(manifests) == 3 and set(manifests) == {PACKAGE+'/'+name for name in CONTROL_PINS},
                    'D26 original seal/control binding missing')
    preserved = [row['path'] for row in data['preserved_files']]
    history.require(len(preserved) == ORIGINAL_FILES-ARCHIVED_FILES
                    and set(preserved) == set(tree)-selected and data['retained_copies'] == [],
                    'D26 original retained byte roster differs')
    metadata,_ = history.validate(root,index)
    history.require(history.local_file(root,INDEX_PATH).read_bytes() == raw,'D26 archive index changed')
    return raw,metadata


def unchanged(root,wanted,hashes,indexed,index_raw):
    history.require(current_files(root) == wanted,'D26 namespace changed during verification')
    for name in sorted(wanted):
        with current_reader(root,name) as stream:
            sha = hashlib.sha256()
            while block := stream.read(CHUNK):
                sha.update(block)
        history.require(sha.hexdigest() == hashes[name],'D26 retained bytes changed during verification')
    paths = [PACKAGE]
    if index_raw is not None:
        history.require(history.local_file(root,INDEX_PATH).read_bytes() == index_raw,'D26 archive index changed')
        paths.append(INDEX_PATH)
    history.require(index_rows(root,paths) == indexed,'D26 staged bytes or tracking changed during verification')


def validate(root,index=None,original_view=False):
    root = root.resolve()
    history.require(original_view == (index is None),'D26 choose exactly one explicit verification mode')
    if not original_view:
        history.require(index.absolute() == root/INDEX_PATH,'D26 archive index outside fixed parent package')
        # Refuse missing, symlinked or special indexes before any historical work.
        history.local_file(root,INDEX_PATH)
    tree = fixed_tree(root)
    plan,rows,selected,controls = contract(root,tree)
    index_raw = None
    metadata = {}
    if not original_view:
        index_raw,metadata = archive_inputs(root,index,tree,selected)
    wanted,indexed = tracking(root,tree,selected,not original_view,index_raw)
    hashes,observed_sha = verify_view(root,tree,rows,set() if original_view else selected,controls)
    unchanged(root,wanted,hashes,indexed,index_raw)
    return dict(metadata,result='PASS',schema='trnm-d26-original-byte-view-verification-v1',
        mode='original-current-preflight' if original_view else 'archived-original-byte-view',
        source_commit=COMMIT,source_tree=TREE,
        original_package_files=ORIGINAL_FILES,original_package_bytes=ORIGINAL_BYTES,
        copy_plan_sha256=CONTROL_PINS['COPY_PLAN.json']['sha256'],
        payload_files_verified=PAYLOAD_FILES,prepared_bytes_verified=PREPARED_BYTES,
        original_payload_bytes_verified=ORIGINAL_PAYLOAD_BYTES,
        gzip_files_decoded=GZIP_FILES,gzip_compressed_bytes_verified=GZIP_PREPARED_BYTES,
        gzip_original_bytes_read=GZIP_RAW_BYTES,gzip_crc_and_trailers_verified=True,
        raw_files_verified=RAW_FILES,raw_bytes_verified=RAW_BYTES,
        controls_verified=2,copy_plan_itself_verified=True,
        payload_observation_sha256=observed_sha,
        sqlite_containers_verified=ARCHIVED_FILES,sqlite_compressed_bytes_verified=ARCHIVED_BYTES,
        sqlite_original_bytes_verified=SQLITE_RAW_BYTES,
        current_files_verified=len(wanted),current_index_bytes_and_modes_verified=True,
        retained_bytes_unchanged=True,original_status='HOLD',original_native_gate_validated=False,
        historical_observations_only=True,sqlite_opened=False,database_recovery_performed=False,
        historical_scripts_executed=False,current_native_tests_executed=0,
        current_work_or_service_qualification=False,original_artifact_zip_reverified=False,
        physical_restore_or_extraction_performed=False,evidence_files_written=0,
        network_fetches=0,production_activation=False,whole_chain_native=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--manifest',type=Path)
    group.add_argument('--original-view',action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.root,args.manifest,args.original_view),sort_keys=True))
        return 0
    except (history.Invalid,KeyError,TypeError,OSError,UnicodeError,ValueError,EOFError,zlib.error) as error:
        print('D26 archive check failed: '+str(error),file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
