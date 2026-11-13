#!/usr/bin/env python3
"""Prepare a source-only corpus union for the selected first-parent + df927 merge.

No checkout source file is replaced, staged, committed, fetched, or executed as a test.
prepare requires the actual unresolved-merge context to have all content conflicts
resolved and staged, with the unchanged first-parent corpus selected temporarily. verify
requires the later real two-parent commit and exact prepared corpus bytes.
"""
from __future__ import annotations

import argparse
import copy
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

BASE = 'da1374a200022bc14dc2bd325cc9ba29dbcd24ab'
BASE_TREE = '00479a98dabc6b1fd91a0ceef82ffbdbffb78067'
C1 = '11c9562252d3cf56b423c7756569be0c669d9606'
C1_TREE = '94e1b4f1718dec1b88bccd7e1996ba83ca29ff8a'
C2 = '8d8c0e64e7a301fc111a6720721a14816639e5aa'
C2_TREE = '7c003a3d183ad33ff4f3349cbcce61564f73a2ba'
UPSTREAM_MIDDLE = 'fcc3c86631c4fb5a1be59ba6da49d9d98d560761'
UPSTREAM_MIDDLE_TREE = 'dcbeaec3ae9cf300c10223f12ae9890e05285b22'
THEIRS = 'df927b6ffaecff293b9e9428e3ba516f47cd101a'
THEIRS_TREE = 'a883a05b590fb8b0113b3715f4294eee7a00275b'
CORPUS = 'config/pon/pq-cross-branch-corpus-v1.json'
CHECKER = 'scripts/ci/check_pq_research_integration.py'
PLAN = 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
INVENTORY = 'trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs'
C3_PREFIX = 'evidence/pon-followthrough-20261110-685a/'
C4_PREFIX = 'evidence/pon-followthrough-20261110-685a/final-integration/'
C3_NEW_EVIDENCE_PREFIXES = ('evidence/pon-followthrough-20261110-685a/',
 'evidence/pon-w1-lifetime-current-20261110-685a/',
 'evidence/pon-w1-qrom-current-20261110-685a/')
BASE_CORPUS_BLOB = 'e8f863a9988aed86797f923864631dac60b5a0b0'
BASE_CORPUS_SHA256 = '8b04622f2dd117ec137dc5995ba4ee00730ae41d6c0ba75b43d0aa2d34abd552'
THEIRS_CORPUS_BLOB = '9781fc7225c50b3a8710ce10a1adba332c2617df'
THEIRS_CORPUS_SHA256 = 'ec51f57a21432c05a296ac64df6483dd96de6a1682d284cf5055eded3b7d4c2d'
CHECKER_BLOB = '21094a39eb15525663925ac2d258deae40502990'
NEW_REQUIRED = ('config/pon/w1-qrom-current-required-tests-v1.json',
 'docs/research/PON_FRESH_REJECTION_COST_V1.md',
 'evidence/pon-w1-lifetime-current-20261110-685a/README.md',
 'evidence/pon-w1-lifetime-current-20261110-685a/project-input.json',
 'evidence/pon-w1-lifetime-current-20261110-685a/project-report.json',
 'scripts/ci/prepare_artifact_upload.py',
 'scripts/ci/test_fresh_rejection_report.py',
 'scripts/ci/test_prepare_artifact_upload.py',
 'scripts/ci/test_w1_qrom_current_ci.py',
 'scripts/ci/w1_native_controls.py',
 'scripts/ci/w1_qrom_current_ci.py',
 'scripts/pon_fresh_rejection_report.py',
 'trillionnium/crates/trnm-crypto-primitives/examples/pon_fresh_rejection_cost.rs',
 'trillionnium/crates/trnm-pon-node/src/store/confirmation_chainwork_tests.rs',
 'evidence/pon-w1-qrom-current-20261110-685a/README.md',
 'evidence/pon-w1-qrom-current-20261110-685a/source-binding.json',
 'evidence/pon-w1-qrom-current-20261110-685a/current-report.json',
 'evidence/pon-w1-qrom-current-20261110-685a/prior-v2-on-c2.command.json',
 'evidence/pon-w1-qrom-current-20261110-685a/prior-v2-on-c2.stdout.log',
 'evidence/pon-w1-qrom-current-20261110-685a/prior-v2-on-c2.stderr.log',
 'evidence/pon-w1-qrom-current-20261110-685a/historical/current-v2.json',
 'evidence/pon-w1-qrom-current-20261110-685a/historical/current-auditor.py',
 'evidence/pon-w1-qrom-current-20261110-685a/historical/current-tests.py',
 'evidence/pon-w1-qrom-current-20261110-685a/historical/current-mapping.md.txt')
THEIRS_NON_EVIDENCE = ('.github/workflows/pon-w1-work-security.yml',
 'config/pon/pq-cross-branch-corpus-v1.json',
 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md',
 'docs/protocol/pon-nakamoto-v1/details/NATIVE_EVALUATION_QUORUM_V2.md',
 'docs/research/PON_W1_LIFECYCLE_COST_V4.md',
 'scripts/ci/test_w1_factorial_native_gate.py',
 'scripts/ci/test_w1_lifecycle_cost_v4.py',
 'scripts/pon_w1_lifecycle_cost_v4.py',
 'trillionnium/crates/trnm-mvcc-fee/src/public_evaluation.rs',
 'trillionnium/crates/trnm-mvcc-fee/src/public_evaluation/quorum_v2.rs',
 'trillionnium/crates/trnm-mvcc-fee/tests/evaluation_quorum_v2.rs',
 'trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs',
 'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs')
THEIRS_PIN_DELTA = {'.github/workflows/pon-w1-work-security.yml': ('c9ab642e0f23194b32a7b283107d215deb534c7a',
                                                '384f1cbe38be7b688e49f4a55c1246e9d3ec4005'),
 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md': ('9e95a0870c3ab8af6871a62d8ad8bc4edc189ab8',
                                                                    'a5ca681129a34363def3dcacf013ec05672e3b58'),
 'docs/research/PON_W1_LIFECYCLE_COST_V4.md': ('d3034555c130a4263e99bea2c7f63972f070955b',
                                               'a71b6e3ce2ff056c3aa4676f563feb1407e5ad1d'),
 'scripts/ci/test_w1_factorial_native_gate.py': ('6c944696db9dc8db8668981958c7117d910aad36',
                                                 'f48a131c4167222a3e0f020ad8822a46e27840eb'),
 'scripts/ci/test_w1_lifecycle_cost_v4.py': ('932e123285a68592583d11eed85f04c958a12e60',
                                             '424f99c2aaa52b589b41ea9f97df241b7c8ed757'),
 'scripts/pon_w1_lifecycle_cost_v4.py': ('06d92b853c8a7b0766b1152104c834109243d308',
                                         '6e9d17012d01f6610f0edd422b86297d4f9f8189'),
 'trillionnium/crates/trnm-mvcc-fee/src/public_evaluation.rs': ('08cef9af222b5f8a72d030acdc56e8de5ce867a1',
                                                                '662ec394bffc84f568bca0f117456aa13f03e8b5'),
 'trillionnium/crates/trnm-mvcc-fee/src/public_evaluation/quorum_v2.rs': ('8843158bec9b6c1c9872a357d400ac43cf52a552',
                                                                          'e0c9345b649d138bc239b9c698c27ce124bd1572'),
 'trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs': ('1073fbf92c159b82f0822f13281018a46198e1a8',
                                                                                        '4fe60f533f051cd1a68c4358e96d210d8f7d32c0'),
 'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs': ('53a987e18949fc57edc3e39318c32f2f7df93c33',
                                                                'af04938d292dd28bb52d75a22fed2e45dff8e78c')}
CI_RESOLUTIONS = {'.github/workflows/pon-recent-batch-acceptance.yml': {'after_blob': '89171c7274109594c3b5d82df8664d66eda710f8',
                                                       'after_bytes': 36087,
                                                       'after_sha256': '598f24ce01ecfffc3e2e8225c3bc6456dd2ec94702597b6da56e0d34472dc3e4',
                                                       'before_blob': '4f863aa86694735aceac19542c2cc825010e36f8'},
 '.github/workflows/pon-w1-work-security.yml': {'after_blob': '08d044a5f4c69ac6022446e7fd03965f0d35da90',
                                                'after_bytes': 39763,
                                                'after_sha256': '010ed1e5466c7f226724da591a51d1f8c2feab3898bfa26cdae9c8038a04a616',
                                                'before_blob': '08d044a5f4c69ac6022446e7fd03965f0d35da90'},
 'scripts/ci/test_w1_factorial_native_gate.py': {'after_blob': '02c78134f2bacd9ddd6df68dfdd878f02f5a8e1c',
                                                 'after_bytes': 18452,
                                                 'after_sha256': 'ffb64f1941eb929842d7a5ec9df02c5264efec3433fcd315b5d7590cbba53340',
                                                 'before_blob': '8e95f890e9e40415aa5ada408ee9dedae964abdd'},
 'scripts/ci/w1_native_controls.py': {'after_blob': '63fb1d15fbc9fa52f880fca3c66dd300b907cb17',
                                      'after_bytes': 19669,
                                      'after_sha256': 'e6f5a02dcf735fb0b9fed1543ce89c85ee3ecb6e60911f2a1f2e38982e997662',
                                      'before_blob': 'afe6bd671352ab92518ebd94ee4c6b2a832f2a5f'}}
C3_ALLOWED_SOURCE_PATHS = ('.github/workflows/pon-next-architecture-security.yml',
 '.github/workflows/pon-w1-qrom-closure.yml',
 '.github/workflows/pon-w1-qrom-implementation.yml',
 '.github/workflows/pon-w1-work-security.yml',
 'config/pon/pq-authority-effects-v1.json',
 'config/pon/pq-cross-branch-corpus-v1.json',
 'config/pon/pq128-lifetime-budget-v1.json',
 'config/pon/pq128-source-lock-v1.json',
 'config/pon/w1-qrom-current-required-tests-v1.json',
 'config/pon/w1-qrom-implementation-current-v2.json',
 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md',
 'docs/security/PQ128_LIFETIME_BUDGET_V1.md',
 'docs/security/PQ_AUTHORITY_EFFECT_REGISTER_V1.md',
 'docs/security/W1_QROM_CURRENT_SOURCE_MAPPING_V2.md',
 'scripts/ci/check_ci_contract.py',
 'scripts/ci/check_pq_research_integration.py',
 'scripts/ci/ci_job.sh',
 'scripts/ci/pq_authority_effect_register.py',
 'scripts/ci/prepare_artifact_upload.py',
 'scripts/ci/test_cell_storage_convergence_ci.py',
 'scripts/ci/test_ci_contract.py',
 'scripts/ci/test_pq_authority_effect_register.py',
 'scripts/ci/test_prepare_artifact_upload.py',
 'scripts/ci/test_w1_factorial_native_gate.py',
 'scripts/ci/test_w1_lifetime_ledger.py',
 'scripts/ci/test_w1_qrom_current_ci.py',
 'scripts/ci/test_w1_qrom_current_implementation_audit.py',
 'scripts/ci/w1_native_controls.py',
 'scripts/ci/w1_qrom_current_ci.py',
 'scripts/w1_lifetime_ledger.py',
 'scripts/w1_qrom_current_implementation_audit.py',
 'trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs')
REVIEW_INPUT_SHA256 = {'ci_union_manifest': '0553ef1bd07d50c9c6a4d5974c0a6174227cd31724fadf2454b251f3c38a58bf',
 'ci_union_patch': '7c7580e37c28e4656ae4f1452274d3d1e206ce27ce51879522873c82e650f06c',
 'former_corpus_helper': '1e80cad195fb03a18f57387575b4b89e4ef7eb4be697c0887263ee682fb9a6d9',
 'inline_store_pin_manifest': '65b910e86a3ef1d6e6fa0dd6d4c38bd11de2a12363e145b819d4abd70c229810',
 'inline_store_pin_patch': '1015327d23d479c3536594c7fe3be097ed10012991252f8e70c68c8457d70e49',
 'upstream_review': '0a940a616084081dbce713521bdb4f2cb016620d4786b6abe0a619e0b753a51c'}

REGULAR_MODES = ("100644", "100755")
HISTORICAL_PREFIXES = ("evidence/", "qualification/")
FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
ENV = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", PYTHONDONTWRITEBYTECODE="1")
MAX_METADATA = 16 * 1024 * 1024

class Refusal(ValueError):
    pass

def require(condition, reason):
    if not condition:
        raise Refusal(reason)

def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(Refusal("nonfinite JSON")))

def oid(value):
    require(type(value) is str and re.fullmatch("[0-9a-f]{40}", value), "full SHA-1 identity required")
    return value

def safe_path(value):
    require(type(value) is str and value and not value.startswith("/")
            and not any(c in value for c in "\\\0\r\n\t")
            and all(p not in ("", ".", "..") for p in value.split("/")), "unsafe repository path")
    return value

def file_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)

def actual_blob(root, relative, expected):
    """Hash the real bytes with Git through a checked nonblocking descriptor."""
    safe_path(relative)
    require(expected["mode"] in REGULAR_MODES and expected["type"] == "blob", "nonregular Git input: " + relative)
    root = Path(root).absolute()
    require(root.anchor == "/" and ".." not in root.parts, "unsafe checkout root")
    fds, held = [], []
    process = None
    try:
        parent = None
        components = [root.anchor, *root.parts[1:], *relative.split("/")[:-1]]
        for component in components:
            fd = os.open(component, FLAGS | os.O_DIRECTORY, dir_fd=parent)
            fds.append(fd)
            metadata = os.fstat(fd)
            held.append((parent, component, fd, metadata.st_dev, metadata.st_ino, metadata.st_mode))
            parent = fd
        leaf = relative.split("/")[-1]
        fd = os.open(leaf, FLAGS, dir_fd=parent)
        fds.append(fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size == expected["bytes"], "nonregular or wrong-size current input: " + relative)
        require(bool(before.st_mode & 0o111) == (expected["mode"] == "100755"), "Git executable mode differs: " + relative)
        process = subprocess.Popen(["git", "-C", str(root), "hash-object", "--stdin"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            require(bool(chunk), "truncated current input: " + relative)
            process.stdin.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        require(not os.read(fd, 1), "growing current input: " + relative)
        process.stdin.close()
        process.stdin = None
        stdout, stderr = process.communicate(timeout=30)
        require(process.returncode == 0, "git hash-object refused: " + relative)
        require(stdout.decode().strip() == expected["blob"], "actual Git blob differs from staged tree: " + relative)
        require(file_identity(before) == file_identity(os.fstat(fd))
                == file_identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)), "changed current input: " + relative)
        for parent_fd, component, directory_fd, dev, ino, mode in reversed(held):
            for metadata in (os.fstat(directory_fd), os.stat(component, dir_fd=parent_fd, follow_symlinks=False)):
                require((metadata.st_dev, metadata.st_ino, metadata.st_mode) == (dev, ino, mode), "changed current ancestor: " + relative)
        return {"bytes": before.st_size, "sha256": digest.hexdigest(), "git_blob": expected["blob"]}
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()
        for fd in reversed(fds):
            os.close(fd)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def object_id(kind, raw):
    return hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw,
                        usedforsecurity=False).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode()


def git(root, *args, data=None):
    result = subprocess.run(["git", "--no-replace-objects", "-C", str(root), *args],
                            input=data, capture_output=True, env=ENV, timeout=90)
    require(result.returncode == 0, "git command refused: " + " ".join(args)
            + ": " + result.stderr.decode(errors="replace")[-2000:].strip())
    return result.stdout


def gtext(root, *args):
    return git(root, *args).decode().strip()


def read_regular(path, maximum=MAX_METADATA):
    """Read a stable bounded regular file without following any path component."""
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "absolute safe path required")
    held, descriptors, parent = [], [], None
    try:
        for component in ["/", *path.parts[1:-1]]:
            fd = os.open(component, FLAGS | os.O_DIRECTORY, dir_fd=parent)
            descriptors.append(fd)
            metadata = os.fstat(fd)
            held.append((parent, component, fd, metadata.st_dev, metadata.st_ino, metadata.st_mode))
            parent = fd
        fd = os.open(path.name, FLAGS, dir_fd=parent)
        descriptors.append(fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum,
                "nonregular or oversized file: " + str(path))
        chunks, size = [], 0
        while size <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        require(size == before.st_size and size <= maximum
                and file_identity(before) == file_identity(os.fstat(fd))
                == file_identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                "file changed during read: " + str(path))
        for parent_fd, name, directory_fd, dev, ino, mode in reversed(held):
            for metadata in (os.fstat(directory_fd), os.stat(name, dir_fd=parent_fd, follow_symlinks=False)):
                require((metadata.st_dev, metadata.st_ino, metadata.st_mode) == (dev, ino, mode),
                        "file ancestor changed: " + str(path))
        return b"".join(chunks)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def checked_directory(path):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "absolute normalized directory required")
    descriptors, parent = [], None
    try:
        for part in ["/", *path.parts[1:]]:
            parent = os.open(part, FLAGS | os.O_DIRECTORY, dir_fd=parent)
            descriptors.append(parent)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)
    return path


def write_new(path, raw):
    require(path.is_absolute() and ".." not in path.parts, "absolute output path required")
    parent = os.open("/", FLAGS | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, FLAGS | os.O_DIRECTORY, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o644, dir_fd=parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(parent)


def tree(root, identity):
    result = {}
    for row in git(root, "ls-tree", "-r", "-l", "-z", "--full-tree", oid(identity)).split(b"\0"):
        if not row:
            continue
        metadata, raw_path = row.split(b"\t", 1)
        mode, kind, blob, size = metadata.decode().split()
        path = safe_path(raw_path.decode())
        require(path not in result, "duplicate tree path")
        result[path] = {"mode": mode, "type": kind, "blob": oid(blob),
                        "bytes": None if size == "-" else int(size)}
    return result


def regular_entry(entries, path):
    require(path in entries and entries[path]["type"] == "blob"
            and entries[path]["mode"] in REGULAR_MODES,
            "required regular source absent: " + path)
    return entries[path]


def selected_commit(root, identity, expected_tree=None, expected_parents=None):
    raw = git(root, "cat-file", "commit", oid(identity))
    require(object_id("commit", raw) == identity, "raw commit does not hash to selected identity")
    header = raw.split(b"\n\n", 1)[0].decode()
    trees = [line[5:] for line in header.splitlines() if line.startswith("tree ")]
    parents = [line[7:] for line in header.splitlines() if line.startswith("parent ")]
    require(len(trees) == 1, "invalid selected commit tree")
    actual_tree = oid(trees[0])
    for parent in parents:
        oid(parent)
    require(expected_tree is None or actual_tree == expected_tree, "selected commit tree differs: " + identity)
    require(expected_parents is None or parents == expected_parents, "selected raw commit parents differ: " + identity)
    visible = gtext(root, "rev-list", "--parents", "-n", "1", identity).split()
    # BASE may be an explicit shallow boundary. Every selected newer edge must
    # remain visible and exact; no assertion about unavailable global history.
    require(visible[0] == identity and (expected_parents is None or visible[1:] == parents),
            "selected edge is shallow/hidden or differs from raw commit: " + identity)
    return {"commit": identity, "tree": actual_tree, "parents": parents,
            "raw_commit_sha256": sha(raw)}


def git_blob(root, commit, entries, path):
    entry = regular_entry(entries, path)
    require(entry["bytes"] <= MAX_METADATA, "oversized selected metadata: " + path)
    raw = git(root, "show", commit + ":" + path)
    require(len(raw) == entry["bytes"] and object_id("blob", raw) == entry["blob"],
            "selected Git blob differs: " + path)
    return raw


def changed_paths(before, after):
    return {path for path in before.keys() | after.keys() if before.get(path) != after.get(path)}


def preserved(before, after, label):
    require(before.keys() <= after.keys(), label + " deletes a tracked path")
    for path, entry in before.items():
        if path.startswith(HISTORICAL_PREFIXES):
            require(after[path] == entry, label + " rewrites prior evidence: " + path)


def validate_parent_sources(root, c3, ours):
    child_record = selected_commit(root, oid(c3), expected_parents=[C2])
    own_record = dict(child_record) if ours == c3 else selected_commit(root, oid(ours), expected_parents=[c3])
    records = [selected_commit(root, BASE, BASE_TREE),
               selected_commit(root, C1, C1_TREE, [BASE]),
               selected_commit(root, C2, C2_TREE, [C1]), child_record, own_record,
               selected_commit(root, UPSTREAM_MIDDLE, UPSTREAM_MIDDLE_TREE, [BASE]),
               selected_commit(root, THEIRS, THEIRS_TREE, [UPSTREAM_MIDDLE])]
    for record, role in zip(records, ("base", "checkpoint-c1", "checkpoint-c2", "binding-child-c3",
                                     "ours-merge-parent", "upstream-middle", "theirs-merge-parent")):
        record["selected_role"] = role
    require(gtext(root, "merge-base", "--all", ours, THEIRS) == BASE, "unexpected selected merge base")
    base, c2, child, own, their = (tree(root, identity) for identity in
                                 (BASE_TREE, C2_TREE, records[3]["tree"], records[4]["tree"], THEIRS_TREE))
    preserved(base, own, "ours selected parent")
    preserved(base, their, "theirs df927")
    require(child.keys() <= own.keys() and all(own[path] == entry for path, entry in child.items()),
            "selected first parent rewrites a C3 blob or mode")
    added_after_c3 = own.keys() - child.keys()
    require((ours == c3 and not added_after_c3)
            or (ours != c3 and added_after_c3 and all(path.startswith(C4_PREFIX)
                and own[path]["type"] == "blob" and own[path]["mode"] == "100644" for path in added_after_c3)),
            "first parent is neither C3 itself nor its selected evidence-only child")
    require(c2.keys() <= child.keys(), "C3 deletes a C2 path")
    for path in changed_paths(c2, child):
        if path.startswith(HISTORICAL_PREFIXES):
            require(path not in c2 and path.startswith(C3_NEW_EVIDENCE_PREFIXES),
                    "unreviewed C3 evidence mutation: " + path)
        else:
            require(path in C3_ALLOWED_SOURCE_PATHS, "unreviewed C3 source mutation: " + path)
    require({path for path in changed_paths(base, their) if not path.startswith(HISTORICAL_PREFIXES)}
            == set(THEIRS_NON_EVIDENCE), "df927 non-evidence change roster differs")
    require(regular_entry(own, CHECKER)["blob"] == CHECKER_BLOB,
            "C3 mandatory required-path guard differs")
    return records, base, c2, child, own, their


def validate_corpora(base_raw, own_raw, their_raw, base, own, their):
    require(sha(base_raw) == BASE_CORPUS_SHA256 and object_id("blob", base_raw) == BASE_CORPUS_BLOB,
            "baseline corpus raw identity differs")
    require(sha(their_raw) == THEIRS_CORPUS_SHA256 and object_id("blob", their_raw) == THEIRS_CORPUS_BLOB,
            "upstream corpus raw identity differs")
    original, ours, theirs = map(strict_json, (base_raw, own_raw, their_raw))
    require(original.get("schema") == "trnm-pq-cross-branch-corpus-v1"
            and original.get("status") == "research-only-hold-no-go", "historical corpus header differs")
    require(len(original["pinned_blobs"]) == 1079 and len(original["required_paths"]) == 987
            and len(set(original["required_paths"])) == 987, "baseline denominator differs")
    header = {key: value for key, value in original.items() if key not in ("pinned_blobs", "required_paths")}
    for name, corpus in (("ours", ours), ("theirs", theirs)):
        require(set(corpus) == set(original)
                and encoded({key: corpus[key] for key in header}) == encoded(header),
                name + " changes a historical field, status, evidence assertion or source composition")
        require(type(corpus["pinned_blobs"]) is dict and type(corpus["required_paths"]) is list,
                name + " has invalid source collection types")
        require(len(set(corpus["required_paths"])) == len(corpus["required_paths"])
                and set(corpus["required_paths"]) <= corpus["pinned_blobs"].keys(),
                name + " has duplicate or unpinned required paths")
    require(theirs["required_paths"] == original["required_paths"]
            and theirs["pinned_blobs"].keys() == original["pinned_blobs"].keys(),
            "upstream changed the old required list or pin key set")
    their_delta = {p: (b, theirs["pinned_blobs"][p]) for p, b in original["pinned_blobs"].items()
                   if b != theirs["pinned_blobs"][p]}
    require(their_delta == THEIRS_PIN_DELTA and len(their_delta) == 10,
            "upstream delta is not the ten reviewed pin replacements")
    require(ours["required_paths"] == original["required_paths"] + list(NEW_REQUIRED)
            and set(ours["pinned_blobs"]) == set(original["pinned_blobs"]) | set(NEW_REQUIRED)
            and len(ours["pinned_blobs"]) == 1103 and len(ours["required_paths"]) == 1011,
            "ours lost/reordered an old path or changed the exact 24 additions")
    for name, corpus, entries in (("base", original, base), ("ours", ours, own), ("theirs", theirs, their)):
        for path, blob in corpus["pinned_blobs"].items():
            safe_path(path)
            require(regular_entry(entries, path)["blob"] == oid(blob), name + " pin differs from its actual Git tree: " + path)
    ours_delta = [{"path": path, "before": previous, "after": ours["pinned_blobs"][path]}
                  for path, previous in sorted(original["pinned_blobs"].items())
                  if previous != ours["pinned_blobs"][path]]
    return original, ours, theirs, ours_delta, their_delta


def plan_union(base_raw, own_raw, their_raw, candidate_raw):
    require(own_raw.startswith(base_raw) and their_raw.startswith(base_raw),
            "one development plan is not an exact append of the selected base")
    ours_tail, theirs_tail = own_raw[len(base_raw):], their_raw[len(base_raw):]
    require(ours_tail and theirs_tail and ours_tail != theirs_tail,
            "development plan lacks two distinct retained appendices")
    allowed = {base_raw + ours_tail + theirs_tail: "ours-then-theirs",
               base_raw + theirs_tail + ours_tail: "theirs-then-ours"}
    require(candidate_raw in allowed, "merged plan must retain both exact EOF appendices once")
    return {"order": allowed[candidate_raw], "base_sha256": sha(base_raw),
            "ours_append_bytes": len(ours_tail), "ours_append_sha256": sha(ours_tail),
            "theirs_append_bytes": len(theirs_tail), "theirs_append_sha256": sha(theirs_tail)}


def merged_scope(base, own, their, final):
    require(final.keys() == own.keys() | their.keys(), "merged staged tree adds or deletes an unreviewed path")
    resolutions = set(CI_RESOLUTIONS) | {CORPUS, PLAN, INVENTORY}
    for path in sorted(final):
        b, o, t, f = base.get(path), own.get(path), their.get(path), final[path]
        if path.startswith(HISTORICAL_PREFIXES):
            require(o is None or f == o, "merged tree rewrites ours evidence: " + path)
            require(t is None or f == t, "merged tree rewrites theirs evidence: " + path)
        if path == CORPUS:
            require(f == o, "select unchanged first-parent corpus before preparing the union")
        elif path in CI_RESOLUTIONS:
            rule = CI_RESOLUTIONS[path]
            require(o is not None and o["blob"] == rule["before_blob"]
                    and f["mode"] == o["mode"] and f["type"] == "blob"
                    and f["blob"] == rule["after_blob"] and f["bytes"] == rule["after_bytes"],
                    "reviewed CI union target differs: " + path)
        elif path in (PLAN, INVENTORY):
            require(o is not None and t is not None and f["type"] == "blob" and f["mode"] == o["mode"] == t["mode"],
                    "nonregular plan/inventory resolution")
        else:
            expected = o if o == t or t == b else t if o == b else None
            require(expected is not None, "unreviewed overlapping source conflict: " + path)
            require(f == expected, "staged path differs from its exact three-way source: " + path)
    require(regular_entry(final, CHECKER)["blob"] == CHECKER_BLOB,
            "merged required-path guard changed")
    return sorted(path for path in resolutions if final.get(path) != own.get(path))


def validate_object_closure(root, entries_groups):
    sizes = {}
    for group, paths in entries_groups:
        for path in paths:
            item = regular_entry(group, path)
            previous = sizes.setdefault(item["blob"], item["bytes"])
            require(previous == item["bytes"], "inconsistent object size")
    ordered = sorted(sizes)
    raw = git(root, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)",
              data=("\n".join(ordered) + "\n").encode())
    rows = raw.decode().splitlines()
    require(len(rows) == len(ordered), "selected blob closure incomplete")
    for blob, row in zip(ordered, rows):
        require(row == blob + " blob " + str(sizes[blob]), "selected Git blob missing or wrong type/size: " + blob)
    return len(ordered)


def root_guard(root):
    checked_directory(root)
    require(not any(os.environ.get(name) for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_COUNT", "GIT_SHALLOW_FILE")),
            "external Git override refused")
    require(gtext(root, "rev-parse", "--show-toplevel") == str(root), "actual complete worktree root required")
    sparse = subprocess.run(["git", "-C", str(root), "config", "--bool", "core.sparseCheckout"],
                            capture_output=True, env=ENV, timeout=30)
    require(sparse.returncode in (0, 1) and sparse.stdout.strip() in (b"", b"false"), "sparse checkout refused")
    require(all(not row or row.startswith(b"H ") for row in git(root, "ls-files", "-v", "-z").split(b"\0")),
            "nonordinary/hidden index entry refused")
    require(not git(root, "ls-files", "-u", "-z"), "unmerged index entries remain")
    require(not git(root, "diff", "--name-only", "-z"), "unstaged tracked inputs remain")
    require(not git(root, "ls-files", "--others", "--exclude-standard", "-z"), "untracked nonignored inputs remain")


def merge_head_path(root):
    value = Path(gtext(root, "rev-parse", "--git-path", "MERGE_HEAD"))
    return value if value.is_absolute() else root / value


def prepare_guard(root, ours, staged_tree):
    root_guard(root)
    require(gtext(root, "rev-parse", "HEAD") == ours, "HEAD is not the selected first parent")
    require(read_regular(merge_head_path(root), 4096) == (THEIRS + "\n").encode(),
            "actual pending merge does not have exactly the selected df927 second parent")
    require(gtext(root, "write-tree") == oid(staged_tree), "actual staged candidate tree changed")


def refresh_corpus(ours, final):
    updated = copy.deepcopy(ours)
    changes = []
    for path, previous in ours["pinned_blobs"].items():
        current = regular_entry(final, path)["blob"]
        if current != previous:
            updated["pinned_blobs"][path] = current
            changes.append({"path": path, "before": previous, "after": current})
    require(all(updated[key] == value for key, value in ours.items() if key != "pinned_blobs")
            and updated["pinned_blobs"].keys() == ours["pinned_blobs"].keys(),
            "union changed anything beyond existing pin values")
    return updated, changes


def external_output(root, output):
    require(output.is_absolute() and ".." not in output.parts
            and not output.is_relative_to(root) and not root.is_relative_to(output),
            "output must be outside and not contain the measured checkout")
    checked_directory(output.parent)
    require(not output.exists() and not output.is_symlink(), "output already exists; preserve original observations")


def prepare(args):
    root, output = args.root, args.output
    oid(args.ours)
    oid(args.binding_child)
    require(args.theirs == THEIRS, "this reviewed helper accepts only the selected df927 cohort")
    external_output(root, output)
    prepare_guard(root, args.ours, args.candidate_tree)
    records, base, c2, child, own, their = validate_parent_sources(root, args.binding_child, args.ours)
    final = tree(root, args.candidate_tree)
    base_raw = git_blob(root, BASE, base, CORPUS)
    own_raw = git_blob(root, args.ours, own, CORPUS)
    their_raw = git_blob(root, THEIRS, their, CORPUS)
    original, ours, theirs, own_delta, their_delta = validate_corpora(base_raw, own_raw, their_raw, base, own, their)
    resolutions = merged_scope(base, own, their, final)
    plan_observation = plan_union(git_blob(root, BASE, base, PLAN), git_blob(root, args.ours, own, PLAN),
                                 git_blob(root, THEIRS, their, PLAN), git_blob(root, args.candidate_tree, final, PLAN))
    closure_count = validate_object_closure(root, ((base, original["pinned_blobs"]), (own, ours["pinned_blobs"]),
                                                  (their, theirs["pinned_blobs"]), (final, ours["pinned_blobs"])))
    updated, changed_pins = refresh_corpus(ours, final)
    changed = changed_paths(own, final)
    actual = {}
    for path in sorted(set(ours["pinned_blobs"]) | changed | {CORPUS, PLAN, INVENTORY}):
        actual[path] = actual_blob(root, path, regular_entry(final, path))
    for path, rule in CI_RESOLUTIONS.items():
        require(actual[path]["sha256"] == rule["after_sha256"], "CI union actual byte SHA differs: " + path)
    prepare_guard(root, args.ours, args.candidate_tree)
    candidate_raw = encoded(updated)
    review = {"schema": "pon-upstream-corpus-two-parent-review-v1", "selected_commits": records,
              "candidate_index_tree_before_corpus_refresh": args.candidate_tree,
              "ours_existing_pin_delta": own_delta,
              "ours_added_required_paths": list(NEW_REQUIRED),
              "theirs_existing_pin_delta": [{"path": path, "before": a, "after": b}
                                             for path, (a, b) in sorted(their_delta.items())],
              "actual_merged_pin_delta_from_ours": changed_pins,
              "explicit_resolution_paths_changed_from_ours": resolutions,
              "plan_retention": plan_observation,
              "changes_from_ours": [{"path": path, "ours": own.get(path), "theirs": their.get(path),
                                     "candidate": final.get(path)} for path in sorted(changed)],
              "selected_blob_objects_available": closure_count, "actual_verified_members": actual,
              "git_history_shallow": gtext(root, "rev-parse", "--is-shallow-repository") == "true",
              "complete_global_history_claimed": False,
              "source_checkpoint_bindings_rewritten": False, "historical_evidence_rewritten": False,
              "distributed_inventory_check_executed": False,
              "distributed_inventory_check_required": ["python3", "-B", "scripts/refresh_distributed_source_inventory.py", "--check"],
              "native_executed": False, "project_tests_executed": False, "merge_commit_created": False,
              "native_full_suite_passed": False, "merge_acceptance_claimed": False,
              "security_status": "HOLD", "production_activation": False, "review_input_sha256": REVIEW_INPUT_SHA256}
    patch = "".join(difflib.unified_diff(own_raw.decode().splitlines(keepends=True),
        candidate_raw.decode().splitlines(keepends=True), fromfile="a/" + CORPUS, tofile="b/" + CORPUS)).encode()
    require(patch, "the selected two-parent source union unexpectedly changes no corpus pins")
    files = {"base-corpus.json": base_raw, "ours-parent-corpus.json": own_raw,
             "theirs-df927-corpus.json": their_raw, "merged-corpus.json": candidate_raw,
             "corpus-update.patch": patch, "review.json": encoded(review)}
    receipt = {"schema": "pon-upstream-corpus-preparation-v1", "scope": "source binding preparation only",
               "ours_commit": args.ours, "ours_is_binding_child": args.ours == args.binding_child, "binding_child_c3": args.binding_child, "theirs_df927": THEIRS,
               "expected_merge_parent_order": [args.ours, THEIRS], "selected_base": BASE,
               "candidate_index_tree_before_corpus_refresh": args.candidate_tree,
               "corpus_path": CORPUS, "required_paths": 1011, "pinned_blobs": 1103,
               "retained_original_required_paths": 987, "retained_original_pin_paths": 1079,
               "retained_ours_additions": 24, "theirs_replaced_pins": 10,
               "historical_non_pin_fields_preserved": True,
               "helper_sha256": sha(read_regular(Path(__file__).absolute())),
               "files": {name: {"bytes": len(raw), "sha256": sha(raw), "git_blob": object_id("blob", raw)}
                         for name, raw in files.items()},
               "native_executed": False, "project_tests_executed": False, "merge_commit_created": False,
               "merge_acceptance_claimed": False, "native_full_suite_passed": False,
               "production_activation": False, "security_status": "HOLD"}
    files["receipt.json"] = encoded(receipt)
    output.mkdir(mode=0o755)
    for name, raw in files.items():
        write_new(output / name, raw)
    print(json.dumps({"status": "PREPARED_HOLD_NO_ACCEPTANCE", "output": str(output),
                      "receipt_sha256": sha(files["receipt.json"]), "required_paths": 1011,
                      "pinned_blobs": 1103, "native_executed": False, "merge_commit_created": False}))


def verify(args):
    root, output = args.root, args.output
    external_output(root, output)
    root_guard(root)
    checked_directory(args.prepared)
    require(not output.is_relative_to(args.prepared) and not args.prepared.is_relative_to(output),
            "verification output overlaps original preparation records")
    require(not args.prepared.is_relative_to(root) and not root.is_relative_to(args.prepared),
            "preparation records must remain outside the checkout")
    receipt_raw = read_regular(args.prepared / "receipt.json")
    require(sha(receipt_raw) == args.receipt_sha256, "prepared receipt hash differs")
    receipt = strict_json(receipt_raw)
    require(receipt.get("schema") == "pon-upstream-corpus-preparation-v1"
            and receipt.get("helper_sha256") == sha(read_regular(Path(__file__).absolute()))
            and receipt.get("theirs_df927") == THEIRS and receipt.get("security_status") == "HOLD"
            and receipt.get("required_paths") == 1011 and receipt.get("pinned_blobs") == 1103,
            "prepared source contract differs")
    require(set(receipt["files"]) == {"base-corpus.json", "ours-parent-corpus.json", "theirs-df927-corpus.json",
                                     "merged-corpus.json", "corpus-update.patch", "review.json"}, "prepared file roster differs")
    files = {}
    for name, expected in receipt["files"].items():
        raw = read_regular(args.prepared / name)
        require(expected == {"bytes": len(raw), "sha256": sha(raw), "git_blob": object_id("blob", raw)},
                "prepared original changed: " + name)
        files[name] = raw
    ours, c3 = oid(receipt["ours_commit"]), oid(receipt["binding_child_c3"])
    records, base, c2, child, own, their = validate_parent_sources(root, c3, ours)
    original, ours_corpus, theirs_corpus, _, _ = validate_corpora(
        files["base-corpus.json"], files["ours-parent-corpus.json"], files["theirs-df927-corpus.json"], base, own, their)
    for commit, entries, name in ((BASE, base, "base-corpus.json"), (ours, own, "ours-parent-corpus.json"),
                                  (THEIRS, their, "theirs-df927-corpus.json")):
        require(git_blob(root, commit, entries, CORPUS) == files[name], "retained parent corpus differs from real Git")
    require(gtext(root, "rev-parse", "HEAD") == oid(args.merge)
            and not git(root, "status", "--porcelain"), "verify requires the actual clean merge HEAD")
    pending = merge_head_path(root)
    require(not pending.exists() and not pending.is_symlink(), "merge has not concluded")
    merge_record = selected_commit(root, args.merge, expected_parents=[ours, THEIRS])
    staged_before = tree(root, oid(receipt["candidate_index_tree_before_corpus_refresh"]))
    final = tree(root, merge_record["tree"])
    require(staged_before.keys() == final.keys()
            and all(final[path] == value for path, value in staged_before.items() if path != CORPUS),
            "merge changed a staged source beyond the prepared corpus replacement")
    merged_scope(base, own, their, staged_before)
    desired, _ = refresh_corpus(ours_corpus, staged_before)
    require(files["merged-corpus.json"] == encoded(desired)
            and git_blob(root, args.merge, final, CORPUS) == files["merged-corpus.json"],
            "actual merge corpus is not the prepared exact source union")
    for path, blob in desired["pinned_blobs"].items():
        require(regular_entry(final, path)["blob"] == blob, "merged corpus pin differs: " + path)
        actual_blob(root, path, final[path])
    actual_blob(root, CORPUS, final[CORPUS])
    root_guard(root)
    require(gtext(root, "rev-parse", "HEAD") == args.merge and not git(root, "status", "--porcelain"),
            "merge checkout changed during verification")
    report = {"schema": "pon-upstream-corpus-actual-merge-verification-v1", "source_binding_verified": True,
              "actual_merge": merge_record, "actual_parent_order": [ours, THEIRS],
              "prepared_receipt_sha256": sha(receipt_raw), "selected_commits": records,
              "required_paths": 1011, "pinned_blobs": 1103,
              "unchanged_ours_evidence": True, "authority_pq128_w1_qrom_checkpoint_bindings_unchanged": True,
              "unchanged_theirs_evidence": True,
              "native_executed": False, "project_tests_executed": False,
              "merge_acceptance_claimed": False, "native_full_suite_passed": False,
              "production_activation": False, "security_status": "HOLD"}
    output.mkdir(mode=0o755)
    write_new(output / "source-binding-verification.json", encoded(report))
    print(json.dumps({"status": "SOURCE_BINDING_VERIFIED_HOLD", "merge": args.merge,
                      "output": str(output), "native_executed": False, "merge_acceptance_claimed": False}))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="phase", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--binding-child", required=True, help="actual C3, direct child of C2")
    p.add_argument("--ours", required=True, help="actual first-parent HEAD: C3 itself or its evidence-only child")
    p.add_argument("--theirs", required=True, help="the reviewed df927 full commit")
    p.add_argument("--candidate-tree", required=True, help="actual git write-tree after reviewed conflict resolution")
    p.add_argument("--output", type=Path, required=True, help="new external directory; never overwrite")
    p = sub.add_parser("verify")
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--prepared", type=Path, required=True)
    p.add_argument("--receipt-sha256", required=True)
    p.add_argument("--merge", required=True, help="actual completed two-parent merge HEAD")
    p.add_argument("--output", type=Path, required=True, help="new external verification directory")
    args = parser.parse_args(argv)
    try:
        (prepare if args.phase == "prepare" else verify)(args)
        return 0
    except (Refusal, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print("UPSTREAM_CORPUS_UNION_REFUSED: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
