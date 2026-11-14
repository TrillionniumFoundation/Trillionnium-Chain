"""Freeze a concrete W1 relation and its lifecycle cost accounting boundary.

This checks source bytes and a research contract. It neither attests a running
native binary nor proves a lower bound over all algorithms. No acceptance flag
from a submitted report is used as authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASELINE = "b16bae2824e6c8236ef2011fc93a74df3ac7f039"
BASELINE_TREE = "49392edc1b49a1ad92c1956f8a37c741d835677a"
NATIVE_TREE = "bf84f89b235adfcffcb0d3540c22c120f4031e13"
CONTRACT_PATH = "formal/pon-nakamoto-v1/contracts/work-cost-contract-v1.json"
PIN_ROOTS = ("trillionnium", "formal", "config", "rust-toolchain.toml")
QUALIFICATION = {
    "all_legal_algorithm_cost_lower_bound": False,
    "variable_u_native_relation": False,
    "native_time_daa_upgrade": False,
    "joint_cp_cq_cg_proof": False,
    "lifetime_security_bound": None,
    "same_iteration_deployment": False,
    "real_hepta_product_loop": False,
    "production_activation": False,
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def loads(data):
    def no_number(_):
        raise ValueError("NON_INTEGER_JSON_NUMBER")
    value = json.loads(data, object_pairs_hook=unique, parse_float=no_number,
                       parse_constant=no_number)
    return value


def canonical(value):
    # Booleans are allowed as booleans, never as integer quantities.
    def walk(item):
        if item is None or type(item) in (str, bool):
            return
        if type(item) is int:
            require(-(1 << 512) < item < (1 << 512), "INTEGER_RANGE")
            return
        if type(item) is list:
            for child in item:
                walk(child)
            return
        require(type(item) is dict and all(type(k) is str for k in item),
                "JSON_TYPE")
        for child in item.values():
            walk(child)
    walk(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(b"TRNM-WORK-COST-CONTRACT-V1\0" + canonical(value)).hexdigest()


def git(root, *args):
    return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=root)


def source_entries(root=ROOT):
    """The roster comes from the immutable baseline tree, not the caller's list."""
    require(not git(root, "for-each-ref", "--format=%(refname)", "refs/replace/").strip(),
            "SOURCE_REPLACEMENT_REFS")
    graft = git(root, "rev-parse", "--git-path", "info/grafts").strip().decode()
    require(not (Path(root) / graft).exists(), "SOURCE_GRAFTS")
    require(git(root, "rev-parse", BASELINE + "^{tree}").strip().decode() == BASELINE_TREE,
            "BASELINE_TREE")
    raw = git(root, "ls-tree", "-rz", "--full-tree", BASELINE, "--", *PIN_ROOTS)
    entries = []
    for row in raw.split(b"\0"):
        if not row:
            continue
        meta, path = row.split(b"\t", 1)
        mode, kind, oid = meta.decode("ascii").split()
        require(kind == "blob" and mode in ("100644", "100755"), "SOURCE_KIND")
        entries.append({"path": path.decode("utf-8"), "mode": mode,
                        "git_blob": oid})
    return sorted(entries, key=lambda row: row["path"])


def bytes_at(root, path, mode):
    require(type(path) is str, "SOURCE_PATH")
    parts = PurePosixPath(path)
    require(path == parts.as_posix() and not parts.is_absolute()
            and ".." not in parts.parts and "\\" not in path, "SOURCE_PATH")
    def fingerprint(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts.parts[:-1]:
            next_parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=parent)
            os.close(parent)
            parent = next_parent
        before = os.stat(parts.name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode), "SOURCE_KIND")
        require(bool(before.st_mode & 0o111) == (mode == "100755"), "SOURCE_MODE")
        fd = os.open(parts.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before), "SOURCE_CHANGED")
            data = stream.read()
            require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before)
                    and len(data) == before.st_size, "SOURCE_CHANGED")
        require(fingerprint(os.stat(parts.name, dir_fd=parent, follow_symlinks=False))
                == fingerprint(before), "SOURCE_CHANGED")
        return data
    except OSError as error:
        raise ValueError("SOURCE_IO:" + path) from error
    finally:
        os.close(parent)


def definition():
    return {
        "work_profile": "pon-matmul-transcript-64-v1",
        "numeric_semantics": {"n": 64, "rank": 8, "field_modulus": 4294967291,
                              "word_bytes": 4, "encoding": "canonical-u32-little-endian",
                              "proof_bytes": 49188, "noise_hash_limit_per_label": 128},
        "statement": {"inputs": ["A", "B"], "task": "H(task,LE32(A),LE32(B))",
                      "challenge": "H(challenge,complete-exact-header)",
                      "proof": "PNW1 || A || B || decoded-AB || full-prefix-transcript-digest",
                      "success": "complete-W1-verify-at-original-expected-target",
                      "native_admission": "separate-complete-parent-state-and-block-application"},
        "freedom": {
            "parent_and_task": "selected-only-from-parent-valid-branch-state",
            "nonce": "u64-header-field; every evaluated nonce and discarded result counted",
            "time": "valid-header-choice remains an adversarial search dimension",
            "target": "derived-from-selected-parent; not a miner-selected verifier argument",
            "transactions_and_outputs": "all legal root/miner/witness choices remain in attack game",
            "proof_serialization": "one canonical fixed-length encoding; no trailing bytes",
            "optimizer": "all algorithms satisfying the identical accepted relation; no official-algorithm restriction",
        },
        "fixed_p0_research": {
            "threshold_hex": "7" + "f" * 63,
            "p0_under_uniform_ticket_hypothesis": {"n": 1, "d": 2},
            "uniform_independence_established": False,
            "native_variable_u_supported": False,
            "u_semantics": "requires a new mandatory joint relation and fresh parameter namespace",
            "same_success_standard": "fixed completion probability and deadline under a declared resource model",
        },
        "lifecycle": {
            "initial_state": ["public-model-and-input", "private-advice", "precomputation",
                              "cache", "unused-valid-results", "nonce-bank", "quantum-state"],
            "charge_events": ["setup", "all-attempts", "failed", "aborted", "withheld",
                              "post-winner", "proof-construction", "verification", "transport",
                              "storage", "recovery", "cross-version-state", "helpers"],
            "quantum_events": ["state-preparation", "reversible-computation", "uncomputation",
                               "oracle-construction", "measurements", "cross-round-state"],
            "resource_dimensions": ["cpu_ns", "wall_ns", "peak_concurrent_rss_bytes", "gpu_ns",
                                    "storage_byte_seconds", "network_bytes", "physical_energy",
                                    "provider_charges"],
            "unknown_measurement": None,
            "peak_rss_rule": "concurrent-live-total; do not sum sequential maxima",
            "reorg_rule": "resource and operation history does not rewind with chain history",
            "cost_bound_rule": "best measured legal implementation is an upper bound on minimum cost",
        },
        "proof_identity": {
            "native": "full-recomputation-PNW1",
            "succinct_backend_in_this_contract": None,
            "guest_image": None, "control_root": None, "compiled_air": None,
            "unmeasured_identity_rule": "null is HOLD, never a wildcard or a zero-cost measurement",
        },
        "integration": {
            "chain_source": BASELINE,
            "hepta_main_observed": "732e934ba496d90fbe042b8d41d479ef901643e5",
            "single_deployed_cross_repository_identity": None,
            "work_order_and_payment_do_not_authorize_adoption": True,
            "next_use": "original-owner current permission + actual loaded model + next task",
            "legal_no_update": "retain complete parent identity; do not invent improvement or reset",
        },
    }


def capture(root=ROOT):
    """Explicit developer freeze; the checked-in validator never refreshes pins."""
    entries = source_entries(root)
    for row in entries:
        data = bytes_at(root, row["path"], row["mode"])
        oid = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        require(oid == row["git_blob"], "BASELINE_SOURCE_DRIFT:" + row["path"])
        row.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    return {"schema": "pon-work-cost-contract-v1", "source_commit": BASELINE,
            "source_tree": BASELINE_TREE, "native_tree": NATIVE_TREE,
            "source_entries": entries,
            "source_inventory_digest": digest(entries), "definition": definition(),
            "qualification": dict(QUALIFICATION)}


def check_contract(contract, root=ROOT):
    require(type(contract) is dict and set(contract) == {
        "schema", "source_commit", "source_tree", "native_tree", "source_entries",
        "source_inventory_digest", "definition", "qualification"}, "CONTRACT_KEYS")
    require(contract["schema"] == "pon-work-cost-contract-v1"
            and contract["source_commit"] == BASELINE
            and contract["source_tree"] == BASELINE_TREE
            and contract["native_tree"] == NATIVE_TREE, "SOURCE_IDENTITY")
    require(canonical(contract["definition"]) == canonical(definition()), "DEFINITION_DRIFT")
    require(canonical(contract["qualification"]) == canonical(QUALIFICATION), "CLAIM_PROMOTION")
    entries = contract["source_entries"]
    require(type(entries) is list and digest(entries) == contract["source_inventory_digest"],
            "SOURCE_INVENTORY_DIGEST")
    expected = source_entries(root)
    require(len(entries) == len(expected), "SOURCE_ROSTER")
    total = 0
    for row, want in zip(entries, expected):
        require(type(row) is dict and set(row) == {"path", "mode", "git_blob", "bytes", "sha256"},
                "SOURCE_ENTRY")
        require({k: row[k] for k in want} == want, "SOURCE_ROSTER")
        require(type(row["bytes"]) is int and row["bytes"] >= 0, "SOURCE_SIZE")
        data = bytes_at(root, row["path"], row["mode"])
        oid = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        require(oid == want["git_blob"] and len(data) == row["bytes"]
                and hashlib.sha256(data).hexdigest() == row["sha256"], "SOURCE_BYTES:" + row["path"])
        total += len(data)
    # Validate actual profile integers independently of the prose contract.
    profile = loads((Path(root) / "config/pon/work-profile-v1.json").read_bytes())
    for key, value in (("n", 64), ("rank", 8), ("field_modulus", 4294967291),
                       ("proof_bytes", 49188), ("maximum_noise_hashes_per_label", 128)):
        require(type(profile[key]) is int and profile[key] == value, "NUMERIC_PROFILE")
    return {"schema": "pon-work-cost-contract-check-v1", "contract_digest": digest(contract),
            "source_commit": BASELINE, "source_tree": BASELINE_TREE,
            "verified_source_entries": len(entries), "verified_source_bytes": total,
            "contract_and_source_consistent": True, "native_binary_executed": False,
            "qualification": dict(QUALIFICATION), "status": "HOLD_NO_GO"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=ROOT / CONTRACT_PATH)
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.capture:
        require(not args.capture.exists(), "CAPTURE_DESTINATION_EXISTS")
        args.capture.write_text(json.dumps(capture(), indent=2, ensure_ascii=True) + "\n")
        return
    result = check_contract(loads(args.contract.read_bytes()))
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        require(not args.output.exists(), "OUTPUT_EXISTS")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
