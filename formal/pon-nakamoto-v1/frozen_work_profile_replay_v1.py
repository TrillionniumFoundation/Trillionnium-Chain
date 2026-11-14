"""Explicit replay of an immutable historical W1 contract by current research.

The reference directory is evidence input, never an imported execution path.
Its identity comes from the fixed Git commit/tree and the original byte checker;
a directory name, submitted hash or earlier successful report is not authority.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import work_profile_contract_v1 as contract

SCHEMA = "pon-frozen-work-reference-v1"


def check_reference(value, source, research_root=contract.ROOT):
    reference = Path(source).resolve(strict=True)
    research = Path(research_root).resolve(strict=True)
    contract.require(
        not reference.is_relative_to(research) and not research.is_relative_to(reference),
        "FROZEN_REFERENCE_SEPARATION",
    )
    top = Path(contract.git(reference, "rev-parse", "--show-toplevel").strip().decode()).resolve()
    contract.require(top == reference, "FROZEN_REFERENCE_ROOT")
    head = contract.git(reference, "rev-parse", "HEAD").strip().decode()
    tree = contract.git(reference, "rev-parse", "HEAD^{tree}").strip().decode()
    native = contract.git(reference, "rev-parse", "HEAD:trillionnium").strip().decode()
    contract.require(head == contract.BASELINE, "FROZEN_REFERENCE_HEAD")
    contract.require(tree == contract.BASELINE_TREE and native == contract.NATIVE_TREE,
                     "FROZEN_REFERENCE_TREE")
    # Keep every original roster, mode, Git blob, byte-length and SHA-256 check.
    # Neither old pins nor the default checker are changed for this replay.
    checked = contract.check_contract(value, root=reference)
    contract.require(contract.git(reference, "rev-parse", "HEAD").strip().decode() == head,
                     "FROZEN_REFERENCE_CHANGED")
    return {
        "schema": SCHEMA,
        "directory": str(reference),
        "source_commit": head,
        "source_tree": tree,
        "native_tree": native,
        "baseline_contract_check": checked,
        "scope": "fixed historical source contract; not current native cost qualification",
        "current_native_cost_qualified": False,
        "native_binary_executed": False,
        "production_activation": False,
    }


def check_reused_inputs(value, research_root=contract.ROOT):
    """Pin the baseline relation inputs actually reused by current research.

    New research modules keep their current-source identity. Baseline modules
    already imported by the named suites, plus the catalog's baseline data
    inputs, must still have the original bytes. Loading an alternative current
    W1 oracle cannot borrow the historical relation's successful source check.
    """
    import legal_optimization_catalog_v1 as catalog

    root = Path(research_root).resolve(strict=True)
    for name in ("legal_optimization_catalog_v1", "work_oracle", "contract_wire", "reference"):
        module = sys.modules.get(name)
        if module is not None:
            expected = root / "formal" / "pon-nakamoto-v1" / (name + ".py")
            contract.require(Path(module.__file__).resolve() == expected,
                             "FROZEN_REPLAY_MODULE_ORIGIN:" + name)
    entries = {row["path"]: row for row in value["source_entries"]}
    selected = {path for path in catalog.SOURCE_PATHS if path in entries}
    for module in tuple(sys.modules.values()):
        filename = getattr(module, "__file__", None)
        if not filename:
            continue
        path = Path(filename).resolve()
        if path.is_relative_to(root):
            relative = path.relative_to(root).as_posix()
            if relative in entries:
                selected.add(relative)
    required = {
        "formal/pon-nakamoto-v1/work_oracle.py",
        "formal/pon-nakamoto-v1/contract_wire.py",
        "formal/pon-nakamoto-v1/vectors/header.bin",
        "config/pon/work-profile-v1.json",
    }
    contract.require(required <= selected, "FROZEN_REPLAY_RELATION_INPUTS")
    result = []
    for relative in sorted(selected):
        expected = entries[relative]
        data = contract.bytes_at(root, relative, expected["mode"])
        oid = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        actual = hashlib.sha256(data).hexdigest()
        contract.require(
            oid == expected["git_blob"] and len(data) == expected["bytes"]
            and actual == expected["sha256"],
            "FROZEN_REPLAY_INPUT_DRIFT:" + relative,
        )
        result.append({"path": relative, "git_blob": oid, "bytes": len(data), "sha256": actual})
    return result


def verify_research_source(root, expected_head):
    # Reuse the repository's full raw-byte, mode and hidden-index-flag checker.
    ci = str(Path(root).resolve() / "scripts" / "ci")
    if ci not in sys.path:
        sys.path.insert(0, ci)
    from verify_ci_source import verify
    return verify("head", expected_head, root=Path(root).resolve())
