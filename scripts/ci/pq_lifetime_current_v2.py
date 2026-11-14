#!/usr/bin/env python3
"""Bind the frozen PQ128 model to an explicit current declared-path map.

The V1 reader, manifest and source lock keep their original meaning. This
separate entry checks current bytes without relabeling the frozen experiment,
proving a Git revision, importing historical code or granting qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

import pq_lifetime_budget as legacy
from pq_source_reader import SourceReadError, read_regular

SCHEMA = "trnm-pq128-lifetime-current-result-v2"
MAP_SCHEMA = "trnm-pq128-source-correspondence-current-v2"
DEFAULT_MAP = "config/pon/pq128-source-correspondence-current-v2.json"
FROZEN_REVISION = "0f9b30549328e5be20f4d3e6e27bd132b42d90de"
MANIFEST_SHA256 = "0315e07ca2988b3b209a6fd2980ca6d9aa22a5bb3aa98b5444a041852b2f0afd"
SOURCE_LOCK_SHA256 = "094dcae805f3872ee621d6554ab26a7a3a34c498e21be669740949ada424ccb2"
EXPECTED_MAP_SHA256 = "2aa06a43b36deca1f6a4b3b6d345468fc50b9b60e0cc3ee764f3a14a289b0c93"
EXPECTED_CURRENT_FILES_SHA256 = "5b409e39276cdd6df0a012625c31e75d382944f87d2c87725b51e089464a8140"
EXPECTED_PATHS = frozenset((
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/pq_profile_auth.rs",
    "trillionnium/crates/trnm-data-availability/src/cell.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/manifest.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/model_root.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/pq.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/retained.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_content.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_content_closure_v3.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/migration.rs",
    "trillionnium/crates/trnm-pon-node/src/consensus.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_rollback_witness.rs",
    "trillionnium/crates/trnm-pon-node/src/store.rs",
    "trillionnium/crates/trnm-pon-node/src/store/funding/payment.rs",
    "trillionnium/crates/trnm-release-bundle/src/pq_release.rs",
    "trillionnium/crates/trnm-research-protocol/src/hepta_handoff/pq.rs",
    "trillionnium/crates/trnm-service-settlement/src/native_budget.rs",
))
MAX_MAP_BYTES = 32768
MAX_REPORT_BYTES = 262144
QUALIFICATION = {
    "actual_lifetime_failure_bound": None,
    "whole_chain_pq_qualified": False,
    "pq_128_qualified": False,
    "production_activation": False,
    "composition_coverage_proved": False,
    "theorem_applicability_verified": False,
}


class CurrentBudgetError(legacy.BudgetError):
    pass


def require(ok, message):
    if not ok:
        raise CurrentBudgetError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def frozen_identity():
    return {
        "source_revision": FROZEN_REVISION,
        "manifest_path": legacy.DEFAULT_MANIFEST,
        "manifest_sha256": MANIFEST_SHA256,
        "source_lock_path": legacy.DEFAULT_SOURCE_LOCK,
        "source_lock_sha256": SOURCE_LOCK_SHA256,
    }


def inspect(root):
    """Read only the fixed model, lock, map and all 21 current source paths.

    Each descriptor read is bounded and identity checked. Separate reads are
    not an immutable checkout snapshot or protection from a privileged writer.
    Source correspondence is not a theorem, deployment or Git provenance proof.
    """
    root = Path(root)
    try:
        map_raw = read_regular(root, DEFAULT_MAP, MAX_MAP_BYTES)
        require(hashlib.sha256(map_raw).hexdigest() == EXPECTED_MAP_SHA256,
                "current correspondence map differs from reviewed bytes")
        mapping = legacy.strict_json(map_raw)
        legacy.fields(mapping, "schema status frozen_model current_source_files_sha256 "
                      "current_source_snapshot_sha256 qualification", "current correspondence")
        require(mapping["schema"] == MAP_SCHEMA and mapping["status"] == "HOLD",
                "unsupported current correspondence namespace")
        require(canonical(mapping["frozen_model"]) == canonical(frozen_identity()),
                "frozen model identity cannot be replaced by current identity")
        require(canonical(mapping["qualification"]) == canonical(QUALIFICATION),
                "current correspondence cannot promote a lifetime claim")
        expected = mapping["current_source_files_sha256"]
        require(type(expected) is dict and set(expected) == EXPECTED_PATHS,
                "current paths must equal the fixed 21 declared event paths")
        for path, digest in expected.items():
            require(type(digest) is str
                    and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                    "invalid current source SHA-256: " + path)
        require(mapping["current_source_snapshot_sha256"] == EXPECTED_CURRENT_FILES_SHA256
                and hashlib.sha256(canonical(expected)).hexdigest()
                == EXPECTED_CURRENT_FILES_SHA256,
                "current source map differs from the independent snapshot pin")

        manifest_raw = read_regular(root, legacy.DEFAULT_MANIFEST, legacy.MAX_BYTES)
        lock_raw = read_regular(root, legacy.DEFAULT_SOURCE_LOCK, legacy.MAX_BYTES)
        require(hashlib.sha256(manifest_raw).hexdigest() == MANIFEST_SHA256,
                "frozen model manifest differs from reviewed bytes")
        require(hashlib.sha256(lock_raw).hexdigest() == SOURCE_LOCK_SHA256,
                "frozen source lock differs from reviewed bytes")
        model = legacy.evaluate(legacy.strict_json(manifest_raw))
        model["manifest_sha256"] = MANIFEST_SHA256
        lock = legacy.strict_json(lock_raw)
        legacy.fields(lock, "schema source_revision files", "frozen source lock")
        require(lock["schema"] == legacy.SOURCE_LOCK_SCHEMA
                and lock["source_revision"] == FROZEN_REVISION,
                "frozen source lock revision mismatch")
        require(type(lock["files"]) is dict and set(lock["files"]) == EXPECTED_PATHS
                and set(model["source_paths"]) == EXPECTED_PATHS,
                "frozen and current declared path sets must be identical")
        require(model["purpose"] == "research-model"
                and model["experiment"]["source_revision"] == FROZEN_REVISION
                and model["source_revision_bound"] is False
                and model["source_binding_scope"] == "unbound"
                and model["source_lock_sha256"] is None,
                "frozen arithmetic must not claim a current source binding")
        for key, value in QUALIFICATION.items():
            require(type(model[key]) is type(value) and model[key] == value,
                    "frozen model qualification changed: " + key)

        observed = {
            path: hashlib.sha256(read_regular(root, path, legacy.MAX_BYTES)).hexdigest()
            for path in sorted(EXPECTED_PATHS)
        }
        for path in sorted(EXPECTED_PATHS):
            require(observed[path] == expected[path],
                    "current correspondence source hash mismatch: " + path)
        # Retain the original small metadata bytes across all source reads.
        for path, raw, limit in (
                (legacy.DEFAULT_MANIFEST, manifest_raw, legacy.MAX_BYTES),
                (legacy.DEFAULT_SOURCE_LOCK, lock_raw, legacy.MAX_BYTES),
                (DEFAULT_MAP, map_raw, MAX_MAP_BYTES)):
            require(read_regular(root, path, limit) == raw,
                    "correspondence metadata changed during inspection: " + path)
        return {
            "schema": SCHEMA, "status": "HOLD", **QUALIFICATION,
            "frozen_model_identity": frozen_identity(),
            "frozen_model": model,
            "current_source_correspondence": {
                "schema": MAP_SCHEMA, "source_files_checked": True,
                "source_binding_scope": "declared-event-paths-only",
                "source_revision_bound": False,
                "map_sha256": EXPECTED_MAP_SHA256,
                "source_snapshot_sha256": EXPECTED_CURRENT_FILES_SHA256,
                "source_files_sha256": observed,
                "changed_from_frozen_paths": sorted(
                    path for path in EXPECTED_PATHS if observed[path] != lock["files"][path]),
            },
            "note": "The frozen arithmetic remains unbound. The current map checks only the same 21 declared event paths; it proves no Git revision, theorem applicability, complete dependency coverage, deployment or lifetime security bound.",
        }
    except (legacy.BudgetError, SourceReadError, KeyError, TypeError, ValueError) as error:
        if isinstance(error, CurrentBudgetError):
            raise
        raise CurrentBudgetError(str(error)) from error


def verify_report(root, raw):
    """Recompute current bytes; never trust a supplied report or its own hashes."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_REPORT_BYTES,
            "invalid current correspondence report bytes")
    try:
        report = legacy.strict_json(raw)
        expected = inspect(root)
        matches = type(report) is dict and canonical(report) == canonical(expected)
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise CurrentBudgetError("invalid current correspondence report") from error
    require(matches, "current correspondence report differs from fresh inspection")
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    try:
        result = inspect(args.root)
    except (CurrentBudgetError, OSError) as error:
        print(json.dumps({"schema": SCHEMA, "status": "REFUSE",
                          "reason": str(error), **QUALIFICATION}, sort_keys=True),
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
