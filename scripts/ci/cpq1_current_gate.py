#!/usr/bin/env python3
"""Current CPQ1 source gate with the original bounded profile guards.

The frozen V1 entry and its manifest remain unchanged and may reject newer
source. This entry checks the reviewed current correspondence and retains every
original semantic refusal; it does not qualify cryptography or production.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

import check_pq_research_integration as frozen
import pq_corpus_current_v2 as current

SCHEMA = "trnm-cpq1-current-source-gate-v1"


def _check_original_contracts(root: Path, m: dict) -> None:
    # Original guard predicates are copied without weakening their values or
    # type checks. Byte correspondence, recursive coverage and the canonical
    # provider guard are performed by current.inspect with the frozen owners.
    if m.get("schema") != "trnm-pq-cross-branch-corpus-v1" or m.get("status") != "research-only-hold-no-go":
        raise frozen.IntegrityError("corpus must remain research/HOLD")
    if m.get("parent_profile") != "pon-nakamoto-v1":
        raise frozen.IntegrityError("wrong profile")
    heads = m.get("upstream_heads")
    if not isinstance(heads, dict) or set(heads) != frozen.REQUIRED_UPSTREAM:
        raise frozen.IntegrityError("missing provenance parent")
    if not all(type(v) is str and re.fullmatch("[0-9a-f]{40}", v) for v in heads.values()):
        raise frozen.IntegrityError("malformed provenance commit")
    assertions = m.get("assertions")
    if not isinstance(assertions, dict) or set(assertions) != frozen.REQUIRED_FALSE:
        raise frozen.IntegrityError("missing acceptance gate")
    if any(value is not False for value in assertions.values()):
        raise frozen.IntegrityError("unaccepted capability claimed true")
    pins = m.get("pinned_blobs")
    required = m.get("required_paths")
    if (not isinstance(pins, dict) or not isinstance(required, list)
            or not required or len(required) != len(set(required))
            or any(type(p) is not str or p not in pins for p in required)):
        raise frozen.IntegrityError("incomplete source pins")
    # PNQ1/OpenSSL-only records remain historical evidence, not the active
    # source contract for this canonical-provider PNQ2 candidate.
    if "native_network_owner_slice_v1" in m:
        raise frozen.IntegrityError("superseded PNQ1 native slice cannot select this candidate")
    native = m.get("native_network_owner_slice_v2")
    if (not isinstance(native, dict)
            or set(native) != set(frozen.NATIVE_V2_EXPECTED) | {"evidence"}
            or any(type(native.get(key)) is not type(value) or native.get(key) != value
                   for key, value in frozen.NATIVE_V2_EXPECTED.items())
            or not frozen.NATIVE_REQUIRED_PATHS.issubset(required)):
        raise frozen.IntegrityError("canonical PNQ2 bounded-profile contract changed")
    evidence = native.get("evidence")
    if (type(evidence) is not str
            or not evidence.startswith(("evidence/", "qualification/"))
            or not evidence.endswith("/README.md")):
        raise frozen.IntegrityError("native PQ evidence locator")
    # Presence/readability is not test acceptance. The report must distinguish
    # recovered executable measurements from newly compiled exact-source runs.
    frozen._safe_regular(root, evidence)
    account = m.get("native_account_owner_slice_v1")
    if (not isinstance(account, dict)
            or account.get("profile") != "native-pq-qtx1-account-v1"
            or account.get("feature") != "pq-native-openssl"
            or account.get("contract") != "docs/security/PQ_NATIVE_ACCOUNT_OWNER_V1.md"
            or account.get("evidence") != "evidence/pon-pq-account-native-20261028/README.md"
            or account.get("migration_wire") != "PQG1/v1"
            or account.get("transaction_wire") != "QTX1/v1"
            or type(account.get("transaction_byte_limit")) is not int
            or account["transaction_byte_limit"] != 8192
            or type(account.get("transaction_count_limit")) is not int
            or account["transaction_count_limit"] != 16
            or account.get("liability_mode") != "all-source-records-locked"
            or account.get("transfer_only") is not True
            or account.get("original_m06_nonce_fee_owner") is not True
            or account.get("dual_possession_signatures_required") is not True
            or account.get("miner_roster_permission_required") is not False
            or account.get("independent_source_history_authenticated") is not False
            or any(account.get(flag) is not False for flag in frozen.NATIVE_FALSE)):
        raise frozen.IntegrityError("native PQ account bounded-profile contract changed")
    frozen._safe_regular(root, account["evidence"])
    overwrites = m.get("overwrites")
    expected_overwrites = {
        "formal/pon-nakamoto-v1/pq_cell_custody.py": "cell",
        "formal/pon-nakamoto-v1/pq_account_migration.py": "migration",
        "formal/pon-nakamoto-v1/pq_pql5_quorum.py": "witness",
        "formal/pon-nakamoto-v1/test_pq_pql5_quorum.py": "witness",
    }
    if overwrites != expected_overwrites:
        raise frozen.IntegrityError("unreviewed source substitution")
    actual_consensus = frozen._json(root, "config/consensus-mainline.json")
    actual_devnet = frozen._json(root, "config/pon/devnet-v1.json")
    pq = frozen._json(root, "config/pon/post-quantum-transition-v1.json")
    if (actual_consensus.get("production_consensus_activation") is not False
            or actual_consensus.get("runtime_implemented") is not False
            or actual_consensus.get("active_consensus_implementation") is not None
            or actual_devnet.get("production_activation") is not False
            or actual_devnet.get("max_transaction_bytes") != 2048
            or pq.get("production_activation") is not False
            or pq.get("allow_classical_fallback") is not False
            or pq.get("reference_signature", {}).get("signature_bytes") != 3309
            or pq.get("existing_devnet_limits", {}).get("post_quantum_transaction_wire_compatible") is not False):
        raise frozen.IntegrityError("installed consensus or PQ gate changed")


def inspect(root: Path) -> dict:
    root = Path(root).absolute()
    original_raw = frozen._safe_regular(root, frozen.REL_MANIFEST)
    original = current.strict_json(original_raw)
    _check_original_contracts(root, original)
    result = current.inspect(root)
    if frozen._safe_regular(root, frozen.REL_MANIFEST) != original_raw:
        raise frozen.IntegrityError("original contract changed during current inspection")
    return {**result, "schema": SCHEMA, "original_profile_contracts_checked": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    try:
        result = inspect(args.root)
    except (frozen.IntegrityError, current.CurrentCorpusError, OSError, ValueError,
            TypeError, KeyError, AttributeError, RecursionError) as error:
        print(json.dumps({"schema": SCHEMA, "status": "REFUSE",
                          "reason": str(error), **current.QUALIFICATION},
                         sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
