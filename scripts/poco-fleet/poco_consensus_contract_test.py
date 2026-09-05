#!/usr/bin/env python3
"""Fixed vectors and mutation controls for the independent PoCO contract."""

from __future__ import annotations

from poco_consensus_contract import (
    canonical_lab_genesis_hash,
    reference_parameters_hash,
)


PARAMETERS_HASH = "49e6ddaf2ef8e59844b0fd8fc78322019cd04ce3b704466d71c5f7b8d8e0b885"
GENESIS_HASH = "6f860345cc7966ba0dcec54fd57d19b12f8c768283d35c823c5506b6b2e339ce"


def genesis(
    *,
    chain_id: str = "trnm-poco-g3-lab-v0",
    first_id: bytes = bytes.fromhex("01" * 32),
    first_key: bytes = bytes.fromhex("11" * 32),
    first_power: int = 1,
) -> bytes:
    return canonical_lab_genesis_hash(
        chain_id,
        (
            (first_id, first_key, first_power),
            (bytes.fromhex("02" * 32), bytes.fromhex("22" * 32), 1),
            (bytes.fromhex("03" * 32), bytes.fromhex("33" * 32), 1),
            (bytes.fromhex("04" * 32), bytes.fromhex("44" * 32), 1),
        ),
    )


def main() -> None:
    assert reference_parameters_hash().hex() == PARAMETERS_HASH
    baseline = genesis()
    assert baseline.hex() == GENESIS_HASH
    assert genesis(chain_id="trnm-poco-g3-lab-v0-mutant") != baseline
    assert genesis(first_id=bytes.fromhex("05" * 32)) != baseline
    assert genesis(first_key=bytes.fromhex("55" * 32)) != baseline
    assert genesis(first_power=2) != baseline
    print(
        "poco_consensus_contract_self_test=passed vectors=2 mutations=4 "
        "deployment_inputs_absent=true"
    )


if __name__ == "__main__":
    main()
