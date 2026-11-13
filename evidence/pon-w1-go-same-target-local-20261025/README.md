# Local Go W1 cost and Python parity — explicitly non-qualifying research

This package is attached to PR #336, not a production proof or a W1 replacement.
The W1 transcript/partial updates/field arithmetic are implemented independently
in `formal/pon-nakamoto-v1/work_go_probe.go`. The Python test
`test_w1_go_research.py` independently reconstructs exact challenge, task,
49,188-byte proof, decoded product and transcript hashes for four public matrix
shapes and three seeds (12 cases). The Go probe additionally checks direct
A×B and refuses transcript, product, task and proof-length mutations.

The same-target experiment uses an artificial SHA-256 challenge stream, not
actual block-header work; it counts **every full honest proof** until Ticket
meets the same 256-bit threshold as a cheap fabricated trace. The forged-ticket
path produces zero valid work and is rejected by full transcript replay.
This is the documented W1 verification-amplification threat, not a verified
public-network exploit or an optimized adversarial mining strategy.

### Recorded local evidence

* Local environment: Linux container, Go 1.23.2; no installed Rust toolchain.
* 128 process runs (32 seeds each for dense, zero, rank-one and sparse).
* Scope: `time.Now` monotonic **wall** spans inside each Go process; not CPU
  cycles, process-tree CPU, GPU, energy, peer ingress or whole-block cost.
* Original raw file: [raw_32_per_shape.json](raw_32_per_shape.json),
  SHA-256 `7de9342241df4ed9ac381f062269f77a1c762c5e2a92878b7d54964f10a51537`.
* Go executable SHA-256: `80d1414474e9eba5f678cd0dccad7e23847603e60e596137b9d4c75140e7ff0c`.
* Go source SHA-256: `f4b593aee5ab6a34aa32caf6dc6fff8b37eea71d6d776f2dd4561baf9f6d6db8`.
* Python differential source SHA-256: `2605d96e6ae0d33e28444379ad435e9c81a2de535826b83494627b4497ad9365`.
* Stable input/result-identity digest excluding nondeterministic timing:
  `8dfd4857f9b18a124a8519526e6c70c881ce68654b91b3148933abdeb4c836f3`.

Run from `formal/pon-nakamoto-v1` in a compiler-enabled checkout:

```sh
python3 -m unittest -v test_w1_go_research.py
python3 w1_go_cost_campaign.py --samples 32 --output /absolute/new/raw_32_per_shape.json
```

The output path MUST NOT already exist. An exact rerun is expected to match
canonical input/proof identities; wall-time values may differ and must remain
as independently recorded observations. There is no claim of source-equivalent
native Rust W1 execution or of an externally administered test.

## Open gates

Cheapest *legal* full proof (including fixed-material preparation reused across
many challenges), fast ASIC/GPU strategies, proof-flood resource amplification,
honest public peer fairness, effective adversary share, and network partition
safety remain unqualified. Four input structures and one Go implementation
cannot establish a computational lower bound. No W1 byte, DAA rule, Q4 lease,
genesis maintenance, model reward, activation or existing gate was changed.
