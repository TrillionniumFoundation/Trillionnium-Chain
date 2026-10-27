# PoN DAA bounded timestamp beam — non-activated adversarial research V1

Scope: M02/M17 research under the existing `TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`.
**No consensus selection, W1 production, Hepta model activation, source renewal, genuine network
operator, proof of work, released consensus or new versioned native runtime is implemented here.**
Neither the historical 16-block target rule nor Q4/revision12/PNW1 bytes change.

## The deterministic experiment

The Python search uses the existing `daa_research_oracle.py` for the installed legacy
16-block endpoint retarget and the separate raw/MTP11 ASERT research proposals.
Genesis time is zero; local wall time advances as `height * 10` seconds, and a legal
candidate timestamp must exceed MTP11 of up to the preceding 11 ancestors and must not
exceed the local wall clock by more than 120 seconds. The search enumerates a finite
candidate set (MTP minimum, parent, parent+1, wall, maximum future allowance, its
predecessor and midpoint). At every height, a bounded beam retains candidates with
large targets and candidates with small endpoint timestamps to preserve potentially
interesting future intervals. The algorithm deliberately does **not** claim to search
all legal timestamps or optimal adversarial policy. Every selected final schedule
is independently replayed from genesis and checked for all timestamps, targets and
cumulative target-derived chainwork.

The three algorithms receive equal hypothetical 80-header opportunities. They **do
not** actually perform W1 work; the ability to generate all candidate headers within
the assigned clock is an assumption, not a measured miner achievement.
No model task, lease, malicious peer, partition or private-block release is executed.
The work metric is the exact target-derived sum `floor(2^256/(target+1))`, never a
model score, observed lucky ticket or amount of performed neural work.

The independent Go process reads the emitted canonical report and recomputes every
legacy target, fixed-point aserti3-2d raw/MTP11 target, MTP and future-time decision,
full 256-bit chainwork, honest timestamp baseline and canonical case digest. A separate
negative driver changes inputs **and recomputes the report hash**: invalid time, false
target, inflated work, altered honest baseline, manufactured native-W1 proof count,
duplicate algorithms and unknown fields must still fail. Four half-lives 3600,
7200, 14400, 28800 seconds are covered by the Go process tests.

## Reproduction

From `formal/pon-nakamoto-v1`, with Python 3.13 and Go 1.23 installed:

```sh
python3 -m unittest -v test_daa_timewarp_beam_research.py
python3 daa_timewarp_beam_research.py --blocks 80 --beam-width 64 \
  --output /absolute/new/nonexistent/timewarp.json
GO111MODULE=off go run daa_timewarp_go/main.go /absolute/new/nonexistent/timewarp.json
python3 -m unittest -v run_daa_timewarp_go_negative.py
```

`run_daa_timewarp_go_negative.py` is intentionally opt-in: invoking it without the
Go compiler is a failure rather than a silent skipped independent oracle. The
Python-only test is available for normal Python discovery. The exact frozen sample
is `timewarp_beam_80.json`; its file SHA-256 is
`9346f9382c7d85126c868587453fb0a5e86dfcadaadd4e7e7f8d9a54b962b3bf`.

Recorded local Python 3.13.5 / Go 1.23.2 results, **not native PoN evidence**:

| Rule | Best beam terminal target / initial | Beam cumulative chainwork / honest | Case SHA-256 |
| --- | ---: | ---: | --- |
| legacy16 | 1.800000 | 0.638889 | `7cc25848249fa0d784cf59f7e6cf18e414915bb53f14d545f553a978c7675f92` |
| asert_raw | 1.011658 | 0.988621 | `930252ae85438d301a52a5af25d56f4ad1fc9f89f3b88a4cec250dc46821d0b1` |
| asert_mtp11 | 1.006775 | 0.988659 | `8ef34d6c2cd5df67e8ad0456a1a1a3e034f88b7b04f40219478810a37e8e6d74` |

The work ratios show why a more relaxed target is not evidence that a lighter
fork beats a heavier fork. They are neither confirmation-risk probabilities nor
verified proof production costs.

## Strict blockers preserved

- **P0-A/B:** native ordinary Hepta admission, unambiguous original-operation
  Q4 renewal/lost-ACK, all-32 native reclamation and independent client path.
- **P0-C:** genuine least-cost valid W1 proof across CPUs/GPUs/FPGA/ASIC,
  full third-party validation, Sybil ingress/invalid-proof DoS and cheapest-input
  work-class independence.
- **P1-A/B/C:** native exact-head Rust compile/differential and W1 fork cohorts,
  partition/withholding and network-time manipulation at declared attacker work
  fractions; independently reviewed, explicitly versioned consensus activation.
- **P2:** independent operators, pre-registered 72-hour WAN + cold-store/recovery
  experiment, signed evidence and failure accounting.

The test's fixed wall-time path excludes proof-search time and wall-clock delays
from actually finding a proof. No result is a release/production acceptance claim.
