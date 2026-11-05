# W1 literal domains, restricted search, interrupted setup and Fast DAA arithmetic

Status: **research evidence / HOLD**. Tested source:
`4cf25c59ca97cdc2d24a35953a47cb8ec2cf4a2c`. The retained comparison source is
`a9b8602706b66adba82655c3c2ce90bde88620a2`.

These observations do not activate consensus, qualify quantum resistance or
establish a mixed-resource security threshold. “Native shape” below means the
actual 64x64, rank-8, 32-bit W1 relation. Complete PNW1 checks use the independent
scalar `work_oracle.verify`; they are **not execution or admission by the native
Node**. Task eligibility, parent state, required target and timestamp admission
remain separate obligations.

## Frozen-source validation

Preflight passed on the tested commit. All 20 declared literal-domain source
inputs were committed at that HEAD, with no uncommitted declared inputs. Both
event campaigns likewise reported committed source inputs and retained their
source inventories. These checks bind source bytes; they are not hardware
execution attestations or validation of unrelated native changes.

| Check | Observed result at the frozen source |
| --- | --- |
| Literal-domain campaign and full replay | PASS; 6 cases, 48 native-shape nonces, 768 reduced-shape nonces, 15 independent complete PNW1 winning-proof checks, 3 measurement controls |
| Retained event campaign and seeded/integer readback | PASS; 30 runs, 40,434 events, 77,847 trace rows |
| Expanded adversarial campaign and independent arithmetic readback | PASS; 45 runs, 57,163 events, 139,936 trace rows |
| Full restricted-construction campaign | PASS; 5 cases, 60 literal candidates, 3 complete native-shape PNW1 winning-proof checks, 2 actual reduced leaf-gate controls, 25 discarded full winners; 249.160 seconds |
| Full restricted-construction replay | PASS; 5 cases / 60 candidates / 3 native-shape proofs / 2 gate controls / 25 discarded winners; all 18 source inputs committed; 274.855 seconds |
| Joint research test suite | PASS; 234/234 executed tests, 281.932 seconds |
| Source check | PASS; 2,636 local links, 26 packages, 25 dependency edges, 1,125 Rust files; committed and clean; 211.517 seconds |
| Source-integrity controls | PASS; 34 tests, 12.446 seconds |
| Rust formatting / locked offline metadata | PASS; 54.832 / 0.994 seconds |
| Strict Clippy | Not closed: first attempt timed out at 600.013 seconds (exit 124); the single 1,200-second-budget retry lost its execution environment before a final receipt was recovered. Retry exit/timeout status is unknown. |

The domain campaign exited 0 in 26.934271 seconds; its complete replay exited 0
in 27.304513 seconds. Network run/replay took 19.601445/24.427285 seconds;
adversarial run/replay took 21.469694/28.217809 seconds, all with exit 0. These are
classical observer/simulator runtimes, including serialization and verification,
not mining speed or quantum oracle clocks.

The published integration checkpoint is
`f8d65e96ecf4c0fed8da74fc0c5fc338dc08996c`, with parents `7a88207...` and
`4cf25c59...`. Its separate committed-and-clean repository gate passed in
135.484 seconds: 26 packages, 25 normal dependency edges, 1,130 Rust files and
2,654 local links. Independent byte review found all 221 frozen formal Python
files unchanged and preserved all 16 concurrent non-overlap files. The merged CI
retains all four relevant old/new test invocations and its recalculated source
pin. These structural results do not certify concurrent native migration logic.

### Native Clippy gate remains unclosed

The strict workspace command was
`cargo clippy --workspace --all-targets --locked --offline -- -D warnings`
from `trillionnium/`, at the frozen source. The first invocation reached its
600-second limit. One cache-assisted retry used the same command, Rust/Cargo
1.95.0, `CARGO_BUILD_JOBS=1`, and a 1,200-second budget. At the last successful
progress observation (979.5 seconds), its log had advanced through later workspace
packages, with no completion receipt.

The executor then disconnected. After the environment was restored, one
read-only recovery returned `Unknown process id 70143`; no final retry JSON
existed. Thus the retry's actual exit code, whether its timeout handler ran, final
elapsed time and child-group cleanup remain **unknown**. A configured limit is
not an observed timeout. No further build was started. The frozen tracked source
was read back clean, and integration changes during recovery were confined to
these two evidence files. The last saved retry log hash and exact start parameters
are retained in the reproduction record.

This gate is not green. The completed Python research tests, independent replays
and committed integration structural gate keep their separate source scope;
these observations do not certify a complete native build or release.

## Actual fixed-header nonce domains

The census evaluates actual challenged headers, bounded rejection sampling,
ordered tiled-prefix traces and tickets. A target change changes the challenge
and requires recomputation; rethresholding a retained ticket table is rejected.
Public AB is computed once per native-shape census, then every observed native
winner is materialized as PNW1 and independently scalar-verified.

| Case | Enumerated nonces | Full winners | Prefix-restricted winners | Noise exhaustion | Complete PNW1 checks |
| --- | ---: | ---: | ---: | ---: | ---: |
| Native PNH1 | 16 | 9 | 9 | 0 | 9 |
| Native PGH2 | 16 | 6 | 6 | 0 | 6 |
| Native PNH1, target=1 | 16 | 0 | 0 | 0 | 0 |
| Reduced PNH1 | 256 | 255 | 61 | 1 | 0 |
| Reduced PNH1, target=1 | 256 | 0 | 0 | 1 | 0 |
| Reduced PGH2, target=1 | 256 | 0 | 0 | 1 | 0 |

The native censuses cover the 4-bit low-nonce subspace, with the remaining nonce
bits fixed. They do not characterize nonce64. Reduced cases are explicitly
different work relations. All 48 native raw prefixes happened to pass the
restriction; this small observation does not prove general prefix retention or
prefix/ticket independence. Narrowing nonce width leaves overlapping nonces'
headers and tickets unchanged, so a new domain identifier does not imply
independent work opportunities.

The literal native empty domain remained empty through four modeled measurement
batches and paid one setup. Switching between two literal reduced empty domains
paid three setups over five batches under the declared single-resident policy.
Every parallel measurement pays its candidate check, including failures and zero
Grover iterations. The successful control stops after its first winning batch;
duplicate measurements are not credited as new blocks. These controls admit no
native blocks and use supplied cost assumptions.

## Restricted construction and its actual lost winners

The restricted campaign's native low-two-bit domains contain 2 PNH1 winners,
zero after a target change, and 1 PGH2 winner. In its reduced 32-nonce control,
the full relation has 32 winners while the restricted construction retains 7:
25 otherwise legal winners are deliberately discarded. Grover uses the original
nonce dimension and the restricted marked count; it receives no freely prepared
filtered initial state. Two reduced basis-interpreter executions each run
9,370,519 gates including the inverse and outer operations, preserve the nonce,
restore ancillas, and return the expected opposite phase outcomes.

| PNH1, 64-bit nonce construction census | Full | Restricted |
| --- | ---: | ---: |
| Reserved logical qubits | 22,253,173 | 22,029,941 |
| Compute/mark/uncompute gates | 17,718,016,715 | 15,992,168,955 |
| Phase depth upper bound | 1,969,835,151 | 1,102,032,975 |

The 9.740637% gate and 44.054558% serial depth-bound reductions compare two
particular constructions. They do not measure physical latency or establish a
minimum attacker cost. Native-size gate execution and exhaustive nonce64 search
were not performed. The resource and proof records, including PGH2, are in the
reproduction manifest. The restricted replay time covers a complete subprocess;
the 249.160-second run timer covers its internal measurement and source recheck.

## Author-derived Fast DAA arithmetic

[The component](../../formal/pon-nakamoto-v1/fast_daa_reference_component.py)
implements the approximate-agreement and retarget equations inspected in the
author-linked September 15, 2026 *Parallel Blockchains and Applications* slides.
Its [source manifest](../../formal/pon-nakamoto-v1/vectors/fast-daa-author-slides-retarget-v1.json)
pins the downloaded PDF hash and PDF pages 61--63 (displayed slides 52--54),
and distinguishes the proceedings, revised ePrint and slide versions.

Eleven tests in the joint suite check exact rational arithmetic, invariance,
refusal of ambiguous/unsupported histories and the distinction from an ordinary
trimmed mean: the recorded example gives 13/2 instead of 33/4. Ascending grouping
and odd-length medians are explicit declared interpretations; unsupported or
ambiguous cases refuse. This component is
not a complete Fast DAA network backend. The complete backend still refuses;
cross-chain reference validation, epoch rules, ledger extraction, integer target
encoding and security-parameter mapping remain open. No seconds-level native
confirmation promise follows from the source's constant-time asymptotic result.
A later targeted author/IOG lookup recovered only a two-page official explainer;
its full-paper link still points to ePrint. This does not fill the formal
protocol or establish equivalence between published versions.

## Event observations, including unsuccessful outcomes

All 75 runs reached their declared horizon; no trace was truncated. Combined
totals are 97,597 events, 217,783 trace rows and 16,399 synthetic blocks.

The retained 30-run grid contains three observed confirmation reversals and six
runs with the probe still unconfirmed at the horizon. Its largest reorganization
is 88 blocks in `private_fast_oracle_sensitivity`, seed 4102, using an **assumed**
0.01-second quantum iteration clock. This is a conditional model observation,
not an executed attack on Trillionnium or a calibrated W1 quantum miner.

The 45 expanded runs contain no observed confirmation reversal, a maximum
reorganization depth of two, and three unconfirmed probes at the horizon. That
finite absence does not establish safety. Their separate arithmetic reader
checked 6,416 synthetic blocks, 449 branch retargets and 24 admissible backward
adjacent timestamps; it did not verify W1 proofs. Three persistent M=0 controls
each retained one empty domain, completed 9,468 candidate checks and produced
zero quantum blocks.

## Retained failures and repaired regressions

1. **Interrupted setup was undercharged.** The before/after witness uses the same
   seed, fixed M=0 domain, unchanged supporting dependencies and a two-second
   setup interrupted after 0.5 seconds, with resumption at one second. At the
   earlier source, cancellation left only 0.5 seconds charged and later trials
   treated setup as complete. The frozen source carries the remaining 1.5
   seconds and charges two seconds total without replacing the domain.

   | Processors | Setup seconds, before -> after | Setup processor-seconds, before -> after | Completed candidate checks, before -> after |
   | --- | ---: | ---: | ---: |
   | 1 | 0.5 -> 2.0 | 0.5 -> 2.0 | 3 -> 1 |
   | 4 | 0.5 -> 2.0 | 2.0 -> 8.0 | 12 -> 4 |

2. **The prefreeze domain runner inherited an insufficient I/O cap.** An accepted
   4096-nonce reduced census serialized to 2,236,235 bytes, exceeding the reused
   2,000,000-byte reader/parser/writer cap. One explicit 16 MiB bound now covers
   all three paths; oversized objects fail without fallback. The regression
   exercises a real census above the old cap and no-clobber publication.
3. **The prefreeze restricted helper retained the original `FILES` binding.**
   The restricted campaign now owns explicit source-inventory and commitment
   routines, including its new inputs. Its parser also preserves the legitimate
   inclusive probability denominator `2**256`. The complete campaign result is
   recorded above; full replay also returned
   `RESTRICTED_W1_DIFFERENTIAL_REPLAY_PASS` on the frozen source.

The setup witness is an abstract-clock accounting counterexample, not measured
quantum work. The [original and repaired witness record](setup-before-after.json), four small
traces and [executable witness](setup_interruption_witness.py) retain their source identities.
Do not reclassify the original undercharge as a passing observation.

The first Rust gate invocation used the repository root, which has no
`Cargo.toml`, and failed before checking Rust. Repeating from `trillionnium/`
passed formatting and locked offline metadata; strict Clippy's 600-second
observation remains a timeout. These attempts and their exact exit codes are
retained rather than overwritten.

## Reproduce

From a fresh checkout of the exact tested commit, run the following from the
repository root. Use a new output directory; retained outputs are not overwritten.

```sh
bash scripts/project-preflight.sh
QUANTUM_REPRO_OUT="$(mktemp -d -t trnm-quantum-4cf25c59-XXXXXX)"
python formal/pon-nakamoto-v1/experiments/w1_marked_domain_campaign.py run \
  --output "$QUANTUM_REPRO_OUT/domain.json"
python formal/pon-nakamoto-v1/experiments/w1_marked_domain_campaign.py replay \
  --input "$QUANTUM_REPRO_OUT/domain.json" --output "$QUANTUM_REPRO_OUT/domain-replay.json"
python formal/pon-nakamoto-v1/experiments/quantum_network_campaign.py \
  --out "$QUANTUM_REPRO_OUT/network"
python formal/pon-nakamoto-v1/experiments/quantum_network_campaign.py \
  --verify "$QUANTUM_REPRO_OUT/network"
python formal/pon-nakamoto-v1/experiments/quantum_adversarial_campaign.py \
  --out "$QUANTUM_REPRO_OUT/adversarial"
python formal/pon-nakamoto-v1/experiments/quantum_adversarial_campaign.py \
  --verify "$QUANTUM_REPRO_OUT/adversarial"
python formal/pon-nakamoto-v1/experiments/w1_restricted_oracle_campaign.py \
  --out "$QUANTUM_REPRO_OUT/restricted"
python formal/pon-nakamoto-v1/experiments/w1_restricted_oracle_campaign.py \
  --verify "$QUANTUM_REPRO_OUT/restricted"
```

The exact joint suite was:

```sh
PYTHONPATH=formal/pon-nakamoto-v1:scripts/ci python -m unittest \
  test_reversible_components test_w1_quantum_oracle test_quantum_oracle_resources \
  test_quantum_resource_clock test_quantum_network_sim test_quantum_adversarial_search \
  test_quantum_daa_model test_pq_quantum_daa_scenarios test_parallel_variable_ohie \
  test_w1_marked_domain test_w1_quantum_restricted_oracle \
  test_fast_daa_reference_component -v
```

For the setup witness, run the retained script with `PYTHONPATH` pointing to the
formal directory at each declared before/after source, and pass a fresh output
prefix. For example, using this evidence script from the integration checkout:

```sh
PYTHONPATH=formal/pon-nakamoto-v1 python \
  evidence/pon-quantum-domain-20261104/setup_interruption_witness.py \
  "$QUANTUM_REPRO_OUT/setup-after"
```

The exact research implementation was tested at the frozen source. The final
integration also preserves concurrent historical-account migration work from
`7a88207db3c50d2789787ff3af6f3b8ff7620ac5`. Concurrent native changes do not inherit
these quantum-research results. Large generated reports and campaign traces are
regenerated with these commands; only compact identities and the small setup
counterexample are retained here. Paths inside original observations identify
the original run location, not an additional hosted artifact.


## Small artifact identities

The [reproduction manifest](reproduction.json) retains source hashes, command outcomes,
timings, witness parameters and artifact hashes. These are the observed raw-file
SHA-256 values; the domain replay's canonical-JSON digest excludes its newline.

| Artifact | SHA-256 |
| --- | --- |
| Literal-domain report | `5c2be8064e3ae69589601cbbbdcc04a61e5b507713179ea1bea69206efe173f3` |
| Literal-domain replay | `685ee7cf77a297051165213f2550d86b5fe30c5dfe2a6bd716d54907c941fdf1` |
| Network report | `ee80f359a8eb6c7e4a07b91ff1533caa8daf7160e487109bd021ca279b669a5b` |
| Expanded adversarial report | `b841e77641702657fac751e04e387264295c32efc3e5b630c7c51126951549ee` |
| Restricted-construction report | `d37da6ebb9681090f9b987c3e1c45b21f46ddd971b1d847f0eeb52fd69d16ada` |
| Setup before/after record | `f2dd2fca72eaca4082b48761dd5c55f64b376dd610b8ffb0bd2ee2a9b3a31921` |

## Remaining acceptance boundaries

Constructive gate/qubit/depth counts are upper bounds for particular schedules,
not attacker-minimum costs. Physical error rates, correction overhead, magic-state
factories, routing, memory, controller behavior and quantum clocks remain declared
assumptions without calibrated hardware or a verified fault-tolerant layout.

Literal censuses do not automatically bind the event simulator's evolving
synthetic targets to realizable W1 domains. Uniform/binomial ticket premises,
fresh-domain correlations and reuse policies need their own justification. The
restricted construction may discard legal winners and must use its own marked
count; free filtered state preparation is not supplied.

Attacker-minimal legal costs, full-domain probability mapping, physical
calibration, complete Fast DAA fidelity, OHIE theorem/profile correspondence and
mixed classical/quantum prefix, growth, quality and transaction-liveness arguments
remain open. Native pure-PoN target, chainwork and fork-choice rules are unchanged;
no sqrt(D) or multi-resource score is activated. No original native four-second /
sixteen-hostile-producer acceptance result is inherited from these experiments.
