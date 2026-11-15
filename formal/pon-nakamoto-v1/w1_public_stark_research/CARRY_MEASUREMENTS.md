# Carry backend measurement report — 2026-11-08

**Qualification: HOLD_NO_GO.** The five-lane carry backend reduced the measured
complete research pipeline relative to the prior STARK arithmetic backend.
It did not establish positive end-to-end benefit relative to native W1,
noninteractive/PQ128 security, a universal resource bound, or Node qualification.

## Scope and reproducibility

Two arithmetic candidates preserve all 81,920 original Dot8 relations and the
original complete SHA plan. See [CARRY_BACKEND.md](CARRY_BACKEND.md) for the exact
integer lifting argument, fixed transcript domains and wire-admission boundary.
The full manifests, per-process stdout/stderr, GNU time resource outputs,
execution logs and failure ledger are retained in
[evidence/carry-backend-20261108](evidence/carry-backend-20261108).
[The structured ledger](CARRY_MEASUREMENTS.json) includes all individual samples,
source and binary hashes, parameter shapes and unresolved qualification gates.

Each ABBA run used a fresh process for prepare, both real component proofs,
serialization with persistence, and independent public-preprocessing rebuilding
and verification. No cached or proof-supplied VK was used. The reported pipeline
sums these complete subprocess wall times. It does not include production node
admission or live network transport. Transmission figures are exact serialized
statement-plus-proof sizes, not a bandwidth model.

Each comparison is ABBAABBA: four fresh full W1 proofs per variant on one retained
input. Thus the two comparisons plus the resource-cap check produced 17 accepted
fresh full proofs but only **one independent input task**. The host was not
exclusive. The packed comparison waited until the team's original-profile wire
benchmark completed. Both variants shared eight CPU affinities and Rayon 8;
cgroup controls actually read `cpu.max=800000 100000` and
`memory.max=85899345920`. No sample was discarded, including slow prepare/fsync
observations and the earlier variable baseline. There is no population-wide
confidence or production latency claim from this sample count.

## Packed candidate: measured comparison

A is the original 516-column arithmetic AIR. B is five-lane carry: 370 main
columns, 180 public columns, 16,384 rows, with all 81,920 original relations.

| Median metric | Original A | Packed B | B / A |
| --- | ---: | ---: | ---: |
| Full research pipeline (s) | 23.555767751 | 13.304787172 | 0.564820782 |
| Proof subprocess (s) | 22.579316363 | 12.258656613 | 0.542915313 |
| Independent verification subprocess (s) | 0.930409233 | 0.860259125 | 0.924602954 |
| Proof peak RSS (KiB) | 2,383,916 | 2,029,160 | 0.851187710 |
| Total statement plus proofs (bytes) | 5,264,276 | 5,187,252 | 0.985368548 |

| Run | Variant | Pipeline (s) | Verify (s) | Total bytes |
| ---: | --- | ---: | ---: | ---: |
| 0 | A | 24.009289222 | 0.965830334 | 5,264,276 |
| 1 | B | 13.348682195 | 0.820617069 | 5,187,252 |
| 2 | B | 12.876979858 | 0.880299569 | 5,187,252 |
| 3 | A | 23.102246280 | 0.941953626 | 5,264,276 |
| 4 | A | 24.406064590 | 0.918864840 | 5,264,276 |
| 5 | B | 13.497919350 | 0.885784738 | 5,187,252 |
| 6 | B | 13.260892150 | 0.840218681 | 5,187,252 |
| 7 | A | 22.818513953 | 0.883994004 | 5,264,276 |

The receiver direction improved in both separately retained ABBA blocks:

| Block | Mean pipeline B / A | Mean verifier B / A |
| ---: | ---: | ---: |
| 0 | 0.556671774 | 0.891566694 |
| 1 | 0.566628911 | 0.957370248 |

The arithmetic proving phase is approximately 0.92–0.95 seconds in B versus
10.11–10.76 seconds in A. The SHA proving phase remains approximately 10–11
seconds and now dominates. This is measured complete-W1 work, not decoding time
or theoretical amortization. The packed payload is still 104.780269
times the 49,506-byte original candidate reference. Native receiver economics
and production network behavior therefore remain unqualified.

## Earlier candidate and negative observations retained

The ungrouped carry AIR used 74 main and 36 public columns at 131,072 rows.
Its original comparison is retained with exact source commit
`ac4927c52266e7bd1fae547f92a1d0753f4f96d6`.

- Median pipeline: A 32.328418271 s; ungrouped B 15.541584470 s.
- **Verifier regressed:** A 0.967995241 s; B 1.251528519 s;
  B/A = 1.292907718.
- All four original A pipeline samples are preserved: 44.058103, 32.511755,
  32.145081 and 23.805703 seconds. Their variability is not attributed to a
  demonstrated cause. This was a nonexclusive host.
- Ungrouped payload was 5,039,604 bytes; packed payload is 147,648 bytes larger.
  Packing trades wider per-query openings for fewer trace rows and less padding.
- One initial tool invocation was rejected before any child launched because
  `python3` was not an absolute executable path; the corrected explicit
  `/usr/bin/python3` invocation is separately identified in the failure ledger.
- The cgroup `cpuset.cpus.effective` file was unavailable. That read error is
  retained. CPU affinity was applied by the successful `sched_setaffinity` call.

## Explicit 2 GiB check: one retained fixture only

A separate job read an actual `memory.max=2,147,483,648` and completed a fresh
prepare, two proofs and independent verification. Its cgroup peak was
2,098,737,152 bytes, leaving only
48,746,496 bytes of headroom.
Proof RSS was 2,027,636 KiB; proof wall time was
12.901455769 s; verification was
0.910360378 s. The full cgroup event counters are
retained. This is evidence for this one execution, **not** a global production
memory bound, adversarial rejection bound, or fleet-wide qualification.

## Strict checks and remaining obligations

The source used for the packed runs passed 30 release tests, offline/locked
builds, and release strict Clippy. Tests include maximal and limb-boundary
inputs, every single-lane witness-bit mutation, non-Boolean bits, the prior
Goldilocks whole-dot alias, 2,048 deterministic u128 reference rows, packed final
lane rejection, full original-row identity, and real PCS rejection for changed
goal, VK, opening and the old transcript domain. The retained conditional RBR
estimate remains 63.9538452964 bits and explicitly is not a complete
noninteractive or quantum-security bound.

The added research examples have not yet incorporated the original-profile
wire scanner. Components 3 and 4 require their own fixed-shape allocation and
admission rules. Production Node activation, complete PCS/hash/Fiat–Shamir
lifecycle accounting, global malicious-input resource bounds and the universal
physical cost lower bound remain open. No production verifier was activated.
