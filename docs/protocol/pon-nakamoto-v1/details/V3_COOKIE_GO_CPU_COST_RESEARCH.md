# P2 — measured W1 / synthetic V3 Cookie CPU cost (Go reference)

Status: **experimental, bounded, unqualified; protocol and native Rust unchanged**.

The executable `formal/pon-nakamoto-v1/go_w1_oracle/cmd/pon_w1_cost/main.go`
uses the existing independent Go W1 mathematical evaluator to compare real
complete useful-work search, successful work replay, fabricated-ticket search,
full false-TRANSCRIPT rejection and exact V3 leading-zero SHA256 search
**on the same canonical zero A/B and final challenge**.

The Go CPU source is Linux `getrusage(RUSAGE_SELF)`, including all Go runtime
threads and garbage collection; intervals may be null when unavailable.
Elapsed wall time is never substituted. The harness records the exact W1 task,
challenge, target, proof SHA256 digests, all attempted W1 and fake trials,
successful/capped Cookie trials, and full search CPU. The Cookie ID is a
**synthetic 32-byte deterministic digest**; this does not perform the signed
V3 HMAC/server handshake, network I/O, GPU mining or original Rust M06 admission.

## Exact original-source instructions

On a checkout of this branch:

```sh
bash scripts/project-preflight.sh
cd formal/pon-nakamoto-v1/go_w1_oracle
GOTOOLCHAIN=local GOPROXY=off go test ./... -count=1
GOTOOLCHAIN=local GOPROXY=off go run ./cmd/pon_w1_cost \
  --samples 3 --work-cap 32 --false-cap 128 --cookie-cap 262144 \
  --out /new/unique/pon-w1-v3-go-cost.json
```

The output file is created exclusively and never overwritten. Input caps
enforce finite cost; exhausted W1/fake proof searches return a failure, not a
synthetic success. Cookie exhaustion is recorded as capped and never given
a made-up price ratio. No target, signed resource profile, ledger operation,
total effective chainwork or production flag is changed.

## Local Go 1.23.2 / Linux-amd64 actual CPU observation, 2026-10-25

Three finite samples on one non-exclusive model workspace.
Go source was locally formatted and tested, then published to this research
branch. Local source Git blob identity matches the new GitHub
`cmd/pon_w1_cost/main.go`; test file Git blob identity also matches.
Reported timings are **not** an exact-source native Rust W1 or signed V3 result.

| Sample | Complete false W1 reject | Fake from-zero search | 8-bit Cookie search | 12-bit Cookie search | 16-bit Cookie search |
| --- | ---: | ---: | ---: | ---: | ---: |
| 0 | 2.497 ms | 0.002 ms | 0.075 ms (339 trials) | 3.032 ms (7,711 trials) | 4.959 ms (14,287 trials) |
| 1 | 2.806 ms | 0.003 ms | 0.058 ms (273 trials) | 0.258 ms (1,090 trials) | 20.073 ms (64,108 trials) |
| 2 | 2.436 ms | 0.002 ms | 0.054 ms (249 trials) | 3.612 ms (12,888 trials) | 23.429 ms (73,495 trials) |

Same-run honest full W1 searches (all failures included): 5 attempts /
13.794 ms, 1 / 2.665 ms and 1 / 3.357 ms. All three complete false
proofs passed the cheap precheck and were rejected by exact W1 mathematical
replay with `Transcript`. All three valid proofs passed W1 verification.
Process CPU includes Go runtime and allocation effects, which explain why
warm-up/GC can change timings materially. Do not infer a universal
hash-to-CPU conversion or hardware-independent cost floor.

Raw local JSON SHA256:
`9e6896c21e3548e3394038e9b6911d66292f22bd5ae7b9318c5ab7b506492637`.
The local artifact remains separate from repository-truth certification and
requires independent host/cgroup/provenance verification before promotion.

## Acceptance interpretation

1. 8-bit tickets cost considerably less than one complete Go W1 rejection
   in all three samples, allowing significant local validation amplification.
2. 16-bit tickets were costlier than one Go W1 rejection in these **three**
   individual software samples, but an attacker using GPU/ASIC or batching
   may pay far less, while honest clients may need more.
3. 12-bit results vary: no acceptable default follows from three samples.
   Real Cookie issuance, proof-body validation, memory/queue competition,
   honest signed request rates and cross-process host budgets are omitted.
4. Repeating a valid security ticket across distinct receivers, loopback
   relays or application calls is a distinct issue from a per-receiver CPU
   price; #339 studies the receiver-local approach separately.

**P2 remains OPEN.** Before an actual price can be recommended, freeze same
hardware/GPU, honest/attacker work and production binary, selected difficulty,
all failed attempts, packet network overhead, 2-second Cookie lifetime,
legitimate authorization/clock costs, original host budget and honest failure
rate. Compare a complete cumulative attack budget, not just CPU ns per proof.
P0 native Rust, P1 full Host ownership, P3 mixed hostile traffic, P4 A03 3×3×3,
P5 sound/efficient W2 and P6 independent cryptography are also OPEN.


## Additional 64-sample bounded CPU cohort, 2026-10-25

The Go diagnostic was extended from at most eight to at most **64**
sample indices, while retaining the same work cap 32, false-search cap 128,
Cookie cap 262,144, fixed zero task, deterministic seeds, Go code paths
and explicit capped status. Local source file Git Blob:
`b416cdb6988e8ff81a6f447e251961e5226d4f11` (matches the
published updated Go source); the tests passed before this collection.

```sh
GOTOOLCHAIN=local GOPROXY=off go run ./cmd/pon_w1_cost \
 --samples 64 --work-cap 32 --false-cap 128 --cookie-cap 262144 \
 --out /new/unique/go-w1-cookie-64.json
```

All 64 cases' correct original W1 proofs were generated/verified and all
64 false transcripts were rejected as `Transcript`; the ratio does not
count a fabricated ticket as chainwork. The same 64 false receiver samples
had median **3.442 ms process CPU**. Cookie CPU values include all attempts
and do not replace any capped search with a fake winning record.

| Cookie bits | Valid observed ticket successes | Median actual process CPU | Minimum–maximum successful ticket CPU | Median observed full fake-W1 reject / (fake search + Cookie CPU) |
| --- | ---: | ---: | ---: | ---: |
| 8 | 64/64 | 0.056 ms | 0.002–3.760 ms | 66.56 |
| 12 | 64/64 | 1.051 ms | 0.020–22.272 ms | 3.96 |
| 16 | 63/64; **1 capped** | 34.024 ms (63 successes) | 0.171–2,211.906 ms | 0.114 |

For 16-bit, the *capped* case consumed all 262,144 hashes, was retained
as `capped=true` and excluded only from the **conditional on success**
CPU median. It remains in the complete 64-case raw JSON denominator.
The unusually high measured process CPU for a successful 16-bit case is
also retained. Go process CPU spans all runtime threads and is not
the V3 server's per-client thread clock; a process CPU value above two
seconds is not by itself evidence of the signed 2-second V3 wall-clock
expiry, especially under unrelated concurrent scheduling.

The new local JSON object is **137,098 bytes**, SHA256:
`2041ba86799e02a340c6152c2b4573f5f990f6850f18a8e07e8006182c66586b`.
This is a single unprivileged Go-on-Linux environment, not a second
independent hardware domain. No GPU, signed-cookie issuance, actual native
Host cgroup, attack bandwidth, consumer SLA or A03 service run was
measured. There is no justified difficulty-selection verdict and P2
remains **OPEN**. Original per-host attack/honest CPU/GPU equal-budget
calibration is mandatory before any signed policy revision.
