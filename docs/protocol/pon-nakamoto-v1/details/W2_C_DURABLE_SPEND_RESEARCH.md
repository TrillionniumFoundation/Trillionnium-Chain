# W2-C durable paid-spend ownership across cloned local processes

Status: **research-only / HOLD_NO_GO**. Exact parent is Chain PR #339 at
`2787ad3959359bc5377d982a7ab46a2d76d44e0e`. This adds a candidate
durable *resource-admission* experiment, not a consensus profile, W1 replacement,
signed V3 protocol change, Chainwork credit, model reward or activation.

## Actual cloned-epoch counterexample

`w2c_stateless_receiver.StatelessReceiverAdmission` binds a server
HMAC/receiver/process epoch/caller/proposal/ticket and tracks exact paid
grants in an **in-memory** map. If a second process starts with a clone of
the same receiver credential and epoch but an empty map, the old paid ticket
can again return READY and trigger costly invalid W1 replay. The original
red test remains and must not be deleted.

The new optional `w2c_durable_paid_claims.DurableStatelessReceiver`
derives from the research stateless admission verifier and binds all granted
resource consumption to one SQLite WAL-backed paid owner.

- One trusted operator provisions the database **once**, in an owner-only
  directory with an owner-only regular file, through
  `provision(absolute_path, receiver, epoch, capacity=..., lifetime_ms=...)`.
  Re-provisioning over an existing database is rejected, never treated as
  an empty new epoch.
- The database holds a single policy row binding original **receiver,
  epoch, 1..1024 maximum concurrent paid claims and exact grant lifetime**.
  Processes with larger capacity, a different epoch or altered live policy
  fail closed. DB schema version, file mode/link count and clock watermark
  are checked rather than invented after a crash.
- The original stateless HMAC, proposal/caller, expiry, ticket target and
  strict encoding checks remain mandatory before a resource ticket can be
  claimed. This is NOT an independent verifier of cryptographic arithmetic.
- The accepted claim's exact SHA-256 identity is written in a SQLite
  `BEGIN IMMEDIATE` transaction, with `synchronous=FULL` and a WAL
  journal. Atomic uniqueness and an unexpired-row capacity test are carried
  under the same database write lock **before the caller can begin W1**.
  Failed verification does not refund a spent grant. A process exit after
  commit but before W1 never grants the same claim again.
- Storage failure, busy/locked owner, unknown commit outcome, schema or
  policy change fail closed as a **local resource refusal**, never as
  consensus-invalid W1 or a new Chainwork claim. The service does not
  silently recreate a lost DB or widen resource limits. A DB high-watermark
  disallows clock regression among processes accessing the same owner.
- A separate independent process that copies the credentials **AND
  uses a different database** can still accept the same ticket. This is
  an explicit negative test. One local SQLite file does not prove unique
  authority among permissionless operators, remote hosts, other file
  namespaces, or a compromised privileged storage administrator.
- The path checks are research-only and are not a hardened production
  directory/file-descriptor capability: there remains a TOCTOU window
  between checking a pathname and SQLite opening it. No WAN, user-supplied
  path, untrusted local filesystem, shared NFS or remote DB placement is
  authorized by this prototype.

## Executable local controls

```sh
python3 formal/pon-nakamoto-v1/test_w2c_durable_paid_claims.py -v
```

The 13 cases cover a real separate-process pool with 12 concurrent/contending
submissions (exactly one READY), restart and replay, abrupt process exit
after **durable commit before W1**, capacity exhaustion, cloned key plus
different DB as a **deliberate replay vulnerability**, persisted clock
high-watermark, changed policy/schema/capacity/epoch, missing file,
symlink/path ownership, changed authenticated caller and fail-closed outcomes.

In this assistant execution environment, 13/13 local tests completed.
The generated source and test bytes were uploaded to GitHub unchanged and their
Git blob SHA-1 values matched the local `git hash-object` output.
This local execution used the original H domain/Grant interface reproduced in
a small test sandbox; it is **not** a full checked-out Trillionnium-Chain,
signed native V3 execution, external reviewer, exact-source Cargo test, measured
W1 verification, cost-hardness qualification or P4 A03 physical campaign.

## Costs, threat boundaries and remaining blockers

Durable SQLite writes add filesystem latency, CPU, WAL disk usage, pressure
on the global write lock and crash/recovery obligations. Under attack, a
full paid table can refuse honest callers, and a GPU attacker may still
spend very little on a valid admission ticket relative to the server's
complete rejected W1. This changes neither W1's mathematical validity nor
proof-of-useful-work cost asymmetry. It is an experimental anti-replay
component, not a ready-to-install second receiver.

P0 must retain all original four false transcripts and exact native Rust
admission invariants. P1 needs physical host-wide verification across V3,
pinned polling, native sync, relay/loopback and independent processes with a
monotonic original owner. P2 needs actual CPU/GPU/ASIC cost and public signed
Cookie calibration. P3 needs sustained malicious peer, rotated identity,
false-trace, valid-work/wrong-StateRoot traffic alongside signed honest work.
P4 requires three runs in each of three attack modes with 3/3 timely
independently verified honest confirmations each run. P5 still lacks a
sound *succinct* W2 proof with qualified economics. P6 still requires
genuinely independent cryptographic review and cross-implementation
adversarial acceptance. No other source or local test can silently close
these dependencies.

Status stays **SHADOW_ONLY / HOLD_NO_GO / production off**.

The 13th test additionally uses the unmodified Python W1 oracle
(`work_oracle.py`, Git blob `9cbfccd2d50af48fc43522b967ffdfb1f45ec098`)
to assert that **paying and durably consuming** a W2-C resource ticket
still produces `TRANSCRIPT` for a complete forged W1 matrix trace, while
the previously paid ticket stays spent after a second local process restarts.

Local evidence captured on 2026-10-27: all 13 tests passed with process
exit code 0. Exact Git blobs: `w2c_receiver_admission.py`
`045700db730d330df05670351fa40a94fe4dd510`,
`w2c_stateless_receiver.py` `8a800f526bbcfddb3308a1966fc4c406ee29c5d0`,
new `w2c_durable_paid_claims.py`
`7b8a51e7912749d4ad284b711e9339f85be8e7fb`, and new test
`cf91d3b9405409cf287b3811d69ab41828e507d2`.
These are local Python observations, not a verified Rust binary or public
A03/cryptographic qualification. Independent database clones remain an
explicit **FAILED** security boundary, not a hidden success.

## Original same-proof CPU overhead research (2026-10-27)

Bounded local command, from a fresh owner-only temporary SQLite WAL path:

```sh
python3 formal/pon-nakamoto-v1/w2c_durable_cost.py \
  --samples 8 --bits 8 --cap 16384 \
  --out /new/unique/w2c-durable-cost.json
```

For each of eight unique, valid 8-bit resource tickets under one fixed
synthetic header/challenge/task and **identical false W1 proof**, the experiment
records every hash search, an in-memory baseline consumption, a durable
`BEGIN IMMEDIATE`+FULL synchronous consumption, one unmodified Python
W1 oracle `TRANSCRIPT` rejection, and another process-local admission
instance refusing exact replay against the durable paid record.

| Stage | Local Python CPU median | Local wall median |
| --- | ---: | ---: |
| In-memory stateless paid consumption | 0.026 ms | 0.026 ms |
| SQLite durable paid consumption | 2.017 ms | 6.908 ms |
| Full fake-W1 Python oracle rejection | 121.068 ms | 121.300 ms |
| Replay check after new local receiver instance | 2.248 ms | 2.250 ms |

Observed per-ticket hash attempts were 532, 127, 1145, 121, 172, 144,
466 and 18; all eight passed their ticket cost then still failed full
W1 with `TRANSCRIPT`.

These **single-host, nonexclusive, Python-only** measurements must not
be compared as if they were matched with the previously reported Rust
full-replay costs. In particular a ~7 ms fsync/wall delay may be larger
than the entire native W1 invalid rejection on faster kernels, harming
honest queue latency even if replay is fenced. This prototype therefore
must **not** be inserted directly into the native V3 public path.
Prospective research must compare a carefully bounded single durable
writer, group commit with *no READY before durability*, or a
kernel-enforced immutable epoch with trusted hardware ownership.
None of those is implemented or accepted here.

No GPU/ASIC price, public transport, actual Rust native W1 budget,
multi-host WAN, Source A03 original-service 3×3×3 outcomes or
independent cryptography acceptance is conferred by these numbers.
