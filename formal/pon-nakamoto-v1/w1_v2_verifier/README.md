# Full W1 V2 verification and bounded research workers

This verifier checks the existing complete V2 guest image, the exact public
header, external model/input artifact commitments, complete output and original
WorkID. It generates no proof. It is not a Node ingress and does not authorize
parent eligibility, task permissions, revocations, transaction execution or a
state root. Those checks remain owned by the original Node.

## Local input and rejection types

The CLI opens files with `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` on Unix, checks
regular-file type and size on that same descriptor before reading, bounds the
actual bytes and refuses a changed length. A FIFO without a writer cannot block
at open; a symlink cannot replace the selected final file. Parent directories
and the local filesystem remain trusted inputs. Regular-file kernel I/O is not
a hard real-time guarantee. Unsupported platforms refuse this input path.

Exit codes are deliberately separate:

| Exit | Meaning | Eligible for the research rejection cache |
| --- | --- | --- |
| 0 | Complete pinned V2 research statement verified | No positive cache |
| 20 | Receipt wire format rejected | Exact proof/context only |
| 21 | Public statement rejected | Exact proof/context only |
| 22 | Frozen construction/full cryptographic verification rejected | Exact proof/context only |
| 1 or another nonzero code/signal | Operational failure, resource limit, panic or untyped refusal | Never |

The previous `W1_V2_WIRE_REJECT`, `W1_V2_PUBLIC_REJECT` and
`W1_V2_CRYPTO_REJECT` diagnostics remain. Local profile initialization is checked
before input verification and cannot select a statement-invalid exit code.
Neither error-text matching alone nor any nonzero exit is sufficient for the
supervisor to cache a rejection.

## Research supervisor

[`scripts/w1_v2_supervisor.py`](../../../scripts/w1_v2_supervisor.py) wraps the
single-call verifier. One shared `VerifierOwner` provides the following bounds:

- At most two active requests by default, including snapshot preparation. Each
  reserves the full maximum receipt plus header and artifact bytes before read.
- Before launching a worker, the private receipt snapshot must have the bounded
  12-byte Succinct framing, a nonzero seal count and a seal body fitting the
  actual bytes. These match the Rust decoder's necessary early checks and do
  not replace canonical decoding or full cryptographic verification.
- One finite 8 CPU-second campaign account. Each child reserves its full
  2 CPU-second hard limit before launch; actual `wait4` usage and the owner's
  measured thread CPU are charged before the unused reservation is returned.
  There is no refill or identity-dependent account. An unknown child settlement
  retains its reservation and blocks new work. Its unobserved CPU/start fields
  are null, not zero/false. The CLI persists that result, ledger and retained
  snapshot path before attempting close, and records a close refusal without
  refunding the reservation.
- A default 1 CPU-second soft limit and 2 CPU-second hard limit, 256 MiB address
  space, bounded file descriptors/file output, and no core dump per worker.
  These are kernel `RLIMIT` settings installed before executing the verifier.
- The earlier caller deadline or default three-second request deadline covers
  snapshot preparation, execution and cleanup. The existing
  [`bounded_process`](../bounded_process.py) owner drains bounded streams, sends
  `SIGKILL` to the owned process group while its leader remains waitable, then
  reaps it. A late return does not gain verification or Invalid semantics.
  The original absolute deadline is passed through to that owner; a scheduling
  pause before entry cannot restart it. An already expired call refuses before
  spawn with a distinct known-no-child Deadline result.
- The executable is explicitly SHA-256 pinned and descriptor-executed, with a
  second hash check under the worker's limits. Input copies live in a private
  temporary directory. No caller-supplied proof environment selects a backend.
- A finite TTL cache keys the executable/profile and complete receipt, header
  and external expected-artifact bytes through length-bound SHA-256 hashes.
  It never keys only on WorkID, peer identity or claimed chainwork. `Busy`,
  `Deadline`, I/O failure, abort and OOM never populate it.
  The bounded framing preflight can cache a definite exact-byte format refusal;
  other semantic failures require the typed verifier exit and matching layer.
- Every explicit batch leaf uses the same original deadline/account. There is
  no automatic split, retry, native full-replay fallback or hidden second pool.
  All request shapes are checked and frozen before executing the first leaf,
  so a malformed later request cannot discard earlier paid results.

The returned statuses are `VerifiedResearchStatement`, `Invalid`, `Busy`,
`Deadline` and `OperationalFailure`. `Invalid` only describes this submitted
research proof under the supplied context; `consensus_validity` remains null.
`public`, `history`, `recovery` and `relay` are diagnostic labels with identical
admission rules. They do not establish that the real Node paths are connected.

### Limits of these bounds

This is an isolated Linux research owner, not the existing Node `scalar_cpu`
account. Recreating the owner/process resets this volatile experiment; it must
not be offered as public admission or as durable anti-Sybil accounting. Node
integration must reuse its original owner across all actual ingress paths.

`RLIMIT_AS` bounds each trusted verifier process's address space, not aggregate
physical RSS; `wait4` reports this child and descendants it reaped, not a cgroup
total. The installed verifier is trusted local code, not a sandboxed arbitrary
executable. Same-group descendants are killed, but escaped sessions and
uninterruptible kernel waits retain the existing process owner's limitations.
Networking, parent/task authorization, host restart, durable CPU custody,
whole-machine quotas and public-service availability remain unqualified.
Observed owner CPU is the measured thread scope including snapshot/cache work;
it excludes caller/network work and the final telemetry/settlement bookkeeping.

## Reproduce

Build without any guest compiler or proof generation:

```sh
bash scripts/project-preflight.sh
cargo test --locked --release --manifest-path formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.toml
cargo build --locked --release --manifest-path formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.toml
cargo clippy --locked --release --all-targets --manifest-path formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.toml -- -D warnings
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_bounded_process*.py'
python3 -m unittest discover -s scripts -p test_w1_v2_supervisor.py
```

The supervisor's process/resource tests use explicitly labelled Python fixture
programs. They demonstrate real CPU/memory/pipe/timeout/cleanup behavior, not a
W1 proof. One separate fault injection checks lost wait4/unknown bookkeeping and
result retention; it does not pretend an actual child was launched or reaped.
Independently run the actual saved-proof campaign with the newly built
Rust binary and its externally computed SHA-256:

```sh
python3 scripts/w1_v2_supervisor_controls.py \
  --verifier /absolute/path/to/w1-verify-v2 \
  --verifier-sha256 ACTUAL_BINARY_SHA256 \
  --receipt evidence/pon-w1-full-v2-20261105/succinct.bin \
  --header evidence/pon-w1-full-v2-20261105/header.bin \
  --expected-artifacts evidence/pon-w1-full-v2-20261105/expected-artifacts.bin \
  --out /new/control-directory
```

That campaign first requires the complete real proof to verify. It then checks
late-seal, public-context and wire rejection; exact-byte negative reuse; a good
proof with the same WorkID after a bad proof; and Deadline followed by a new
successful request. All original failed observations remain separate. Passing
this finite corpus is not a global invalid-cost upper bound, a four-second
confirmation result, a W1 cost-security result or production activation.
