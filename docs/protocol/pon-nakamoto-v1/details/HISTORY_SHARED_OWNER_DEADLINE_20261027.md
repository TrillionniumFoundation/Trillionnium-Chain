# Native History shared owner and deadline continuation

Base: PR #498, `4b6b8a91b6dfe41fbd7f40f40b359d535c2c4251`.
This is an implementation continuation under the existing development plan.
Production activation, PoN/PNW1, target/chainwork, signed domains and persistent
schema are unchanged. It provides no public readiness or independent acceptance.

## Implemented boundary

`ingress/history_import.rs` is the single paid History importer used by the
exclusive compatibility API, new shared public API and pinned-peer importer.
With a shared Node, CPU refill, packet decoding and complete native W1 replay
run outside the Node mutex. Context/permit checks, native M06 plus durable
commit, activation and epoch metadata still use the original writer. Ordinary
prechecks reuse V3's existing bounded header path; final native admission
repeats full parent, state, clock and owner-policy checks. A candidate parent
may be a valid competing branch, not only the current active tip.

Each History scope holds its own reference to the existing ordinary active
epoch. The first importer cannot clear the marker while another importer or
V3 listener still owns it. Each scope settles its own actual CPU operations;
the last close checks the complete account before removing the marker. Other
live reservations do not falsely make an earlier scope's close unclean.
An unwind or failed epoch close fences the same account and retains the
marker. No per-peer, per-port, per-page or restart credit is introduced.

The #498 continuous-mode denial remains explicit before paid native work:
`OWNER_CONTINUOUS_HISTORY_DURABLE_REQUIRED`. A scalar CPU reservation is not
the continuous owner's operation-ID journal, and this change does not claim
to implement that missing authorized durable import scope.

## Deadlines and completed facts

The existing one-page wrappers have a 30-second local deadline. Sync helpers
and CLI sync use one 300-second business deadline across all pages. Public
V2/V3 and authenticated History RPC phases only shorten their existing network
limits to that original deadline. Decode, refill, W1, M06 checkpoints and
writer acquisition never renew it per packet or phase. Explicit shared/before
APIs allow the local caller to supply an earlier business deadline.
An individual refill wait is additionally capped at two seconds so a depleted
peer cannot occupy the poller's entire runtime; that cap never extends the
original deadline and does not hold the Node writer.

Deadline cancellation is not invalid PoN work. Settlement and epoch cleanup
still run after cancellation. A completed native commit remains committed,
including when activation, CPU accounting or reply completion later fails.
SQLite/fsync and other indivisible sections are not hard-preempted; this is
not a claim of zero deadline overshoot under kernel or storage stalls.
If a shared writer cannot be reacquired for cleanup within the original
deadline, the original CPU account is conservatively fenced and the durable
marker retained. Automatic recovery from that held scope remains unimplemented.

## Native controls added

- Expired ingress cannot create a CPU account or durable epoch.
- Decode cannot restart the original W1 deadline.
- Actual cold-credit refill and mid-transcript W1 checkpoints permit concurrent
  access to the same Node mutex.
- One importer cannot clear another import's live epoch.
- Concurrent false Product, valid-W1/wrong-State-ROOT and honest work share
  the same original CPU account; invalid blocks never become stored facts.
- A separate test process is SIGKILLed at four source-controlled cuts:
  after the durable marker, halfway through actual W1 transcript replay,
  after native block commit but before CPU settlement, and after activation
  but before its settlement. Cold reopen must reject new credit at every cut;
  block/active-tip facts survive exactly where the original commit occurred.

SIGKILL is an abrupt process test, not a physical power-cut or disk-controller
durability certificate. The test hook exists only in Linux test builds and
cannot be selected by a remote request or a production environment variable.

## Reproduction and existing qualification gaps

Use the pinned Rust 1.95.0 toolchain and original lockfile:

```sh
bash scripts/project-preflight.sh
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib history_import -- --test-threads=1
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib ingress::tests -- --test-threads=1
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib peer_polling::tests -- --test-threads=1
```

The first real build exposed inherited test fixture mismatches: six
`PublicDispatchObservation` constructions omitted `w1_rejection_cache`, and
two private History callers still expected the older five-argument helper.
Those fixtures are repaired without disabling accounting or adding a public
addressless import API. Build/test observations must be read from the matching
local validation record, not inferred from these command examples.

The first wider History regression also exposed #498's failing remote-error
identity control: `Error::remote` changed the kind but retained a typed local
code parsed from peer text. Remote text now has no local `ErrorCode`; its exact
wire/display text is retained. Authenticated terminal/retryable status keeps
its separately controlled constructor. The original failure is retained in
the validation record; strengthening this boundary does not authorize retry
or convert a local dependency failure into invalid work.

M06/SQLite remain under the writer. Full original A03 hostile modes, sustained
load, honest fairness under a stated adversarial arrival envelope, physical
Host/power-cut qualification, cheapest GPU/ASIC attack cost and independently
administered WAN acceptance remain open. A finite local concurrency test does
not close those gates. No hashcash, stake, bond, whitelist or voting committee
is added as PoN block eligibility by this change.
