# SP27-01: native credit and full-history accounting

This continuation tests one explicit contract on the publication baseline
`5b591754b426c6f88bea6d399fafcd77e31255d8`, after restoring the exact observer
`5e49c682d612c1237d00f2c89e225d3633ee5584`. It adds an opt-in native test and a
process supervisor. It does not install a consensus rule or grant production
qualification. The actual implementation commit, binary, lockfile and run IDs
are frozen in each new run's manifest; this document is not an execution receipt.

## Falsifiable contract

For a fixed maintenance task and legal header/nonce stream, retaining a
`PreparedTask` and recreating it at search boundaries with the same full-generation
implementation must produce identical completed proof and packet bytes, Node
admission, branch chainwork, canonical selection and branch reward state. Both
policies reuse their preparation across misses within a search. A duplicate
packet must not add another block or reward.
Producer attempts that miss, are cancelled, or remain unfinished must remain in
the cost history and cannot be converted into observed ledger credit.

The native code computes each admitted block's branch increment as
`floor(2^256/(target+1))`. This is target-derived work, not an assertion about
producer CPU consumption or an unavoidable algorithmic cost. Admission,
canonical membership, unspendable reward entitlement, and matured account
balance are separate observations.

The protocol already allows cached canonical A/B/product preparation. Cache
permission does not waive a new challenge transcript, current parent/target,
task eligibility, complete proof verification, application execution, roots,
or durable admission. The experiment changes cache retention, not validation
authority. See the existing [work profile](../protocol/pon-nakamoto-v1/details/WORK_PROFILE.md).

## Native path and scope

The explicit ignored test `sp27_cost_attribution_tests::native_credit_observer`
uses the original `Node::prepare_from_matrices`, `Node::admit`,
`Node::activate_observed`, `Node::exact_packet_observation`, `Node::state_at`
and `Node::read_active` paths. Both paired strategies use the same
`PreparedTask` implementation and separate Node stores. All header preparation
is a distinct fixture cost owner, including the preparation performed inside
the native candidate constructor. It is included in the total history rather
than hidden as a free setup step.

The fixture uses `native-public-evaluation-dev-v1` and the ordinary development
fee profile. It has no independent business-demand witness or market-valued
reward. Local exact-packet observation does not establish independent History
confirmation or finality. Unchanged production activation flags remain false.

The cases cover duplicate admission, equal-work sibling activation, a heavier
fork, reward maturity and reorganization, a clean Node reopen, native partial
generation cancellation, and a genuinely terminated partial attempt. The
state-root negative control rebinds the changed header challenge and generates
a fresh complete target-hitting proof before asking Node admission to refuse
it. It is a separate negative-control workload.

## Reproduction

Use a clean checkout of the implementation commit from the run manifest and
the repository-pinned Rust toolchain. First run the normal boundary check:

```sh
bash scripts/project-preflight.sh
cargo +1.95.0 test --manifest-path trillionnium/Cargo.toml --locked -j2 \
  -p trnm-pon-node --lib --no-run --message-format=json > build.jsonl
```

Select the `compiler-artifact` record with `profile.test=true` and the
`trnm_pon_node` library-test executable. Retain the build command, exit status,
compiler version, executable digest and complete build log. Then run:

```sh
python3 scripts/research/sp27_01_native_credit.py \
  --repo /absolute/clean/checkout --binary /absolute/native/test-executable \
  --output /absolute/new/run-directory --run-id sp27-01-native-credit-run-01 \
  --source-sha IMPLEMENTATION_SHA --source-tree IMPLEMENTATION_TREE \
  --timeout-seconds 1800
```

The supervisor freezes four process modes before launch: full, cancel, fail
(the explicit rejection control), and unfinished. It synchronously records
each process start, actual exit, original timeout or termination request,
inclusive child CPU counters, stdout/stderr hashes, and native event hashes.
The unfinished mode first syncs a marker from inside an actual partial proof
generation; the supervisor sends SIGTERM only to its own new child process
group. An unfinished attempt has no fabricated end event or zero completion
cost. Failed builds, unexpected exits and timeouts remain in the run record.

## Recorded functional execution

The first formal supervised execution is `sp27-01-native-6811a88764ac-01`:

| Identity | Value |
| --- | --- |
| Experiment source | `6811a88764acc5f3cab73c7d2c18176370067ece` |
| Experiment tree | `6661f20faa885061dcc6ea490a2b1badeded67bf` |
| Executable SHA-256 | `569a229499f068d00c5a8115826686b3f030285ee8b40bd596f6af2660f42535` |
| Supervisor manifest SHA-256 | `d4389678c316d1869915980b443e00101dc392eee689baf4c2ebfe4199f9163e` |
| Execution receipt SHA-256 | `c22a980910dc236ce5ef196d9e45b655e9106336e2ddca702bfb0618e246582a` |

The actual Cargo artifact uses the test profile with optimization level 3,
debug assertions and overflow checks enabled. It is not a release-profile
performance experiment. The three `full`, `cancel` and `fail` processes returned
zero. The `unfinished` process durably reached the native partial-attempt marker
and returned `-15` after the supervisor's planned SIGTERM. All four registered
process outcomes matched the declared control, and source and executable
identities were unchanged at the recorded bookends. `fail` is an expected native
ROOT rejection control, not an unexpected process crash. The unfinished control
does not perform a post-kill Node ledger readback.

The original Papers consumer, SHA-256
`09c20c73b91383b5740c0537d659240cc11d28b3da81168bb215db1524b9c82f`,
read this actual run and returned zero on its first invocation. It also invoked
the exact pinned SP27-06 reader. The full raw run, consumer outputs and their
manifests belong under SP27-01's `native_credit_v1` evidence directory in the
Papers delivery. A local reader pass is not an SP27-02/06 owner acknowledgment.

The exact-source nine retained legal-attempt controls executed and passed.
Formatting, strict Node library/test Clippy and 43 source-integrity rejection
controls also passed. The remote experiment used a sparse checkout: its whole
repository source guard refused the hidden entries, and that failure is retained.
The separately declared materialized build-scope check covers 4,765 entries.
A separate complete local checkout at the same experiment SHA passed the
unmodified whole-source checker over 27,893 entries / 2,553,972,961 bytes.
These are different source-check observations. Neither is a hosted-CI receipt;
the draft PR's actual workflow runs and exact head must be reported separately.

## Consumption and research decision

The paired packet bytes, complete JSONL event stream and Node state snapshots
are the functional and accounting evidence. Stage clocks and inclusive process
CPU have different scopes and must not be added. A missing stage CPU measurement
remains null. These runs are diagnostic and do not qualify a speedup, energy
reduction, attacker profit, useful-computation gain, or physical cost lower bound.

SP27-01's consumer checks belong in its own Papers research directory. An
adapter may pass lifecycle/cost telemetry to the fixed SP27-06 reader, but
must not invent business transaction IDs, confirmation flags, or received
interfaces. Local reader execution and Agent 02/06 owner acknowledgment are
separate statuses. Shared catalog changes are requests to the coordinator.

The historical 28,792 attempts and 18,380 attempts omitted by success-only
session selection remain attached to the original source and raw archive.
Their 63.84% ratio is a count omission, not a CPU saving. Unless this native
continuation finds a new significant mechanism, counterexample or theorem,
the scientific disposition remains **INTEGRATE into SP27-02/06**, with no
independent-paper GO.
