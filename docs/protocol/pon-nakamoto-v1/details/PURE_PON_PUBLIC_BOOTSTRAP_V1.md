# Explicit pure PoN public bootstrap and rejection filter

`public-pure-pon-development-v1` is a separate signed resource namespace for
the existing PNH1/W1 development node. Select that name explicitly on both server
and client. Its acknowledgement nonce is exactly zero; the client performs zero
transport hash-search trials. Nonzero `--admission-bits` with this name rejects.
The historical public V3 profile keeps its original defaults and digest; selecting
its name with zero bits rejects in the CLI. A failed pure-profile call never retries
using a historical profile. This is a development transport and finite validation
repair, with public-network, useful model work and work-hardness acceptance false.

## Existing authority and budgets

Any new caller key can fetch the public genesis maintenance task and submit W1.
The caller signature binds a connection and body; there is no caller allowlist,
stake, committee or additional hashcash work threshold. The original common CPU,
connection, grant, queue, byte, deadline and crash-fence limits still apply.
Listeners for the same Node share the existing owner and pools, and a cold owner
starts with zero mutation CPU credit. Local budgets bound served resources; they
do not prove public fairness or an adversarial sender/receiver cost ratio.

The exact fixed genesis A, B and independently computed AB can be retained as
one bounded local fact (about 49 KiB per listener). A mismatching public product
is rejected before full W1 transcript replay. A match confers no work, task,
completion priority or execution authority: original full W1 and native admission
still run. Unknown tasks use the original path. A correct C with a fabricated
winning trace still needs the original transcript rejection; this important
attack class is not repaired by the product filter.

## Public material and explicit selection

The new read operation 9 returns `pon-public-genesis-task-bootstrap-v1`. The
bundle includes exact public matrix bytes, task, work/task profile, network,
parameters, genesis, maintenance purpose, zero useful-output credit and false
hardness acceptance. A receiver checks every field against its already pinned
Settings; a remotely self-consistent object cannot select another genesis or
mint a task. The bounded file form is canonical JSON, at most 128 KiB.

`public-task-export` creates the same bundle locally, while `public-task-fetch`
obtains it from a pinned server using the explicit pure profile. `mine` and `make`
accept `--public-task-bundle FILE` and reuse the existing native maintenance
producer. Combining this option with task bootstrap, a signed task file or
`--consensus-maintenance` rejects; an expired/invalid selected signed task is
never automatically replaced. Output files use create-new semantics.

This exposes the already existing revision-12 continuity task. Its indefinite
public availability supplies development chain continuity, **not new useful
neural demand**. Permissionless useful neural task registration still needs a
typed registry, task-admission and demand/evaluation rules; no source or model
quality qualification is inferred here.

## CLI example

Build the existing `trnm-pon-node` binary with the repository's required Rust
toolchain. In the commands below, `NODE` is its absolute executable path;
`GENESIS` is the same pinned Unix timestamp for every participant. `SERVER_KEY`
and `CALLER_KEY` name locally owned mode-0600 files containing 32-byte hexadecimal
development secrets; `SERVER_PUBLIC` is the pinned server public key.
`POOL_POLICY` is the existing local pool policy file described by the native
pool contract, and does not contain a caller roster. Choose fresh output paths.

Start the listener (replace the loopback address with a separately qualified
deployment only after satisfying the existing host-kernel requirements):

```sh
"$NODE" serve --development --store receiver --genesis-time "$GENESIS" \
  --evaluation-policy native-public-evaluation-dev-v1 \
  --task-profile consensus-maintenance-continuity-dev-v1 \
  --public-development-network --listen 127.0.0.1:19091 --seconds 120 \
  --pool-policy "$POOL_POLICY" --auth-secret "$SERVER_KEY" \
  --admission-profile public-pure-pon-development-v1
```

Fetch and verify the exact public task, generate real W1 and submit it:

```sh
"$NODE" public-task-fetch --development --genesis-time "$GENESIS" \
  --evaluation-policy native-public-evaluation-dev-v1 \
  --task-profile consensus-maintenance-continuity-dev-v1 \
  --peer 127.0.0.1:19091 --auth-secret "$CALLER_KEY" \
  --server-public "$SERVER_PUBLIC" --output public-task.json \
  --admission-profile public-pure-pon-development-v1

"$NODE" mine --development --store miner --genesis-time "$GENESIS" \
  --evaluation-policy native-public-evaluation-dev-v1 \
  --task-profile consensus-maintenance-continuity-dev-v1 \
  --public-task-bundle public-task.json --output mined.packet

"$NODE" push --development --genesis-time "$GENESIS" \
  --evaluation-policy native-public-evaluation-dev-v1 \
  --task-profile consensus-maintenance-continuity-dev-v1 \
  --peer 127.0.0.1:19091 --auth-secret "$CALLER_KEY" \
  --server-public "$SERVER_PUBLIC" --packet mined.packet \
  --admission-profile public-pure-pon-development-v1
```

The fetch report must show `transport_hash_trials: 0`; a completed push must show
`solve_trials: 0`. These counters cover transport acknowledgement only. The
actual W1 producer still performs its original challenge-dependent neural-work
relation and ticket search. A valid task does not guarantee an accepted block:
parent, time, target, execution and branch checks remain authoritative.

## Validation scope

Tests exercise exact-C late-rejection savings with the unchanged production
verifier, correct-product/false-transcript refusal, signed cookie and response
isolation in both namespace directions, a pure client refusing a real legacy
cookie before acknowledging without a second connection, and actual two-listener
TCP fetch/mine/reject/admit/cold-reopen. The actual CLI integration test checks
fetch, file equality, native mining, pure push and incompatible profile refusal.
These finite tests do not establish 72-hour adversarial WAN liveness, task
non-amortization, energy costs, ML improvement or production activation.

The separate [finite cost and ingress campaigns](PURE_PON_COST_CAMPAIGNS_V1.md)
retain the fixed strategy matrix, all attempted work, unique false-trace floods,
honest interleaving and cold-reopen observations without upgrading those claims.
