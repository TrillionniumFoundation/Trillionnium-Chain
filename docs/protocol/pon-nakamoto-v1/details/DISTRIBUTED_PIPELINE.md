# Separate native development roles and full local confirmation

This is an implemented caller interface, not a second development plan. The sole
engineering sequence remains the [development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
Public, production, hardness and independent-operator acceptance remain false.

`trnm-pon-node --example distributed_pipeline` has three entrypoints:

```text
distributed_pipeline fingerprint
distributed_pipeline run PRIVATE_CONFIG_JSON
distributed_pipeline resume SAME_PRIVATE_CONFIG_JSON
```

The producer, authenticated validator and full-sync confirmer run as three separate
processes with separate durable owners. Actual physical-host placement and native LAN
routing must be observed by the external controller. A local-process test explicitly
records that scope and cannot grant LAN or independent-operator acceptance.

The producer constructs canonical signed tag1 transfers, explicitly uses the existing
signed genesis maintenance task, completely verifies and admits its own packet, activates
it and sends it through the existing authenticated protected Submit. The validator uses
`serve_authenticated_protected`; the confirmer obtains a signed Head, independently
receives and verifies every history packet through the native owner, and calls its own
`Node::confirmations`. Server-provided chainwork or confirmed booleans never substitute
for the confirmer's local work, state, transaction membership or depth/work checks.

## Strict configuration

JSON duplicate/unknown fields reject. The exact fields are:

| Field | Contract |
|---|---|
| schema | `pon-distributed-role-config-v1` |
| role | `producer`, `validator` or `confirmer` |
| scope | `lan-development` or explicit `local-process-test` |
| run_id | 1..64 ASCII letters, digits, underscore, hyphen or dot |
| run_root | absolute, new directory for `run`; same original directory for explicit `resume`; distinct for each role |
| source_pin | exact `commit`, `tree`, `inventory_digest`, `binary_digest` from that role binary's fingerprint |
| genesis_time | common positive UTC seconds, not in the future |
| workers | 1, 2, 4 or 8 |
| evaluation_policy | `closed-round-all-eligible-min-v1` or `native-public-evaluation-dev-v1` |
| task_profile | explicitly `signed-task-dev-v1`; no legacy fallback |
| pattern | `hot` or `disjoint4` |
| data_blocks | 1..128 |
| transactions_per_block | 1..256 |
| drain_blocks | 6..32; total height no more than1000 |
| pace_ms | 0..60000; LAN requires at least1000 |
| server_seconds | 1..3600, greater than the scheduled block span |
| poll_ms | 10..10000 |
| timeout_seconds | 1..3500, no greater than server lifetime; in-flight socket operations retain their existing bounded timeout |
| listen | validator SocketAddr; null for other roles |
| peer | producer/confirmer SocketAddr; null for validator |
| auth_secret | dedicated business identity file;64 lowercase hexadecimal digits, optional final newline;0600, regular single-link and no symlink |
| peer_roster | validator's1..64 unique canonical public-key JSON array, at most16384 bytes; regular single-link, no group/other write; null for other roles |
| server_public | pinned validator Ed25519 public key; null for validator |
| session_generation | matching1..i64::MAX on all roles |

LAN scope requires non-loopback, non-unspecified addresses and a nonzero port.
Address selection is a configuration claim; it does not prove that the roles inhabit
three physical hosts. IPs, SSH aliases, secrets and private deployment JSON remain in the
operator's local dataset, never in the public repository. Use management SSH separately
from native application traffic. An SSH tunnel is an explicitly different observation.

All roles must use the same genesis/evaluation/task context and workload identity;
otherwise the native namespace owner or independent business checks reject. Source
pins are per binary: different architectures/builds may have different binary digests,
but the controller must verify the same intended source and chain context.

## Source and receipt binding

Before freezing source, run `python3 scripts/refresh_distributed_source_inventory.py`,
then its `--check`. It embeds the exact retained Rust source, Cargo graph and configuration
bytes. Adding a native source file requires refreshing this inventory before commit.
For a real LAN build, set `TRNM_DISTRIBUTED_SOURCE_COMMIT` and
`TRNM_DISTRIBUTED_SOURCE_TREE` to the exact clean Git commit/tree before Cargo compilation.
`fingerprint` records those builder declarations, the embedded source inventory and the
actual current executable byte digest. The controller must check inventory bytes against
the retained Git tree and verify its clean build procedure. Environment strings alone
are not authenticated compiler provenance or remote hardware attestation.

The four-byte-length domain-separated SHA256 hashes use the existing `TRNM-PON1` helper:
source-file domain `distributed-source-file-v1`, canonical inventory JSON domain
`distributed-source-inventory-v1`, executable domain `distributed-binary-v1` and receipt
body domain `distributed-receipt-v1`. These are not ordinary `sha256sum` values.

Each role retains `fingerprint.json`, exact original `config.json` bytes, all locally verified active packets, its own
SQLite owner and `receipts.jsonl`. Receipts bind source, binary, run, role identity, chain
profile and workload; a monotonically increasing sequence and previous receipt digest
form a signed hash chain. Every attempted request and failure remains recorded. No
receipt attests independent operation, unavoidable work, neural benefit or public readiness.

The confirmer verifies the exact planned signed transfer workload, packet heights and
transaction IDs after full native admission. It separately reports local confirmed count,
active state root, height and locally derived cumulative work. Completion requires every
submitted transfer locally confirmed and the exact expected data/drain height. Validator
completion also requires the entire planned workload; expiry or premature shutdown fails.
The external controller must compare all three final tip/root/height/work identities and
retain the full signed receipts, raw packets and immutable database bytes for replay.

## Explicit owner recovery

`run` requires a fresh role directory. `resume` requires the existing original store,
packet directory, byte-identical configuration and fingerprint, the same role identity
and session generation, and a byte-identical validator roster. There is no hot source,
identity, workload, clock-context or profile upgrade. Completed finite roles reject
resume; a fresh process cannot extend this task window or reset the campaign history.

The receipt journal is opened without following a symlink, requires a regular
single-link private file and is exclusively locked throughout validation and append.
Every newline-terminated row must have canonical encoding, exact expected run binding,
sequence and previous digest, and a valid strict Ed25519 signature. Any completed
malformed, blank, reordered or tampered row rejects without rewriting the journal.
An unterminated final row is uncommitted: its exact bytes and an exact full pre-recovery
journal copy are created and fsynced before truncating only that tail. Resume then appends
one `role-resumed` receipt at the next sequence; it never emits a duplicate start header.
The journal limit is256MiB and each completed row is at most8MiB.

Producer packet bytes are atomically retained and fsynced before native admission and
activation. Recovery checks the planned business content of the active ancestry, restores
any damaged copied artifact from the native owner while retaining the failed bytes,
and finishes the exact durable authenticated pending Submit before allocating a new
request. It replays the stored active prefix idempotently to the validator and reuses
any next prepared packet instead of mining replacement blocks. A historical duplicate
acknowledges the exact submitted block; the remote active tip may already be later.
Final three-role tip/root/work comparison remains required. An incomplete prepared
artifact with no authoritative native packet fails closed for owner inspection.

The confirmer first completes its exact pending Head or History request. A History page
still passes the existing native packet verifier and context/cursor checks before the
next request. Partial prefix failure preserves the durable request; it never substitutes
a different request under the same nonce. Observer durations after a restart describe
only the new process segment. Repeated observation of an unchanged verified tip reuses
its local confirmation count and writes no duplicate full confirmation batch; a new or
reorganized tip triggers fresh local membership and confirmation checks.

The `distributed_roles` restart test deliberately kills producer and confirmer processes,
retains the original logs, appends an incomplete receipt tail and damages only a copied
packet artifact. It then resumes the same owners, requires one continuous signed receipt
chain, preserves the failed bytes and obtains all final confirmations from the independent
full-sync store. A separate regression creates a real pending protected Submit, reopens
its durable owner and completes the identical authenticated request.

## Bounds, timing and remaining scope

No consensus rule, work verifier, confirmation policy, public evaluation score or reward
is replaced by this runner. Maintenance earns zero model utility. The fixed16-demand
context and bootstrap height1000 cannot become72-hour/7-day same-chain liveness by
restarting a process or genesis. The lifecycle successor must be explicitly integrated
under its own fresh profile before using it here.

Times describe same-process monotonic durations and local UTC observations. The
confirmer's startup-to-completion duration is an observer duration, not a transaction's
submission-to-confirmation latency. It cannot be subtracted from another host's clock.
No transaction-only RPC/mempool exists in this interface. GPU inference, saturation,
high-state-scale, WAN independence and public attacker economics remain separate gates.

The ignored `distributed_roles` test starts three real OS processes with three separate
stores, checks native history verification and local confirmation, matches final roots/work,
and verifies signed receipt chaining and tampering rejection. To execute it deliberately,
build the example, provide `TRNM_DISTRIBUTED_TEST_BINARY` and an unused absolute
`TRNM_DISTRIBUTED_TEST_OUTPUT` outside the repository, then run:

```text
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test distributed_roles -- --ignored --nocapture
```

This retained conformance test has local-process scope. A successful result is not a
measurement of three physical machines or an independent public deployment.
