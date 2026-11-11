# Typed content graphs and full-state ancestry readback

Status: **candidate implementation / HOLD_NO_GO**. This continuation starts
from #908 at `6ac9a79c2fb37d6102c526c354fe2d448a9f4e6d`. It adds TCG3 and
CMH2; it does not alter CCH1, TCM2, TCC2, CST1, CMG1, existing block IDs,
consensus roots, proof relations or deployment authority. Execution results
belong to the separately source-bound evidence record, not this specification.

The [hash-purpose contract](HASH_USE_CONTRACT_V1.md) distinguishes the protected
event from a generic query exponent. A longer outer digest cannot restore
information lost by an inner digest. Both new interfaces read actual content
and require a new independently retained complete CCH1 expectation. They do
not recover the historical authenticity of an old SHA-256 commitment.

## 1. TCG3: traverse the edges in the verified bytes

[TCG3](../../trillionnium/crates/trnm-data-availability/src/cell/content_graph_v3.rs)
is a new model-node grammar. A node contains a family, one complete payload
CCH1 claim, and exactly five tagged dependency slots in Base, Parent,
Tokenizer, Layout, Runtime order. Each slot explicitly says Absent, Leaf or
Node. Only Base and Parent may be absent. Their absence is a declaration by
the root's owner, not evidence that an old ancestor never existed.

All integers are unsigned big-endian where applicable. The exact node wire is:

| Field | Encoding |
| --- | --- |
| Namespace | Four bytes `TCG3` |
| Family | U8 byte count, then 1–64 ASCII letters, digits, dot, underscore or hyphen |
| Payload | One complete 213-byte CCH1 claim, ModelPayload |
| Five ordered slots | U8 role (1–5), U8 type (0 absent, 1 leaf, 2 node); a present slot has one complete CCH1 claim |

The enclosing node is observed under ModelManifest. Its payload must have the
same profile, instance and generation. Every reachable object uses the same
profile; dependencies retain their own independently committed instance and
generation. Leafs use ModelPayload; child nodes use ModelManifest. Unknown
types, reordered roles, missing required slots, malformed lengths, other
versions and trailing bytes are refused.

`verify_cell_content_graph_v3` accepts an independently pinned complete root
claim and a resolver for complete claims. It first reads a node's exact bytes
and EOF and verifies CCH1. Only then does it decode that node and traverse its
payload and dependency claims. There is no caller-provided sidecar edge list
that can silently omit the descendants of a verified node.

Reserved model-container prefixes, including TCM2/TCC2/TCG3, cannot be passed
off as terminal payloads to avoid this traversal. Arbitrary terminal bytes
still have no automatic executable semantics. In particular this prefix
check does not discover an ELF dependency, Python import, plugin, device
requirement, remote fetch or an arbitrary loader's hidden references.

The verifier keys objects by the entire 213-byte CCH1 record. Within one
traversal a repeated identical claim shares its complete read; the same
profile/kind/instance/generation with a different length or digest is an
ambiguity and is refused. An active recursion cycle is refused. The completed
node cache retains subtree height, so reaching a shared node along a deeper
path cannot evade the depth cap. No observation cache survives into a later
verification call.

Structural limits are caller-selected positive values beneath fixed caps:
256 nodes, 1,792 objects, 1,536 edges, and 32 node levels. Single-object and
total content-byte caps cannot exceed the existing 64 GiB Cell limit. These
are finite logical caps, not evidence that such a large traversal is useful
or affordable. Only small node encodings and four-byte terminal prefixes
are buffered; payloads stream through CCH1's existing 8 KiB buffer.

Every unique object's complete read shares the caller's `ContentReadBudget`.
The resolver opens lazily after the original length-plus-EOF reservation, so
missing-object and open failures are charged as well. Errors do not refund
reservations. The caller supplies cancellation, transport deadlines and
source custody. A successful result means all edges declared by this typed
format were followed and their complete claims matched; it is not an atomic
filesystem snapshot, a model-quality result or a production loader approval.

The result has private construction and no deserializer. The declaration-only
node observation and the older payload/direct-closure observations cannot be
converted into `CellContentGraphReadbackV3`.

## 2. CMH2: commit actual ancestry and every retained State

[The M06 adapter](../../trillionnium/crates/trnm-mvcc-fee/src/content_commitment_v1/history_v2.rs)
streams actual genesis State/configuration and the complete Header, trace and
State/configuration at every height through the selected checkpoint. It
reuses the original bounded CST1/SCF1 encoding. It never substitutes an old
state root or checkpoint locator for those State rows.

The exact content is:

| Section | Encoding |
| --- | --- |
| Archive prefix | `CMH2`, network (32), parameters (32), genesis locator (32), selected checkpoint locator (32), BE64 genesis timestamp, BE64 non-genesis block count |
| Genesis | BE64 encoded length, followed by complete CST1/SCF1 initial State and configuration |
| Each height in ascending order | `HST2`, BE64 height, complete 318-byte PNH1 Header, 32-byte trace, BE64 CST1 byte length, complete State/configuration |

There is no fabricated genesis Packet. Genesis-only archives explicitly have
zero non-genesis entries. The supported genesis grammar, configured timestamp
and actual initial state root must agree. Each entry has exactly the next
height, correct network/parameters, and a parent equal to the preceding
actual Header/trace's legacy block ID. Its actual State must match the
existing configured state-root function. The last complete entry must equal
the selected checkpoint locator. Omission, reordering, duplication or an
unread prefix cannot become a complete archive.

The fresh candidate format admits at most **32 non-genesis blocks** and
**32 MiB of complete encoded content**. A longer branch is refused in full;
there is no implicit last-32-block truncation. Full long-lived chains require
a separately specified bounded continuation or archival format. The adapter
holds immutable references and streams existing row encodings; it does not
allocate a second full history byte string. Cancellation checks include the
final EOF probe. Encoding reads use the original cumulative CCH1 budget;
this budget is not a measurement of preparatory SQL, root CPU or resident memory.

`verify_migration_history_v2` compares a fresh observation with an independently
retained complete CCH1 claim. A checkpoint locator or a claim received with an
untrusted archive is not an independently authenticated expectation. The
opaque history-readback type grants no migration, CURRENT or FinalUse right.

## 3. Actual Node owner

[The Node adapter](../../trillionnium/crates/trnm-pon-node/src/store/migration_history_v2.rs)
uses the existing retained source inside one SQLite read transaction. It
checks namespace, storage context, readiness and source pins, verifies the
actual genesis record and State, and reads every selected retained packet
and reconstructed State. The original `packet` and `state_at` checks remain
in force. A complete-State-unavailable growth backend and unsupported PQ
snapshot configuration are refused.

Before materializing a State, the same transaction checks the complete selected
header chain and admits source dimensions. A snapshot BLOB is at most 32 MiB;
each block has at most 131,072 delta rows; selected active KV has at most 65,536
rows. Keys are at most 160 bytes and individual delta/KV values at most 4,096
bytes. The aggregate admitted snapshot, delta and selected-active-KV source
bytes cannot exceed 128 MiB. Bounded SQL row probes read one extra row to
detect excess and refuse it; they never silently truncate a successful history.
These checks precede the old owner's full BLOB copying and State reconstruction.

The complete traversal also has an explicit caller deadline no more than
30 seconds away, a conservative retained-encoding cap, the 32-block cap, and
final zero-SQL-write/read-transaction checks. Source-dimension admission and
the final CCH1 length-plus-EOF reservation are separate. JSON object allocation,
SQLite pages/sorting, auxiliary owner indexes and repeated replay reads do not
equal the admitted byte count. Individual SQL, JSON and root stages remain
cooperative; the deadline is not hard preemption or a process-memory guarantee.
Error paths release the read transaction. No block, tip, account, source
retirement record or external effect is changed.

A retained side branch is a valid independently selected byte source. Its
successful readback does not imply canonical membership or finality. Packet
bodies are read for their existing consistency check, but **CMH2 does not
commit complete transaction bodies, proof bodies or receipt bodies**. It also
does not newly reverify W1 or replay every transaction. Those stronger checks
remain with the existing authenticated migration and consensus owners.

## 4. Qualification and migration boundaries

TCG3 closes traversal over its supported typed declarations. CMH2 closes a
bounded genesis-to-checkpoint State/header byte archive. Neither result
establishes all live model dependencies, a complete long-chain migration,
historical key ownership, prior-registry timing, source retirement, non-co-
restored freshness, effect/revocation journal migration, or current adoption
authorization. Existing source keys, services and deployed data are untouched.

Actual migration still needs a currently authorized new commitment, independent
owner/recovery pins, explicit obsolete-authority retirement and preserved
liabilities. The required cryptographic reductions, multi-target/preprocessing
model, shared-query accounting and physical attack costs remain separate.
`security_bits` and actual lifetime failure bounds remain null; whole-chain PQ
qualification and production activation remain false.

## 5. Reproduction

The native suites cover multi-level shared graphs, a deep substitution, typed
edge confusion, an ambiguous complete-object identity, shared-cache depth
bypass, EOF/open failures and budget accounting. CMH2 controls cover all
historical State rows, missing/reordered ancestors, inconsistent roots, a
self-consistent replacement that fails the old complete pin, genesis-only
input, the finite bounds, corruption of real retained packet/snapshot/delta
data, fork selection and cold reopen. Synthetic corruption controls do not
constitute a practical SHA-256 collision.

The [independent graph vectors](../../scripts/ci/check_cell_content_graph_vectors_v3.py)
recompute the TCG3 wire and CCH1 digests in Python; the Rust suite consumes the
same committed vector bytes. Existing CCH1/TCM2/TCC2 vectors remain unchanged.

```sh
bash scripts/project-preflight.sh
python3 scripts/ci/check_content_commitment_vectors.py
python3 scripts/ci/check_cell_content_graph_vectors_v3.py
python3 scripts/ci/test_hash_use_contract.py
python3 scripts/ci/hash_use_contract.py
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --lib cell::content_graph_v3
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-mvcc-fee --lib content_commitment_v1::history_v2
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::migration_history_v2
```

The existing full-content workflow additionally retains complete component
libraries, all-features tests, doc tests, exact-source checks, locked graphs,
formatting and strict Clippy. A documented command is not an execution receipt.
