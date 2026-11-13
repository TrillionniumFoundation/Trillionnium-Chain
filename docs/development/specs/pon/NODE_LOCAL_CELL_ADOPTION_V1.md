# Node-local Cell adoption V1

This contract adds an explicit local model-data choice owner. Candidate
publication, computation verification, evaluation evidence, chain settlement,
local selection and permission to execute remain separate facts. The sole
development plan remains the [canonical plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Existing authorization boundaries

The existing PQ release authority has distinct NodeSoftware,
ProtocolConfiguration, CellManifest and CellActivation roles, separate root
rotation authorization, signed role/version/checkpoint bindings, and fresh
current-use checks. Those rules remain unchanged. Its single current content
per role is an authorization mechanism, not an open candidate directory:
accepting another CellManifest can invalidate an earlier CellActivation.

A participant's submission or new evaluation must therefore not be translated
automatically into an acceptance call on that authority. Node-local selection
cannot override a genuine withdrawal, expiry, Root change, software policy or
FinalUse requirement either.

## Separate local state

The new `CellAdoptionOwnerV1` uses a fresh TCA1 SQLite namespace. Its immutable
policy binds the node identity, policy identity, Cell scope, complete model
boundary and finite capacities. The caller is the local operator or its
authorized policy service. This library has no public submission listener and
does not authenticate a caller merely because it can construct a Rust value.
Model/tool processes must not receive that owner's writable files or authority.

`observe_candidate` stores complete TCV1 metadata, a direct-parent reference
and commitments to optional evaluation, reproduction, chain-observation and
settlement records. It never changes the selected version or decision revision.
The records contain no caller-supplied `qualified`, `independent`, `finalized` or
`authorized` flags. Their digests identify evidence; the actual evidence owners
still have to authenticate and evaluate it.

The independently pinned anchor is a trusted bootstrap checkpoint. It may
already have a declared history. This owner does not manufacture verification
of ancestors preceding that checkpoint. Subsequent candidates require an
already retained complete parent TCV1, matching parent context, the actual
parent TMR1 identity and a strictly later model generation. This profile has
one direct parent; a merge requires a separately specified extension.

Each explicit decision binds a nonzero operation identity, exact expected
snapshot, target candidate, local review commitment and the candidate evidence
set actually present at that decision. A snapshot contains policy identity,
revision, selected complete-version commitment and chained history digest.

| Decision | Eligibility | Effect |
| --- | --- | --- |
| Adopt | Target differs from current; its parent is current, or it is the pinned bootstrap anchor when no version is selected | Select target; advance revision |
| Defer | Target is a retained candidate other than current | Preserve current; record deferral and advance revision |
| Retain | Target equals current | Preserve current; record the explicit decision and advance revision |
| Rollback | Target differs from current and this node previously selected it | Select the retained target; advance revision |

Re-adopting B after A to B to A is permitted as a new local operation when B's
parent is the current A. It is not new training, a new independent experiment
or proof of new knowledge. Every decision, including retain and rollback,
advances the local revision. A to B to A never revives A's old snapshot.

The same operation identity and exact input return the original historical
receipt. A changed input with the same identity refuses. Replaying that receipt
does not rewrite current state and is not permission to use its old version.

## Model updates cannot enlarge the execution boundary

`CellModelUpdateBoundaryV1` derives its allowed surface from the approved
complete anchor. It fixes:

- the complete declared environment closure and its dependency inventory;
- model family, base reference, tokenizer, layout, runtime and loader profile;
- file paths, roles, dependency edges and roots;
- all payloads outside the explicitly allowed Base, Adapter or Router roles;
- finite model payload and chunk limits.

An operator may allow no mutable roles. Configuration, tokenizer and
preprocessor payloads cannot be made mutable through this model-choice policy.
Manifest locators may change with a model's parent; frozen files must retain
the same payload length, payload hash, chunk size and complete chunk identities.

The local execution boundary also binds six independently supplied identities:
network, consensus, fees, Root authority, node software and protocol
configuration. All six must still match at selected use. Changing the model
candidate cannot change these policy pins. A different boundary requires a
separate authorized migration and fresh owner namespace.

These are exact identity comparisons, not host attestation. The hosting
execution owner must obtain the current identities from its protected sources,
parse safe model-data formats, forbid model-supplied executable loaders and
retain its actual authorization/resource guard. This module neither installs
nor executes any environment member.

## Real consumption and concurrency

`CellResidentVersionV1::with_selected` composes the existing immutable resident
TCV1 consumer with the durable choice owner. It checks the task's original
deadline and cancellation before reading the owner and again immediately before
delivering actual resident model/environment bytes. The owner replays its
bounded history, requires the exact current snapshot and complete version,
rechecks the execution boundary, and holds a SQLite immediate transaction
through the consumer callback. A cooperating second writer refuses immediately
instead of switching the version during consumption or waiting on itself.

The existing `with_local` API remains a lower-level data API for callers with
their own release/authority guards. Adding `with_selected` does not establish
that every deployed caller has adopted it. Neither API creates a FinalUse,
tool-execution, payment or consensus capability. A consumer can copy public
bytes; a later local choice cannot recall them. A callback error or lost return
after an external effect must be reconciled by the original effect owner.

## Persistence, recovery and chain changes

Candidate observations and selection decisions share atomic transactions but
have distinct semantics. The database uses SQLite DELETE journaling with EXTRA
synchronization. The file lease requires a canonical private local directory,
same-user ownership, regular non-hard-linked files and unchanged file/directory
identity. Replaced files, foreign schema objects, altered policy, journal
corruption, stale CAS snapshots and exhausted capacities fail closed.

Reopening requires a separately retained recovery-floor snapshot. Full replay
must contain that exact snapshot as an ancestor of the current state. A database
restored before a known floor refuses; a running owner also retains its most
recent observed floor. Restoring both the database and its old floor together
does not provide freshness. A different path on the same host does not prove
independent custody or resistance to complete-host rollback.

The first bounded profile permits at most 16 candidates, 16 evidence reference
sets per candidate and 1,024 decisions, with optional tighter local limits.
It never evicts history or resets a full journal automatically. Capacity
migration and evidence custody require an explicit owner operation.

A chain reorganization does not rewind this local journal. A new chain
observation may be recorded, but must not silently apply an old selection.
Checking whether evaluation, funding or current authority remains valid after
that reorganization belongs to the original owners. A revoked version cannot
be made executable by choosing Retain or Rollback here.

## Explicit local CLI

`trnm-cell-adoption` provides `init`, `status`, `observe`, `decide` and
`verify-selected`. `--help` documents the strict policy/evidence/floor schemas.
The operator provides an independent policy file and approved anchor. Init
selects nothing; observe only records a candidate. All later commands require
an explicitly supplied recovery floor. Output includes the observed current
floor for independent retention, even when a decision request returns an older
idempotent receipt.

Policy, approved anchor, current execution pins, recovery floor and expected
snapshot use a separate operator-input reader: an absolute path, canonical
same-user private parent, and a same-user single-link regular file with mode
0600 or 0400. Held-descriptor and named-path metadata must remain stable across
the read. Candidate and evidence files remain untrusted public inputs; they
cannot supply a replacement local policy or execution authority. Keeping a
floor outside the database directory is required by the CLI, but is not proof
that it has independent custody.

`verify-selected` requires the exact expected snapshot, independently supplied
current execution pins and an existing TCL4 cache. While holding the choice
guard it performs the original complete-version cache verification over actual
model and environment bytes. Metadata alone cannot pass that command. A pass
is an actual byte-read observation, not inference, independent model benefit,
chain confirmation, production authorization or a new release signature.

The new binary and schemas do not change TCV1 bytes, old signed release domains,
consensus rules, fee accounting or deployed Root material. The local owner and
CLI are opt-in until a deployment explicitly connects its protected policy and
ordinary consumer. Cross-repository ordinary learning, independent evaluation,
live chain evidence and protected production activation keep their existing
acceptance gates.

## Implementation and tests

- [Persistent choice owner](../../../../trillionnium/crates/trnm-data-availability/src/cell/adoption.rs)
- [Model/execution boundary](../../../../trillionnium/crates/trnm-data-availability/src/cell/adoption_boundary.rs)
- [Resident consumer](../../../../trillionnium/crates/trnm-data-availability/src/cell/residency/version.rs)
- [Local operator CLI](../../../../trillionnium/crates/trnm-data-availability/src/bin/trnm-cell-adoption.rs)
- [Decision and recovery controls](../../../../trillionnium/crates/trnm-data-availability/src/cell/adoption/tests.rs)
- [Actual selected-byte consumption controls](../../../../trillionnium/crates/trnm-data-availability/src/cell/residency/selected_version_tests.rs)
- [Subprocess CLI controls](../../../../trillionnium/crates/trnm-data-availability/tests/cell_adoption_cli.rs)
