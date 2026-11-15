# One durable owner for W1 proof starts

## Closed implementation gap

The earlier `exercise` command created `WorkStartBudget::new(1)` in every fresh
process, while `reopen` had no such counter. Starting another process therefore
replenished the effective allowance for expensive complete proof verification.
Those original observations remain historical; they never established lifetime
accounting.

The current research CLI requires an explicitly provisioned, common proof-start
owner for **both** admission and cold observation. The owner has one independently
supplied policy and at most 16 fixed slots. Each invocation must reserve a slot
before creating its output directory, loading a bundle, entering a proof stage,
or opening/recovering a receiver Node. A failed load, malformed proof,
cancellation, verifier error or process exit never refunds that slot. Merely
reading `owner-status` consumes no slot.

All qualifications remain **HOLD_NO_GO**. This change closes a local
cross-process accounting defect in the research adapter. It does not provide a
global adversarial-resource bound, a quantum-query bound, production admission,
a same-resource throughput gain, or a complete post-quantum theorem.

## Fixed policy and namespace

The new policy schema is `trnm-w1-proof-start-owner-policy-v1`. It binds an
operator-chosen 32-byte `owner_id`, the exact research proof profile, network,
parameter digest, genesis and `maximum_starts` in the closed range 1 through 16.
The identifier is a scope label, not an authenticated operator identity. A
policy file is supplied separately on every CLI invocation; the owner's stored
file cannot choose, enlarge or replace that policy. Unknown fields, invalid
types, unsupported profiles and mismatched policies fail closed.

Provisioning is a separate create-only operation. It never opens a missing
owner as an empty budget and never repairs an interrupted initialization.
Changing the policy requires a separately reviewed new owner namespace. This
implementation provides no reset, refund, deletion or replenishment API.

The owner contains exactly these entries:

| Entry | Role |
| --- | --- |
| `policy-v1.json` | Exact canonical bytes of the independently supplied policy |
| `complete-v1` | Policy digest written after initialization data |
| `starts-v1/01.start` through the fixed maximum | Create-once, nonrefundable reservation slots |

The owner directory and **every ancestor** must remain protected from untrusted
namespace mutation for the owner lifetime. This is an operator precondition,
not a property established by canonicalization. An owner mode of 0700 alone
does not protect it when an ancestor can be renamed or replaced by an attacker.

Owner and slot directories require Unix mode `0700`; files require `0600` and
one hard link. The configured path must be absolute and canonical. Symlinks,
unexpected entries, extra slots, loose permissions, oversized metadata and
an observed replacement of an already opened owner or slot-directory inode
are refused at the explicit checks. Those path and inode checks do not pin the
whole ancestry, authenticate its history or defeat rename/exchange/ABA races.
No malicious same-UID or attacker-writable-ancestor isolation is claimed.
The small fixed slot inventory bounds each scan. No signature or success flag
inside a slot can replenish the allowance.

## Concurrency and crash boundary

Each slot is acquired through a filesystem `create_new` operation. Concurrent
processes may observe a stale inventory, but they cannot create the same slot
twice. The loser leaves that slot untouched and tries the next one. There is no
process-local reservation counter to reset and no persistent lock to clear
after a crash.

After creating a slot, the owner writes its start record, synchronizes the
file, synchronizes the slot directory, checks the opened file identity and
revalidates the fixed owner. Only then does it return a private,
non-deserializable, non-cloneable reservation. The metered verifier consumes
that value and checks its policy against the actual bundle context before the
first cryptographic checkpoint. A returned diagnostic JSON record cannot
construct a reservation.

Every existing regular slot counts, including zero-byte files and partial
records left by an interrupted write. A write, synchronization or identity
check error returns no permit and leaves any created slot spent. A crash
before synchronization can lose a slot only before the caller has permission
to start proof work. A crash after a returned reservation cannot be handled by
silently deleting its record or reinitializing its owner.

This argument assumes the filesystem honors local create-once and
synchronization semantics and the configured owner storage is preserved. It
does **not** defend against privileged or malicious same-UID actions, an attacker
with write access to an ancestor, or any such process deleting
slots, restoring an older backup, cloning an owner, or selecting a new owner
path. Reopening an authentic-looking rolled-back directory does not prove its
history. Those require an external monotonic/authenticated storage design and
remain open; the emitted snapshot explicitly records
`backup_rollback_protection_established=false`.

## Proof and native-state semantics

The actual complete SHA and arithmetic proofs, independent expected artifacts,
canonical packet binding, current Node context checks, native W1 verification,
admission and recovery behavior remain required. The charge is an additional
precondition; it never substitutes for a cryptographic or native check.

New diagnostic namespaces distinguish the changed contract:

- `trnm-w1-node-adapter-exercise-v2`;
- `trnm-w1-node-adapter-admission-v3`;
- `trnm-w1-node-adapter-reopen-v2`;
- `trnm-w1-proof-start-owner-snapshot-v1`.

Admission and reopen results carry the exact start record beside the already
bound bundle operation. A slot records a start, not successful verification,
native commit or activation. A failed or interrupted run may have only the
slot and process logs. As before, a successful diagnostic process exit alone
does not establish proof acceptance: inspect `error`, `outcome`, native state
and the actual proof result.

The original `verify_bundle` and `observe` library functions remain explicitly
unmetered research entry points; their diagnostic proof-start field is null.
The `native` comparator also remains a separate measurement command. This
finite owner does not assert that every possible caller or every hash operation
is charged. It counts the two declared complete-proof CLI paths only.
`lifetime_quantum_query_bound_established` therefore remains false.

## Reproduction

Use the checked-in lockfile and read the repository development boundary first.
Supply a trusted policy derived from the selected fixture's independent
`operator-plan.json`, not from a proof envelope. The helper constructor
`ProofStartPolicy::for_plan` validates the same context and bound.

```text
w1-node-adapter-research owner-init EXPECTED_POLICY NEW_OWNER_DIR
w1-node-adapter-research exercise FIXTURE PROOF NEW_OUTPUT CANCEL_OR_none OWNER_DIR EXPECTED_POLICY
w1-node-adapter-research reopen FIXTURE OUTPUT OPERATION_DIR OWNER_DIR EXPECTED_POLICY
w1-node-adapter-research owner-status EXPECTED_POLICY OWNER_DIR
```

Both old CLI forms without an explicit owner are rejected. Historical
resource-pressure scripts remain pinned to their original binary and source;
their recorded timing and failed observations are not relabeled as results of
this changed command contract.

The updated [independent-process runner](run_node_controls.py) retains the five
original exercise cases and four cold reopen cases, with one shared nine-slot
owner. It adds separate provisioning and read-only final status processes;
there are eleven subprocesses and nine charged verification attempts. These
are retained-proof replays, with zero new proving executions. The final owner
must be exhausted, and all policy, input, harness and binary pins must remain
unchanged.

The [owner integration tests](tests/proof_start_owner.rs) additionally cover
cold-process exhaustion, empty/partial slots, policy rebinding, interrupted
initialization, symlink/hardlink and permission refusals, stale inode refusal,
context checks before crypto, input-load failure, eight simultaneous CLI
processes competing for three slots, and real complete proof/native admission
followed by a separately charged cold readback. The original 12 retained-proof
and native-state controls are preserved with the new explicit CLI owner inputs.

The exact tested source, command exits, raw logs and any failed observations
must accompany the delivered candidate. Passing these controls establishes
only the named implementation behavior; all complete-work, proof-system,
lifetime, independent-host and production qualifications remain unchanged.
