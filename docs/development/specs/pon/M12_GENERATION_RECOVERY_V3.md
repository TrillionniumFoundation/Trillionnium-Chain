# M12 witnessed generation recovery V3

Status: **implemented candidate; production qualification HOLD**. This is an
opt-in ordinary Node/M12 owner entry, `NodeGenerationOwnerV3`, for profile
`trnm-m12-witnessed-full-generation-v3`. It uses the existing actual Node funding,
task assignment, W1 verification and native settlement paths. Its inner V2
journal is private. Its `begin` and `prepare_settlement` methods can return `New`
only after an authenticated independent witness CAS. It has no unwitnessed
fallback. The original `NodeGenerationOwnerV2` remains a research API and has
**not** been migrated or qualified against full local backup rollback.

This specification refines the existing development plan. It does not activate
a service, implement provider idempotency, certify independent operators, clear
any recorded Unknown outcome or establish whole-Node recovery qualification.

## Authorities and complete binding

Domain A contains the actual Node, its task-assignment database and the complete
M12 generation journal. Domain B owns the separately retained authenticated
monotone witness. Its live signing key, registration policy, independently pinned
current generation and reopen checkpoint must survive an A rollback. A copied
pin next to the restored journal is insufficient. Domain C is the authoritative
provider/effect owner; B's dispatch fence cannot establish whether C executed,
stopped, consumed resources or transferred money.

The new M12 binding domain is
`TRNM/M12/full-generation-effect-witness/binding/v3`. It binds the authority
generation, both independent ML-DSA-65 identities and a SHA-512 context over the
entire V2 configuration and random durable journal identity. The checkpoint
domain is `TRNM/M12/full-generation-recovery/checkpoint/v3`; it binds that context,
the full validated event-chain root and the exact event sequence. The empty
journal uses checkpoint sequence one. PNQ2 network bindings do not match this
domain. The existing bounded, challenge-bound signed CAS register transport and
its original 250 ms exchange limit are reused without changing PNQ2 bytes.

The V2 event bytes and stored schema are unchanged. No signature is created over
a caller-supplied statement that purports to be a validated journal head. Every
checkpoint computation replays the actual journal and checks its schema,
configuration, sequence, roots, canonical event bytes and state transitions.
The outer SHA-512 commitment does not upgrade the original V2 SHA-256 event
chain's cryptographic strength or establish whole-chain PQ qualification.

## Actual effect boundary

The V3 constructor requires an explicit independent binding pin and authenticated
live B head. It does not create B, adopt a local pin or rewrite a stale checkpoint.
It compares the complete local checkpoint with B before opening the local
task-assignment owner. A missing, stale, conflicting or unauthenticated witness
refuses construction. No restored chain snapshot supplies dispatch authority.

For each operation:

1. Authenticate B's current head and require exact equality with A's validated
   complete journal checkpoint.
2. Recheck that exact authenticated head inside the ordinary SQLite transaction
   before an owner callback or event application. A concurrent writer between
   external read and local transaction cannot be silently incorporated.
3. Commit the ordinary intent or observation locally. Retain the exact checkpoint
   produced by that transaction; a later arbitrary local successor is not eligible
   for the owner's witness signature.
4. Advance B from the exact previous checkpoint to that exact immediate successor.
   Local errors, uncertain CAS, invalid replies and concurrent mutation quarantine
   the owner and do not return `New`.
5. Before returning `New`, check the original controller clock and absolute
   business deadline again. Time spent on signing and witness work is included;
   a late authenticated CAS never creates a replacement deadline.

The same fence covers preparing a task, dispatch intent, concrete job binding,
full proof verdict, cancellation, typed terminal observations, exact settlement
intent and authoritative native payment observations. The current native owner
continues to validate funding, signed wire, branch context and payment identity.
The wrapper cannot sign a transaction, call a provider, submit a payment or release
resources on the provider's behalf.

## Crash and uncertain-result behavior

| Cut | Retained state | Allowed next behavior |
| --- | --- | --- |
| B unavailable before A's transaction | Original local head | Quarantine; no new dispatch |
| A commits, B does not commit | Local successor; external predecessor | Cold reopen refuses; explicit external reconciliation required |
| B commits, reply lost or invalid | Same local and B successor; caller is uncertain | Reconnect the same independently pinned witness and journal; existing intent returns `Pending`, never another `New` |
| Owner action errors after a real local commit | Local successor; external predecessor | Quarantine without signing the observed successor |
| A restored to an older whole backup | Old local root; newer B root | Refuse before dispatch; retain historical evidence |
| B's file restored while a newer independent reopen pin survives | Old witness root; independent newer expected root | Existing witness service refuses reopen |
| Both authorities and every independent pin restored together | No surviving evidence of the future | Outside the guarantee; no claim of detecting indistinguishable history |

A cold owner accepts only exact equality with B. It does not infer non-execution
from absence, expire an Unknown into a fresh request, advance an unwitnessed
local successor, invent another operation or reallocate the original cap.
Historical reads remain available with an explicitly historical API and confer
no authority. V3 errors are not a reason to fall back to V2.

The original M12 state machine retains stable task, provider operation, request
digest, journal, job and settlement wire. Provider retry/reconciliation must use
the same identity and all original parameters. Provider retention expiration or
unavailability cannot be translated into `REJECTED`/not executed. A complete
provider-side atomic idempotency and authoritative query contract remains a
separate requirement. In particular, the historical #782 Unknown operations are
unchanged by the new component tests.

## Resource and qualification limits

The actual journal bounds remain `1 <= max_records <= 4096`, no more than
`12 * max_records` events, and at most 16,384 bytes for a stored configuration or
event payload. SQL checks byte lengths before copying event blobs. New restore
tests exercise event-count and payload-size refusal. Journal identity and both
metadata/event roots require SQLite blob type and exactly 32 bytes in the SQL
projection before a Rust `Vec` is copied. Controls bypass stored CHECK constraints
and inject 0-, 31-, 33- and 16,777,216-byte fields into actual SQLite databases;
both live and cold paths refuse before the generation owner callback. SQLite's
own page parsing and I/O still require a separately enforced total service budget.
These are finite application-copy data
bounds, **not** an accepted CPU service budget. V3 performs additional complete
replays and ML-DSA exchanges; its CPU and latency can increase with journal size.
The original four-second/16-worker service, cumulative CPU, independent WAN and
provider accounting qualifications must run on this exact profile before any
deployment or throughput claim.

The native controls use real Node operations, real SQLite commits, real ML-DSA
requests/replies and an actual durable witness. Runtime/provider values and the
controller clock are explicitly identified fixtures. A and B are separate local
directories on one host, not independent administrative, storage, power or
funding domains. Local process/cut simulation does not establish physical
power-loss durability, current independent revocation, provider terminal results,
ordinary Hepta FinalUse or a full RR-01 through RR-12 acceptance campaign.

Whole-chain anti-rollback, independent live custody, current revocation floors,
all Node effect-entry migration, real provider reconciliation and production
activation remain **HOLD**.
