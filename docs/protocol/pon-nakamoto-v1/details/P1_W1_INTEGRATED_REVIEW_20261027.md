# W1 P0–P6 safe integration preview — 2026-10-27

Status: **DRAFT / SHADOW_ONLY / HOLD_NO_GO**. This review is neither a
protocol activation, an audit signoff, nor an assertion that all blockers closed.

## Exact branch lineage and non-conflicting integration

The integration preview started from Chain #335 at
`db0dad68f0909460e8b1cf0c248d8bab4b59c129` and combined the
complete changed-file trees from:

- #339 W2-C receiver-local research, head
  `2787ad3959359bc5377d982a7ab46a2d76d44e0e` (6 paths);
- #340 original-domain pinned peer work charging, head
  `7ed523093e89bd50ce85775ca023028fdc3a58c7` (3 paths);
- #342 fixed-host remote History sync W1 containment, head
  `e55107450eb1a1f051a6c98101f3f88b7afa8f91` (3 paths).

All twelve paths were unique, and no child ref was moved or rewritten. The
initial combined tree was `4550961a8ecc30aaa215cfdcbb74ec52fb0b2193`.
Follow-on P5 research changes appear only on the integrated preview branch.

**Do not** treat the Git tree equality of those three file sets as an actual
merge with the independently changing #328 integration candidate. #328 and
its future merge preview require fresh exact-source review; none is performed
by this assembled tree.

## P1 original resource ownership

- Public V3 has its original bounded paid mutation CPU domain and one
  Node/Host kernel owner. V2 nonloopback is refused. Legacy authenticated
  nonloopback requires signed transport admission and the same physical host
  cgroup as V3.
- #340's pinned History peer full W1 replay now acquires the Node's *already
  bound* CPU domain before math, and settles through M06 scoped-worker joins
  and ledger admission. It does not permit a new per-peer allowance.
- #342 makes addressless `receive_page` private and routes public History
  import through `receive_page_from`, with fixed Host resource checks.
  Raw/signed/durable remote sync variants also require the same original
  physical cgroup before network and after each W1 page.

Unclosed P1 scope: actual compilation and full independent callgraph
inspection; verified physical cgroup identity across all OS tasks, Unix
sockets, multi-process relays and loopback proxies; honest-service fairness
under saturation; worker CPU after process crash and reorg; direct local
`Node::admit` invoked by trusted embeddings outside the public listener.
Source guards without these external observations are NOT complete proofs.

## P5 W2-C issuer policy and durable-spend experiment

Prior W2-C stateless research accepted a caller-chosen difficulty between
8 and 24 bits. The integrated preview adds an immutable
`required_bits` per receiver. Both grant issuance and verified authentic
grant consumption enforce that policy. A tampered unsigned difficulty still
fails HMAC; a real old cheaper signed grant cannot buy verification after
an explicit policy upgrade.

A separate opt-in `w2c_durable_spend.py::SQLiteSpentOwner` shares one local
persistent SQLite transaction owner among cloned receiver instances.
- The immutable local ledger identity binds receiver, issuer epoch,
  expected difficulty and capacity.
- A successful ticket inserts its SHA-256 commitment in a UNIQUE-key table
  under one `BEGIN IMMEDIATE` writer lock *before* W1 replay.
- Atomic cross-process contention grants exactly one READY and returns
  REPLAY to competing consumers. A clean database close/reopen cannot
  reclaim the same ticket; a persistent monotonic millisecond watermark
  rejects rollback before expired rows can be reissued.
- Capacity and expiry are evaluated in the same transaction. Closed DB,
  unavailable SQLite storage and unknown rollback state never return
  READY. No bad W1 proof gains VerifiedWork or chainwork from a paid ticket.
- The original volatile version remains separate and retains its explicit
  cloned-secret/epoch replay counterexample; there is no hidden fallback
  that silently changes installed public V3 protocol or consensus work.

**Intentionally retained counterexample:** two independent SQLite databases
containing cloned receiver identity, secret and epoch can *both* accept the
same ticket. Sharing a local database is not decentralized replay safety;
independent failure domains need independently unique authenticated receiver
identities, secure epoch lifecycle and/or a globally coordinated original
spent owner. Writable/symlink-swapped database paths, storage corruption,
reboot time base, real kernel durability and private-key export controls are
not production-qualified by this prototype.

## Reproduced finite local component tests

A standalone Python 3.13 run materialized the exact Git blobs for:

| File | Exact committed Git blob |
| --- | --- |
| `w2c_stateless_receiver.py` | `b498bfaea05e506f98e90b52047ed4a2ae48452c` |
| `test_w2c_stateless_receiver.py` | `0c4c04a0b4cc17f5d51c18e9fb6d9885aab6f882` |
| `w2c_durable_spend.py` | `905d4589e5d807cf0093c290014c89c11f6c8281` |
| `test_w2c_durable_spend.py` | `d72a8568e1c6630bf1cfe5c0bca0bb2024e489c1` |
| `w2c_receiver_admission.py` | `045700db730d330df05670351fa40a94fe4dd510` |
| `work_oracle.py` | `9cbfccd2d50af48fc43522b967ffdfb1f45ec098` |

Only the exact domain-separated `contract_wire.H(tag,*parts)` hashing function
was reproduced in an isolated shim; full repository configuration schemas
were not loaded. The **22 exact repository test methods plus 4 supplemental
local policy tests passed (26/26)**, including a truly independently spawned
four-process SQLite contention exercise, replay after close/reopen, expiry,
policy downgrade, and the negative independent-store double-accept case.

This is not a Rust compiler/host process attestation, full repository
preflight, public V3 network test, measured GPU cost, independent third-party
review, native Node State/Chainwork differential or A03 acceptance. All
existing acceptance and failure datasets must be retained.

## P0–P6 remaining source-to-product blockers

| Gate | Status and missing independent close condition |
| --- | --- |
| P0 | Four W1 false transcripts are fixed by earlier regressions; fresh exact Rust/native testing and prior original bytes/CPU provenance remain necessary |
| P1 | Child source mitigations integrated by tree; physical shared CPU limits, remaining authentic ingress and loopback embedding reachability, crashed-service reconciliations not accepted |
| P2 | Original V3 signed-Cookie CPU/GPU/ASIC equal-budget economics; complete honest/attacker input throughput and latency unmeasured on current source |
| P3 | Full identity churn, wrong StateRoot, mixed valid/invalid, retransmission and independently signed honest traffic under sustained stress not accepted |
| P4/A03 | Three attack modes × three full runs × 3/3 timely real client confirmations per run: not executed on this integrated head |
| P5 | W2-A sampled proof has explicit unsampled-fraud acceptance; W2-B is full witness/replay, not succinct; W2-C paid ticket still has single-host economic amplification. No sound low-cost W2 final proof |
| P6 | Third-party independent cryptanalysis, independently operated validator signatures, native W2 wire/genesis/fork-weight migration and explicit governed activation missing |

No tests, CI thresholds, target difficulty, block byte grammar or
`production_activation=false` value may be softened to mark closure.
