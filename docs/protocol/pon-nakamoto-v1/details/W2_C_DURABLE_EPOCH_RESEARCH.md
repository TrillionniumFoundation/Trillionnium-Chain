# P3 / W2-C: durable single-database receiver admission epoch

Status: **research-only / SHADOW_ONLY / HOLD_NO_GO**. This implementation
does **not** modify W1, PNW1, the original V3 Cookie, chainwork,
consensus rules, state root, accepted Block ID or final-use authority.
Original parent: Chain #339 head
'2787ad3959359bc5377d982a7ab46a2d76d44e0e'.

## Reproduced open issue

The previous 'w2c_stateless_receiver.py' has a correctly retained negative
test: copying the same issuer receiver, secret, epoch and fresh empty spent
state to another process permits one already paid ticket to be accepted again.
Cryptographic authentication and in-memory one-use checks do not establish
restart-safe uniqueness or global singleton ownership.

## Implemented same-filesystem mitigation

'w2c_durable_epoch_owner.py' wraps the original
'StatelessReceiverAdmission' without changing its signed Grant grammar:

- One **trusted local** SQLite database with a fixed receiver binding, 0600
  regular-file checks, a schema-tagged singleton authority row, a checked
  monotonic sequence, and a fresh 32-byte random epoch contribution.
  A newly opened owner increments and commits the sequence under
  'BEGIN IMMEDIATE' / 'synchronous=FULL' before issuing any grants.
- An older open instance sharing the **same database file** must recheck
  its epoch and returns 'STALE_EPOCH' on offer/consume. Its cloned
  in-memory token, HMAC key and original epoch are not enough to reissue
  the same service entitlement.
- The paid-grant digest is stored via a unique database key under the
  same writer transaction; the service returns 'READY_RESOURCE_ONLY'
  **only after COMMIT succeeds**. A failure/crash before completion gives
  no positive receipt; a crash after COMMIT retains the original charged
  spend, possibly without any W1 work.
- Full table saturation returns 'PAID_CAPACITY_BUSY'; previously paid
  exact retransmissions return 'REPLAY'. No prior paid token receives
  additional credit, and unpaid grant issuance stores no paid row.
- Concurrent calls in one process are serialized by an original instance
  mutex. Calling from a forked child that inherited the Python object
  fails with 'FORKED_OWNER' before any SQLite or W1 operation.
- This owner offers only resource admission. It has **no W1, Node, fork
  preference, VerifiedWork, ledger payment or model installation API**.

## Exact local tests

    python3 -B formal/pon-nakamoto-v1/test_w2c_durable_epoch_owner.py -v

Twelve local cases executed on one Linux scratch interpreter:

1. Paid and unpaid old grants fail after ordinary restart and epoch rotation.
2. Two live instances opening the same DB: the older is fenced.
3. Capacity remains bounded by actually paid grants, not issued offers.
4. SQLite write failure cannot return a successful READY.
5. Insecure 0644 files and symlinks fail before DB access.
6. An **actual separate child process** commits a paid record and calls
   'os._exit(0)'; reopen reads the original payment and rotates the epoch.
7. Different receiver identity cannot replace the original authority.
8. Invalid target nonce persists no paid grant.
9. Thirty-two concurrent paid consumes have exactly one READY and
   thirty-one REPLAY decisions.
10. An inherited object after actual OS fork cannot emit new grants.
11. Positive cost admission never mints Chainwork/VerifiedWork.
12. **Negative unsolved cross-host counterexample**: two separate local DB
    paths, intentionally cloned credential and epoch entropy, can still each
    accept the **same** paid grant. This test passes when the security
    limitation is reproduced, not when universal safety is proven.

Exact new source Git blob:
'995d47aa32f55e54583b89a39f739ee57bef3eab'.
Test blob:
'f944cccb107ed26f2166bfbb5369dc224f12e261'.
Original matched parent source blobs:
- 'w2c_receiver_admission.py':
  '045700db730d330df05670351fa40a94fe4dd510'
- 'w2c_stateless_receiver.py':
  '8a800f526bbcfddb3308a1966fc4c406ee29c5d0'.

The local testing directory is an exact-code subset, **not** a complete
Git checkout, a native Rust test, physical power-loss verification, hardware
attestation or independent third-party cryptanalysis. Original remote CI
status is not used as a blocker or as an acceptance receipt.

## Residual threats that this patch does not solve

1. Two databases cloned onto **different filesystem/host authorities** do
   not have a shared transaction lock or durable sequence. Even matching
   sequence and RNG can reissue one paid ticket; externally anchored unique
   identities/leases and an independent observer are required.
2. An old instance can already have received READY before a new epoch starts.
   The eventual downstream Native commit would need a separate current-epoch
   and original Node/FinalUse fence at its actual commit boundary. This
   research component does not provide or assert such a fence.
3. 'offer' remains a stateless crypto operation which costs CPU. It has
   no independent front-door DoS fairness or real V3 public network binding.
4. The trusted path and SQLite connection are **not** hardened against a
   hostile same-UID filesystem actor, physical rollback of the DB, forked
   database snapshots, compromised administrator, unsynced hardware storage,
   or a host OS lying about durable writes.
5. The caller supplies trusted monotonic milliseconds and issuer credentials;
   attacker-selected time, copied owner keys, original secret reuse and
   dishonest operators remain outside this measured experiment.
6. Even perfect anti-replay does not make 8- or 12-bit W2-C hash work expensive
   enough to compensate for the real CPU/GPU price of false W1 transcript
   rejection. P2 pricing and W2 cryptographic completeness remain separate.
7. P1 all native public/sync paths, P3 mixed honest service, P4 the original
   A03 three-mode/three-run/three-confirmation standard, and P6 an external
   independent security review remain **OPEN**.

Independent activation requires a new versioned policy, original owner
integration, actual resource observations and governed release. No hidden
fallback to a different consensus mechanism is allowed.


## P2 original-W1 cost and durable issuer overhead: four finite CPU samples

Added 'formal/pon-nakamoto-v1/w2c_durable_cost.py', which freezes the
same 318-byte research header, 64x64 zero A/B/C, task, W1 target
'7f' + 31 'ff' bytes and fake transcript generation. Every PNW1
ticket attempt (including misses) is retained. Each receiver sample
performs an independently bound durable W2-C grant, complete cost-ticket
search, synchronous SQLite paid commit, exact paid replay refusal,
the **original Python scalar W1** false-transcript rejection and
ordinary epoch rotation. Every case reports actual process CPU and wall
timestamps; the standalone hash loop and issuer are not a V3 handshake.

| W2-C bits / sample | False W1 target trials | Cost-ticket hashes | Attacker W2 search CPU ms | Issuer/paid CPU ms | Full receiver W1 rejection CPU ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| 8 / 0 | 2 | 84 | 0.2164 | 0.0958 / 0.3523 | 73.3991 |
| 8 / 1 | 2 | 114 | 0.3039 | 0.0948 / 0.2585 | 76.5749 |
| 12 / 0 | 2 | 1,058 | 2.5625 | 0.0806 / 0.2864 | 72.3908 |
| 12 / 1 | 2 | 8,868 | 21.1148 | 0.0831 / 0.4596 | 73.1053 |

Each fake W1 proof was also independently generated in about 0.66–0.73 ms
of Python process CPU; this is a **separate numerator**, not zero effort.
Issuer/paid costs are **defender** costs and must not be added to attacker
search CPU. The W1 verdict was 'TRANSCRIPT' in all four cases; all
Chainwork and public-activation fields remain false. The finite research
report sha256 is:
'3ed3a0a259902ba53ca5d459a62d73760f03bfe377b3c2c5291a73faf8c89379'.

Reproduce with a new exclusive output path:

    python3 -B formal/pon-nakamoto-v1/w2c_durable_cost.py \
        --bits 8 12 --samples 2 --cap 65536 \
        --out /unique/empty/filename.json

The analyzer bounds samples to 1..16, cost-ticket bits to 8..20 and
search attempts to 1..1,048,576, rejects a duplicate bit arm and keeps
exhausted costs separately. No fixed CPU-/GPU-independent hardness lower
bound, fork-choice activation or attack-service SLA is inferred from
these four Python-only cases. The added two cost-report tests expand
the isolated local suite to **14/14 passed**. The new source blob is
'd231675b41a8c0cb36be8aa5ef4e3282eeaa8849' and latest test blob is
'da8864af75311452426b51e0636987d59481beaf'.

**Security verdict remains HOLD_NO_GO**. These observations confirm that
8-bit W2-C tickets can be hundreds of times cheaper in this Python setup
than one expensive transcript refusal, even after adding a durable
paid record. The two 12-bit samples vary substantially; selecting bits
from a finite winning sample would be an invalid hardness/fairness claim.
GPU/ASIC cost, actual V3 signed-cookie overhead, multi-receiver network,
operator economics and independent attack/cryptography signoff remain OPEN.

The final 14-case test source isolates the actual `fork()` negative inside its own
single-threaded Python subprocess rather than forking a potentially
multithreaded test runner. All 14 local cases were rerun and passed with
that final exact test blob. The original cloned-database negative remains
intentionally reproducible and blocks claims of cross-host ownership.
