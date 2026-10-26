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
