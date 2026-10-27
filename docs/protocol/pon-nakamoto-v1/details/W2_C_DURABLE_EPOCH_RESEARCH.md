# W2-C persisted receiver Epoch — research only, no production activation

Base: PR #339 at 2787ad3959359bc5377d982a7ab46a2d76d44e0e.
This is a research-only local security mechanism; it does not change W1,
PNW1, V3 signed Cookie, Genesis, Chainwork, targets, fork choice, Node
ledger authority or any production flag.

## Actual replay vulnerability

The stateless W2-C admission research binds each paid ticket to one
HMAC-authenticated receiver and a process Epoch, but keeps the already-spent
set in volatile memory. On a restart that duplicates the identical key and
Epoch, the once-paid grant is accepted again. PR #339 deliberately retained
the cloned-epoch negative counterexample.

## Local persisted Epoch research

Source: formal/pon-nakamoto-v1/w2c_durable_epoch.py

A private 0700 owner directory holds one mode-0600 one-hardlink regular log.
Creation uses O_EXCL and O_NOFOLLOW, and a nonblocking exclusive file lock is
held for the full process lifetime. Every startup validates all prior fixed
records and appends a new SHA256-linked record containing a strictly increasing
counter and 32 independently generated fresh random bytes. The log is limited
to 4096 records and never silently truncated or reset. Both the file and its
directory are fsynced before the resulting 32-byte Epoch is returned.

Previously created but empty, truncated, malformed, inaccessible or overfull
logs reject restart. Runtime checks require the original PID, directory inode
and path, file inode and path, and private modes to remain unchanged. Fork,
directory replacement, path replacement and permission widening deny new
admission operations. The ScopedResearchReceiver adapter enforces that live
owner check for both ticket issuance and consumption; it is not a network
service, a consensus verifier or an authorization token.

There is no generated W1 valid-work capability. An old ticket with a different
Epoch fails the original stateless W2-C receiver CONTEXT check. The same
statically configured secret is not sufficient to recreate the old Epoch
after ordinary honest sequential startup.

## Reproduction

Run on Linux/POSIX from a complete repository checkout:

    python3 formal/pon-nakamoto-v1/test_w2c_durable_epoch.py -v
    python3 formal/pon-nakamoto-v1/test_w2c_durable_crash.py -v

Twelve first-suite local negative tests passed. Cases include an original
stateless paid W2-C grant, normal restart, same-inode owner contention, fork
PID isolation, corrupted and torn journals, hardlink/symlink, permissions,
directory/inode replacement, missing entropy, fsync failures and the retained
snapshot rollback failure counterexample.

A thirteenth independently launched Python subprocess holds one persisted
original Epoch; a concurrent owner cannot acquire it. After OS SIGKILL the
replacement obtains a different persisted Epoch. This test also passed locally.
Those outcomes are local Python source tests, not native Rust receipts.

Exact locally executed source Git object identities:
- w2c_durable_epoch.py: 513323ab752e7909a5c8526a7fc7e777cae71f13
- test_w2c_durable_epoch.py: 8ee1afea19f891b145bfc395d35d82dc5c8011a0

The scratch integration used locally copied W2-C ticket helpers, not a full
independent Git checkout. Compiler, repository preflight, security review,
real CPU accounting and physical deployment qualification remain separate.

## Important negative results and remaining blockers

1. **Snapshot rollback remains vulnerable.** A disk rollback coupled to a
   cloned random generator can reproduce an old Epoch exactly; the unit test
   confirms this known failure rather than claiming protection. A malicious
   same-UID storage owner can edit the unkeyed checksum chain. Production
   requires an external rollback-resistant monotonic owner or independently
   attested platform counter and fault-domain tests. A copy of the same
   secret/epoch on two hosts is not a second independent operator.
2. The code does not pay a complete W1 verifier. Locally unique Hashcash
   tickets can remain much cheaper than W1 rejection, particularly with
   GPUs or ASICs. Stateless issuance HMAC/RNG costs and host-wide budgets
   require original V3 integration and real matched-cost measurements.
3. Failure on journal exhaustion deliberately requires controlled migration
   to a fresh namespace and a new, independently audited owner; resetting
   the file or counter to zero is prohibited.
4. All unchanged P0–P6 gates remain: P0 native four-false proof replay,
   P1 authentic Host/loopback exposure and CPU ownership, P2 honest/attacker
   CPU/GPU Cookie pricing, P3 mixed valid-work/bad-StateRoot traffic, P4 A03
   three attack modes by three runs with 3/3 timely confirmations, P5
   economically secure and cryptographically sound W2 proof, and P6 external
   independent review and exact activation/fork tests.

Status remains SHADOW_ONLY / HOLD_NO_GO; no production activation or merge.


## Additional whole-suite observation and timing control

After the initial individual test success, one whole-suite run of 12 + 1
tests **FAILED** because the SIGKILL child process did not announce its
original persisted Epoch within the first 5-second local observation
deadline. That result remains a failed observation, not a 13/13 pass.
The source was subsequently changed to retain bounded 15-second process
readiness, diagnostic child exit status, and available child stderr.
No W2-C relation, epoch validity or native-node deadline was relaxed;
this change affects this scratch test's OS child startup observation only.
Two complete source-equivalent 13-test combined runs then passed in
opposite test order. The earlier failed run is not retroactively erased.
The revised real-crash test Git blob is
'e43ac3c831ad0d68058f6027a1d7f1f9d363d9f3'.

This is a local Python process startup result, not a proof that 15 seconds
is acceptable for a real protected public W1 service. Production P3 must
preregister separate startup, proof, and honest-business confirmation
deadlines and report all failures.
