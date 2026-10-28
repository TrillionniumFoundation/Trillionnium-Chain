# Original 131f native campaign and PQ backend readback

These are original-source observations, not acceptance of this evidence commit.
The exact Chain source is `131f673d9563e72aca7139f3239856957d118d49`, tree
`b8bdd87dca3cd6288c38f63848b24b1a2df6a09d`. The original native campaign is
[run 40620917256 / job 122594446727](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40620917256/job/122594446727).

All three predeclared repetitions ran their real fixed Host. All nine controller
receipts passed, but every service phase failed, including the three baselines.
Confirmations were **0/27 planned**, with nine observed failures and 18 unobserved
rounds. Only 63 of 189 planned business packets were issued; all 63 received
timely acknowledgements. History network responses were 24/24 timely, while
ordinary local imports were 15/24 successful and nine hit PUBLIC_REQUEST_DEADLINE.
No attack phase reached real paid-credit depletion: **0/6**. Refill compensated
the 4.066–4.242 CPU seconds paid per attack phase; sampled credit remained above
1.981 seconds. All 144 late attack errors and all absent rounds remain in scope.

The independent hotspot supplement finds complete account-graph verification
dominates the observed native verify-state intervals. The intervals are nested,
not additive. Receiver and local History verifier have separate Node CPU ledgers
while sharing the physical 0.25-core Host. Their difference is not an established
unmetered-work exploit. These runs do not establish restart-credit safety: all
144 attack processes exited normally and each phase initialized a fresh epoch.

The separate required-receipts reader preserves four original from-zero lanes:
5/5 named native tests each, followed by failing confirmation acceptance. Test
selector success cannot replace the service reader's result or full denominator.

The PQ review is read-only. Rust OpenSSL wrappers are version-locked, but the
all-features hosted lanes lack the same explicit 3.5+ backend contract as the
local 3.5.9 compile check. Their E0599 is a build-contract failure, not proof of a
cryptographic bypass. The runtime oracle's bare `openssl pkey` call returned
nonzero before its strict DER parser; actual CLI identity and diagnostic stderr
were not retained, so backend/configuration mismatch is a candidate explanation,
not a confirmed cause. Subsequent original 131f runtime logs also fail all eight
account fixtures. No blocked native operation was rerouted or executed here.

Readback clarification: the earlier PQ text's 96 `test result:` matches per
recent log consist of 85 output-line matches and 11 echoed grep-command matches.
Neither number is a deduplicated testcase denominator. The original bytes are
preserved; this clarification does not change any lane's E0599 failure.

Full original native ZIP: 50,535,162 bytes; SHA-256
`2882b94bb4edc617ecee45b65fe4e3ad9607a8330505e1ccc38ec13933e680f5`;
1,765/1,765 internal payload files verified. The complete original archives and
private paired-project observations are retained separately; this public folder
contains Chain-only readback. No source, profile, budget, selector, or permission
was relaxed to produce these results. Work packages 2B and 3 remain unaccepted.
