# W1 v2: one fresh complete proof and 58 real receipt controls

This is a research observation, not production or post-quantum qualification.
One new full proof completed within the unchanged 7,200-second budget: total
6,253.711474144 seconds, fresh proof pipeline 6,248.484106799 seconds. All 52
stages passed, including 43 segment proofs, recursion, a fresh independent fixed
image verifier, 100 fixed-receipt replays, 1,000 native replays, serialization and
actual single-host TCP loopback transfers. No previous proof receipts were reused.
Build/setup and input fixture construction are outside this declared proof budget.

The fixed guest image, guest source, dependency locks and independent verifier
were not changed. See [exact guest rebuild](../pon-w1-pinned-rebuild-20261105/README.md).
The executed clean source was commit 2810f7c2b1b5e549302b3fdb2cf41b2a6ee19bff;
`executed-source.bundle` preserves it, with prerequisite repository commit
2ef9e2fa1985881721a1bff4d546a1b2bdc5ae47. The published API commit with equivalent
source tree is a635200956843f0d2f335f929977d602b48b36ec. The bundle can be verified
with `git bundle verify` and fetched into a separate local branch.

## Controls repair and actual results

The first control invocation failed before testing (0/58). Its log and entire
output directory are preserved. SDK 3.0.6 valid receipts can encode the journal
both inside the unpruned claim and in the outer Receipt. Requiring a globally
unique domain marker was incorrect. The repaired locator anchors to the fixed
outer `Journal { bytes: Vec<u8> }` followed by the 32-byte ReceiptMetadata digest,
checks exact length/domain/bounds and external bindings, and never searches for
a marker in the seal. This locator is not a general decoder or verifier. The
mandatory first control must pass the independent canonical decoder and full
proof verifier before any negative control runs.

All original 58 controls then passed in 4.629197061 seconds under their unchanged
120-second common budget: 1 positive, 57 negative, zero unexpected acceptances,
zero timeout and zero panic. Expectations were not weakened. The canonical-C,
paired journal/external-A/B and seal mutation cases require W1_V2_CRYPTO_REJECT;
that context includes construction checks and full receipt verification, but
is not a claim that every rejection traversed every STARK check.

Replay the saved controls from the repository root using the independently built
locked release w1-verify-v2 executable:

    RAYON_NUM_THREADS=8 python3 scripts/w1_v2_receipt_controls.py \
      --verifier /absolute/path/to/w1-verify-v2 \
      --receipt evidence/pon-w1-full-v2-20261105/succinct.bin \
      --header evidence/pon-w1-full-v2-20261105/header.bin \
      --expected-artifacts evidence/pon-w1-full-v2-20261105/expected-artifacts.bin \
      --out /new/empty/controls-output

Verifier binary SHA256 during these observations was
9c3e3f321a24e1acb66638058fd77f67906824593422692f9e296e70a688fe65.
The fresh run used the command in the archived observation declaration, with
RAYON_NUM_THREADS=8 and a new empty checkpoint-3 directory. Physical historical
source paths and cache remapping are required as documented in the rebuild note.

## Evidence and limits

`proof-result.json` and `controls-result.json` retain full summaries. Three raw
archives preserve successful proof observations, the initial control failure,
and all repaired control observations/mutations. `raw-index.json` lists hashes
and sizes of every archived file. `asset-sha256.json` binds the saved proof,
header, input, independent expected commitments, guest, bundle and raw archives.
Archive paths are historical observations, not portable replay path instructions.

Regression checks: 30 observer tests and 43 source-integrity tests passed. Two
new wire-layout tests cover identical inner/outer journals, a seal marker,
corrupted outer domain/length, truncation and trailing data; these are parser
fixtures, never synthetic proof evidence.

The previous [deadline failure](../pon-w1-v2-deadline-20261105/README.md) remains
valid negative evidence. This success does not erase runtime variance or establish
prover p99, complete process-tree memory accounting, PQ128, admission, parent
eligibility, real WAN propagation, confirmation, stale-block rate, economic
advantage, or production activation. A repeated verifier replay is not another
independent proof trial. No merge, deployment, pin rotation or trust relaxation
was performed.
