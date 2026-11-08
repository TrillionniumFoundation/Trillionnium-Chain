# W1 lifetime source convergence, 2026-11-08

Scope: restore the existing lifetime ledger's selected-source survey on the
unified #812 candidate. **Security remains HOLD. No native Node, signature or
proof execution, quantum resource measurement or production activation is
claimed by these Python runs.**

## Fixed identities and retained outcomes

| Observation | Exact committed source | Result |
| --- | --- | --- |
| Original suite before correction | `7e044b65454f4c9ea505591727332acffb33e7e5` / tree `0cd23efee58e9c08a80a9f38d135d504c96469ea` | Exit 5, `setUpClass` error, zero tests executed |
| Same 19 named methods after correction | `954f4ab44e53fb8961b5a7693084df252017ee25` / tree `0c1e2aa12e0098d72dbdf2801c643b98987a7047` | 19 passed, no skipped/failed methods |
| Original ledger CLI after correction | Same `954f4ab44` source | Source survey executes; three qualification fields remain false and project probability/target fields remain null |

The original recorder checks all 23,326 tracked entries before and after each
command, with equal receipts. It reads 2,380,209,342 bytes on the unmodified
candidate and 2,380,211,144 bytes on the source-only correction. Its filename
contains `native`, but the exact recorded argv here invokes Python; that name
does not turn these observations into native execution.

The before receipt and raw log are retained unchanged. It fails because
`store.rs` is still pinned to SHA-256
`b712a86b9997a098df5e8257f309d22445b2c749c9aa474457e958a0f65f5153`,
whereas #812 contains
`e6e322d670d28ca86c3c94a19bb3b5d53feab3265631d3c83a278e9d5892fb8e`.
The correction changes only the selected base identity and this pin, expands
the existing tamper method to all 20 selected files, and documents the boundary.
It does not relabel the old native evidence or alter consensus/PQ behavior.

## Review before changing the pin

The [source review](source-review.json) and [losslessly compressed complete diff](reviewed-source.diff.gz)
compare the original selected base `7150d96a2112875b4afcf3023361a5cef4a0e4b1`
with #812. Nineteen of the twenty selected files are byte-identical, including
the native relation owner `pon_work.rs` and all of `consensus.rs`.

Seven separately retained byte comparisons cover the direct, progress-aware
and arithmetic-fact W1 entry points; PNH1 header encoding and challenge; the
negative-cache key's tag/profile/context/proof inputs; and the original
admission `parent.work + required_work(h.target)` expression. These retain
the complete W1 input expressions used by the two source-survey statements
that cite `store.rs`.

Other changes are not hidden: `store.rs` adds asynchronous task/demand and
observation modules, cold reconciliation, admission and state-readback changes;
the rejection-cache wrapper adds reservation/observation metadata; the wire
payload decoder adds the separately defined funded-service variants. The
record makes no equivalence claim for those complete paths, no fixed runtime
hash-call count, and no exhaustive query inventory. `other_unmapped` and all
actual quantum/query/lifetime unknowns remain in the existing ledger.

## Reproduction and evidence readback

The [manifest](manifest.json) records every original receipt/log and review
artifact's byte length and SHA-256. Each command receipt also hashes its raw
log and binds identical whole-source records before and after execution.
The outer Git whitespace check initially rejected the raw unified diff's
space-only context lines. That refusal is retained. The published gzip expands
to the exact original diff hash in the source review; no diff content was edited.
The original 19-method roster is retained; its source-mutation method now
rejects one-byte changes independently in every selected file, including the
integrated store.

On a checkout containing both frozen source objects:

```sh
python evidence/w1-lifetime-source-convergence-20261108/review_selected_source.py \
  --root . --output /tmp/w1-lifetime-source-review
python -m unittest discover -s scripts/ci -p test_w1_lifetime_ledger.py -v
python scripts/w1_lifetime_ledger.py
```

Run future qualification on the actual combined candidate and retain its own
receipt. The evidence-only child that publishes this directory does not imply
that these commands ran on a later integrated or prospective-merge source.
