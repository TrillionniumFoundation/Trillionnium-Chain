# Current PQ declared-source correspondence V2

This directory retains the original frozen-source refusal and the complete
bounded inventory of current differences. It contains no new native or
cryptographic acceptance result.

## Original observations

- Source commit: `92ec9b983dfd7a9194c3c1e2dd75076a1e1b4cf7`.
- Source tree: `7118a8748cfaa2a580e703afd6090eee559a9a58`.
- CPQ1 workflow run: 45644157214; original ARM job: 139310473789.
- `original-source-integrity.json` and `original-source-integrity.log` are the
  exact bytes extracted from original artifact 15037737018. The retained ZIP
  SHA-256 is `4406e03c1e0f93c585702e8046b23aa37d5855a5cfb1ed2699284ad57bc096c0`.
- The command exited 1 after 7.470137729 seconds, with clean exact source before
  and after. It refused the changed closure workflow. This remains an actual
  failed command; no subsequent CPQ native result is implied.
- The same source's repository-truth job 139310475919 also rejected the embedded
  native inventory. It lacked the two newly added modules.

`original-current-drift.json` compares every one of the frozen corpus's 2,613
blob pins with the original current Git tree: 30 differ and none is missing.
That record is retained unchanged. The new sole-plan prefix and inventory
correction naturally have their own later bytes in the current delta map.

## New source-only boundary

The independent map at `config/pon/pq-corpus-current-source-v2.json` preserves
the immutable corpus and guard identities, retains all old declared paths, and
adds the two reviewed modules. Exactly 30 replacements and two additions are
allowed. The reader binds both the map bytes and the complete merged blob-map
digest independently, and invokes the unchanged coverage and provider checks.

The new reader does not assert that a collection of separate descriptor reads
is a Git revision or a complete dependency closure. Its own bytes, tests and
workflow are outside that declared historical path set and require the new CI
lane's complete exact-head before/after source verification. The original V1
checker and all four existing workflow callers remain unchanged and may still
refuse this different source. The new source-only lane cannot replace them.

The inventory's original policy requires three additional paths: both native
modules and the new map itself. The final expected count is 1,750. There is no
map hash cycle because the inventory embeds paths and source bytes through
`include_bytes!`, without embedding a digest of the map.

All original qualification flags remain false and the actual lifetime failure
bound remains null. Local metadata controls and future CI must retain their
own exact source, named execution, failures and inclusive cost; neither can
inherit a native, scientific, security or production qualification.
