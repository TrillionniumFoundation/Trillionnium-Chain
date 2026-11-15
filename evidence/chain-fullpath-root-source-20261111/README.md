# Root dependency source review for the fullpath continuation

Status: **HOLD**. This is a reviewed source-binding repair. No native campaign,
throughput measurement, dependency-security qualification or production
activation is established by these records.

## Original source and failure

The complete review uses base commit
`53e1b98a7955898b9feff4778f7136c0fd0199c8`, tree
`094ccb0afc9e7ffbbcc83f85efb6ca4ad8d54aa0`.
The existing checker returned exit 2 with
`source hash mismatch: trillionnium/Cargo.lock`. Its original 42-test suite
returned exit 1 with four failures and one error. The original
[failure stream](before-tests.stderr.txt) is retained unchanged.

## Reviewed change

[All 37 declared sources](review.json) were read from both the old reviewed
Git snapshot and the new fixed commit, then compared with regular working
files. The 35 unchanged hashes stay unchanged. The only two differences are:

- `trillionnium/Cargo.lock`: rustix 1.1.4 becomes 1.1.6 with its corresponding
  checksum. A parsed package comparison confirms every other package and
  dependency edge remains unchanged.
- `trillionnium/crates/trnm-crypto-primitives/Cargo.toml`: the Linux test
  dependency selects exact rustix 1.1.6 with the same `time` feature.

The manifest and trusted checker's exact review-base/map constants now bind
that source. The current canonical source-map SHA-256 is
`8195617385b57241b7fa420dfd1d05f0d3b6287c818c1edcafc65697598ab577`.
The checker has no runtime accept-current mode. Its declaration grammar,
37-path roster, all role/suite/query obligations and limits are unchanged.

## Actual focused validation

All 42 retained tests plus a new reverted-dependency control passed: **43/43**,
zero failures/errors. The additional control reinstates the old rustix
version **and matching checksum**, requires refusal against the current
source hash, then changes the manifest hash and requires the trusted frozen
map to refuse that attempted rebinding too.

[Validation metadata](validation.json) binds the four changed working-file
hashes, command outcomes and original streams. This is a working-source
focused test observation; a final combined candidate has its own identity and
must execute its required checks. The [inspector result](register-result.json)
returns exit zero with `status=HOLD`, `source_files_checked=true`,
`source_revision_bound=false`, eight null domain bounds and
`production_activation=false`. The [passing stream](after-tests.stderr.txt)
does not replace the original failure or qualify the four-second or three
30-second service gates.
