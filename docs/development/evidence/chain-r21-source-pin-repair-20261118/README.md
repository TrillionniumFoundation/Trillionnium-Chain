# Rebind current source pins after r21 backpressure

The 27d6 backpressure candidate changed public_v3.rs and its multiprocess
controls, but retained the previous current-source map and one inline test
blob pin. The existing validators correctly refused those mismatches.
This is a regression introduced by the r21 change, not a pre-existing CI
failure. The archived base, head and prospective-merge logs establish the
before/after relationship.

## Change

Five files receive exact hash updates. The current PQ correspondence map
rebinds only the changed public_v3.rs bytes and its canonical 21-path map
digest. The current reader and current composition manifest/reader use those
same two identities. The recent-batch workflow pins the current multiprocess
test blob 7053c78e6a6626af763092fa4d8a031e48f6122e.

All historical frozen model manifests, source locks and cross-branch corpus
remain byte-identical. The 21-path set, HOLD status, false/null qualification
fields, strict comparisons, negative controls and reader control flow are
unchanged. Native Rust, attacker loops, signed policy, four-second deadline,
resource limits and confirmation criterion are unchanged.

## Validation

The original failure reproductions are retained: the budget suite had one
source-hash error among 58 tests, and the CI contract rejected the stale inline
pin. After the update, all 186 existing tests pass: 58 budget, 25 current
correspondence, 60 composition, and 43 source-integrity controls. The actual
CI contract checks all 26 inline pins successfully. The distributed source
inventory check and git diff check pass. The pin update adds no test bypass,
weakening, qualification promotion or new synthetic native measurement.

The independent read-only review compares all five complete files and the
exact 6,089-byte patch, verifies the AST/JSON scopes and confirms that strict
checks and historical identities remain intact. No extra model or native
campaign was executed for that review.

VALIDATION.json binds the exact changed inputs, commands, raw outputs and
archive hashes. targeted-validation-originals.tar.xz retains red and green
outputs. chain-r21-ci-failure-originals.tar.gz retains the nine original CI
logs and the source/metadata evidence used for regression attribution.
chain-r21-pin-repair-review.tar.gz retains the independent review inputs,
script and result. This evidence does not claim that all automatic CI lanes
have completed successfully.

## Keep the actual native measurement separate

The original-window result belongs to source
27d6a4b19ff58de78f3f5804e44ccae41857c794: x64 and arm64 each confirmed 1/1 in
3.346073556 s and 2.106682700 s. Complete raw originals and the earlier 119c
0/1 failures are persistently retained at evidence commit
0f152b34ae7b4c406cbd9adf84ab23a8bb638586 under
`docs/development/evidence/chain-original-records-20261118/`.
This later source-pin candidate does not relabel those measurements.

The local prepublication cf54 commit and actual remote 27d6 commit have the
same complete source tree and parent. Their raw commit objects differ in the
final line feed of the commit message; the native CI used 27d6. No broader
claim about the cause of that message transformation is required.

Production activation, public-network qualification, independent-operator
qualification and an actual lifetime security bound remain unestablished.
