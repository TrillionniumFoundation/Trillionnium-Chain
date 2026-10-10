# Native evaluation confirmed-chain observation v1

`trnm_pon_node::Node::evaluation_observation(candidate, observed_now,
max_ancestry_blocks)` reads the existing native public-evaluation owner. The returned
`EvaluationObservation` and `EvaluationAnchor` have private fields and no deserializer
or unchecked constructor. A caller cannot supply a score, roster, phase height or
confirmation flag to construct them.

This is an additive local observation interface. Native tags14–17, admitted-height
deadlines, mandatory closure, tag8 adoption and funded tag9 claims keep their existing
rules. Work, signed domains, network/parameter/genesis bytes, database schema and
chainwork are unchanged. The old formal policy and its signing domain are not implicitly
converted into the native protocol.

## Source of the observation

The method checks the existing namespace/recovery owner, reads the root-checked active
State, and reconstructs the candidate's frozen evaluation from its active contribution
or retained archive. It binds the frozen context to the installed network, parameters,
family and model/task plan, and recomputes the native frozen-round digest. It finds the
actual submission block on the active ancestry, checks its transaction sequence root
and exact candidate tag6 membership, and compares the frozen plan with the historically
committed submission State. A closed result must also equal the result in the actual
active ancestor at its recorded closure height; an admitted inactive fork is not a
closure anchor.

Every ancestor header is checked with the existing admitted-header metadata owner and
the fresh `observed_now + future_skew_seconds` bound. Heights, parent links and cumulative
work must agree. For each block, confirmation uses the installed depth and the actual
tip-work minus included-block work, compared with that block's target-dependent required
work multiplied by the installed confirmation multiplier. No bare height or `head minus
depth` shortcut is a confirmation fact.

The confirmed prefix starts at genesis and stops at the first ancestor that does not
meet both installed conditions. Individual target-dependent thresholds need not be
monotone after retargeting; a later qualifying block cannot skip an earlier unconfirmed
one. Candidate and closure anchors separately report their actual depth, work difference,
threshold and confirmation status. A closure anchor is a committed block-State fact,
not invented transaction membership for an empty mandatory-close block.

The result separates `admitted_phase` from `confirmed_phase`. The latter is absent until
the candidate submission itself is confirmed and belongs to the continuous confirmed
prefix. It then refers to the conservative actual
confirmed prefix. A caller still needs to respect the native admission window: a
confirmed phase does not reopen an already ended admitted phase. Aborted, null-score and
zero-score results stay unchanged; a positive signed score is not objective model value.

## Freshness, bounds and authority

`observed_now` comes from the caller's trusted local clock observation. It is not an
independent or externally authenticated time certificate. The observation binds one
active tip and generation; both are checked again before
return. `Node::check_evaluation_observation(prior, observed_now, max_ancestry_blocks)`
rejects a different namespace, tip or generation and re-observes the clock and result
before current-view reuse. It does not cache another caller's clock verdict. An extension
or reorg requires a new observation. The existing operations/session owner must retain
and reconcile that lifecycle; this module creates no second durable ledger.

`max_ancestry_blocks` is required in1..4096, and complete ancestry must fit. There is no
partial-success frontier on overflow. These finite reads and iterations are software
work bounds, not preemption of SQLite or a wall-time SLA. Longer chains require an
explicitly reviewed successor observation strategy. Already admitted work is not replayed
here; this is the same local storage-integrity and native-validation trust scope as the
existing confirmation API, not protection against arbitrary whole-database rewriting.

All returned finality, adoption/reward/execution authority, objective quality, independent
governance and public-readiness flags are false. Serialized output is an unsigned local
observer receipt. It neither proves an independent node's execution nor provides public
roster governance, funded appeal adjudication, scientific work hardness, useful model
quality or permission to activate a public network.

## Actual local regression scope

The dedicated `trnm-pon-node/tests/evaluation_observation.rs` uses real signed native
candidates, commits, reveals, missing-reveal closure, funded adoption, matured reward
claim, archived appeal and late signed conflict. It checks unconfirmed versus confirmed
closure, admitted versus confirmed phases, fresh-clock/ancestry-limit/profile refusal,
SQLite restart and a heavier fork invalidating the prior observation. A separate pure
arithmetic control checks that the work threshold can reject despite sufficient depth.
These regressions validate their finite development interface; their pass does not close
the public evaluation gate or certify prospective independent evaluator custody.

## Local executable query

The native CLI exposes the same private-constructed result:

```text
trnm-pon-node evaluation-observe --development --store OWNED_STORE \
  --evaluation-policy native-public-evaluation-dev-v1 --candidate CANONICAL_HEX32 \
  --ancestry-blocks 4096
```

Supply the store's existing genesis/task/model or explicit operator context flags;
the command cannot reinterpret a store under another namespace. `--candidate` must be
canonical lowercase32-byte hex. `--ancestry-blocks` defaults to4096 and must be1..4096.
Both are validated before a store is created or opened. No peer, authentication,
admission, pool or mining options, or bare height, are accepted by this command.

The default clock is the existing `ingress::now()` local wall observation. Existing
`--logical-now SECONDS` selects an explicit trusted local test-clock input and the output
labels `clock_scope=logical-test`; it is not an external time attestation. Successful
stdout contains the typed observation under `result`; all its authority and readiness
flags remain false. Invalid input, unknown candidate, historical evaluation profile,
deferred clock and exceeded ancestry bound return exit2 with no success object.

The query uses normal `Node::open` with its exclusive owner and normal recovery. It
may create or recover a store and write recovery/checkpoint metadata; this command is
not an OS read-only database opener. A live store already held by another native owner
cannot be queried by launching a second CLI owner. Serialized results are unsigned
observations, not reusable signed phase or reward certificates.

`tests/evaluation_observation_cli.rs` executes the real CLI against a closed archived
candidate, checks API/CLI field identity and restart, wall/test-clock labels and all
false authorities. Invalid hashes/bounds/options reject before creating their store;
unknown candidate, historical profile and deferred-clock cases preserve exit2. These
finite ordinary regressions do not imply public peer observation or operator independence.
