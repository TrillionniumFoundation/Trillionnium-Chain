# Actual native SmolLM NoUpdate iteration and recovery

## Observed result

The original native ignored test passed on **27849cbdcfc0d4afc69764d6c1742af22c41c293**
(tree **af50e58bf382891fb41861810cbf5425ca0da5a9**) in **44.615 seconds** on ai395.
It used the original **60-second nextest watchdog and zero retries**. The actual
Runtime job was `1a1bcaf717a-138b0-409`; its durable terminal state is retained in
[runtime-terminal-v8.json](runtime-terminal-v8.json). Private implementation
continues in [Hepta draft #5393](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/5393).
The tested commit, its compiled archive, Python driver and all 11,207 tracked
source files were pinned and verified before and after the actual run. Later
maintenance source must be assessed separately.

This is a complete **research NoUpdate branch**: an actual new training iteration,
evaluation, retention of the complete parent, original native selection,
a different next task, acknowledged output, model STOP, original terminal learning
checkpoint, and recovery of both generation and learning owners. It is not a
successful adoption of the newly trained candidate.

The same new operation, `learning-d9fb-native-v8`, created its frozen evaluation
configuration and native coordinator before its own training. It then executed
ten optimizer steps on the pinned SmolLM2 model, loaded the exact recorded parent,
wrote a new 933,544-byte LoRA checkpoint and evaluated both parent and candidate
on all four frozen rows. The candidate scored **1/4**, against the parent's **3/4**.
The previously frozen strict-improvement rule returned **NoUpdate**. The actual
new next task loaded the retained parent and produced the retained full
49,152-element logits and Q32 scores.

The four rows and prior outcomes were already public and exposed to the
experimenter. Their rule was frozen before this iteration's training; this is
not independent evaluation, a prospective quality result or evidence of
general model improvement.

## Actual identities and recovery

| Observation | Original value |
| --- | --- |
| Operation | `learning-d9fb-native-v8` |
| Native final checkpoint SHA-256 | `f615357c44d865317a33a07ee1bc538468407f223e4f009df999cfe20e574263` |
| Original ACKed readback SHA-256 | `662a5e0163701c7dccfc35dbc4ae559cc2e896b67aef0bac4c4afce36cd385ef` |
| Frozen plan SHA-256 | `0c23c05e31a285edaca57ea0fad02545fcd3c1326bb8b413ccc2353085960e31` |
| Parent adapter | `e1a9ce940c9d4b04bb827490708604178d4e2391e7afd81a3ca63008389d1e53` |
| Parent file SHA-256 | `a946c2cd7073092e607fb5ee3fd9b2dc78053ba5dc3d357a0a27c273ebbf95e2` |
| Candidate adapter | `6d3ad4295d628df7e5d0927f9044f46dd4375511b2788eeb1606a2cb6d48aa34` |
| Candidate file SHA-256 | `9ed906784ad969209386762f514ba2d209899c7180076d52306c268b7587e64d` |
| Actual next-task output SHA-256 | `5b803dad6abdaaf5e732496b85f3c1d90440bf06975375513b0350a16d11ff22` |
| Actual hot / cold worker PIDs | `203339` / `203366` |
| Original worker ledger counters | Hot `0 → 1`; cold `1 → 1`; after negative controls `1` |
| Native final-use nonce count | `1` throughout recovery |
| Native daemon OS restart | `false` |

Counter claims come from distinct fresh original-worker inspect requests, not
cached open replies or constants assigned from an action name. They are
**source-bound live-worker ledger delta inference**, not an external hardware
instrument for forward invocation. The full original hot and cold protocol
transcripts, counter replies, unchanged output, request-conflict refusal and
`FORWARD_BUDGET` refusal are retained.

The native owner recovery ran in the same test process. It actually stopped and
dropped the old actor, completed the existing Fleet retirement/start lifecycle,
opened fresh daemon state, recovered the original CURRENT/publication/nonce and
generation journals, then recovered the original completed learning checkpoint.
The Python worker was a distinct OS process. The cold original native readback
remained equal to the original ACKed readback; no next-task reexecution or extra
nonce was observed. These distinctions are explicit in the original result.

## Original failures remain visible

All attempts used fresh operation/output directories and their own exact source.
A later success does not overwrite or relabel the preceding operations.

| Run | Source prefix | Original outcome | Durable progress / publication boundary |
| --- | --- | --- | --- |
| v3 | `4f559bf` | Archive extraction directory missing before the model test | No coordinator or generation owner created |
| v4 | `4f559bf` | Native `InvalidGrant`, 36.120 s | Actual training/evaluation and checkpoint 4; CURRENT prepared, not published; zero nonce-claim bytes |
| v5 | `1571b5c` | Fresh-start config rejected Running identity, 41.115 s | Original Selection checkpoint 5; CURRENT published; 40 claim bytes |
| v6 | `b3ed953` | Predecessor not retired, 40.887 s | Hot actual next task and ACK; checkpoint 5; CURRENT published; 40 claim bytes |
| v7 | `681642e` | Prompt durable owner `StateLocked`, 40.171 s | Actual terminal checkpoint 6 and original Chain join passed; cold test failed; CURRENT published; 40 claim bytes |
| v8 | `27849cb` | Original native test PASS, 44.615 s | Same-iteration terminal checkpoint, owner/worker recovery and original Chain join passed |

The v4 outer JUnit collector also initially searched the wrong extraction path.
Its original exit 100 and native rejection are preserved; the original JUnit was
subsequently read from the actual workspace target directory. The v4 preparation
used a grant lifetime above the original 300,000 ms cap. A later source restricted
the research grant to 90,000 ms; the production cap and original native watchdog
were unchanged. The v5-v7 failures exercised existing identity/retirement/lock
gates. Later research-driver fixes released owners through the original lifecycle;
they did not relax those gates.

CURRENT and nonce files in `owner-originals/` are exact bounded post-run
readbacks from each isolated owner directory. The export manifest records when
these observations were collected; they are not falsely timestamped at the
failure instant.

## Unchanged Chain completion reader

The existing `scripts/cell_learning_completion_join.py` directly accepts the
original v7 and v8 CAS checkpoints 0, 5 and 6 plus their exact ACKed actor
readbacks. Checkpoint 0 is the actual before-training owner snapshot, not a
synthetic truncation of a terminal snapshot. The freeze request and owner values
come from that snapshot. Expected actor pins are explicitly observed research
values, not independently trusted expectations.

For both operations, the reader verifies the HEPLCP02 receipt chain, exact
unchanged prefix, complete-parent NoUpdate, exact final appended NextUse receipt,
task/owner/publication identities, ACK and model STOP. It keeps all its
independent authority, native-origin authentication, model-training verification
and production capability flags **false**. The actual native execution receipt
provides a separate source-bound experiment record; a structural reader PASS
does not authenticate that execution by itself.

The native envelope's base commit/tree fields are SHA-256 commitments to the
canonical lowercase Git object ID text. They are not raw Git object IDs.
The original 40-character source commit and tree are retained separately.

## Subsequent source maintenance

Private maintenance commit `6c4bb7e97dddd4b6935513a2881606e41bb921fd`
is distinct from tested commit `27849c`. Its
[source relationship record](maintenance/source-relationship.json) records the
four changed source-file hashes and Python AST equivalence. Rust imports and
Python layout were formatted; the research receipt-attestation method now clones
the same original actor handle/request and releases its mutex guard before the
same owner reads. No tests were rerun after maintenance, following Hepta AGENTS.md.
The v8 actual execution PASS belongs to `27849c`, not these later bytes.

The first formatting attempt genuinely failed because `uv` was absent; its
[failed attempt](maintenance/attempt-1.json) remains. An isolated verified tool
installation supplied the repository's original frozen formatter command. The
[second attempt](maintenance/attempt-2.json) records successful scoped `just fix`,
strict Clippy with `-D warnings`, and `just fmt`. Full private source patches and
logs stay in the private repository's execution workspace; this public bundle
retains their identifiers and outcomes only.

## Replaying the evidence

Run from the Chain checkout:

```sh
python3 evidence/hepta-real-native-learning-20261108/verify_originals.py
```

This checks all **517 original files** against the pinned export manifest,
original refusal boundaries, original JUnit, exact source/archive/runtime
identities, pre-training freeze bindings, candidate artifact and evaluation
identity, all full model output tensors, real worker counter/PID recovery and
the unchanged Chain reader. It does not rerun training. Derived reader inputs,
commands and outputs are in `joins/`; the original material remains unchanged.

The public evidence contains original bounded run/worker/owner records, this
verifier and outer orchestration. It contains no private Hepta source patch,
checkout, compiled private test archive, production credentials or full model
base weights. The earlier [actual Cell transfer](../smollm-same-iteration-20261108/README.md)
is a separate fixed-#807 operation; this v8 native loop does not claim a new
independent network transfer.

**Qualification remains HOLD_NO_GO:** research keys and same-operator custody;
no independent provider, public discovery, long-term hosting, production
FinalUse/root capability, payment, new-candidate adoption or activation.
