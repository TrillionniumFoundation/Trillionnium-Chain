# Bounded native Cell verification — retained observation

This record supports the separately named
[native Cell profile](../../docs/development/specs/pon/USEFUL_CELL_NATIVE_V1.md).
It does not activate a consensus rule or authenticate an external task owner.

## What actually ran

The final native suite passed **12 tests, with no failures or ignored tests**.
The seven cross-language oracle cases are inside one of those tests. Earlier
A2/A3 executions repeat the suite and are not additional tests. Strict Clippy
for the library, actual Node binary and Cell test, workspace formatting and
locked/offline Cargo metadata all passed. The [retained index](retained-validation.json)
records exact commands, exit codes and durations.

The archive contains 12 case directories, **11 distinct complete Cell claim byte
strings and 55 distinct full W1 proofs**, deduplicated by SHA256. Each claim
retains all five W1 proofs, independent owner input, actual intermediate tensors,
output, after-state and after-model. This count includes the clearly identified
retired-model counterfactual control; it is not a count of independent external
tasks. Legacy and Authenticated history cases share one claim and are counted once.

Cold replay constructed **three fresh Node stores** and made **six fresh
historical-verifier invocations** over **two distinct claims containing ten
distinct W1 proofs**. Legacy and authenticated history share one claim and
verify before and after the active tip advances; masked sampling/training
repeats its claim at the same verified parent. Separate status/submission
processes perform ordinary store setup. This replay generated zero new proofs
and used no Cell historical clock override. The cold 2/10 subset is not a
replay of the entire retained 11/55 corpus.

The [recovered acc2 concurrent record](../pon-cell-concurrent-revalidation-20261107/README.md)
retains the subsequent native gates and cold subset on the combined source.
Its 40 case files match A4 byte-for-byte. Repeats do not increase unique counts.

## Review and reproduction

- [Complete archive](retained-runs.tar.gz) and [archive size/SHA](ARCHIVE.json).
- [Member inventory](FILES.json), covering the 298 payload files; the manifest
  itself is the 299th archive member and is not self-hashed.
- [Source, Cargo.lock and binary fence](final-source-fence.json). These ten native
  files and the lockfile also match the final merged source bytes.
- [Detailed scope and replay instructions](REPRODUCTION.md) and the exact
  [cold replay script](cold_replay.py).

Extract the archive into a new directory. Its root is `native-validation/`.
`a4-cli/native-cases/<case>/` contains `owner-admission.json`, `claim.json`,
`settings-and-context.json` and, for history cases, the exact packet bytes.
`a4-cold-replay/` contains actual fresh-process commands and raw outputs.

The original Clippy diagnostics, sparse-checkout formatting failure and
pre-execution transfer SHA rejection are retained alongside successful reruns.
No failed raw result was rewritten.

## Qualification boundary

These are synthetic, bounded integer correctness fixtures. The native encoder
accepts independently pinned UTF-8 snippets and executes the declared ASCII
tokenizer; it does not authenticate Git provenance or implement general multimodal
encoders. Historical time comes from verified Node parent state. Live checks do
not grant current task-owner authority.

This record does not consume a real owner operation, grant FinalUse, commit an
owner checkpoint, execute tools, prove external delivery or production model
adoption, or qualify model quality and work cost. The private Hepta owner path
does not consume this public native proof in these observations. A pure verifier
may accept the same valid claim repeatedly. All corresponding qualification and
production-activation flags remain false in the retained index.
