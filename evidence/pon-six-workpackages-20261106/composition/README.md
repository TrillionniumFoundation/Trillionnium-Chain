# Composition with the concurrent Cell transport continuation

The original integration branch advanced to `1f723bba961ec5f8d7e25e7b33db222dac7ef50c`
while this work was being validated. The source composition preserves that head
as its first parent and `038c063e48bf2f42884a44f62c65f22ac626595e` as its second
parent. It does not overwrite the three concurrent commits. Their complete
[evidence](../../cell-bt-composition-20261106/README.md), original failures and
35-second / 272,189,990-byte cold-cohort HOLD remain intact.

The concurrent custody-window fix and this work's owner fix use the same
`check_effects` call at the same boundary. The merge keeps one call in retain
and one in repair, together with both owner-generation and custody-window
explanations. It does not apply the guard twice. The native implementation,
without line comments, equals the incoming production implementation. Both
`height_window` and `replay_owner` regression modules remain registered.
The complete combined storage selector has 22 controls: 15 original, two
concurrent height-window controls and five owner-replay controls.

The source corpus is the union of both required-path/pin sets, recalculated
against the actual merged files. The generated native inventory includes all
new files from both branches. No signed domain, stored schema, budget, deadline
or readiness flag was changed to resolve the merge.

The 95 explicit V4 execution inputs still match their recorded bytes. M09 and
Node changed outside that limited closure, so the V4 measurements remain tied
to their original source and ELF; they are not a new binary performance run.
The earlier `validation/source-applicability.json` describes the first
candidate before this composition. Its storage input identity is not silently
reused for the combined source. The original 20/20 native result, the later
first-candidate 20/20 and nine sampler controls, and all other completed gates
are preserved in [the first-candidate archive](first-candidate-validation.tar.gz)
with [every member indexed](first-candidate-validation-index.json).

The combined source requires fresh M09 all-target/all-feature and documentation
controls, the 22-test storage selector, M12 native-budget controls, the sampler
unit controls, full strict Clippy, source integrity, graph, formatting and
repository-link checks. Those results must name their actual merged source;
older H2 or first-candidate success cannot supply them. None of these component
checks replaces the original public-service, History, externally funded task,
whole-Cell proof or independent adoption requirements. All six workpackages
remain HOLD / NO-GO.
