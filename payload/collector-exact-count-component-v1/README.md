# Exact owned-process collector control count

Local component commit: f0f6a4192dc3bcda2fca20110322f7cff07e4644
Tree: f2301d62786c8cca73d16c52ae24a2a2dc82e65d
Single parent: 08c9becab740ab2c375b970f376a7638f44c9e8e

The original M5 Linux lane was reported by root to finish all 16 collector tests, then fail because the subsequent exact-count parser still required 14. Root retains the full original ROG summary/stdout/stderr separately. baseline-proof/root-reported-original-failure.json preserves the supplied original references and clearly labels their provenance; it is not a fabricated copy of those original logs.

This component changes exactly three files. ci_job.sh and the independent check_ci_contract.py block each require exactly 16 collector controls. Their shared original strict count, OK, zero-skip logic and dynamic refusal message remain unchanged. test_ci_contract.py keeps the original bad 0/13 cases and adds rejection of the old 14 and incomplete 15 counts. The other 11 suite counts, source commands, failure propagation and deadlines are unchanged. The collector production file and all 16 collector methods were not edited.

The independent baseline proof reads fixed Git blobs at M4, C5 and M5. All original 14 methods are identical in both raw source and AST. C5 and M5 have byte-identical whole collector/test modules and exactly the two named additional ClosedExecGateSignalControls methods.

Actual validation:
- Four selected original W1PostwinLaneTests passed, zero skips.
- The actual check_ci_contract.py command passed.
- bash syntax and git diff checks passed.
- Ten synthetic inline-parser cases verified the original rejection of 16, updated acceptance of exact 16, and refusal of 14/15/17/0, skipped/failed output, duplicate counts and missing logs.
These synthetic count fixtures are not native collector executions or hardware observations. No collector/full Linux/Host workload was rerun here.

The first external validation launcher had a quoting SyntaxError before any checks ran. Its original text and terminal failure remain preserved; the corrected launcher did not change the repository patch. No failed observation was rewritten.

The local branch is fix/chain-owned-process-control-count-20261114; it was clean after the three-path normal commit. Root's source stayed at the original clean M5 checkpoint during this component. Plan/corpus updates and the final full lane are root composition responsibilities. No remote or ROG write was performed.
