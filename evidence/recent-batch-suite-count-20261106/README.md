# Recent-batch error-boundary count correction

At candidate `502fb53cb120e85f8c33a7b362883c2ffc10d24b`, all four jobs in
[run 42140107619](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42140107619)
executed all 16 error-boundary tests successfully. The following shell guard
still required exactly 13 passed tests, so it exited 1 and skipped the subsequent
steps. These are retained failing workflow observations, not failed Rust tests.

The four `.txt` files are verbatim libtest running/name/summary lines extracted
from the respective GitHub job logs, with only the GitHub timestamp prefix
removed. They are excerpts, not complete job logs. Jobs 127638016541 and
127638016822 tested the prospective merge; jobs 127638016683 and 127638016786
tested the head. Each roster matches the 16 tests in the current source module.

The correction requires exactly 16 passed, zero failed and zero ignored tests.
The original pinned compiler, release profile, complete module command,
pipefail, three exact individual replays and their identity checks remain.
A focused regression checks all four real excerpts against the old and new
guards, matches their names to source, and rejects incomplete, reduced, extra,
failed and ignored summaries. The workflow runs that regression before its
unchanged native command and triggers on its test and fixture paths.

Local validation: four Python regression cases pass, including all four retained
job excerpts. This replays the shell guard; it is not a new native test run.
The reset local computer has no Cargo compiler available. No Rust source,
resource budget, acceptance limit, activation flag or global HOLD gate changed.
Success of later native workflow steps remains to be observed on the new commit.
