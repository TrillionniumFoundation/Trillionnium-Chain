# PQ startup fixture and unsupported archive boundary repair

This focused repair is based on the unchanged PQ development head
`bbc511c7942de24b75054d1b4c3e5d0e4f4a5ab3`.
It changes no large-state CPU-budget or arithmetic implementation and does not
include the separate system/PQ integration candidate. Production activation and whole-chain
qualification remain false.

## Reproduced failures and preserved semantics

The original [Node runtime CI job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41063116512/job/124087549718)
reported 780 passed, 8 failed, and 21 ignored. Six failures were in the seven
`operator_pq_startup::tests` cases. The exact original development source was
also run locally with Rust 1.95.0, the locked Cargo graph, release optimization,
all features, and one test thread. It reproduced **1 passed, 6 failed**;
`original-native.log` and `original-native.json` retain the output and input
hashes. The other two original Node failures are capacity tests; their unmodified
final-executable reruns are recorded below.

Five startup failures reached the real M06 `FUNDS` check. The fixture meant to
transfer **7**, but encoded that inherited M06 amount as big endian. The existing
executor reads the amount as little endian, so it actually received
**504403158265495552** against the original **100000000** account balance.
The fixture now uses the existing little-endian amount grammar. The PQ envelope
and memo-length encodings are unchanged. No amount, balance, fee, CPU budget,
Work limit, or original assertion was relaxed.

Two readbacks also selected a nonexistent `active.id` column. Both now use the
actual schema's `tip` for `singleton=1`, matching `Node::active`.

The first repaired native run reached **5 passed, 2 failed**. Both remaining
failures were genuine `ExternalContext` refusals on cold reopen. The fixture
reused its original signed budget while generating a new allocation expiry of
`now + 300 seconds`; that exceeded the retained delegation expiry. Production
`check_delegation` correctly rejected it. The fixture now retains the first
signed expiry in `Outside` and reuses that upper bound after restart. Added
assertions require every view and allocation to remain within that original
window. The revoked-task test additionally requires `PQ5_TASK`, so a malformed
owner authorization cannot masquerade as a successful revocation test.

The final bounded-window startup run passed **7 of 7 tests**, with no failures
or ignored tests and actual Cargo exit 0. The complete log and source hashes are
in `candidate-bounded-reopen-native-restored.log` and its JSON record. All checked
inputs remained unchanged during execution. The original 1/6 failure, the
intermediate 5/2 failure and the targeted stack trace remain available.

An earlier bounded-window compilation lost its completion record during a tool
transport interruption. Its remaining log contains only a compilation line; its
Cargo exit and termination cause are unknown. It is explicitly recorded as
`INCOMPLETE`, never as a passing or failed test sample. The next offline attempt
returned Cargo exit 101 because previously reclaimed dependency archives were
missing. Both attempts are retained. The final successful run followed a normal
original-lock dependency fetch through the unchanged configured proxy.

## Archive boundary

The reference `AuthenticatedStateArchive` still binds retained packets with the
classical codec and uses the classical authenticated execution relation. Opening
an empty archive with a PQ application could previously create a database before
a nonempty record reached that unsupported path.

`UnsupportedProfile` is now returned before the progress callback or SQLite open.
The same guard protects operations on an already-open archive before inspecting
or changing its state. This closes an unsupported path; it does not implement PQ
archive execution, namespace migration, or activation.

All **8 archive tests passed**, both in the intermediate run and again using the
exact final startup test executable, including the seven retained classical tests
and a real NPQ6 negative. `final-archive-native.json` retains its executable hash
and exact command. The new case verifies that a missing archive stays absent,
a missing parent directory is not created, an existing empty file remains empty,
and a populated classical database plus WAL/SHM bytes remain identical after
refused PQ access. Classical reopen and state readback still succeed.

## Original capacity tests on the same final executable

The two original large-parent tests were run sequentially after startup and
archive verification, without another Cargo build. All three follow-up runs
used the actual Node library executable reported by the successful startup run,
with SHA-256 `ceab53aff05d196bcc1036cd6b38f2020d006a91448836620fb70618208da8bd`.
Both original capacity tests passed, including all of their later original
state, work, owner, worker, readback and cold-reopen assertions.

| Retained test branch | Owner plus scoped-worker CPU | Original limit | Result |
| --- | ---: | ---: | --- |
| Paired test, Legacy | 918454457 ns | 2000000000 ns | PASS |
| Paired test, Authenticated | 1428148517 ns | 2000000000 ns | PASS |
| Supplementary test, Authenticated | 1581700078 ns | 2000000000 ns | PASS |

The fixture still has 8625548 actual UTF-8 key/canonical-value bytes and the
original 8391103-byte lower-bound observation. Each receipt reports two started,
finished and known workers. `final-capacity-observation-summary.json` links the
complete logs, input hashes and exact executable identity. Neither test input,
CPU budget, schedule, implementation nor original assertion was changed here.

The previously retained `da31aff` baseline authenticated observations were
2807473643 and 2791540228 ns and failed. These new runs observe the arithmetic
candidate already present in `bbc511c`; they are not an optimization supplied
by this focused startup/archive patch. The shared host was not qualified or
exclusive, and identical baseline/candidate hardware conditions are not
established. These fixture results do not demonstrate default-genesis growth,
sustained concurrent honest service, budget depletion, WAN throughput or
whole-chain post-quantum security. All original qualification flags remain false.

## Verification and limits

The exact source checker covers 226 pinned blobs and still returns `HOLD_NO_GO`.
Its 32 negative tests pass. The two archive files are mandatory source inputs,
and reviewed source pins were explicitly refreshed. A checker refusal during
that explicit pin update is recorded in `local-checks.json`.

The changed Rust files pass formatting and the changed implementation/configuration
sources pass whitespace checks. The raw final test logs retain libtest's trailing
blank line byte-for-byte, so a whole evidence diff whitespace check reports that
artifact formatting; those original logs and their hashes are not normalized.
The full workspace formatting check still fails on four **unmodified**
files in the original development head; see `full-workspace-format.json` and its
complete log. This draft does not describe that full gate as passing. Strict
Clippy and the original complete Node/CI matrix remain remote gates.

The first offline dependency-preparation failure is preserved separately. The
missing archives were subsequently fetched through the configured proxy using
the original lockfile. Native runs used an isolated target, one build job, and
no incremental compilation. The 8 GiB cgroup already had 38 OOM and 8 OOM-kill
observations before these runs; no increment was observed in the completed
baseline, intermediate or final executions. Their JSON records distinguish actual
Cargo exits from the runner process exit.
