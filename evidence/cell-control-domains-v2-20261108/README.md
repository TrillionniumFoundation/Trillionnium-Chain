# Four-domain Cell control material: executed qualification

## Result and exact source

**Local implementation checks pass; independent deployment remains HOLD_NO_GO.**
The implementation is GitHub commit
`ca8ca808ee636cc282dfee9558e419ab1225820f`, tree
`13d136f1a8732fb454f12f3d196cd69816c9a53b`, continuing #787 at
`e02126dabef04f13792dec45d96ac5d6916d0651`. Its five changed paths were
published through the authorized GitHub connector as administrator ProfHepta.
The local development commit `aa53711c754cd136bd5ad1dc006ab58549bcb3b9`
has the identical tree. Validation below ran after fetching the actual published
implementation and does not relabel the local commit as a GitHub commit.

The [machine summary](summary.json), [frozen command plan](validation/plan.json),
[all command outcomes](validation/results.json) and
[executed runner](executed-command-runner.py.txt) retain the exact arguments,
timeouts, timestamps, exit statuses and raw-output digests. Evidence publication
is a later change; it does not claim that its own commit was the executed source.

## What changed

The [V2 reader](../../formal/release-finality-v2/control_domains.py) executes the
unchanged seven-role V1 check, binds its original owner inputs and reads exact
canonical source-document bytes. Administration, funding control and custody
are joined across the same controller identities, including transitive and
cross-axis relations. Known funding control also restricts reviewers. Failure
dependencies are checked separately on the same mandatory role pairs, including
storage-controller pairs. Missing documents or unknown axes cannot become an
independence result. Withholding a document cannot erase a pinned adverse link.

The [contract](../../docs/development/specs/pon/CELL_CONTROL_DOMAINS_V2.md)
specifies bounds, the new namespaces, exact document statement binding, current
time checks and the distinction between common authority and common failures.
The existing campaign gate runs the original signed V3 parent/NoUpdate verifier
before the added material check. Neither layer grants native authority.

## Frozen validation

All **15 planned commands completed with exit 0** on the published source.
The listed unit-test method executions total **329**, including repeated use of
underlying verification functions; they are not independent deployments.

| Scope | Result |
| --- | --- |
| Complete release reference conformance | 140 passed, zero failed/errors/skipped; includes the 20 new domain/join tests |
| Original generation / context / parent suites | 7 / 8 / 10 passed |
| Original signed learning-owner check | Two valid existing V3 cases and two actual wrong-parent refusals passed |
| Negative source-integrity controls | 43 passed; expected refusal records printed by these tests are not suite failures |
| Project-boundary controls | 16 passed |
| Existing CI contract suite | 105 passed |
| Repository and local Markdown links | Passed |
| Locked complete Cargo dependency graph | Passed |
| Rust formatting | Passed |
| Workspace, all targets, all features, strict Clippy | Passed with `-D warnings` |
| Exact full tracked bytes before and after | Identical source receipts: 11,570 entries, 1,092,808,076 bytes |

The complete original source-identity JSON is retained in
[source-before.stdout.txt](validation/source-before.stdout.txt) and
[source-after.stdout.txt](validation/source-after.stdout.txt), which are byte
identical. The runner's `source-before.json`/`source-after.json` paths hold command
metadata: its metadata write reused the path selected for the tool's receipt.
No identity content was discarded from the raw stdout streams, and both streams'
hashes remain in that metadata. This filename collision is retained explicitly;
the streams, not a reconstructed execution, are the source evidence.

Development observation before this frozen run: the 20 selected new tests and
140-test reference suite passed; the source-integrity and boundary suites also
passed. Those development repetitions are excluded from the 329 count. A git
transport dry-run could not acquire an HTTPS username; the authorized connector
then published the matching tree successfully. That transport limitation is
not a source or test result.

## Scope that remains unaccepted

All new controller IDs, domain assignments and documents are explicitly synthetic
test fixtures. Hash and statement equality do not authenticate documentary facts,
prove complete beneficial-control disclosure, or create independent operators.
The result retains all independence, physical installation, native FinalUse and
activation flags as false, with no joint independent-operator count.

Actual complete administrator/fault/funding/key-custody observations, external
authentication, original learning actor-to-controller association, current
revocation, independent WAN/fault campaigns, funding and real consumer use remain
required. The inherited WAN V4 matching audit remains a separate requirement.
No native runtime test, protected-main merge or production activation was executed
by this control-material validation. Hosted CI and prospective-merge outcomes
remain separate from these local passes.
