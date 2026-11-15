# W1 fixed field certificates and separate route audit

Status: **complete security HOLD**. Finite algebra and fixed source correspondence
do not supply a complete STARK/QROM theorem, quantum extractor, recursive
composition, lifetime error bound, or production/consensus admission.

## Frozen source and completed coverage

- Baseline: `e2a02f9271b49f146e70806c8a66e161b5973971`.
- Tested code: `eeeaafbc742d4b384e8e8b0d53c65b7e8b3bf182`.
- Tested tree: `3149b20d568422f39fba74197ab9ae5874136834`.
- The complete tracked-source observations before and after the final local
  Python run each verified **26,171 entries / 2,501,252,940 bytes**, clean.
- The remote original 50-method suite has the same complete before/after source
  checks. These are source-identity checks, not additional tests.
- Completed current-source method coverage is **374 + 50 = 424**, across
  **eight selected Python suites, different hosts and attempts**. This does
  not count every repository test or hosted CI, and is not one all-green invocation. The
  interrupted local suite is retained and contributes no completed-suite count.
- The earlier 424-method run on `c561fcb5a1c99d77722bb2f5e85e7b4e61961ce7` remains historical evidence
  and is not added to current coverage. The 789 small-field polynomial cases
  are inside existing methods. New field/route methods are 38, plus one new
  CI-contract method.

| Scope | Host | Observed result |
|---|---|---|
| Seven completed Python suites | Managed executor | 374 methods, OK without skips |
| Original local repository suite | Managed executor | SIGKILL (-9); no completed-suite count |
| Same original repository suite, later run | Desktop | 50 methods, OK without skips |
| Workspace metadata default/all; workspace/P3 formatting | Managed executor | Exit 0 |
| Original P3/RISC metadata attempts | Managed executor | Missing-cache failures retained |
| P3 locked graph recovery | Managed executor | 74 resolved nodes; 73 registry archives and extracted bytes checked in retained records |
| RISC locked graph recovery | Desktop | 193 resolved nodes; 188 registry archive checksums checked in retained records |
| Strict Clippy, original | Managed executor | Exit 101; ENOSPC |
| Strict Clippy, retry 01 | Managed executor | Exit 101; compiler SIGKILL, cause unknown |
| Strict Clippy, retry 02 wrapper | Managed executor | Exit 1 before compiler launch; input snapshot FileNotFoundError |
| Original remote provider preparation | Desktop | Cancelled (-15) after two download timeouts; Clippy had not started |
| Strict Clippy, final supplementary attempt | Desktop | Exit 0; effective gate passed: true |

Successful supplemental runs do not overwrite the original failures. Metadata
resolution, archive checksums, formatting, compiler linting, and native proof
execution are separate observations. The final Clippy record preserves the
original flags, Rust 1.95.0 and selected provider 3.5.9 inputs; selected input
identity is not a complete compiler-closure proof.

## Records and interpretation

The [manifest](manifest.json) indexes every archived record by byte count and
SHA-256, including the individual members of nested record archives. The
[raw records](records.tar.gz) retain runs, stdout/stderr, summaries, available
runners, historical observations, fixture-cleanup records and failures.
Dependency caches, build targets and fixture binary payloads are excluded.
The raw Hepta host-status observation is explicitly omitted because it includes
private runtime metadata; no omitted value is reproduced in this evidence.

Archive SHA-256: `90f70aa9c721a18b282b587ad7ba485913283c051552b5389e3a83e300c3e898`.

The [instance audit](../../docs/security/W1_STARK_ROUTE_INSTANCE_AUDIT_V1.md)
and [literature review](../../docs/protocol/pon-nakamoto-v1/details/STARK_THREE_ROUTE_LITERATURE_20261109.md)
state the exact scope. The historical roster retains 15 IDs: one pinned-version
correspondence sub-obligation closed, 14 other historical obligations, zero
fully discharged security obligations, and eight open implementation interfaces.
All PQ/extraction/recursion/production/admission qualifications remain false;
complete security bits and lifetime budget remain null. Hosted-CI completion and
publication were not established by this packaging operation. The evidence
directory is written after validation and does not relabel its own future
commit as tested code.
