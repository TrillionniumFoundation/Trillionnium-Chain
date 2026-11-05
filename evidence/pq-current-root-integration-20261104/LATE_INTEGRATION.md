# Late integration and actual verification

**Status: HOLD / NO-GO for whole-chain qualification and activation.**
This follow-up belongs to existing Draft PR #688. It records actual executions
on commit `dba49c2f66d8a72d6845c70958c4a24d6c4e7e89`, tree `25ae0d2035b763b916575292d04571e93a512dd1`. It does not move an earlier execution
to a later commit or provide independent organizational acceptance.

## Source and preserved concurrent work

The fixed code merge has parents `fc86ed8e927a8eb4e048b160437126a6c0b96c0d`
and `8f8462803f190e6c60e3e8d87f6673c3480504b7`. It preserves the current-root,
checkpoint and original PNQ2 deadline fixes together with concurrent Cell,
Growth, public-service startup/request observation and shared-material changes.
The final merge combines only the plan, generated inventory and source corpus
where both sides changed them; exact incoming production blobs are retained.

Later commit `160b6f91e39708454d1edd200ab9ef2b4192192e` changes exactly four
shared-material evidence paths. Its complete tree was reconstructed and the
non-evidence diff from this fixed code is empty. This source-delta observation
does not relabel any command as an execution on 160b6f91.

Every completed command on this code verified all **9,771 tracked entries /
960,078,192 bytes** before and after execution. These are head-checkout runs;
a prospective merge with protected main and a complete Chain/runtime deployment
were not executed. Each earlier F command retains its own source identity.
The composition audit checks **487 source pins**, **405 required paths** and a
**52-control roster**. A roster is not an execution count. All explicitly checked
qualification/activation fields remain false.

## Actual results on the fixed code

| Scope | Observed result |
| --- | --- |
| M06, M09, M12, M15 default-feature native command | **671 pass, 0 fail, 8 ignored**, including 14 compile-fail documentation checks. M06: 241 runtime + 2 documentation; M09: 352 runtime/CLI + 10 documentation; M12: 46 runtime + 2 documentation; M15: 18 runtime. |
| Shared-material native example | **6 pass**. This does not establish work savings, proof-backend soundness or hostile-service capacity. |
| Selected M03 recovery targets | **33 pass**: 15 cold recovery, 15 binary-module and 3 CLI-refusal controls. Three positive AF_UNIX cross-process cases remain outside the selector. |
| Node canonical selectors | 9 pass: 3 PNQ2 completion, 2 exact startup deadline and intake domain controls, 4 request lifecycle controls; original canonical profile retained. |
| Source/model/public-observation/shared-operator Python controls | **370 pass**, including the unchanged actual-source and conditional-DAA controls and added image-binding/complete-operator checks. |
| Recorder, claim, authority-inventory and CI-contract controls | **135 pass**: 4 + 22 + 11 + 98. Repeated/imported coverage is not claimed as independent additional assurance. |
| Strict Clippy | **7 packages**, all targets/features, warnings denied: Node, mvcc-fee, service-settlement, checkpoint-store, release-bundle, data-availability and crypto-primitives. |
| Workspace and repository | Corrected full-workspace formatting, source inventory, exact corpus, diff checks and **2,967 local links** pass. |
| Locked offline graph | 26 workspace members, 175 default resolved packages, 180 lockfile package entries. |

The eight ignored cases are existing explicit component timing/RSS experiments.
They were not executed or counted as passing. The four-package command uses
default features; the all-feature Clippy result is compilation/static analysis,
not an all-feature runtime test claim. Source guards and arithmetic/report tests
do not prove the cryptographic goals in the six-domain acceptance contract.

## Failures and resource observations remain visible

On F (`8f846280...`), six-package strict Clippy passed, but the authority/storage
command failed after **322 passes and five CLI spawn failures**. M15/M12 were not
reached by that failed command. The failing `cell_closure_cli` ELF embedded the
removed `target-authority/debug/trnm-cell` path while its `.d` metadata claimed
the current `target-integrated` path. The evidence establishes an artifact-path
inconsistency; it does not identify the historical operation that caused it.
The M09 package cache was removed and rebuilt. On the fixed final code all five
closure CLI cases pass within the successful four-package command. No symlink,
test relaxation or production-code workaround was used for the cache failure.

The first final structure command omitted `cargo fmt --all` and failed with
`Failed to find targets` before checking formatting. Its raw failed receipt and
the successful corrected command are both retained.

The shared filesystem reported zero generally available space during this work;
a later statvfs observation still reported 2,603,180,032 free bytes to the root
process. Availability alone is not treated as a command failure. Only this
session's reproducible build caches were removed, including already-completed
test executables and non-test examples; their identities and cleanup scopes are
recorded. Sources, raw logs and records were retained. The attempted stop review
sent no signal to a Cargo process, and the recorded component, Clippy and
crypto/recovery commands completed successfully. These executions are not
isolated-host timing or memory qualification samples.

The original e05 canonical Node compiler SIGKILL, its separate debug-disabled
diagnostic, the earlier AF_UNIX EPERM and the cancelled source-control receipt
remain unchanged in the original archive. Later success does not rewrite those
attempts. Historical shared-material reports likewise retain their own executed
source; this integration does not relabel them as fresh production measurements.

## Authorization and activation boundaries

The `trnm-release-bundle::pq_release` authority kernel still has no production
caller in the inspected Chain tree. Cell release requires the supplied complete
current expectation, but the consuming owner must supply a fresh view and bind
it atomically to the actual effect. New typed storage/provider paths do not by
themselves supply that current publisher/root authority. A CLI acquisition policy,
an observer clock, a claimed Hello identity and a local completion receipt are
not authorization for CURRENT, FinalUse, a payment or an external effect.

Stricter manifest replay can refuse histories previously accepted under the
older rule. Historical rights, nonce/debt floors and already-entered external
effects still require an explicit migration/reconciliation procedure and
independent recovery evidence. Live journal validation remains O(journal records);
the fixed-buffer implementation does not establish a production recovery budget.

The [six-domain remaining evidence](README.md#six-domains-remaining-closure-evidence)
and [implementation boundaries](../../docs/security/PQ_RECOVERY_RELEASE_TRANSPORT_BOUNDARIES_V1.md)
remain open. In particular, preserve the original four-second / at-least-sixteen
hostile W1 requirement, CPU/Host budgets, depth-six/required-work confirmation and
4,105-block History. Full W1/backend security, cheapest legal quantum attack cost,
DAA/timestamp/fork/propagation closure, actual PQ-wire whole-service capacity and
independent fixed-source deployment/activation are not established by these tests.

## Reproduction and original records

[late-integration.json](late-integration.json) contains exact commands, statuses,
source identities, per-target outcomes and archive member hashes. The raw
[late verification archive](late-verification-records.tar.gz) is
**190,071 bytes**, SHA256 `4aada0ef7aac926cd5c9ff39fc3e0cb079395d2971a7e9704eb022101d08342c`.
It contains 45 members, including the two failed command records,
source preservation reviews and cache-failure evidence.

The prior [verification archive](verification-records.tar.gz) is unchanged:
SHA256 `07bad156351ad39895ad0a05e027104976148c03bf7effc3fd977077fe68c039`.
Its source scopes remain as described by [reproduction.json](reproduction.json).

Use a clean checkout of the fixed code, an allowed `fix/chain-*` branch,
`bash scripts/project-preflight.sh`, Rust 1.95.0, one Cargo job, no incremental
compilation and one Rust test thread. Preserve the exact lockfile and command
profiles. The observed native provider binary is OpenSSL 3.5.9 with SHA256
`35f28c82e7e4fdcd06b0a42062efd224a5fd5d32d5cc9894252f8206219d496e`;
its identity and locked graph are recorded separately from runtime-test claims.
No protected-main merge, production activation or independent approval is
represented by this evidence update.
