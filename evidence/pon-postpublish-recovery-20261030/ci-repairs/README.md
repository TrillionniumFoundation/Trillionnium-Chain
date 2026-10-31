# Narrow CI repair and real local controls

This recovery follows published source `1d11f875493f8125e36b9adceacb342df108e5e5`
and the reviewed current-main merge `00cb41115c9b3ea4a67f513a087d226390e3de0c`.
It does not recreate the lost unpublished local commit or its receipts.

## Changes

- Move only the test-module declaration into rustfmt order. The previously
  reported formatting pass was wrong; the original hosted failure remains a
  failure. New hosted formatting results require their own source identity.
- Give admission Rustup installation a run/attempt/architecture-specific home,
  forwarded through the existing `rustup show home` systemd handoff. Compiler
  1.95.0, components, matrix, quotas, deadlines and test predicates are unchanged.
- Match main's exact zero-byte homepage. The detailed-contract check still
  rejects any nonempty homepage. No ordered-parent source gate is weakened.

## New actual observations

The [focused test](exact-empty-readme.stderr.log) executes the real 18-module
contract with the empty README, then checks refusal of LF, space, UTF-8 BOM and
restored homepage text. It passed; the [process observation](exact-empty-readme.process.json)
records its actual invocation, exit status and measured elapsed time.
The [source integrity suite](source-integrity.stderr.log) passed all 34 original
negative controls; its [process observation](source-integrity.process.json) has
the same limited scope. These were newly executed after the workspace reset.

[Workflow syntax](workflow-static.json) records successful YAML parsing and
`bash -n` over all seven shell blocks after substituting inert expression
placeholders. It is not a hosted ARM installation or native campaign.

The local controls ran on a working candidate whose recorded parent was the
reviewed merge. They are not clean committed-source attestations. No native
workload, complete proof, full V5 capture or finite pressure campaign was rerun
for these controls. The full Cargo graph, strict Clippy, formatting and hosted
service results remain attributable to their actual separately recorded source.

The unchanged source guards, proof relation, receiver bounds, pure PoN chainwork
and original finite-service criteria remain in effect. Whole-protocol security,
public-service qualification and production activation are not claimed.
