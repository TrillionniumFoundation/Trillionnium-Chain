# Fresh local validation of the rebuilt candidate

These logs were produced in the replacement workspace from integration baseline
`540d72356a921da31dde1113537382e5c0f0c4fd`. They are new observations, not recovered
measurements from the unavailable earlier local commit. Rust 1.95.0, the existing
locked dependencies and the pinned Python reader environment were installed
again. The setup logs and initial failures are retained.

Formatting correction: the enclosing README's original pass statement was
incorrect. A shell sequence continued after the formatter failed; a later
successful command concealed that exit status. The published `1d11f875` V5 and
branch CI formatting checks also failed. The follow-up moves one test-module
declaration to the formatter's required order. This correction does not change
the native test or Clippy observations below, and a later formatting result
does not become an earlier-source pass.

The host is shared. Its reported cgroup limits are eight CPU equivalents and
8 GiB memory; it has no systemd manager. No fixed-Host qualification campaign is
claimed from this environment. Native TCP controls use real local sockets.

## Native records

- [M01 release output](m01-tests.stdout.log): 130 passed, zero failed or ignored.
  The three added controls cover scalar error ordering, correct-product/false-
  trace replay under fresh challenges, and 65th-challenge cache eviction.
- [Consensus output](node-consensus.stdout.log) and
  [process scope](node-consensus.process.json): six passed.
- [Ingress output](public-ingress.stdout.log) and
  [process scope](public-ingress.process.json): 183 passed. Expected refusal and
  caught-panic stderr belongs to actual negative controls.
- [Final pressure controls](pressure-controls-final.stdout.log) and
  [process scope](pressure-controls-final.process.json): 19 passed, 16 ignored.
  This binary was rebuilt after the final actor/wait4 retention edit, as shown
  in [the build record](pressure-after-retention-fix.jsonl).
- [Authenticated-caller rerun](authenticated-caller-final.stdout.log): the same
  two controls already included in the ingress suite; not two additional tests.
- [Main strict Clippy](final-main-clippy.stderr.log): crypto and node packages,
  all targets, all features, release, locked and offline, `-D warnings`.
- [Original V5 test-profile build](v5-test-build.stderr.log): one build job,
  incremental disabled, test debug info zero, original package opt overrides.
  Building this executable is not running the full V5 native campaign.

Main Rust/manifests/locks were observed in
[source-after-final-native-controls.json](source-after-final-native-controls.json).
The earlier [post-M01 observation](source-after-m01.json) keeps its original
scope. These were uncommitted source observations, not complete clean-commit
attestations. The native process records accurately leave `source_sha` null.
The [Cargo metadata](main-cargo-metadata.json) records the 26 workspace members;
the manifests and lockfiles were not changed. The complete Linux resolution is
also retained for [default features](main-cargo-resolved-linux.json) and
[all features](main-cargo-resolved-linux-all-features.json), both produced by
locked, offline Cargo metadata commands.

## Other controls and limits

The source-integrity negative suite passed 34 tests after an initial command
used a nonexistent filename. Both attempts are retained. Project-boundary
controls passed 16 tests, risk-model controls passed 23, and quantum-DAA controls
passed seven, including all three real Rust parity controls. These tests check
implemented arithmetic and evidence rules; they do not qualify quantum security.

The [repository check before final documentation](repository-before-docs.stdout.log)
passed over the full checkout with 1,610 local links. Its printed head/tree are
the baseline and its `source_state` is explicitly `dirty-candidate`.
Later source guards and final link counts belong to the exact publication
verification and must not be backfilled into this older record.

The later `repository-final-docs` attempt ran while the proof-packaging owner was
still writing its final binding. It refused the then-missing
`fixture-packaging-v2/validation-binding.json` link; its stderr is retained.
A post-freeze whole-repository check is a separate required observation.

The enclosing evidence README supplies the cross-lane interpretation. No local
test, source inventory, manifest, or metadata record changes consensus, workload
credit, release policy or readiness.
