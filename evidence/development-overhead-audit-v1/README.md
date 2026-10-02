# Development overhead audit evidence

This package records local maintenance verification, including initial failures.
It does not qualify a public network, work primitive, model product or release.

The [source-equivalence record](source-equivalence.json) names the original
PR #204 head and the reviewed first-tranche code commit, inventories each removed
source by its original SHA-256, and retains exact compiled-source hashes and
compiler dependency files before/after. Removed source remains retrievable from
that named Git commit. Only the generated distributed-source projection changes
its runtime data; old qualification records are not rewritten or inherited.

[Artifact hashes](artifact-sha256.json) cover the retained raw command output and
measurement JSON. Logs are verbatim local output. Some runs occurred before the
first tranche was committed; the source-equivalence record specifies the exact
reviewed code identity and explicitly limits the timing observations. The
[main audit](../../docs/development/DEVELOPMENT_OVERHEAD_AUDIT_20261002.md) records
scope, commands, interpretation and remaining verification work.

Notable negative observations:

- [Missing observer](repository-truth-missing-observer.log): the first repository
  check run failed because this container has no `/usr/bin/time`. The supported
  explicit `TRNM_GNU_TIME` setting selected an already installed real GNU time;
  the [configured aggregate](repository-truth-configured.log) passed.
- [Unstaged removal](external-evidence-unstaged-removal.log): historical cost
  verification rejected a source path still present in the Git index after its
  working file was removed. Staging the reviewed deletions corrected the current
  inventory; the existing historical verifier then passed and reported that the
  historical measured inputs do not match current source.

Neither failure was handled by a stub, a reduced threshold or a validator bypass.
