# Documentation and implementation authority

The sole plan is `docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`.
The selected target is `pon-nakamoto-v1`. The portability inventory binds each actual
Cargo package to exactly one M00-M17 owner; absent implementation is stated explicitly.

Old consensus code, protocol directories, byte registries, launchers and legacy appendices
are deleted. Git is the archive; no old decoder or automatic fallback remains in the
active build. New domains/schemas require fresh namespaces, not in-place database reuse.

Retained task/MVCC/settlement stores have LOCAL monotonic commit semantics. They are not
an implemented branch/undo layer. Storage and evaluator trust thresholds are application
contracts, not ledger quorum or fork choice. No source rename grants new proof authority.

Source integrity, retained component tests, work hardness, actual node operation, model
future-window efficacy and deployment are separate facts. Activation remains false.
Do not modify protected-main requirements, self-approve, or replace a missing domain with
a default-success stub. Required CI retains the five existing check names and tests only
actual portable source plus clearly scoped reference models. No old fixture is relabelled
as new consensus/security/efficacy evidence.
