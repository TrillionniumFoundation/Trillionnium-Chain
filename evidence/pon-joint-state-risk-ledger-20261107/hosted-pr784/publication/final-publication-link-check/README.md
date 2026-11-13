# Final publication source and Markdown gate

Fixed publication commit `b5c655ebe9611b3d62cf739e61e6867decc053e3` and tree `51ae39a63851cdbfbe5ad4ebc1fb039a9b95abff` were checked against tested source `2d46d8682201bc0619f5b156af50e77fb399322e`.

- [Gate result](commit-b5c655ebe961/result.json)
- [Exact inputs](commit-b5c655ebe961/inputs.json) and [command records](commit-b5c655ebe961/commands.json)
- [Complete tested non-evidence path map](commit-b5c655ebe961/non-evidence-tested.json), [publication path map](commit-b5c655ebe961/non-evidence-publication.json), and [differences](commit-b5c655ebe961/non-evidence-differences.json)
- [Required ancestry](commit-b5c655ebe961/ancestry.json)
- [Committed-tree Markdown result](commit-b5c655ebe961/tree-links/result.json)
- [Prior 12-test verifier binding](commit-b5c655ebe961/prior-checker-tests-binding.json)

The same fixed verifier is used. Its existing 12 negative tests were not reexecuted. Actual Markdown inputs and the complete Git tree are retained by the verifier in the attempt directory. This gate does not execute the canonical full `check_repository.py`, JSON/TOML/raw-fixture gates, Cargo, or complete CI. It explicitly retains `canonical_check_repository_executed=false` and `full_repository_gate_pass_claimed=false`; source-test results remain bound to their independently recorded commits and scopes. No source file, commit, or remote ref is modified by this gate.
