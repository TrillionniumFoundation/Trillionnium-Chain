# Security boundary

Report vulnerabilities privately through the repository's GitHub security reporting
channel. Do not publish credentials, private tasks, live keys or deployment secrets.

Portable components are candidates, not a production node. No consensus activation,
historical compatibility or fallback is authorized. Important threats include parser
and crypto ambiguity, unsafe model loading, namespace replacement and rollback, stale
authorization, resource exhaustion, dishonest evaluations, contribution replay, and
reorganization causing duplicate external effects.

A local commit, storage threshold, signed assessment or reference-model result is not
ledger finality or a qualified neural-work proof. Preserve these distinct meanings.

Pull requests use isolated hosted runners, read-only permissions and no retained
checkout credentials. Existing protected-main reviews and no-force-push requirements
remain unchanged. Dependency and supply-chain review are still required. Historical
content remains in Git, outside active builds and deployment paths.
