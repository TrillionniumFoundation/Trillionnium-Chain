# AI-native threat-to-invariant register v1

Status: **candidate register contract; findings open by default**.

Each row is:

```text
id
threat
invariant
retained negative mutant
owner
severity
status
evidence_root
```

Minimum threat families include:

- model/data/tokenizer/runtime/version substitution;
- prompt/input/output privacy leakage and low-entropy commitment inference;
- malicious tools and evaluator poisoning;
- DA decompression, withholding, repair amplification and retention abuse;
- ZK setup/VK/soundness/verifier cost;
- TEE quote/TCB/freshness/rollback/key custody;
- stake-verifier collusion and related-party/Sybil concentration;
- optimistic challenge griefing and timeout races;
- duplicate settlement, insolvency, stale pricing and MEV/reordering;
- session-key/controller/remote-signer compromise;
- state-sync/JMT/root substitution and anti-rollback failure;
- unsafe governance/emergency actions;
- loss or rewriting of raw incident evidence.

A Critical or High finding in consensus, finality, custody, migration, light-client acceptance, DA, settlement conservation, profile authority or upgrade blocks G4, C0 and G5. A closed finding requires an immutable evidence root and retained regression mutant.
