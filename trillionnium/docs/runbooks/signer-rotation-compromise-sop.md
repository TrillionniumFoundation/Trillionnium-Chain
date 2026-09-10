# Native PoCO Signer Rotation and Compromise SOP

Use `native-poco-validator-operations.md` as the controlling runbook.

Consensus, operator and governance keys are separate. Rotation requires
possession proof, governed approval, an activation boundary, preserved
anti-equivocation state and a tested rollback. Suspected compromise requires
immediate isolation, evidence preservation and replacement with a newly
generated key; never clone the affected secret.
