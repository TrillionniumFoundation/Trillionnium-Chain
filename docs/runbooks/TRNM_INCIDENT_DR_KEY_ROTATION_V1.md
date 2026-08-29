# Incident, disaster-recovery and key-rotation runbook contract v1

Status: **candidate operator contract; not exercised**.

## Incident sequence

```text
detect
 -> freeze affected admission/effect class
 -> preserve immutable traces and disk/namespace evidence
 -> identify earliest invalidated gate
 -> fence signer and external checkpoint
 -> reproduce from exact source/tree
 -> remediate with retained mutant
 -> independent review
 -> new evidence epoch and downstream rerun
```

Never restore a rollbackable database and resume signing merely because a local checksum matches.

## Disaster recovery

- restore only into a staging namespace;
- verify chain/genesis, source checkpoint, validator set, complete chunks, JMT/application root and live DA/legal holds;
- compare against external monotonic anchor and signer watermark;
- atomically swap only after fresh readback;
- never import or lower legacy Comet WAL, keys, SafetyState or watermarks;
- after PoCO finality, recovery is forward-only under explicit governance/migration rules.

## Key rotation

- bind old/new key, validator/operator identity, role, purpose, epoch/height and governance decision;
- persist Safety/intent/watermark before the new signer can release a signature;
- prove old key fencing and revocation;
- test response loss, HSM outage, rollback and partial fleet rotation;
- light clients verify the validator-set/epoch transition.

Emergency pause may stop admission but cannot rewrite finalized blocks or silently downgrade protocol/profile authority.
