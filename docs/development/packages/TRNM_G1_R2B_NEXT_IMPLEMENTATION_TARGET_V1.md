# G1-R2B next implementation target v1

The next code change after R2-A verification is a concrete sealed authority
inside the existing G1 process/Core boundary.

It must consume the coordinator's exact `CoreReplayRequestV1`, invoke the real
private Core ingress, and construct `CoreDurableReplayReceiptV1` only after:

```text
Core input accepted
 -> SafetyState/Core revision persisted
 -> durable state reopened/read back
 -> whole-node predecessor checkpoint unchanged
 -> acknowledgement digest derived from the durable result
```

Required fault cuts:

```text
before Core input
Core accepted / before persistence
persistence / before readback
readback / before replay ack
replay ack / before completion
completion / before response
```

Any uncertain Core outcome retains the pending record and returns no receipt.
No caller, CLI, generic callback or test carrier may construct the receipt in
production code.
