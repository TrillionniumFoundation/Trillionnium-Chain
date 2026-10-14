# Versioned deterministic finality profile

`trnm-committee-finality-v1` is a new, disabled profile for a future deterministic
release boundary. It is not a fallback and does not reactivate any retired protocol.

The profile is isolated by a fresh genesis and namespace. It requires an explicit epoch
membership manifest, a 2f+1 certificate over the exact genesis/epoch/height/parent/state/
availability tuple, replay protection, availability evidence and independent verification.

A certificate can make a model release fact deterministic after the profile is qualified;
it cannot replace the Hepta artifact owner, evaluation owner, FinalUse authority,
withdrawal frontier or revocation owner. Chain inclusion, depth and cumulative work
remain insufficient for external effects.

All fields are specified-disabled until the required independent, WAN, partition, power-loss,
deep-reorg and artifact-retrieval evidence is accepted. No legacy profile bridge or automatic
fallback is permitted.
