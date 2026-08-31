# G1-R2A dependency invalidation v1

Any change to the G1-R1 WAL format, namespace digest, target digest semantics,
acknowledgement format, publication recovery rule or lock/path boundary
invalidates all R2-A evidence and requires a source rebase plus full gate replay.

Any change to the future Core receipt, SafetyState revision semantics or
whole-node predecessor checkpoint invalidates R2-B and every dependent G1
claim.
