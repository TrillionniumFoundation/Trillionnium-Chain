# G1-R2 truth boundary v1

R2-A is a recoverable coordinator candidate, not a Core authority.

The following remain false until R2-B has real process evidence:

```text
live_core_adapter=false
core_ack_generated_by_core=false
core_ack_atomic_with_core=false
node_process_integration=false
whole_node_anti_rollback=false
production_candidate=false
production_consensus_activation=false
```

A passing unit test, local fake Core, package manifest or Draft PR cannot change
those facts.
