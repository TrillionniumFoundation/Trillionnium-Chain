# G1-R2A crash matrix v1

| Cut | Durable observation | Required recovery |
|---|---|---|
| before pending sync | no authoritative pending | Core must not be called |
| after pending sync | exact pending request | redeliver same idempotency key |
| after Core durable receipt | pending, no replay ack | exact Core idempotent replay |
| after replay ack | pending plus exact G1-R1 ack | complete without Core call |
| after completion temp sync | retained temp evidence | ambiguous stop |
| after final hard-link | final plus temp/pending residue | no automatic guess |
| after temp removal | final plus pending residue | authenticate both, clear pending |
| after pending removal | final only | exact idempotent result |
| after response | final only | exact idempotent result |

R2-B must execute these cuts with real child processes and add the internal
Core/SafetyState persistence cuts.
