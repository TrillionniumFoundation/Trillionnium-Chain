# Original RootStatement V3 successor identity

The private native entry decodes one exact custom original
`RootStatementV3` for Rotate, Recover, or PolicyChange. It checks and uses
the canonical full successor policy and embedded roster from the same
immutable statement bytes. It reuses the bounded roster, derivative key ID
and ordering helpers of the bootstrap value entry. It also verifies the
original typed statement context and complete exhaustion, keeping the
original nested decode before enclosing typed context checks. It publishes
the original 64-byte `operation_id()` only on success, computed with the
original Operation domain and big-endian length binding; no supplied hash
or copied intermediate bytes from the caller are used.

Input is the exact original statement. Output and scratch are disjoint
64-byte and 132,256-byte spans. Status 0 is success; 1 Codec; 2 Policy; 3
Capacity; 4..8 original classified roster errors; 9 Context; 102 private
buffer extent; 103 private computation failure; 104 out of profile for other
original actions. The node does not use or trust this entry. This computes
an inert value only, and does not evaluate a successor against a current
policy, authorize or sign anything, verify signatures, mutate state, or
implement recovery, reconfiguration or deployment.
