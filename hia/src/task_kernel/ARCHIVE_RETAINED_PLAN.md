# Original retained archive-plan records
This private HIA projection returns the exact Borsh vector of
`TaskArchivePlanV1::retained_records()` from an immutable typed planner
input. Input is the existing bounded typed archive-selection format
(without the sealed projection's previous-hash suffix). The native
typed planner executes its original policy, record/retention, hold and
ordering checks first. The projection copies exactly the admitted full
record byte spans not selected by that plan, in canonical terminal
height then task ID order. No caller-provided index or hash is trusted.

The bounded profile admits at most eight records/eight hold IDs and
up to 512 context-string bytes. The caller supplies 6,100 output bytes
(four-byte vector count and at most eight 762-byte records) and 1,496
scratch bytes. The actual Borsh vector is written on success and the
suffix remains unchanged; an empty result is a four-byte zero count.
A checked refusal publishes no output. Existing selected-only and
sealed-batch interfaces retain their wire/result behavior.

This constructs an in-memory diagnostic projection only. It does not
approve removal, read or write any database, mutate live records, pay,
sign, execute an operator action, or change production routing.
