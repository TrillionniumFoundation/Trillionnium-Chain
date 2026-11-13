# Original pair: observed timing and deadline failure

**Figure.** Each panel shows the original phase-relative business release,
last successful packet ACK, every retained independent History page-replay
interval, and the original four-second deadline. Blue intervals were accepted;
the hatched orange interval was refused. The no-pressure phase recorded an
independent confirmation endpoint at 2.704367684 s and its original final gate
was true (1/1). The 16-worker pressure phase recorded no independent confirmation
endpoint and its original final gate was false (0/1); no latency is assigned to
that missing endpoint. All seven packet submissions returned successful ACKs
in each phase, which are not business confirmations.

The pressure phase's fourth independent replay started at 3.877903180 s and
returned `PUBLIC_REQUEST_DEADLINE` at 4.066591277 s. Its complete retained
interval is drawn across the original deadline. This is an independent replay
deadline refusal, not a substituted Host-rejection result. The baseline retained
seven accepted replay intervals; pressure retained three accepted intervals and
this fourth refused interval.

Earlier timing already differs: the baseline business release was 0.000118889 s,
versus 0.078123550 s under pressure; the last successful ACKs were 0.201950838 s
and 1.270197394 s, respectively. The fourth replay's deadline refusal is not
identified as the first causal divergence or as a unique cause.

The panels have separate original traffic epochs; they are not one shared
wall-clock timeline. Native observer-local nested spans are not mixed into
these axes. Display labels round to six decimal places; the companion data JSON
retains the exact integer nanoseconds and raw JSON pointers.

This is one fixed-order baseline-then-pressure pair, not a randomized or
repeated causal experiment. The figure describes the recorded timing and failed
gate; it does not establish the attack mechanism, a causal resource bottleneck,
or a statistical effect. The mechanism remains **UNKNOWN**.

Source: unchanged `from-zero-native/confirmation/report.json`, SHA-256
`4a4ec5d92810f51df792a2f1f08e4af4c9cb47c107c5ed3e3a8e2ef71dae9a1d`.
The plotting code verifies this digest before parsing and creates every output
exclusively. The receipt identifies the exact script, source, runtime and output
bytes.
