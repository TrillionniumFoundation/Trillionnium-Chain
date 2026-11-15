# Independent readback of original service campaign

Original run: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42781760995

Original source: `aaa3c53965bf0cf472e52451e205e9a020e834ab`; tree `fe3ce4c61bc2e3d477ea328b7742d0b2598282b3`. This is not the new candidate.

Archive `13761459229`: 83,560,661 bytes; SHA-256 `715587a56f595588c4eca4b36ba6e0a326b78e69078a4240cc878959e1f02cfe`.

Verified 1,768 ZIP entries, 1,767 exact manifest members and 665,828,398 uncompressed bytes, including every CRC/SHA/length. Names, regular-file types and size ceilings were checked without unrestricted extraction.

**Original criteria: 0/3 campaigns and 0/9 phases. Individual confirmations: 6/27 planned rounds, with 15 actual confirmation records and 12 unreached rounds.** All six successful confirmations were in baseline phases; every attack phase had zero.

| Run | Mode | Honest attempts | Client OK | Receiver work accepted | Work rejected | In-window confirmations / 3 planned | Phase criteria | Host CPU s | Parent phase CPU s |
|---:|---|---:|---:|---:|---:|---:|---|---:|---:|
| 1 | baseline | 15 | 14 | 15 | 0 | 2/3 | false | 8.374797 | 8.338462 |
| 1 | from-zero | 7 | 7 | 7 | 2288 | 0/3 | false | 8.882670 | 8.838096 |
| 1 | late-product | 7 | 7 | 7 | 2280 | 0/3 | false | 8.870395 | 8.826756 |
| 2 | baseline | 15 | 14 | 15 | 0 | 2/3 | false | 8.371349 | 8.334137 |
| 2 | from-zero | 7 | 7 | 7 | 2324 | 0/3 | false | 8.875800 | 8.832659 |
| 2 | late-product | 7 | 7 | 7 | 2243 | 0/3 | false | 8.870130 | 8.825447 |
| 3 | baseline | 18 | 17 | 17 | 0 | 2/3 | false | 8.343107 | 8.307005 |
| 3 | from-zero | 7 | 7 | 7 | 2351 | 0/3 | false | 8.872243 | 8.826935 |
| 3 | late-product | 7 | 7 | 7 | 2295 | 0/3 | false | 8.849058 | 8.806770 |

Honest submissions: 90 attempts, 87 client success responses, 89 receiver full-work accepts. The three baseline final requests returned late client errors; two nevertheless matched accepted receiver observations. Hostile requests yielded 13781 receiver full-work rejections and zero hostile client success responses. All 144 attacker processes were launched and reaped; no actor hit its cap or required forced kill.

## Scope and accounting

No budget depletion was observed; the attack-phase original depletion condition also failed.

The fixed public Host has a 25000/100000 CPU ceiling and 2 GiB ceiling; controller/attackers use the original 400000/100000 and 16 GiB ceilings. These are not reservations.

Host CPU delta is the fixed parent cgroup aggregate, containing its descendants. Whole phase process CPU, setup and paid mutation CPU are nested scopes, never an additive total.

Controller RUSAGE_CHILDREN covers reaped attacker processes and the Host launcher; it excludes the systemd-owned public phase process. Max child RSS is not simultaneous summed memory.

Whole phase wall/CPU includes setup and cleanup outside the 30-second business window. Throttled microseconds are not CPU consumed.

This is a readback of retained same-host x86_64 release-profile observations at the original head. It does not rerun native verification, establish causality for all delays, qualify the new candidate, or prove WAN/independent-operator service, hardness, finality or production activation.

## Original report SHA-256

- `run-1-raw/report.json`: `b96c4e005020a21b6b517f4c23e8904d6309d33b6ba71dd725bf6dcb67a4db0e`
- `run-2-raw/report.json`: `fb174b9ff583604cf71d2d134c67b8afac2712ed1e56a1ed30248e06f469dd51`
- `run-3-raw/report.json`: `0cbb68b43030aa8fe138642037fd727d7e5fc2cba93617029494339b26eea175`

The original manifest and small original metadata are in `original-small/`; `original-pins.json` records their exact hashes. The 166.7 MB of original reports remain in the pinned archive and were not copied into git. `summary.json` contains integer counters, confirmation outcomes and separate nested CPU scopes for every phase. No campaign or retained binary was executed.
