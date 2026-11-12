# Native formatting fixture repair: preserved validation records

This directory records a test-fixture defect and its local repair. It is not a new
native experiment, performance measurement, or scientific sample. The four
SP27-02 CI batches and their original outcomes remain unchanged.

The [original failed CI job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43131136331/job/130895274019)
ran from source ff35430d27eea56dd803e05aa6d48573e37ed4c9. Its complete log is retained
verbatim, including errors beyond the fixture error identified here. No claim is
made that this is the only failure in the job or the complete CI set.

The production formatting-copy driver requires four explicit out-of-line test
modules. The older positive fixture created only fresh_challenge.rs. The retained
local reproduction at evidence commit a6e79dfbfc30d829a8527d0546091d005ecdce06
therefore failed with FileNotFoundError for sp27_receiver_controls.rs.

| Observation | Actual result |
|---|---|
| Original CI job log | Preserved without rewriting its historical test results |
| Local targeted positive fixture before repair | 1 test; 1 error; exit 1 |
| Local complete driver suite after repair | 149 tests; OK; exit 0 |

The only edited test method now creates four explicit, different byte fixtures and
their corresponding #[path] declarations. It checks every staged module against
its original bytes and verifies that all original files remain unchanged. The
flattening negative control, missing-module negative control, and real-source
module-coverage test remain unchanged. The production driver, native mechanism,
Host contract, permission gates, four-second window, resources, and cancellation
gates are unchanged. No ignored native selector was executed for this repair.

[MANIFEST.json](MANIFEST.json) binds [records.zip](records.zip), every raw member,
the original CI source/run/job, the fixture source before and after the edit, and
the actual fail-before/pass-after receipts. The ZIP is a new preservation package;
its member contents are the original captured bytes. It does not replace any
older archive, reader, result, or scientific batch.

Run the byte-integrity check from this directory:

~~~sh
python3 verify_records.py
~~~

Run the complete current driver suite from the repository root:

~~~sh
python3 scripts/ci/test_run_from_zero_native.py
~~~

To reproduce the old fixture failure, use an isolated checkout of
a6e79dfbfc30d829a8527d0546091d005ecdce06 and run:

~~~sh
python3 scripts/ci/test_run_from_zero_native.py BinarySelectionTests.test_format_copy_retains_out_of_line_module_and_original_bytes
~~~

That historical command is expected to exit nonzero. The unit controls simulate
compiler and service processes where declared; their synthetic observations are
not promoted to native measurements. The mechanism conclusion remains UNKNOWN,
and these local results do not claim that a later CI workflow is green.
