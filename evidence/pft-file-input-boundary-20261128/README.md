# Bounded PFT regular-file inputs

The previous PFT helper bounded the bytes read after `Path.open`, but opening a
FIFO without a writer could wait indefinitely. The first reproduction on exact
parent `0a415445326ed74d1dc816a2cd3070ad3f5f81ab` exceeded the 350 ms observation
deadline. Its owned child was killed and reaped; no process was left running.
[FIRST_FAILURE.json](FIRST_FAILURE.json) retains that original observation.

`read_bounded` now opens with `O_NONBLOCK`, `O_NOFOLLOW` and `O_CLOEXEC`, requires
a regular file and acceptable size using the opened descriptor, and reads at
most the caller's limit plus one byte. Before returning, it checks actual byte
count and stable device, inode, mode, size, mtime and ctime on that descriptor.
The descriptor closes on every path. Final-component symlinks refuse; parent
directory confinement is not added or claimed.

`O_NONBLOCK` prevents this FIFO-open wait. It does not promise a hard wall-time
bound for arbitrary remote regular-file I/O. Metadata checks do not create an
atomic filesystem snapshot or authenticate contents. The existing independently
retained expected SHA-256 checks remain necessary and unchanged.

## Actual controls

[FIRST_CONTROLS.log](FIRST_CONTROLS.log) and
[FIRST_OBSERVATIONS.json](FIRST_OBSERVATIONS.json) preserve the first 7/7 control
run. A real FIFO without a writer refused in a separately owned child; a real
directory, final symlink and oversized regular file also refused. The FIFO's
40,018,896 ns measured process wall time is one observation, not a latency bound.
A coordinated writer actually rewrote a 128 KiB file to different bytes of the
same length between real reads; the helper rejected it as `PFT_FILE_CHANGED`.
The mutation control changes actual file metadata, without mocking `fstat`.
An independently retained candidate digest still refuses altered candidate bytes.

[PFT_REGRESSION.log](PFT_REGRESSION.log) records 38/38 distinct controls on this
source: the existing 15 identity controls, 16 numerical controls and 7 filesystem
controls. No historical training, historical numerical rerun or final-test read
occurred. The old #1017 first-run hashes and receipts remain their original
observations; this patch does not relabel them as new-source runs.

All serialized schemas, mathematical acceptance thresholds and authority flags
remain unchanged. The existing workflow's tests, permissions, pinned actions and
timeout are retained; the new filesystem controls are an additional step.
Full native Rust gates were not run locally and remain separate requirements.

Run `python3 -B -m unittest discover -s scripts -p 'test_pft_file_inputs.py' -v`.
The helper uses POSIX flags already required by the repository's Linux workflow;
there is no silent fallback to a blocking or symlink-following implementation.
