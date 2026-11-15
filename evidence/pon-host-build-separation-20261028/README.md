# Original Host compilation failure and bounded preparation follow-up

The actual [protocol-contract job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40605070256/job/122542421868)
on source `73ffdd94f0b5461a2217a197a3d03a55b37117d5` passed both original Host
observations and then failed its original 900-second native build deadline.
The [build process receipt](original-build-process.json) records 900.091307825
seconds of wall time, 154.179114 seconds of child CPU, exit -9 and an actual
timeout. No native test ran. The source was checked before and after; the
[complete original manifest](original-native-manifest.json) retains the failure.
The [original artifact index](original-evidence-index.json) binds the unmodified
extracted evidence to the downloaded ZIP, GitHub job and source.

Compilation had run in the same fixed 25% CPU slice used for public service.
The narrow follow-up prepares the same source using the same `cargo test
--locked --release ... --no-run --message-format=json` command in the normal
CI controller. Preparation retains its original 900-second build bound,
stdout, stderr, process CPU, source checks and actual executable digest. It
does not execute a native test or claim public-service measurements.

The existing child invocation and its fixed Host slice remain unchanged.
Inside that slice, the original runner still invokes the actual source build,
checks formatting, executes all five original exact native selectors and
checks the original full reports. It receives no external ELF and no skip
flag. A cache hit within this same source/job is explicitly preparation, not
a newly measured cold build. Preparation and runtime source identities and
binary digests must match before controller acceptance. Failures remain
nonzero; the original timeout is not reclassified.

The runtime resource policy, per-test 90-second process limits, internal
service deadlines, all honest/hostile denominators, required report fields
and all consensus rules are unchanged. Twenty Python controls check the
original Host refusals and new source/build/binary/failure/signal binding.
These synthetic controls do not establish an actual systemd or native test
pass. A fresh hosted run on this candidate is required.

This follow-up also retains `OPENSSL_DIR` and `OPENSSL_STATIC` in the explicit
non-secret build environment passed to the child. It never forwards signing
keys, GitHub credentials or the entire environment. The reviewed provider
and the runtime's actual crypto behavior remain separate gates.

The multi-process campaign's receiver/verifier membership failure is a
separate process-layout issue. This build preparation does not fix it and
does not supply a genuine depleted-budget, sustained-attack service pass.

The [exact candidate run](candidate-controls/receipt.json) binds all 20 Host
controls and all 86 original from-zero reader controls to committed source
`54bc9265a77b9aaa198c3e843551d840ddf4168b`, with matching raw-byte source guards
before and after. No hosted native success is inferred from these controls.
