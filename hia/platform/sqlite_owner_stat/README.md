# Fixed Linux x86-64 owned-file stat relay

This is a separate **qualification fixture**, not the SQLite VFS or a general
filesystem service. The original Rust test owns a freshly generated private
directory and exclusively creates `native.sqlite`. It launches a new native
process with that directory as its cwd. The relay receives no path, fd,
environment selector or request bytes. The fixture uses only fixed generated
ordinary files; this is not a same-UID adversarial or crash-durability test.

The checked HIA emitter writes a 684-byte static ELF image (RX load segment,
RW non-executable stack), using the documented platform compiler executable.
The syscall relay is reviewed x86-64 opcode data emitted from this HIA source;
this does not add a HIA Core syscall primitive or imply that Core has verified
the opcode semantics. There is no runtime libc, C, Rust, Python or assembler
inside the ELF. The Python qualification pins both emitter source and output
and checks the ELF structure. The raw relay accepts no arguments beyond
`argv[0]` and reads no input.

In order it uses `geteuid`, opens literal `.` as a no-follow CLOEXEC
directory and validates the retained dirfd's mode and uid via `fstat`.
Then it opens literal `native.sqlite` relative to that dirfd with read-only,
nonblocking, no-follow and CLOEXEC flags. The two observations are Linux
`fstat(file_fd)` and `newfstatat(dirfd, literal_leaf, AT_SYMLINK_NOFOLLOW)`.
The relay requires exact equality of device, inode, mode, uid, link count,
size and allocated 512-byte blocks, private regular mode 0600, one link,
matching uid, and size at most 8193. The v1 stdout is two little-endian
7-word tuples, 112 bytes, after closing both descriptors. All managed
refusal paths explicitly close any open descriptor without retry, return 70,
and publish no tuple. As with any streamed process response, a failed stdout
write is an unsuccessful run, not an accepted tuple.

The original in-crate test-only witness independently observes the **same
inode while its original Rust descriptor is still live**, at lengths 0, 3 and
8193; it compares all 14 raw words against its two original calls, in addition
to checking `Root::bind_fd` and the original ledger observation. This does
not borrow the original file descriptor across processes or establish
authority over a production VFS file. Nothing changes in the immutable Rust
tree or the shared TaskKernel provider. The normal-source qualification still
works without running the HIA executable in its original-only test.

```sh
python3 -B -m unittest -v hia.tests.test_sqlite_owner_stat_reference
```
