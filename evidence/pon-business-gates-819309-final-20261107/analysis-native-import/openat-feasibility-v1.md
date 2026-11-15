# Retained parent-directory fd: static feasibility decision

## Decision

Do not implement the proposed long-lived directory-fd optimization under the current Host contract. Safe API availability does not establish semantic replaceability. The five limit files would still be freshly read, but a retained directory handle changes which live pathname/mount view is read and which ancestor permissions are consulted. Keeping the existing boot, parent metadata and current-thread membership checks before those opens is necessary but insufficient.

This is static source/document review only. No production source, index or ref was changed; no mount/permission experiment, test, profile or benchmark was run.

## Existing safe capability

- trnm-pon-node/Cargo.toml:35 already directly selects rustix 1.1.4 with fs/net/process/time. Cargo.lock contains rustix 1.1.4, checksum b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190.
- Node src/lib.rs:2 forbids unsafe code. The local pinned rustix source exposes safe openat<P: path::Arg, Fd: AsFd>(...) -> io::Result<OwnedFd> (src/fs/at.rs:78-86), safe fstat (src/fs/fd.rs:156-157), and safe openat2. No new crate or unsafe block is needed for these APIs.
- Existing Node store/growth_reservation_io.rs:35-73 and store/growth/observer.rs:14-45 use safe directory-relative open and explicit named-identity checks. Their storage contract intentionally remains attached to an opened directory if its name changes; growth_reservation_io.rs:20-22 says this explicitly. That is not the Host contract of freshly reopening the one current absolute parent path.

## What an initial binding could prove, and what it cannot

An initially opened directory would need an owned RAII fd, CLOEXEC, directory/non-symlink checks, and fd metadata tied to the freshly checked parent dev/ino plus the original root-owner/nondelegated-mode predicate. Directory opening must not silently add a read-permission requirement: O_RDONLY requires directory read permission, while the current path-to-limit operation can work with search permission. Linux O_PATH is the relevant location-handle primitive, but it does not solve the pathname issues below.

An initial identity match proves which object the handle referred to at that instant. It does not prove that every later absolute pathname resolution would reach that same mount view, or pass the same current ancestor permission checks. Initial or periodic fstat alone cannot close that gap.

## Concrete semantic differences

| Situation | Original fresh absolute limit open | Retained directory fd plus relative openat |
|---|---|---|
| Parent renamed/replaced after the checkpoint's parent metadata and membership reads, before a limit open | Resolves the current fixed pathname; a missing name can fail, or the replacement is what gets opened. | The handle remains attached to the old directory; it can open its still-live limits even when the fixed pathname is now absent or different. |
| An ancestor loses search permission after the checkpoint's earlier full-path metadata lookup | The next absolute open repeats the prefix walk and can return EACCES. | Relative lookup starts at the held directory and does not repeat those ancestor checks. Current permissions on the held directory and final file still matter, but are not equivalent to the full prefix. |
| A different bind-mount view exposes the same directory inode with the same dev/ino/uid/mode but a different child-mount view | Opens from the currently visible absolute mount tree. | The held fd retains its original mount/path reference. The stored metadata tuple has no mount ID and cannot prove the child lookup is the same view. |

The rename and permission examples are interleavings, not executed tests. The mount-view example is a static counterexample model: equal inode metadata is not proof of equal mount identity. These examples identify a changed observation contract; they do not claim the original multi-syscall checker is an atomic filesystem snapshot.

Linux documents that a directory fd stays stable across rename and that directory-relative lookup starts from that fd. Path resolution applies search permissions while walking each prefix component. statx reports mount ID separately from device/inode. Sources: [open(2)](https://man7.org/linux/man-pages/man2/open.2.html), [path_resolution(7)](https://man7.org/linux/man-pages/man7/path_resolution.7.html), [statx(2)](https://man7.org/linux/man-pages/man2/statx.2.html).

Preserving the original exact read/error order matters. An added before/after stat or mount check can reject more transitions and introduce new error precedence, yet still does not make the multi-call check atomic. openat2 restrictions or an administrative promise that names/mounts/permissions remain stable would be new Host assumptions, not this mechanical optimization.

## Parts that are mechanically manageable

Fresh separate limit fds per call would preserve independent offsets and could reuse the original full-read/EOF/short-read/EINTR/UTF-8/128-byte bound logic. A shared parent descriptor used only for relative lookup has no file-content offset to serialize. Rust ownership can keep it alive across concurrent calls without introducing unsafe code. The existing all-five-I/O-before-parsing order and error mapping would still have to be preserved; limit-file NOFOLLOW or other extra restrictions must not be added silently.

These manageable details do not fix the changed pathname/permission/mount semantics. A permanent extra fd and its initial open/fstat also add resource and failure cases that would require explicit accounting.

## Performance boundary and present scope

The source fixes the parent string to /sys/fs/cgroup/trnmponpublic.slice: 34 UTF-8 bytes, with full limit paths 42/48/45/50/43 bytes. This is a source-derived length, not a new observation of the CI host. An optional retained-manifest file read did not yield contents, so no additional actual CI path claim is made.

Even in a stable namespace the proposed change retains all five opens, full data/EOF reads and closes; it targets only repeated prefix pathname resolution. The current raw data measure whole Host intervals, not prefix lookup cost. There is no measurement demonstrating material benefit, and no percentage or four-second-gate improvement is inferred.

Passing the original absolute pathname to openat would retain the original resolution behavior because an absolute pathname ignores dirfd; that provides no proposed prefix benefit. Reopening and validating the current absolute parent repeatedly restores prefix work and adds descriptors/checks, with no demonstrated gain.

The current candidate therefore remains solely the separately reviewed final ordinary-admission full-State root arithmetic connection and regression. Preserve every Host checkpoint, fresh live value, current thread check, complete EOF, failure/cancellation cost and original budget. Retain no limit fd or prior limit value.
