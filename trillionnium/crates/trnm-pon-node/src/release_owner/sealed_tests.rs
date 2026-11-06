use super::sealed::{DataBuilder, Sealed};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
use std::time::{Duration, Instant};

#[test]
fn sealed_copy_survives_in_place_source_rewrite_and_path_replacement() {
    let tree = tempfile::tempdir().unwrap();
    let source = tree.path().join("source");
    fs::write(&source, b"original authenticated bytes").unwrap();
    let expected = Sha256::digest(b"original authenticated bytes").into();
    let (sealed, _) = Sealed::from_path(&source, expected, 28, false).unwrap();
    fs::write(&source, b"replaced inside the old inode").unwrap();
    let replacement = tree.path().join("replacement");
    fs::write(&replacement, b"other bytes").unwrap();
    fs::rename(&replacement, &source).unwrap();
    assert_eq!(sealed.read(64).unwrap(), b"original authenticated bytes");
    assert!(sealed.file().write_at(b"bad", 0).is_err());
    assert!(sealed.file().set_len(1).is_err());
    assert!(sealed.file().set_len(100).is_err());
    assert!(sealed
        .file()
        .set_permissions(fs::Permissions::from_mode(0o700))
        .is_err());
    sealed.recheck().unwrap();
}

#[test]
fn source_rewrite_or_path_exchange_during_sealing_refuses_authentication() {
    for replace_name in [false, true] {
        let tree = tempfile::tempdir().unwrap();
        let source = tree.path().join("source");
        fs::write(&source, b"good").unwrap();
        let path = source.clone();
        super::sealed_faults::set(move || {
            if replace_name {
                let replacement = path.with_extension("replacement");
                fs::write(&replacement, b"good").unwrap();
                fs::rename(replacement, &path).unwrap();
            } else {
                fs::write(&path, b"different length and contents").unwrap();
            }
        });
        assert!(Sealed::from_path(&source, Sha256::digest(b"good").into(), 4, false).is_err());
    }
}

#[test]
fn inherited_fifo_without_writer_is_refused_before_any_blocking_open() {
    let tree = tempfile::tempdir().unwrap();
    let fifo = tree.path().join("fifo");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let original = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo)
        .unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let start = Instant::now();
    let thread = std::thread::spawn(move || {
        let result = Sealed::untrusted_handoff(original.as_raw_fd() as u32, 4096).is_err();
        send.send(result).unwrap();
    });
    let timely = receive.recv_timeout(Duration::from_secs(2));
    // Rescue only a regressed reader so the assertion fails without leaving a
    // detached blocking thread. It is never used to qualify the fixed path.
    let rescue = if timely.is_err() {
        Some(
            OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo)
                .unwrap(),
        )
    } else {
        None
    };
    thread.join().unwrap();
    drop(rescue);
    assert!(timely.unwrap());
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn unsealed_regular_input_and_a_different_sealed_descriptor_are_rejected() {
    let file = tempfile::tempfile().unwrap();
    file.set_len(4).unwrap();
    assert!(Sealed::untrusted_handoff(file.as_raw_fd() as u32, 4096).is_err());
    let first = DataBuilder::new().unwrap().finish(b"same", 16).unwrap();
    let other = DataBuilder::new().unwrap().finish(b"same", 16).unwrap();
    first.require_descriptor(first.raw_fd() as u32).unwrap();
    assert!(first.require_descriptor(other.raw_fd() as u32).is_err());
    assert!(Sealed::untrusted_handoff(first.raw_fd() as u32, 3).is_err());
}

fn elf(kind: u32, tag: u64) -> Vec<u8> {
    let mut bytes = vec![0; 512];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    let machine: u16 = if std::env::consts::ARCH == "x86_64" {
        62
    } else {
        183
    };
    bytes[18..20].copy_from_slice(&machine.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x400180u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&512u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&512u64.to_le_bytes());
    bytes[120..124].copy_from_slice(&kind.to_le_bytes());
    bytes[128..136].copy_from_slice(&256u64.to_le_bytes());
    bytes[152..160].copy_from_slice(&32u64.to_le_bytes());
    bytes[256..264].copy_from_slice(&tag.to_le_bytes());
    bytes
}
fn check_elf(bytes: &[u8]) -> bool {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    let image = Sealed::from_file(
        &file,
        Sha256::digest(bytes).into(),
        bytes.len() as u64,
        true,
    )
    .unwrap();
    image.verify_elf(super::elf::platform().unwrap()).is_ok()
}

#[test]
fn native_elf_profile_rejects_interpreter_dependencies_search_paths_and_wrong_machine() {
    // These are parser fixtures, not a claimed real Node execution.
    assert!(check_elf(&elf(0, 0)));
    assert!(!check_elf(&elf(3, 0)));
    for tag in [1, 15, 29, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff] {
        assert!(!check_elf(&elf(2, tag)));
    }
    let mut wrong = elf(0, 0);
    wrong[18] ^= 0xff;
    assert!(!check_elf(&wrong));
    let mut writable = elf(0, 0);
    writable[68..72].copy_from_slice(&7u32.to_le_bytes());
    assert!(!check_elf(&writable));
}
