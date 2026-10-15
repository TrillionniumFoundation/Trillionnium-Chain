//! One Linux network-namespace lease for the actual V3 CLI process.
//! This is kernel admission ownership, not a payment or Chain ledger. No
//! filesystem path, daemon, arbitrary guest-supplied name or cleanup hook.
//! This does not prove host-wide CPU under separate network namespaces.
#[cfg(target_os = "linux")]
use std::{
    io,
    os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixListener},
    },
};

#[cfg(target_os = "linux")]
const HOST_SLOT_PREFIX: &[u8] = b"trnm-pon-public-v3-host-slot-v1-";
/// One development CLI V3 instance per slot in the SAME Linux network
/// namespace. This is a four-process physical-process *count* cap, NOT a
/// kernel CPU/memory cgroup, durable CPU journal or an identity entitlement.
/// Four slots retain the original multi-node/peer tests without unbounded
/// process-relaunch fanout in a single shared network namespace.
#[cfg(target_os = "linux")]
pub(crate) const MAX_PROCESS_SLOTS: u8 = 4;

#[cfg(target_os = "linux")]
pub(crate) struct Guard {
    _held: UnixListener,
    pub(crate) slot: u8,
}
#[cfg(target_os = "linux")]
impl Guard {
    pub(crate) fn acquire() -> trnm_pon_node::Result<Self> {
        for slot in 0..MAX_PROCESS_SLOTS {
            let mut name = HOST_SLOT_PREFIX.to_vec();
            name.push(b'0' + slot);
            let address = SocketAddr::from_abstract_name(&name)
                .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_SLOT_ADDRESS"))?;
            match UnixListener::bind_addr(&address) {
                Ok(held) => return Ok(Self { _held: held, slot }),
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
                Err(_) => return Err("PUBLIC_HOST_PROCESS_UNAVAILABLE".into()),
            }
        }
        Err("PUBLIC_HOST_PROCESS_CAPACITY".into())
    }
}

// macOS has no Linux abstract namespace. Keep its existing V3 developer CLI
// operable using four cooperative OS file locks under the system root-owned
// sticky temporary directory. This is a weaker SAME-UID local-process bound:
// a compromised same-UID process or administrator could unlink its own lock
// and recreate an inode. It is not a production security qualification.
#[cfg(target_os = "macos")]
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
#[cfg(target_os = "macos")]
pub(crate) const MAX_PROCESS_SLOTS: u8 = 4;

#[cfg(target_os = "macos")]
pub(crate) struct Guard {
    _held: File,
    pub(crate) slot: u8,
}
#[cfg(target_os = "macos")]
impl Guard {
    pub(crate) fn acquire() -> trnm_pon_node::Result<Self> {
        let root = Path::new("/tmp")
            .canonicalize()
            .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_PROCESS_UNAVAILABLE"))?;
        let parent = fs::metadata(&root)
            .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_PROCESS_UNAVAILABLE"))?;
        if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o1000 == 0 {
            return Err("PUBLIC_HOST_PROCESS_UNAVAILABLE".into());
        }
        for slot in 0..MAX_PROCESS_SLOTS {
            let path = root.join(format!("trnm-pon-public-v3-host-slot-v1-{slot}.lock"));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
                .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_PROCESS_UNAVAILABLE"))?;
            let meta = file
                .metadata()
                .map_err(|_| trnm_pon_node::Error::from("PUBLIC_HOST_PROCESS_UNAVAILABLE"))?;
            if !meta.is_file()
                || meta.nlink() != 1
                || meta.uid() != rustix::process::geteuid().as_raw()
                || meta.mode() & 0o777 != 0o600
            {
                return Err("PUBLIC_HOST_PROCESS_UNAVAILABLE".into());
            }
            match file.try_lock() {
                Ok(()) => return Ok(Self { _held: file, slot }),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(_) => return Err("PUBLIC_HOST_PROCESS_UNAVAILABLE".into()),
            }
        }
        Err("PUBLIC_HOST_PROCESS_CAPACITY".into())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) struct Guard {
    // Never constructed because acquire() always fails; retain a portable
    // diagnostic type so unsupported targets compile and fail closed.
    pub(crate) slot: u8,
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl Guard {
    pub(crate) fn acquire() -> trnm_pon_node::Result<Self> {
        Err("PUBLIC_HOST_PROCESS_GUARD_UNSUPPORTED".into())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        env,
        process::{Command, Stdio},
    };

    #[test]
    fn child_guard_probe() {
        if env::var_os("TRNM_TEST_HOST_GUARD_CHILD").is_none() {
            return;
        }
        let acquired = Guard::acquire();
        match env::var("TRNM_TEST_HOST_GUARD_CHILD").unwrap().as_str() {
            "EXPECT_BUSY" => assert_eq!(
                acquired.err().unwrap().to_string(),
                "PUBLIC_HOST_PROCESS_CAPACITY"
            ),
            "EXPECT_FREE" => {
                let _held = acquired.expect("test child must bind released host slot");
            }
            other => panic!("unknown probe: {other}"),
        }
    }

    fn probe(mode: &str) -> std::process::Output {
        Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "host_public_guard::tests::child_guard_probe",
                "--nocapture",
            ])
            .env("TRNM_TEST_HOST_GUARD_CHILD", mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap()
    }

    #[test]
    fn actual_second_linux_process_cannot_mint_a_second_host_slot() {
        let owners: Vec<_> = (0..MAX_PROCESS_SLOTS)
            .map(|_| Guard::acquire().expect("four native peer service slots are available"))
            .collect();
        let mut slots: Vec<_> = owners.iter().map(|x| x.slot).collect();
        slots.sort_unstable();
        assert_eq!(slots, (0..MAX_PROCESS_SLOTS).collect::<Vec<_>>());
        let duplicate = probe("EXPECT_BUSY");
        assert!(
            duplicate.status.success(),
            "second actual process bypassed: {}",
            String::from_utf8_lossy(&duplicate.stdout)
        );
        // Changing PID does not mint a fifth process slot; normal exit returns it.
        assert_eq!(
            Guard::acquire().err().unwrap().to_string(),
            "PUBLIC_HOST_PROCESS_CAPACITY"
        );
        drop(owners);
        let released = probe("EXPECT_FREE");
        assert!(
            released.status.success(),
            "freed slot cannot be recovered: {}",
            String::from_utf8_lossy(&released.stdout)
        );
    }
}
