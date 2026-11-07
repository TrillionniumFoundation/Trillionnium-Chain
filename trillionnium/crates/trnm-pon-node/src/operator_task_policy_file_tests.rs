//! Descriptor substitution tests for the actual restricted-owner journal reader.
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn fifo(path: &Path) {
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        path,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
}

#[test]
#[ignore = "run only by the bounded subprocess regression"]
fn held_file_substitution_child() {
    let work = std::env::current_dir().unwrap();
    for kind in ["regular", "fifo", "directory", "symlink", "hardlink"] {
        let path = work.join(format!("journal-{kind}"));
        fs::write(&path, b"retained journal bytes").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let before = fs::symlink_metadata(&path).unwrap();
        // Use the precise production seam after the checked pathname metadata,
        // without relying on scheduler timing to win a rename/open race.
        if kind != "regular" {
            let retained = work.join(format!("retained-{kind}"));
            fs::rename(&path, &retained).unwrap();
            match kind {
                "fifo" => fifo(&path),
                "directory" => fs::create_dir(&path).unwrap(),
                "symlink" => symlink(&retained, &path).unwrap(),
                "hardlink" => fs::hard_link(&retained, &path).unwrap(),
                _ => unreachable!(),
            }
        }
        let result = open_held_after_check(&path, &before);
        if kind == "regular" {
            let mut file = result.unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"retained journal bytes");
            // Also retain the complete entrypoint, including the UID check.
            assert!(open_held(&path, before.uid()).is_ok());
            assert!(matches!(
                open_held(&path, before.uid().wrapping_add(1)),
                Err(PolicyError::Journal)
            ));
        } else {
            assert!(matches!(result, Err(PolicyError::Journal)), "{kind}");
        }
    }
    fs::write(work.join("completed"), b"all substitution cases executed").unwrap();
}

#[test]
fn held_file_substitutions_reject_without_blocking() {
    let work = tempfile::tempdir().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--nocapture", "held_file_substitution_child"])
        .current_dir(work.path())
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "substitution child failed: {status}");
            assert_eq!(
                fs::read(work.path().join("completed")).unwrap(),
                b"all substitution cases executed"
            );
            break;
        }
        if started.elapsed() >= Duration::from_secs(5) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("journal descriptor open blocked on a substituted special file");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
