// Ordinary temporary-directory/read controls only. These do not satisfy the
// fixed root-owned cgroup opener or qualify a public Host/resource budget.
use super::*;
use std::{cell::Cell, os::unix::fs::symlink};

const CPU: &str = "usage_usec 10\nnr_periods 20\nnr_throttled 3\nthrottled_usec 40";
const COUNTERS: [(&str, &str, usize); 3] = [
    ("cpu.stat", CPU, MAX_CPU_COUNTER_BYTES),
    ("memory.current", "64", MAX_SCALAR_COUNTER_BYTES),
    ("pids.current", "2", MAX_SCALAR_COUNTER_BYTES),
];

fn write_fixture(parent: &Path) {
    for (name, text) in [
        ("cpu.max", "25000 100000"),
        ("cpu.max.burst", "0"),
        ("memory.max", "268435456"),
        ("memory.swap.max", "0"),
        ("pids.max", "32"),
    ] {
        fs::write(parent.join(name), text).unwrap();
    }
    for (name, text, _) in COUNTERS {
        fs::write(parent.join(name), text).unwrap();
    }
}

fn fixture() -> (tempfile::TempDir, PathBuf, ParentDirectory, Limits) {
    let temporary = tempfile::tempdir().unwrap();
    let parent = temporary.path().join("parent");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    write_fixture(&parent);
    let directory =
        ParentDirectory::open(&parent, &fs::symlink_metadata(&parent).unwrap()).unwrap();
    let limits = directory.read_limits().unwrap();
    (temporary, parent, directory, limits)
}

fn sample(
    directory: &ParentDirectory,
    parent: &Path,
    limits: Limits,
) -> Result<KernelResourceSample> {
    // Exercise the production acquisition/parse/bracketing helper with actual
    // inode and five-limit fences. Boot/membership and fixed-parent admission
    // remain KernelBudget::check/open's responsibility, not this fixture's.
    directory.sample_counters(|| {
        directory.verify_path(parent)?;
        directory.verify_limits(parent, limits)
    })
}

struct Fragmented<'a> {
    bytes: &'a [u8],
    used: usize,
    calls: usize,
    eof: bool,
    fail_at_end: bool,
}
impl Read for Fragmented<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        assert!(!output.is_empty(), "an empty buffer cannot establish EOF");
        self.calls += 1;
        if self.calls % 3 == 1 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.used == self.bytes.len() {
            if self.fail_at_end {
                return Err(io::ErrorKind::Other.into());
            }
            self.eof = true;
            return Ok(0);
        }
        output[0] = self.bytes[self.used];
        self.used += 1;
        Ok(1)
    }
}

#[test]
fn counter_reader_keeps_exact_bounds_short_reads_interrupts_and_real_eof() {
    for limit in [MAX_CPU_COUNTER_BYTES, MAX_SCALAR_COUNTER_BYTES] {
        let input = vec![b' '; limit];
        let mut reader = Fragmented {
            bytes: &input,
            used: 0,
            calls: 0,
            eof: false,
            fail_at_end: false,
        };
        let mut buffer = vec![0; limit + 1];
        assert_eq!(
            read_counter_text(&mut reader, &mut buffer).unwrap().len(),
            limit
        );
        assert!(reader.eof);
        let oversized = vec![b' '; 1024 * 1024];
        reader = Fragmented {
            bytes: &oversized,
            used: 0,
            calls: 0,
            eof: false,
            fail_at_end: false,
        };
        assert_eq!(
            read_counter_text(&mut reader, &mut buffer)
                .unwrap_err()
                .to_string(),
            "PUBLIC_HOST_KERNEL_COUNTERS"
        );
        assert_eq!(reader.used, limit + 1);
        assert!(!reader.eof);
    }
}

#[test]
fn counter_reader_refuses_invalid_utf8_and_errors_after_valid_prefixes() {
    for (bytes, fail_at_end) in [(b"42".as_slice(), true), (b"42\xff".as_slice(), false)] {
        let mut reader = Fragmented {
            bytes,
            used: 0,
            calls: 0,
            eof: false,
            fail_at_end,
        };
        let mut buffer = [0; MAX_SCALAR_COUNTER_BYTES + 1];
        assert_eq!(
            read_counter_text(&mut reader, &mut buffer)
                .unwrap_err()
                .to_string(),
            "PUBLIC_HOST_KERNEL_COUNTERS"
        );
        assert_eq!(reader.used, bytes.len());
    }
}

#[test]
fn resource_sampling_reopens_every_counter_and_preserves_parser_bounds() {
    let (_temporary, parent, directory, limits) = fixture();
    let expected = resource_sample(CPU, "64", "2").unwrap();
    assert_eq!(sample(&directory, &parent, limits).unwrap(), expected);
    for (name, original, limit) in COUNTERS {
        let mut padded = original.as_bytes().to_vec();
        padded.resize(limit, b' ');
        fs::write(parent.join(name), &padded).unwrap();
        assert_eq!(sample(&directory, &parent, limits).unwrap(), expected);
        let replacement = parent.join("replacement");
        fs::write(&replacement, "invalid").unwrap();
        fs::rename(&replacement, parent.join(name)).unwrap();
        assert_eq!(
            sample(&directory, &parent, limits).unwrap_err().to_string(),
            "PUBLIC_HOST_KERNEL_COUNTERS"
        );
        for bytes in [
            [padded.as_slice(), b" "].concat(),
            [original.as_bytes(), &[0xff]].concat(),
            vec![b'x'; 1024 * 1024],
        ] {
            fs::write(parent.join(name), bytes).unwrap();
            assert_eq!(
                sample(&directory, &parent, limits).unwrap_err().to_string(),
                "PUBLIC_HOST_KERNEL_COUNTERS"
            );
        }
        fs::write(parent.join(name), original).unwrap();
    }
    fs::write(parent.join("memory.current"), "96").unwrap();
    assert_eq!(
        sample(&directory, &parent, limits)
            .unwrap()
            .memory_current_bytes,
        96,
        "a previous successful sample is not cached"
    );
}

#[test]
fn resource_sampling_refuses_symlink_missing_and_nonreadable_counter_children() {
    let (_temporary, parent, directory, limits) = fixture();
    for (name, _, _) in COUNTERS {
        let original = parent.join(name);
        let detached = parent.join("detached-counter");
        fs::rename(&original, &detached).unwrap();
        assert_eq!(
            sample(&directory, &parent, limits).unwrap_err().to_string(),
            "PUBLIC_HOST_KERNEL_COUNTERS"
        );
        symlink(&detached, &original).unwrap();
        assert!(fs::read_to_string(&original).is_ok());
        assert_eq!(
            sample(&directory, &parent, limits).unwrap_err().to_string(),
            "PUBLIC_HOST_KERNEL_COUNTERS"
        );
        fs::remove_file(&original).unwrap();
        fs::create_dir(&original).unwrap();
        assert_eq!(
            sample(&directory, &parent, limits).unwrap_err().to_string(),
            "PUBLIC_HOST_KERNEL_COUNTERS"
        );
        fs::remove_dir(&original).unwrap();
        fs::rename(&detached, &original).unwrap();
    }
}

#[test]
fn resource_sampling_refuses_a_real_fifo_without_waiting_for_a_writer() {
    use std::{io::Write, os::unix::fs::OpenOptionsExt, sync::mpsc, thread, time::Duration};
    let (_temporary, parent, directory, limits) = fixture();
    let fifo = parent.join("cpu.stat");
    fs::remove_file(&fifo).unwrap();
    rustix::fs::mkfifoat(
        &directory.file,
        c"cpu.stat",
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        ready_tx.send(()).unwrap();
        let result = sample(&directory, &parent, limits).map_err(|error| error.to_string());
        done_tx.send(result).unwrap();
    });
    ready_rx.recv().unwrap();
    let observed = done_rx.recv_timeout(Duration::from_secs(2));
    let returned_without_writer = observed.is_ok();
    // A regressed blocking open fails this test but is still unblocked/reaped;
    // it cannot hang the rest of the native test harness indefinitely.
    let result = match observed {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let mut rescue = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(fifo)
                .unwrap();
            rescue.write_all(b"invalid").unwrap();
            drop(rescue);
            done_rx.recv_timeout(Duration::from_secs(2)).unwrap()
        }
        Err(error) => panic!("counter reader failed: {error}"),
    };
    worker.join().unwrap();
    assert!(returned_without_writer, "counter FIFO open blocked");
    assert_eq!(result.unwrap_err(), "PUBLIC_HOST_KERNEL_COUNTERS");
}

#[test]
fn resource_sampling_keeps_both_current_checks_and_original_error_precedence() {
    let (_temporary, parent, directory, limits) = fixture();
    let checks = Cell::new(0);
    let check = || {
        checks.set(checks.get() + 1);
        directory.verify_path(&parent)?;
        directory.verify_limits(&parent, limits)
    };
    directory.sample_counters(check).unwrap();
    assert_eq!(checks.get(), 2);
    fs::remove_file(parent.join("cpu.stat")).unwrap();
    checks.set(0);
    assert_eq!(
        directory.sample_counters(check).unwrap_err().to_string(),
        "PUBLIC_HOST_KERNEL_COUNTERS"
    );
    assert_eq!(checks.get(), 1, "read errors precede the final check");
    fs::write(parent.join("pids.max"), "64").unwrap();
    checks.set(0);
    assert_eq!(
        directory.sample_counters(check).unwrap_err().to_string(),
        "PUBLIC_HOST_KERNEL_LIMITS_CHANGED",
        "the initial current limit check precedes all counter reads"
    );
    assert_eq!(checks.get(), 1);
}

#[derive(Clone, Copy)]
enum LateChange {
    Parent,
    Permissions,
    Limits,
}

fn change_during_sample(change: LateChange, invalid_cpu: bool) -> String {
    let (temporary, parent, directory, limits) = fixture();
    if invalid_cpu {
        fs::write(parent.join("cpu.stat"), "malformed").unwrap();
    }
    let detached = temporary.path().join("detached-parent");
    let checked = Cell::new(false);
    let result = directory.sample_counters(|| {
        directory.verify_path(&parent)?;
        directory.verify_limits(&parent, limits)?;
        if !checked.replace(true) {
            // Mutate the actual directory only after its initial checks pass.
            // Reads still use the held FD; the final real fence must reject
            // an identically populated replacement or a changed live limit.
            match change {
                LateChange::Parent => {
                    fs::rename(&parent, &detached).unwrap();
                    fs::create_dir(&parent).unwrap();
                    write_fixture(&parent);
                }
                LateChange::Permissions => {
                    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
                }
                LateChange::Limits => {
                    fs::write(parent.join("memory.max"), "536870912").unwrap();
                }
            }
        }
        Ok(())
    });
    result.unwrap_err().to_string()
}

#[test]
fn resource_sampling_final_check_refuses_replacement_permissions_and_limit_changes() {
    for change in [
        LateChange::Parent,
        LateChange::Permissions,
        LateChange::Limits,
    ] {
        assert_eq!(
            change_during_sample(change, false),
            match change {
                LateChange::Parent | LateChange::Permissions => "PUBLIC_HOST_KERNEL_REPLACED",
                LateChange::Limits => "PUBLIC_HOST_KERNEL_LIMITS_CHANGED",
            }
        );
        assert_eq!(
            change_during_sample(change, true),
            "PUBLIC_HOST_KERNEL_COUNTERS",
            "the existing counter parse error precedes a later Host refusal"
        );
    }
}
