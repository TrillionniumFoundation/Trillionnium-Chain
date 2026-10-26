//! New v2 receipt limits. These are stricter local collection limits, not W1 facts.
use serde::Serialize;
use serde_json::{json, Value};
use std::{fs, io, io::Write, path::Path};

pub const MIB: u64 = 1024 * 1024;
pub const CONSTRUCTION_BYTES: u64 = 8 * MIB;
pub const WORKING_BYTES: u64 = 32 * MIB;
pub const PREFIX_BYTES: u64 = 64 * MIB;
pub const FRESH_BYTES: u64 = 96 * MIB;
pub const REPLAY_BYTES: u64 = 8 * MIB;
pub const ATTEMPT_BYTES: u64 = 100 * 1024;
pub const FRAME_BYTES: u64 = 128 * 1024;
pub const CALL_BYTES: u64 = 8 * 1024;

#[derive(Debug)]
pub struct Budget {
    pub limit: u64,
    pub used: u64,
    pub cap_reached: bool,
    pub poisoned: bool,
}
struct Counter(u64);
impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("receipt byte count overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
/// Bound the actual second-pass File writes to the already charged first-pass
/// reservation. Serialize is not assumed to be pure or repeatable.
struct ReservedFileWriter<'a> {
    file: &'a mut fs::File,
    remaining: u64,
    written: u64,
    exceeded: bool,
    first_error: Option<io::Error>,
}
impl Write for ReservedFileWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.first_error.is_some() {
            return Err(io::Error::other(
                "charged reservation writer already failed",
            ));
        }
        if bytes.len() as u64 > self.remaining {
            self.exceeded = true;
            self.first_error = Some(io::Error::other(
                "second serialization exceeded charged reservation",
            ));
            return Err(io::Error::other(
                "second serialization exceeded charged reservation",
            ));
        }
        let written = match self.file.write(bytes) {
            Ok(written) => written,
            Err(error) => {
                let returned = match error.raw_os_error() {
                    Some(code) => io::Error::from_raw_os_error(code),
                    None => io::Error::new(error.kind(), error.to_string()),
                };
                self.first_error = Some(error);
                return Err(returned);
            }
        };
        if written == 0 && !bytes.is_empty() {
            self.first_error = Some(io::Error::new(
                io::ErrorKind::WriteZero,
                "charged reservation File made no write progress",
            ));
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "charged reservation File made no write progress",
            ));
        }
        self.remaining -= written as u64;
        self.written += written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.first_error.is_some() {
            return Err(io::Error::other(
                "charged reservation writer already failed",
            ));
        }
        match self.file.flush() {
            Ok(()) => Ok(()),
            Err(error) => {
                let returned = match error.raw_os_error() {
                    Some(code) => io::Error::from_raw_os_error(code),
                    None => io::Error::new(error.kind(), error.to_string()),
                };
                self.first_error = Some(error);
                Err(returned)
            }
        }
    }
}
pub fn encoded_bytes(value: &Value) -> io::Result<u64> {
    encoded_serialized_bytes(value)
}
pub fn encoded_serialized_bytes<T: Serialize + ?Sized>(value: &T) -> io::Result<u64> {
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.0)
}
#[cfg(target_os = "linux")]
fn publish_no_replace(temporary: &Path, path: &Path) -> io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        temporary,
        rustix::fs::CWD,
        path,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(Into::into)
}
#[cfg(not(target_os = "linux"))]
fn publish_no_replace(_temporary: &Path, _path: &Path) -> io::Result<()> {
    Err(io::Error::other(
        "v2 evidence collection requires the native Linux owner",
    ))
}
impl Budget {
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            used: 0,
            cap_reached: false,
            poisoned: false,
        }
    }
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }
    pub fn summary(&self) -> Value {
        json!({"limit_bytes":self.limit,"used_bytes":self.used,"cap_reached":self.cap_reached,"poisoned":self.poisoned})
    }
    /// Count first, stream once, sync once, then publish. No full JSON byte Vec.
    /// The stage budget charges started/construction/call, including a retained
    /// temporary if I/O fails. It must never be reused after an I/O failure.
    pub fn write(&mut self, path: &Path, value: &Value, file_limit: u64) -> io::Result<u64> {
        self.write_serialized(path, value, file_limit)
    }
    /// The native-I/O profile serializes one/two closed root receipts inside
    /// the existing preparation/phase owner. No full encoded JSON Vec, extra
    /// allowance, drain or refund is introduced by this generic entry.
    pub fn write_serialized<T: Serialize + ?Sized>(
        &mut self,
        path: &Path,
        value: &T,
        file_limit: u64,
    ) -> io::Result<u64> {
        if self.poisoned {
            return Err(io::Error::other("v2 evidence owner poisoned"));
        }
        let result = self.write_inner(path, value, file_limit);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn write_inner<T: Serialize + ?Sized>(
        &mut self,
        path: &Path,
        value: &T,
        file_limit: u64,
    ) -> io::Result<u64> {
        let bytes = encoded_serialized_bytes(value)?;
        if bytes > file_limit || bytes > self.remaining() {
            self.cap_reached = true;
            return Err(io::Error::other("v2 evidence byte cap"));
        }
        if path.try_exists()? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "immutable receipt",
            ));
        }
        let temporary = path.with_extension("partial.json");
        let mut output = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        self.used += bytes;
        let mut bounded = ReservedFileWriter {
            file: &mut output,
            remaining: bytes,
            written: 0,
            exceeded: false,
            first_error: None,
        };
        let serialized = serde_json::to_writer(&mut bounded, value);
        let actual_written = bounded.written;
        if bounded.exceeded {
            self.cap_reached = true;
        }
        // A Serialize implementation may swallow a serializer/write error;
        // the actual File writer's first failure remains sticky independently.
        if let Some(error) = bounded.first_error.take() {
            return Err(error);
        }
        serialized?;
        if actual_written != bytes {
            return Err(io::Error::other(
                "second serialization length differs from charged reservation",
            ));
        }
        // No sync or publication occurs after an over/under-length or failed
        // second pass. Its partial remains conservatively charged in full.
        output.sync_all()?;
        publish_no_replace(&temporary, path)?;
        Ok(bytes)
    }
}

#[test]
fn exact_bytes_are_charged_and_a_cap_cannot_truncate_or_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let row = json!({"proof":"00","cpu_ns":1});
    let bytes = encoded_bytes(&row).unwrap();
    let first = directory.path().join("first.json");
    let second = directory.path().join("second.json");
    let mut budget = Budget::new(bytes);
    assert_eq!(budget.write(&first, &row, bytes).unwrap(), bytes);
    assert_eq!(fs::metadata(&first).unwrap().len(), bytes);
    assert!(budget.write(&second, &row, bytes).is_err());
    assert!(budget.cap_reached && !second.exists());
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&first).unwrap()).unwrap(),
        row
    );
    let mut another = Budget::new(2 * bytes);
    assert!(another
        .write(&first, &json!({"changed":true}), bytes)
        .is_err());
    assert_eq!(another.used, 0);
    assert!(another.poisoned);
    assert!(!directory.path().join("second.partial.json").exists());
    assert!(another.write(&second, &row, bytes).is_err());
    assert!(!second.exists());
    let mut file_cap = Budget::new(2 * bytes);
    assert!(file_cap.write(&second, &row, bytes - 1).is_err());
    assert!(file_cap.cap_reached && file_cap.poisoned && file_cap.used == 0 && !second.exists());
    let raced = directory.path().join("raced.partial.json");
    fs::write(&raced, b"other owner").unwrap();
    assert!(publish_no_replace(&raced, &first).is_err());
    assert!(raced.exists());
    assert_eq!(fs::metadata(&first).unwrap().len(), bytes);
    let mut io_failure = Budget::new(2 * bytes);
    assert!(io_failure
        .write(&directory.path().join("missing/first.json"), &row, bytes)
        .is_err());
    assert!(io_failure.poisoned && io_failure.used == 0);
    assert!(io_failure.write(&second, &row, bytes).is_err());
    assert!(!second.exists());
}

#[test]
fn exact_stage_partition_keeps_the_original_eight_gib_total() {
    let stages = 3 * 24 * PREFIX_BYTES + 24 * FRESH_BYTES + 24 * REPLAY_BYTES;
    assert_eq!(stages, 7104 * MIB);
    assert_eq!(8 * 1024 * MIB - stages, 1088 * MIB);
    const { assert!(CONSTRUCTION_BYTES * 3 < WORKING_BYTES) };
}

/// This serializer deliberately changes its wire length between the count and
/// actual File passes; it is not a Value or a mirror of the writer internals.
struct ChangingWire<'a> {
    passes: std::cell::Cell<usize>,
    first: &'a str,
    second: &'a str,
}
impl Serialize for ChangingWire<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let pass = self.passes.get();
        self.passes.set(pass + 1);
        serializer.serialize_str(if pass == 0 { self.first } else { self.second })
    }
}
fn changing_wire_must_leave_only_a_charged_partial(first: &str, second: &str) {
    const ORIGINAL_CAP: u64 = 32;
    let directory = tempfile::tempdir().unwrap();
    let final_path = directory.path().join("receipt.json");
    let partial_path = final_path.with_extension("partial.json");
    let later_path = directory.path().join("later.json");
    let expected_charge = serde_json::to_vec(first).unwrap().len() as u64;
    assert!(expected_charge <= ORIGINAL_CAP);
    let wire = ChangingWire {
        passes: std::cell::Cell::new(0),
        first,
        second,
    };
    let mut budget = Budget::new(ORIGINAL_CAP);
    assert!(budget
        .write_serialized(&final_path, &wire, ORIGINAL_CAP)
        .is_err());
    assert_eq!(wire.passes.get(), 2);
    assert!(!final_path.exists() && partial_path.is_file());
    let partial = fs::read(&partial_path).unwrap();
    assert!(partial.len() as u64 <= budget.used && budget.used <= ORIGINAL_CAP);
    assert_eq!(budget.used, expected_charge);
    assert!(budget.poisoned);
    assert!(budget
        .write(&later_path, &json!({"retry":true}), ORIGINAL_CAP)
        .is_err());
    assert!(!later_path.exists() && !later_path.with_extension("partial.json").exists());
    assert_eq!(budget.used, expected_charge);
    assert_eq!(fs::read(&partial_path).unwrap(), partial);
}
#[test]
fn stateful_serializer_cannot_outgrow_the_already_charged_file_reservation() {
    changing_wire_must_leave_only_a_charged_partial(
        "x",
        "a second pass that exceeds both the initial reservation and original cap",
    );
}
#[test]
fn stateful_serializer_cannot_publish_a_shorter_second_pass() {
    changing_wire_must_leave_only_a_charged_partial("a longer first pass", "x");
}
