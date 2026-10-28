//! v2 bounded sample chunks: one data sync per sample and one final full sync.
use super::evidence;
use serde_json::{json, Value};
use std::{
    fs, io,
    io::Write,
    path::{Path, PathBuf},
};

pub struct Samples {
    directory: PathBuf,
    chunk_bytes: u64,
    chunk_count: usize,
    output: Option<fs::File>,
    current_bytes: u64,
    total_bytes: u64,
    names: Vec<String>,
    count: usize,
    data_sync_attempts: usize,
    data_sync_successes: usize,
    final_sync_attempts: usize,
    cap: bool,
    error: Option<String>,
    refused_row: Option<Value>,
}
impl Samples {
    pub fn full(directory: &Path) -> Self {
        Self::new(directory, 8 * evidence::MIB, 12)
    }
    fn new(directory: &Path, chunk_bytes: u64, chunk_count: usize) -> Self {
        Self {
            directory: directory.into(),
            chunk_bytes,
            chunk_count,
            output: None,
            current_bytes: 0,
            total_bytes: 0,
            names: Vec::new(),
            count: 0,
            data_sync_attempts: 0,
            data_sync_successes: 0,
            final_sync_attempts: 0,
            cap: false,
            error: None,
            refused_row: None,
        }
    }
    pub fn append(&mut self, row: Value) -> io::Result<()> {
        if self.error.is_some() {
            return Err(io::Error::other("sample owner poisoned"));
        }
        let result = self.write_row(&row);
        if let Err(error) = &result {
            self.error = Some(error.to_string());
            self.refused_row = Some(row);
        }
        result
    }
    fn write_row(&mut self, row: &Value) -> io::Result<()> {
        let bytes = evidence::encoded_bytes(row)?
            .checked_add(1)
            .ok_or_else(|| io::Error::other("sample count overflow"))?;
        if bytes > self.chunk_bytes {
            self.cap = true;
            return Err(io::Error::other(
                "v2 sample exceeds one chunk; preserve in phase terminal",
            ));
        }
        if self.output.is_none() || self.current_bytes + bytes > self.chunk_bytes {
            if self.names.len() == self.chunk_count {
                self.cap = true;
                return Err(io::Error::other("v2 sample phase byte cap"));
            }
            let name = format!("samples-{:02}.jsonl", self.names.len());
            // The previous chunk's last sample was already sync_data'd. Do not
            // add another sync on rotation or change the 50-ms owner schedule.
            self.output = Some(
                fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(self.directory.join(&name))?,
            );
            self.names.push(name);
            self.current_bytes = 0;
        }
        let output = self.output.as_mut().unwrap();
        serde_json::to_writer(&mut *output, row)?;
        output.write_all(b"\n")?;
        self.current_bytes += bytes;
        self.total_bytes += bytes;
        self.data_sync_attempts += 1;
        output.sync_data()?;
        self.data_sync_successes += 1;
        self.count += 1;
        Ok(())
    }
    pub fn finish(mut self) -> Value {
        let mut final_sync_successes = 0;
        let mut final_sync_error = None;
        if let Some(output) = &self.output {
            self.final_sync_attempts += 1;
            if let Err(error) = output.sync_all() {
                final_sync_error = Some(error.to_string());
                if self.error.is_none() {
                    self.error = final_sync_error.clone();
                }
            } else {
                final_sync_successes += 1;
            }
        }
        json!({"sample_files":self.names,"sample_count":self.count,"sample_bytes":self.total_bytes,
            "sample_chunk_bytes":self.chunk_bytes,"sample_chunks_limit":self.chunk_count,
            "sample_cap_reached":self.cap,"sample_io_error":self.error,"unpersisted_sample":self.refused_row,
            "sync_data_attempts":self.data_sync_attempts,"sync_data_successes":self.data_sync_successes,
            "final_sync_all_attempts":self.final_sync_attempts,"final_sync_all_successes":final_sync_successes,
            "final_sync_all_error":final_sync_error})
    }
}

#[test]
fn chunks_preserve_rows_and_sync_denominators_when_the_exact_cap_stops_collection() {
    let out = tempfile::tempdir().unwrap();
    let row_bytes = evidence::encoded_bytes(&json!({"index":0})).unwrap() + 1;
    let mut writer = Samples::new(out.path(), 2 * row_bytes, 2);
    for index in 0..4 {
        writer.append(json!({"index":index})).unwrap();
    }
    assert!(writer.append(json!({"index":4})).is_err());
    assert!(writer.append(json!({"index":5})).is_err());
    let report = writer.finish();
    assert_eq!(report["sample_count"], 4);
    assert_eq!(report["sync_data_attempts"], 4);
    assert_eq!(report["sync_data_successes"], 4);
    assert_eq!(report["final_sync_all_attempts"], 1);
    assert_eq!(report["final_sync_all_successes"], 1);
    assert!(report["final_sync_all_error"].is_null());
    assert_eq!(report["sample_cap_reached"], true);
    assert_eq!(report["unpersisted_sample"]["index"], 4);
    let mut rows = Vec::new();
    for name in report["sample_files"].as_array().unwrap() {
        let raw = fs::read(out.path().join(name.as_str().unwrap())).unwrap();
        assert!(raw.ends_with(b"\n") && raw.len() as u64 == 2 * row_bytes);
        rows.extend(
            raw.split(|b| *b == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| serde_json::from_slice::<Value>(line).unwrap()),
        );
    }
    assert_eq!(
        rows,
        (0..4)
            .map(|index| json!({"index":index}))
            .collect::<Vec<_>>()
    );
    assert!(!out.path().join("samples-02.jsonl").exists());
}

#[test]
fn collision_and_oversize_poison_without_overwriting_the_previous_file() {
    let out = tempfile::tempdir().unwrap();
    fs::write(out.path().join("samples-00.jsonl"), b"retained failure").unwrap();
    let mut collision = Samples::new(out.path(), 32, 2);
    assert!(collision.append(json!({"index":0})).is_err());
    assert!(collision.append(json!({"index":1})).is_err());
    assert_eq!(
        fs::read(out.path().join("samples-00.jsonl")).unwrap(),
        b"retained failure"
    );
    let report = collision.finish();
    assert_eq!(report["sample_count"], 0);
    assert!(!report["sample_io_error"].is_null());
    let mut oversized = Samples::new(out.path(), 2, 1);
    assert!(oversized.append(json!({"index":0})).is_err());
    assert_eq!(oversized.finish()["sample_cap_reached"], true);
}
