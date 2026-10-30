//! Optional, bounded diagnostics. These records never authenticate a proof.
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

const MAX_EVENTS: usize = 32;
const MAX_BYTES: usize = 16 * 1024;

pub(crate) struct PhaseJournal {
    output: Option<File>,
    started: Instant,
    sequence: usize,
    bytes: usize,
    terminal: bool,
}

impl PhaseJournal {
    pub(crate) fn new(path: Option<&Path>) -> io::Result<Self> {
        let output = path
            .map(|path| OpenOptions::new().write(true).create_new(true).open(path))
            .transpose()?;
        Ok(Self {
            output,
            started: Instant::now(),
            sequence: 0,
            bytes: 0,
            terminal: false,
        })
    }

    pub(crate) fn event(&mut self, event: &str) -> io::Result<()> {
        let Some(output) = self.output.as_mut() else {
            return Ok(());
        };
        if self.terminal
            || !matches!(
                event,
                "host-enter"
                    | "input-native-check-enter"
                    | "input-native-check-return"
                    | "sdk-prove-enter"
                    | "sdk-prove-return"
                    | "strict-verify-enter"
                    | "strict-verify-return"
                    | "codec-enter"
                    | "codec-return"
                    | "receipt-write-enter"
                    | "receipt-write-return"
                    | "host-complete"
                    | "host-failed"
            )
        {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "journal event"));
        }
        // event comes only from the fixed ASCII set above, never from a path,
        // backend message, proof payload, exception string or user input.
        let line = format!(
            "{{\"schema\":\"pon-w1-host-phase-v1\",\"sequence\":{},\"pid\":{},\"elapsed_ns\":{},\"event\":\"{}\",\"consensus_authority\":false}}\n",
            self.sequence,
            std::process::id(),
            self.started.elapsed().as_nanos(),
            event
        );
        if self.sequence >= MAX_EVENTS || line.len() > 1024 || self.bytes + line.len() > MAX_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "journal bound"));
        }
        output.write_all(line.as_bytes())?;
        output.sync_data()?;
        self.bytes += line.len();
        self.sequence += 1;
        self.terminal = matches!(event, "host-complete" | "host-failed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    fn path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "trnm-w1-phase-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn exclusive_file_and_terminal_are_enforced() {
        let path = path();
        let mut journal = PhaseJournal::new(Some(&path)).unwrap();
        assert!(PhaseJournal::new(Some(&path)).is_err());
        journal.event("host-enter").unwrap();
        journal.event("host-failed").unwrap();
        assert!(journal.event("host-complete").is_err());
        let raw = std::fs::read_to_string(&path).unwrap();
        assert_eq!(raw.lines().count(), 2);
        assert!(raw.contains("host-failed"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn dynamic_payloads_and_unbounded_events_are_refused() {
        let path = path();
        let mut journal = PhaseJournal::new(Some(&path)).unwrap();
        assert!(journal.event("\"untrusted-payload").is_err());
        for _ in 0..MAX_EVENTS {
            journal.event("sdk-prove-enter").unwrap();
        }
        assert!(journal.event("sdk-prove-enter").is_err());
        assert!(std::fs::metadata(&path).unwrap().len() <= MAX_BYTES as u64);
        std::fs::remove_file(path).unwrap();
    }
}
