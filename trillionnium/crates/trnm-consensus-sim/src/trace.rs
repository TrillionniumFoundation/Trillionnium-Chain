use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEntry {
    tick: u64,
    code: &'static str,
    detail: String,
}

impl TraceEntry {
    pub const fn tick(&self) -> u64 {
        self.tick
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trace {
    entries: Vec<TraceEntry>,
}

impl Trace {
    pub fn entries(&self) -> &[TraceEntry] {
        &self.entries
    }

    pub fn digest(&self) -> TraceDigest {
        let mut hasher = Sha256::new();
        hasher.update((self.entries.len() as u64).to_le_bytes());
        for entry in &self.entries {
            hasher.update(entry.tick.to_le_bytes());
            hasher.update((entry.code.len() as u64).to_le_bytes());
            hasher.update(entry.code.as_bytes());
            hasher.update((entry.detail.len() as u64).to_le_bytes());
            hasher.update(entry.detail.as_bytes());
        }
        TraceDigest(hasher.finalize().into())
    }

    pub(crate) fn push(&mut self, tick: u64, code: &'static str, detail: String) {
        self.entries.push(TraceEntry { tick, code, detail });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TraceDigest([u8; 32]);

impl TraceDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        let mut value = String::with_capacity(64);
        for byte in self.0 {
            use core::fmt::Write as _;
            write!(&mut value, "{byte:02x}").expect("writing to String is infallible");
        }
        value
    }
}
