//! Durable local proposal -> independent M15 CAS -> completed-only recovery.
//! An index is a bounded reference list, not embedded unbounded proof history.
//! This layer yields bytes/observations only; it never grants an exec capability.
use super::files::Files;
use super::frontier::{
    hash, index_digest, invalid, Digest32, ExternalM15Authority, Frontier, Result, Validity,
    MAX_INDEX_BYTES, MAX_PENDING_BYTES,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io;
use std::path::Path;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    schema_version: u32,
    expected: Option<Frontier>,
    next: Frontier,
    index_json: String,
}

fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value: T = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    if serde_json::to_vec(&value).map_err(io::Error::other)? != bytes {
        return Err(invalid("noncanonical M15 owner record"));
    }
    Ok(value)
}

fn fenced() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "M15 owner requires explicit pending recovery",
    )
}

pub(super) struct TransactionStore {
    files: Files,
    namespace: Digest32,
    frontier: Option<Frontier>,
    index: Option<Vec<u8>>,
    fenced: bool,
}

impl TransactionStore {
    pub fn initialize(
        root: &Path,
        namespace: Digest32,
        trust: &mut impl ExternalM15Authority,
    ) -> Result<Self> {
        if namespace == [0; 32] || trust.load(namespace)?.is_some() {
            return Err(invalid(
                "M15 initialization requires independently fresh absence",
            ));
        }
        let files = Files::create(root)?;
        Ok(Self {
            files,
            namespace,
            frontier: None,
            index: None,
            fenced: false,
        })
    }

    pub fn open_existing(
        root: &Path,
        namespace: Digest32,
        trust: &mut impl ExternalM15Authority,
    ) -> Result<Self> {
        if namespace == [0; 32] {
            return Err(invalid("zero M15 namespace"));
        }
        let files = Files::open(root)?;
        let frontier = trust.load(namespace)?;
        if let Some(value) = &frontier {
            value.validate(namespace)?;
        }
        let pending: Option<Pending> = match files.read("pending.json", MAX_PENDING_BYTES)? {
            Some(raw) => decode(&raw)?,
            None => None,
        };
        let attempt: Option<Digest32> = match files.read("attempt.json", 256)? {
            Some(raw) => decode(&raw)?,
            None => None,
        };
        let mut store = Self {
            files,
            namespace,
            frontier,
            index: None,
            fenced: true,
        };
        if let Some(pending) = pending {
            let raw = serde_json::to_vec(&Some(&pending)).map_err(io::Error::other)?;
            let expected_next = Frontier::successor(
                namespace,
                pending.expected.as_ref(),
                pending.index_json.as_bytes(),
            )?;
            let attempt_matches = attempt == Some(hash(b"TRNM/M15/OwnerAttempt/v1\0", &raw));
            // Crash after clearing the attempt but before clearing the pending
            // slot: the exact externally committed index must already be local.
            let completed_cleanup = attempt.is_none()
                && store.files.read("attempt.json", 256)?.as_deref() == Some(b"null")
                && store.files.read("index.json", MAX_INDEX_BYTES)?.as_deref()
                    == Some(pending.index_json.as_bytes());
            if pending.schema_version != 1
                || pending.next != expected_next
                || (!attempt_matches && !completed_cleanup)
                || store.frontier.as_ref() != Some(&pending.next)
            {
                return Err(fenced());
            }
            // Only the exact already-observed external winner can be installed.
            // No CAS retry, launch, or local terminal inference occurs on reopen.
            store.finish(&pending)?;
        } else if attempt.is_some() {
            return Err(fenced());
        }
        let index = store
            .files
            .read("index.json", MAX_INDEX_BYTES)?
            .ok_or_else(|| invalid("missing existing M15 owner index"))?;
        if store.frontier.as_ref().map(|f| f.index) != Some(index_digest(&index)) {
            return Err(fenced());
        }
        store.index = Some(index);
        store.fenced = false;
        store.recheck(trust)?;
        Ok(store)
    }

    pub fn snapshot(&self) -> Result<(Option<&Frontier>, Option<&[u8]>)> {
        if self.fenced {
            return Err(fenced());
        }
        Ok((self.frontier.as_ref(), self.index.as_deref()))
    }

    pub fn recheck(&mut self, trust: &mut impl ExternalM15Authority) -> Result<()> {
        if self.fenced {
            return Err(fenced());
        }
        let result = (|| {
            let observed = trust.load(self.namespace)?;
            self.recheck_local()?;
            if observed != self.frontier {
                return Err(fenced());
            }
            Ok(())
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    /// No external callback follows these exact held-owner/local checks. The
    /// proof owner calls this again after its final signed-clock round trip.
    pub fn recheck_local(&mut self) -> Result<()> {
        if self.fenced {
            return Err(fenced());
        }
        let result = (|| {
            self.files.revalidate()?;
            let pending: Option<Pending> = self
                .files
                .read("pending.json", MAX_PENDING_BYTES)?
                .map(|bytes| decode(&bytes))
                .transpose()?
                .flatten();
            let attempt: Option<Digest32> = self
                .files
                .read("attempt.json", 256)?
                .map(|bytes| decode(&bytes))
                .transpose()?
                .flatten();
            if pending.is_some()
                || attempt.is_some()
                || self.files.read("index.json", MAX_INDEX_BYTES)? != self.index
            {
                return Err(fenced());
            }
            self.files.revalidate()
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    /// Caller is the private proof owner, which fully verifies the candidate and
    /// derives the exact role/root window. It revalidates again after fsync.
    #[cfg(test)]
    pub fn commit(
        &mut self,
        trust: &mut impl ExternalM15Authority,
        index: &[u8],
        validity: Validity,
        mut verify_at: impl FnMut(&[u8], u64) -> Result<()>,
    ) -> Result<()> {
        self.commit_with_files(trust, index, validity, |_, raw, now| verify_at(raw, now))
    }

    pub fn objects(&self) -> Result<&Files> {
        if self.fenced {
            return Err(fenced());
        }
        self.files.revalidate()?;
        Ok(&self.files)
    }

    pub fn commit_with_files(
        &mut self,
        trust: &mut impl ExternalM15Authority,
        index: &[u8],
        validity: Validity,
        mut verify_at: impl FnMut(&Files, &[u8], u64) -> Result<()>,
    ) -> Result<()> {
        self.recheck(trust)?;
        let now = trust.now_seconds()?;
        validity.check(now)?;
        verify_at(&self.files, index, now)?;
        // Verification and authenticated I/O may yield. A newly appeared local
        // proposal must never be overwritten, including the idempotent path.
        self.recheck(trust)?;
        if self.index.as_deref() == Some(index) {
            return Ok(());
        }
        let pending = Pending {
            schema_version: 1,
            expected: self.frontier.clone(),
            next: Frontier::successor(self.namespace, self.frontier.as_ref(), index)?,
            index_json: String::from_utf8(index.to_vec()).map_err(io::Error::other)?,
        };
        let raw = serde_json::to_vec(&Some(&pending)).map_err(io::Error::other)?;
        if raw.len() > MAX_PENDING_BYTES {
            return Err(invalid("M15 pending bound"));
        }
        let attempt = hash(b"TRNM/M15/OwnerAttempt/v1\0", &raw);
        // Every subsequent error, including uncertain remote completion, fences
        // this owner. Exact pending/attempt bytes are retained for cold recovery.
        self.fenced = true;
        self.files.write("pending.json", &raw)?;
        self.files.write(
            "attempt.json",
            &serde_json::to_vec(&Some(attempt)).map_err(io::Error::other)?,
        )?;
        let now = trust.now_seconds()?;
        validity.check(now)?;
        verify_at(&self.files, index, now)?;
        if trust.load(self.namespace)? != pending.expected {
            return Err(fenced());
        }
        // Callbacks and service I/O above may have yielded. Rebind this exact
        // held owner/proposal/attempt/index immediately before the external CAS.
        self.require_pending(&pending, false)?;
        if self.files.read("index.json", MAX_INDEX_BYTES)? != self.index {
            return Err(fenced());
        }
        self.files.revalidate()?;
        trust.compare_and_set(pending.expected.as_ref(), &pending.next, validity)?;
        if trust.load(self.namespace)?.as_ref() != Some(&pending.next) {
            return Err(fenced());
        }
        self.finish(&pending)?;
        self.frontier = Some(pending.next);
        self.index = Some(index.to_vec());
        self.fenced = false;
        // This is durable state only. The separate one-shot launch admission
        // still rechecks current roles/time and held artifact/config/argv.
        self.recheck(trust)
    }

    fn require_pending(&self, pending: &Pending, allow_completed_cleanup: bool) -> Result<()> {
        self.files.revalidate()?;
        let raw = serde_json::to_vec(&Some(pending)).map_err(io::Error::other)?;
        if self
            .files
            .read("pending.json", MAX_PENDING_BYTES)?
            .as_deref()
            != Some(raw.as_slice())
        {
            return Err(fenced());
        }
        let expected = serde_json::to_vec(&Some(hash(b"TRNM/M15/OwnerAttempt/v1\0", &raw)))
            .map_err(io::Error::other)?;
        let actual = self.files.read("attempt.json", 256)?;
        if actual.as_deref() == Some(expected.as_slice()) {
            return Ok(());
        }
        if allow_completed_cleanup
            && actual.as_deref() == Some(b"null")
            && self.files.read("index.json", MAX_INDEX_BYTES)?.as_deref()
                == Some(pending.index_json.as_bytes())
        {
            return Ok(());
        }
        Err(fenced())
    }

    fn finish(&self, pending: &Pending) -> Result<()> {
        // A known external winner does not permit erasing a different locally
        // retained proposal. Keep exact checks between each durable cleanup cut.
        self.require_pending(pending, true)?;
        if let Some(current) = self.files.read("index.json", MAX_INDEX_BYTES)? {
            let digest = index_digest(&current);
            if Some(digest) != pending.expected.as_ref().map(|f| f.index)
                && digest != pending.next.index
            {
                return Err(fenced());
            }
        } else if pending.expected.is_some() {
            return Err(fenced());
        }
        self.files
            .write("index.json", pending.index_json.as_bytes())?;
        self.require_pending(pending, true)?;
        self.require_installed_index(pending)?;
        // Canonical tombstones retain fixed slots; no unlink-based recovery.
        self.files.write("attempt.json", b"null")?;
        self.require_pending(pending, true)?;
        self.require_installed_index(pending)?;
        self.files.write("pending.json", b"null")
    }

    fn require_installed_index(&self, pending: &Pending) -> Result<()> {
        if self.files.read("index.json", MAX_INDEX_BYTES)?.as_deref()
            != Some(pending.index_json.as_bytes())
        {
            return Err(fenced());
        }
        Ok(())
    }
}
