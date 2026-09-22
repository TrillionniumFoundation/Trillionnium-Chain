//! Permanent ordinary-custody retirement in the same authenticated namespace.
//! The complete terminal record is in the atomically replaced mode marker;
//! there is no independently removable terminal sidecar or fabricated intent.
use super::*;

pub(super) const RETIRED_MODE_BYTES: usize = 108 + SIGNER_RETIREMENT_RECORD_BYTES_V1 + 32;
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerRetirementAuthorityCutV1 {
    AfterWriteBeforeFileSync,
    AfterFileSyncBeforeRename,
    AfterRenameBeforeDirectorySync,
    AfterDirectorySyncBeforeReadback,
    AfterTerminalAppendBeforeSync,
    AfterTerminalSyncBeforeReadback,
    BeforeRecoveredTerminalSync,
}
pub(super) const TERMINAL_LOG_BYTES: usize = 8 + 2 + SIGNER_RETIREMENT_RECORD_BYTES_V1 + 32 + 32;
const LOAD_RETIREMENT: u8 = 4;
const RETIRE_SIGNER: u8 = 5;
const RETIREMENT_VALUE: u8 = 6;
const RETIREMENT_REQUEST_PREFIX: usize = 105;

impl ExternalWatermarkAuthority {
    pub(super) fn require_ordinary_active_v1(&self) -> Result<(), ExternalWatermarkAuthorityError> {
        if self.poisoned {
            return Err(ExternalWatermarkAuthorityError::Unavailable);
        }
        if self.retirement.is_some() {
            return Err(ExternalWatermarkAuthorityError::ScopeConflict);
        }
        let mode = read_mode_marker(&semantic_mode_path_for(&self.log_path)?)?.ok_or(
            ExternalWatermarkAuthorityError::InvalidLog("mode marker missing"),
        )?;
        if mode.retirement.is_some() || mode.binding != self.semantic_binding {
            return Err(ExternalWatermarkAuthorityError::ScopeConflict);
        }
        Ok(())
    }
    pub(super) fn validate_retirement_source_v1(
        &self,
    ) -> Result<(), ExternalWatermarkAuthorityError> {
        if let Some(record) = self.retirement {
            self.validate_retirement_candidate_v1(&record)?;
        }
        Ok(())
    }
    fn validate_retirement_candidate_v1(
        &self,
        record: &SignerRetirementRecordV1,
    ) -> Result<(), ExternalWatermarkAuthorityError> {
        let binding = self
            .semantic_binding
            .ok_or(ExternalWatermarkAuthorityError::ScopeConflict)?;
        let source = record.source_v1();
        if binding.lifecycle_mode != ExternalWatermarkSemanticLifecycleModeV1::SignerJournalPair
            || binding.scope != source.scope()
            || binding.journal_id != source.journal_id()
            || self.current.get(&binding.scope).copied() != Some(source)
            || self.semantic_last_watermark.get(&binding.scope).copied() != Some(source)
            || self.current.len() != 1
            || !source.sequence().is_multiple_of(2)
            || self.record_count != self.semantic_record_count
        {
            return Err(ExternalWatermarkAuthorityError::CompareFailed);
        }
        let facts = self
            .semantic_current
            .get(&binding.scope)
            .ok_or(ExternalWatermarkAuthorityError::ScopeConflict)?;
        if record.host_cut_v1().safety_revision <= facts.safety_revision
            || facts.capability != binding.capability
        {
            return Err(ExternalWatermarkAuthorityError::ScopeConflict);
        }
        Ok(())
    }
    /// Read the exact terminal policy with the original semantic capability.
    pub fn load_signer_retirement_v1(
        &mut self,
        binding: ExternalWatermarkSemanticBindingV1,
    ) -> Result<Option<SignerRetirementRecordV1>, ExternalWatermarkAuthorityError> {
        self.preflight_integrity()?;
        if self.semantic_binding != Some(binding)
            || binding.lifecycle_mode != ExternalWatermarkSemanticLifecycleModeV1::SignerJournalPair
        {
            return Err(ExternalWatermarkAuthorityError::ScopeConflict);
        }
        self.validate_retirement_source_v1()?;
        if self.retirement.is_some() && !self.retirement_logged {
            return Err(ExternalWatermarkAuthorityError::Unavailable);
        }
        if self.retirement_logged {
            self.sync_terminal_confirmation_v1(&mut |_| Ok(()))?;
            self.preflight_integrity()?;
        }
        Ok(self.retirement)
    }
    /// An exact retry is idempotent, but no ordinary operation can follow it.
    /// Failure after local I/O poisons this owner; reopen authenticates the
    /// complete mode marker plus both original append-only source histories.
    pub fn retire_signer_exact_v1(
        &mut self,
        binding: ExternalWatermarkSemanticBindingV1,
        record: SignerRetirementRecordV1,
    ) -> Result<SignerWatermarkV0, ExternalWatermarkAuthorityError> {
        self.retire_signer_with_observer_v1(binding, record, |_| Ok(()))
    }
    #[doc(hidden)]
    pub fn retire_signer_with_observer_v1(
        &mut self,
        binding: ExternalWatermarkSemanticBindingV1,
        record: SignerRetirementRecordV1,
        mut observer: impl FnMut(SignerRetirementAuthorityCutV1) -> io::Result<()>,
    ) -> Result<SignerWatermarkV0, ExternalWatermarkAuthorityError> {
        self.preflight_integrity()?;
        if self.semantic_binding != Some(binding) {
            return Err(ExternalWatermarkAuthorityError::ScopeConflict);
        }
        self.validate_retirement_candidate_v1(&record)?;
        if let Some(actual) = self.retirement {
            if actual != record {
                return Err(ExternalWatermarkAuthorityError::CompareFailed);
            }
            if !self.retirement_logged {
                self.append_retirement_terminal_v1(&mut observer)?;
            }
            self.sync_terminal_confirmation_v1(&mut observer)?;
            self.preflight_integrity()?;
            return Ok(actual.terminal_watermark_v1());
        }
        // Set memory terminal first: any uncertain write leaves every ordinary
        // API fenced even before this owner is dropped and reopened.
        self.retirement = Some(record);
        if let Err(error) = write_mode_marker_observed_v1(
            &semantic_mode_path_for(&self.log_path)?,
            Some(binding),
            Some(record),
            &self.directory,
            &mut observer,
        ) {
            self.poisoned = true;
            return Err(error);
        }
        self.append_retirement_terminal_v1(&mut observer)?;
        self.preflight_integrity()?;
        Ok(record.terminal_watermark_v1())
    }
    fn sync_terminal_confirmation_v1(
        &mut self,
        observer: &mut impl FnMut(SignerRetirementAuthorityCutV1) -> io::Result<()>,
    ) -> Result<(), ExternalWatermarkAuthorityError> {
        // A full tail observed after SIGKILL may only reside in the page cache.
        // Reestablish durability before exact retry or readback acknowledges it.
        let result = (|| {
            observer(SignerRetirementAuthorityCutV1::BeforeRecoveredTerminalSync)?;
            self.log.sync_all()?;
            self.directory.sync_all()?;
            Ok::<(), io::Error>(())
        })();
        if let Err(source) = result {
            self.poisoned = true;
            return Err(ExternalWatermarkAuthorityError::Io {
                stage: "sync recovered retirement terminal",
                source,
            });
        }
        Ok(())
    }
    fn append_retirement_terminal_v1(
        &mut self,
        observer: &mut impl FnMut(SignerRetirementAuthorityCutV1) -> io::Result<()>,
    ) -> Result<(), ExternalWatermarkAuthorityError> {
        let record = self
            .retirement
            .ok_or(ExternalWatermarkAuthorityError::InvalidLog(
                "missing terminal mode",
            ))?;
        if self.retirement_logged {
            return Ok(());
        }
        let bytes = encode_terminal_log_v1(record, self.head_hash);
        if metadata_len(&self.log)?.saturating_add(bytes.len() as u64) > MAX_AUTHORITY_LOG_BYTES {
            self.poisoned = true;
            return Err(ExternalWatermarkAuthorityError::InvalidLog(
                "terminal log capacity",
            ));
        }
        let result = (|| {
            self.log.write_all(&bytes)?;
            observer(SignerRetirementAuthorityCutV1::AfterTerminalAppendBeforeSync)?;
            self.log.sync_all()?;
            self.directory.sync_all()?;
            observer(SignerRetirementAuthorityCutV1::AfterTerminalSyncBeforeReadback)?;
            Ok::<(), io::Error>(())
        })();
        if let Err(source) = result {
            self.poisoned = true;
            return Err(ExternalWatermarkAuthorityError::Io {
                stage: "append durable ordinary-signer terminal event",
                source,
            });
        }
        self.retirement_logged = true;
        Ok(())
    }
    pub(super) fn handle_retirement_load_v1(
        &mut self,
        binding: ExternalWatermarkSemanticBindingV1,
    ) -> Vec<u8> {
        match self.load_signer_retirement_v1(binding) {
            Ok(record) => encode_response_v2(record),
            Err(error) => encode_error_v2(error),
        }
    }
    pub(super) fn handle_retirement_cas_v1(
        &mut self,
        binding: ExternalWatermarkSemanticBindingV1,
        record: SignerRetirementRecordV1,
    ) -> Vec<u8> {
        match self.retire_signer_exact_v1(binding, record) {
            Ok(_) => encode_response_v2(Some(record)),
            Err(error) => encode_error_v2(error),
        }
    }
}

impl ExternalSignerRetirementV1 for UnixWatermarkClient {
    fn load_signer_retirement_v1(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerRetirementRecordV1>, ExternalWatermarkErrorV0> {
        let binding = self.retirement_binding_v1(scope)?;
        match self
            .request(RequestV1::LoadRetirement { binding })
            .map_err(map_client_error)?
        {
            ResponseV1::Retirement(record)
                if record.is_none_or(|r| {
                    r.source_v1().scope() == binding.scope
                        && r.source_v1().journal_id() == binding.journal_id
                }) =>
            {
                Ok(record)
            }
            ResponseV1::CompareFailed => Err(ExternalWatermarkErrorV0::CompareFailed),
            ResponseV1::Unavailable => Err(ExternalWatermarkErrorV0::Unavailable),
            _ => Err(ExternalWatermarkErrorV0::InvalidPersistedState),
        }
    }
    fn retire_signer_exact_v1(
        &mut self,
        record: &SignerRetirementRecordV1,
    ) -> Result<SignerWatermarkV0, ExternalWatermarkErrorV0> {
        let binding = self.retirement_binding_v1(record.source_v1().scope())?;
        if binding.journal_id != record.source_v1().journal_id() {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        match self
            .request(RequestV1::RetireSigner {
                binding,
                record: *record,
            })
            .map_err(map_client_error)?
        {
            ResponseV1::Retirement(Some(actual)) if actual == *record => {
                Ok(record.terminal_watermark_v1())
            }
            ResponseV1::CompareFailed => Err(ExternalWatermarkErrorV0::CompareFailed),
            ResponseV1::Unavailable => Err(ExternalWatermarkErrorV0::Unavailable),
            _ => Err(ExternalWatermarkErrorV0::InvalidPersistedState),
        }
    }
}
impl UnixWatermarkClient {
    fn retirement_binding_v1(
        &self,
        scope: [u8; 32],
    ) -> Result<ExternalWatermarkSemanticBindingV1, ExternalWatermarkErrorV0> {
        self.semantic_binding
            .filter(|b| {
                b.scope == scope
                    && b.lifecycle_mode
                        == ExternalWatermarkSemanticLifecycleModeV1::SignerJournalPair
            })
            .ok_or(ExternalWatermarkErrorV0::InvalidPersistedState)
    }
}

pub(super) fn encode_request_v2(request: RequestV1) -> Option<Vec<u8>> {
    let (binding, record) = match request {
        RequestV1::LoadRetirement { binding } => (binding, None),
        RequestV1::RetireSigner { binding, record } => (binding, Some(record)),
        _ => return None,
    };
    let mut bytes =
        Vec::with_capacity(RETIREMENT_REQUEST_PREFIX + SIGNER_RETIREMENT_RECORD_BYTES_V1);
    bytes.extend_from_slice(b"EWM2");
    bytes.extend_from_slice(&[
        2,
        if record.is_some() {
            RETIRE_SIGNER
        } else {
            LOAD_RETIREMENT
        },
        0,
        binding.lifecycle_mode as u8,
        0,
    ]);
    bytes.extend_from_slice(&binding.scope);
    bytes.extend_from_slice(&binding.journal_id);
    bytes.extend_from_slice(&binding.capability);
    if let Some(record) = record {
        bytes.extend_from_slice(&record.encode_v1());
    }
    Some(bytes)
}
pub(super) fn decode_request_v2(
    bytes: &[u8],
) -> Result<RequestV1, ExternalWatermarkAuthorityError> {
    if bytes.len() < RETIREMENT_REQUEST_PREFIX
        || bytes.len() > MAX_FRAME_BYTES
        || &bytes[..4] != b"EWM2"
        || bytes[4] != 2
        || bytes[6] != 0
        || bytes[7] != ExternalWatermarkSemanticLifecycleModeV1::SignerJournalPair as u8
        || bytes[8] != 0
    {
        return Err(ExternalWatermarkAuthorityError::Protocol(
            "retirement request header",
        ));
    }
    let binding = ExternalWatermarkSemanticBindingV1::new(
        bytes[9..41].try_into().expect("scope"),
        bytes[41..73].try_into().expect("journal"),
        bytes[73..105].try_into().expect("capability"),
    )
    .ok_or(ExternalWatermarkAuthorityError::Protocol(
        "retirement binding",
    ))?;
    match bytes[5] {
        LOAD_RETIREMENT if bytes.len() == RETIREMENT_REQUEST_PREFIX => {
            Ok(RequestV1::LoadRetirement { binding })
        }
        RETIRE_SIGNER
            if bytes.len() == RETIREMENT_REQUEST_PREFIX + SIGNER_RETIREMENT_RECORD_BYTES_V1 =>
        {
            let record =
                SignerRetirementRecordV1::decode_v1_exact(&bytes[RETIREMENT_REQUEST_PREFIX..])
                    .map_err(|_| ExternalWatermarkAuthorityError::Protocol("retirement record"))?;
            if record.source_v1().scope() != binding.scope
                || record.source_v1().journal_id() != binding.journal_id
            {
                return Err(ExternalWatermarkAuthorityError::Protocol(
                    "retirement source binding",
                ));
            }
            Ok(RequestV1::RetireSigner { binding, record })
        }
        _ => Err(ExternalWatermarkAuthorityError::Protocol(
            "retirement request shape",
        )),
    }
}
fn response_header_v2(status: u8) -> Vec<u8> {
    let mut b = b"EWR2".to_vec();
    b.extend_from_slice(&[2, status, 0, 0]);
    b
}
fn encode_response_v2(record: Option<SignerRetirementRecordV1>) -> Vec<u8> {
    let mut b = response_header_v2(if record.is_some() {
        RETIREMENT_VALUE
    } else {
        STATUS_NONE
    });
    if let Some(record) = record {
        b.extend_from_slice(&record.encode_v1());
    }
    b
}
fn encode_error_v2(error: ExternalWatermarkAuthorityError) -> Vec<u8> {
    response_header_v2(match error {
        ExternalWatermarkAuthorityError::CompareFailed => STATUS_COMPARE_FAILED,
        ExternalWatermarkAuthorityError::InvalidConfig(_)
        | ExternalWatermarkAuthorityError::InvalidLog(_)
        | ExternalWatermarkAuthorityError::ScopeConflict
        | ExternalWatermarkAuthorityError::Protocol(_) => STATUS_INVALID_STATE,
        _ => STATUS_UNAVAILABLE,
    })
}
pub(super) fn decode_response_v2(
    bytes: &[u8],
) -> Result<ResponseV1, ExternalWatermarkAuthorityError> {
    if bytes.len() < 8
        || bytes.len() > MAX_FRAME_BYTES
        || &bytes[..4] != b"EWR2"
        || bytes[4] != 2
        || bytes[6..8] != [0, 0]
    {
        return Err(ExternalWatermarkAuthorityError::Protocol(
            "retirement response header",
        ));
    }
    match bytes[5] {
        STATUS_NONE if bytes.len() == 8 => Ok(ResponseV1::Retirement(None)),
        RETIREMENT_VALUE if bytes.len() == 8 + SIGNER_RETIREMENT_RECORD_BYTES_V1 => {
            Ok(ResponseV1::Retirement(Some(
                SignerRetirementRecordV1::decode_v1_exact(&bytes[8..]).map_err(|_| {
                    ExternalWatermarkAuthorityError::Protocol("retirement response record")
                })?,
            )))
        }
        STATUS_COMPARE_FAILED if bytes.len() == 8 => Ok(ResponseV1::CompareFailed),
        STATUS_INVALID_STATE if bytes.len() == 8 => Ok(ResponseV1::InvalidState),
        STATUS_UNAVAILABLE if bytes.len() == 8 => Ok(ResponseV1::Unavailable),
        _ => Err(ExternalWatermarkAuthorityError::Protocol(
            "retirement response shape",
        )),
    }
}

fn encode_terminal_log_v1(
    record: SignerRetirementRecordV1,
    previous: [u8; 32],
) -> [u8; TERMINAL_LOG_BYTES] {
    let mut bytes = [0; TERMINAL_LOG_BYTES];
    bytes[..8].copy_from_slice(b"TRNMER01");
    bytes[8..10].copy_from_slice(&1u16.to_be_bytes());
    bytes[10..10 + SIGNER_RETIREMENT_RECORD_BYTES_V1].copy_from_slice(&record.encode_v1());
    let offset = 10 + SIGNER_RETIREMENT_RECORD_BYTES_V1;
    bytes[offset..offset + 32].copy_from_slice(&previous);
    let mut h = Sha256::new();
    h.update(b"trnm.consensus.external-watermark.terminal-event.v1\0");
    h.update(&bytes[..offset + 32]);
    bytes[offset + 32..].copy_from_slice(&h.finalize());
    bytes
}
pub(super) fn validate_terminal_log_v1(
    bytes: &[u8],
    record: SignerRetirementRecordV1,
    previous: [u8; 32],
) -> Result<(), ExternalWatermarkAuthorityError> {
    if bytes != encode_terminal_log_v1(record, previous) {
        return Err(ExternalWatermarkAuthorityError::InvalidLog(
            "terminal event/context/source mismatch",
        ));
    }
    Ok(())
}
