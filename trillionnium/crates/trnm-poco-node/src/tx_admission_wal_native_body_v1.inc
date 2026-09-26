// Exact signed-body persistence for the explicit native client profile. This
// shares the existing nonce SQLite transaction and never changes M05 TxIdV0.
const NATIVE_BODY_SCHEMA_VERSION_V1: i64 = 3;
pub const NATIVE_PUBLIC_PROFILE_V1: &str = "native-public-candidate-v1";
pub const MAX_NATIVE_PENDING_TRANSACTIONS_V1: usize = 256;
pub const MAX_NATIVE_PENDING_BYTES_V1: usize = 16 * 1024 * 1024;
pub const MAX_NATIVE_ADMISSION_OUTER_BYTES_V1: usize = 256 * 1024;
const MAX_NATIVE_RETAINED_BODY_BYTES_V1: usize = 128 * 1024 * 1024;
const MAX_NATIVE_BODY_ROWS_V1: usize = 65_536;

const NATIVE_BODY_SCHEMA_DDL_V1: &str = r#"
CREATE TABLE native_admission_profile_v1 (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    maximum_pending INTEGER NOT NULL CHECK(maximum_pending BETWEEN 1 AND 256),
    maximum_pending_bytes INTEGER NOT NULL CHECK(maximum_pending_bytes BETWEEN 1 AND 16777216),
    maximum_outer_bytes INTEGER NOT NULL CHECK(maximum_outer_bytes BETWEEN 1 AND 262144),
    last_sequence BLOB NOT NULL CHECK(length(last_sequence) = 8),
    migration_digest BLOB NOT NULL CHECK(length(migration_digest) = 32)
);
CREATE TABLE native_admission_body_v1 (
    namespace BLOB NOT NULL CHECK(length(namespace) = 32),
    signer BLOB NOT NULL CHECK(length(signer) = 32),
    nonce BLOB NOT NULL CHECK(length(nonce) = 8),
    digest BLOB NOT NULL CHECK(length(digest) = 32),
    exact_outer BLOB NOT NULL CHECK(length(exact_outer) BETWEEN 1 AND 262144),
    outer_sha256 BLOB NOT NULL CHECK(length(outer_sha256) = 32),
    receive_sequence BLOB NOT NULL CHECK(length(receive_sequence) = 8),
    profile_digest BLOB NOT NULL CHECK(length(profile_digest) = 32),
    local_reason INTEGER NOT NULL CHECK(local_reason IN (0, 1, 2)),
    PRIMARY KEY(namespace, signer, nonce),
    UNIQUE(namespace, digest),
    UNIQUE(namespace, receive_sequence),
    FOREIGN KEY(namespace, signer, nonce) REFERENCES pending_nonce(namespace, signer, nonce)
);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeAdmissionProfileV1 {
    pub profile_digest: [u8; 32],
    pub maximum_pending: usize,
    pub maximum_pending_bytes: usize,
    pub maximum_outer_bytes: usize,
}
impl NativeAdmissionProfileV1 {
    pub fn candidate_defaults(profile_digest: [u8; 32]) -> Self {
        Self {
            profile_digest,
            maximum_pending: MAX_NATIVE_PENDING_TRANSACTIONS_V1,
            maximum_pending_bytes: MAX_NATIVE_PENDING_BYTES_V1,
            maximum_outer_bytes: MAX_NATIVE_ADMISSION_OUTER_BYTES_V1,
        }
    }
    fn validate(self) -> Result<(), TxAdmissionWalErrorV0> {
        if self.profile_digest == [0; 32]
            || self.maximum_pending == 0
            || self.maximum_pending > MAX_NATIVE_PENDING_TRANSACTIONS_V1
            || self.maximum_pending_bytes == 0
            || self.maximum_pending_bytes > MAX_NATIVE_PENDING_BYTES_V1
            || self.maximum_outer_bytes == 0
            || self.maximum_outer_bytes > MAX_NATIVE_ADMISSION_OUTER_BYTES_V1
            || self.maximum_outer_bytes > self.maximum_pending_bytes
        {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAdmissionStatusV1 {
    Pending,
    InFlight,
    Committed,
    Expired,
    Rejected,
}

/// Durable facts about exact native bytes; Committed here still requires the
/// existing sealed application/finality receipt. Pending is no finality claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAdmissionRecordV1 {
    native_tx_hash: [u8; 32],
    exact_outer: Vec<u8>,
    receive_sequence: u64,
    status: NativeAdmissionStatusV1,
}
impl NativeAdmissionRecordV1 {
    pub const fn native_tx_hash(&self) -> [u8; 32] {
        self.native_tx_hash
    }
    pub fn exact_outer_bytes(&self) -> &[u8] {
        &self.exact_outer
    }
    pub const fn receive_sequence(&self) -> u64 {
        self.receive_sequence
    }
    pub const fn status(&self) -> NativeAdmissionStatusV1 {
        self.status
    }
}

#[derive(Debug)]
pub enum NativeAdmissionErrorV1 {
    Wal(TxAdmissionWalErrorV0),
    Decode,
    Rejected(AdmissionReject),
    Backpressure,
    UnsupportedProfile,
    /// The write may have committed. Reopen/reconcile before serving again.
    Uncertain,
}
impl fmt::Display for NativeAdmissionErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wal(e) => write!(f, "native admission: {e}"),
            Self::Decode => f.write_str("invalid exact native transaction bytes"),
            Self::Rejected(e) => write!(f, "native admission rejected: {e:?}"),
            Self::Backpressure => f.write_str("native admission queue is saturated"),
            Self::UnsupportedProfile => f.write_str("native durable-body profile is not installed"),
            Self::Uncertain => {
                f.write_str("native admission outcome is uncertain; recovery required")
            }
        }
    }
}
impl Error for NativeAdmissionErrorV1 {}
impl From<TxAdmissionWalErrorV0> for NativeAdmissionErrorV1 {
    fn from(value: TxAdmissionWalErrorV0) -> Self {
        Self::Wal(value)
    }
}

pub struct NativePendingAdmissionV1 {
    admission: PendingNonceAdmission,
    transaction: BuiltCanonicalTxV0,
    receive_sequence: u64,
}
impl NativePendingAdmissionV1 {
    pub const fn transaction(&self) -> &BuiltCanonicalTxV0 {
        &self.transaction
    }
    pub const fn receive_sequence(&self) -> u64 {
        self.receive_sequence
    }
    pub fn metadata(&self) -> &SignedEnvelopeMetadata {
        self.admission.metadata()
    }
    pub fn handoff(&mut self) -> Result<(), AdmissionReject> {
        self.admission.handoff()
    }
}

fn canonical_native_schema_v1(
    native: bool,
) -> Result<BTreeMap<(String, String), String>, TxAdmissionWalErrorV0> {
    if !native {
        return canonical_sqlite_schema_objects_v0();
    }
    let connection = Connection::open_in_memory().map_err(sqlite_error)?;
    connection
        .execute_batch(SQLITE_SCHEMA_DDL_V0)
        .map_err(sqlite_error)?;
    connection
        .execute_batch(NATIVE_BODY_SCHEMA_DDL_V1)
        .map_err(sqlite_error)?;
    sqlite_schema_objects_v0(&connection)
}

fn initialize_or_validate_native_profile_v1(
    connection: &Connection,
    profile: NativeAdmissionProfileV1,
    created_new: bool,
) -> Result<(), TxAdmissionWalErrorV0> {
    if created_new {
        connection
            .execute(
                "INSERT INTO native_admission_profile_v1 VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    profile.profile_digest.as_slice(),
                    profile.maximum_pending as i64,
                    profile.maximum_pending_bytes as i64,
                    profile.maximum_outer_bytes as i64,
                    0u64.to_be_bytes().as_slice(),
                    [0u8; 32].as_slice()
                ],
            )
            .map_err(sqlite_error)?;
    }
    let (digest, count, bytes, outer, sequence): (Vec<u8>, i64, i64, i64, Vec<u8>) = connection.query_row(
        "SELECT profile_digest, maximum_pending, maximum_pending_bytes, maximum_outer_bytes, last_sequence FROM native_admission_profile_v1 WHERE singleton = 1", [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).map_err(sqlite_error)?;
    if decode_fixed::<32>(digest)? != profile.profile_digest
        || count != profile.maximum_pending as i64
        || bytes != profile.maximum_pending_bytes as i64
        || outer != profile.maximum_outer_bytes as i64
    {
        return Err(TxAdmissionWalErrorV0::NamespaceMismatch);
    }
    decode_fixed::<8>(sequence)?;
    Ok(())
}

fn native_inventory_bounds_v1(
    connection: &Connection,
    namespace: [u8; 32],
    profile: NativeAdmissionProfileV1,
) -> Result<(usize, usize), TxAdmissionWalErrorV0> {
    let (rows, total, maximum): (i64, i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(SUM(length(exact_outer)),0), COALESCE(MAX(length(exact_outer)),0) FROM native_admission_body_v1", [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map_err(sqlite_error)?;
    if rows < 0
        || rows as usize > MAX_NATIVE_BODY_ROWS_V1
        || total < 0
        || total as usize > MAX_NATIVE_RETAINED_BODY_BYTES_V1
        || maximum < 0
        || maximum as usize > profile.maximum_outer_bytes
    {
        return Err(TxAdmissionWalErrorV0::TooLarge);
    }
    let (count, bytes): (i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(SUM(length(b.exact_outer)),0) FROM native_admission_body_v1 b JOIN pending_nonce p USING(namespace, signer, nonce) WHERE b.namespace=?1 AND p.state IN (0,1)",
        params![namespace.as_slice()], |r| Ok((r.get(0)?, r.get(1)?))).map_err(sqlite_error)?;
    if count < 0
        || count as usize > profile.maximum_pending
        || bytes < 0
        || bytes as usize > profile.maximum_pending_bytes
    {
        return Err(TxAdmissionWalErrorV0::TooLarge);
    }
    Ok((count as usize, bytes as usize))
}

fn read_native_body_v1(
    connection: &Connection,
    namespace: [u8; 32],
    profile: NativeAdmissionProfileV1,
    digest: [u8; 32],
) -> Result<Option<NativeAdmissionRecordV1>, TxAdmissionWalErrorV0> {
    let size: Option<i64> = connection.query_row("SELECT length(exact_outer) FROM native_admission_body_v1 WHERE namespace=?1 AND digest=?2",
        params![namespace.as_slice(), digest.as_slice()], |r| r.get(0)).optional().map_err(sqlite_error)?;
    let Some(size) = size else {
        return Ok(None);
    };
    if size <= 0 || size as usize > profile.maximum_outer_bytes {
        return Err(TxAdmissionWalErrorV0::TooLarge);
    }
    type BodyRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);
    let (signer, nonce, outer, sha, sequence, stored_profile, reason): BodyRow = connection.query_row(
        "SELECT signer, nonce, exact_outer, outer_sha256, receive_sequence, profile_digest, local_reason FROM native_admission_body_v1 WHERE namespace=?1 AND digest=?2",
        params![namespace.as_slice(), digest.as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).map_err(sqlite_error)?;
    let signer = decode_fixed::<32>(signer)?;
    let nonce = u64::from_be_bytes(decode_fixed::<8>(nonce)?);
    let sequence = u64::from_be_bytes(decode_fixed::<8>(sequence)?);
    if sequence == 0
        || decode_fixed::<32>(stored_profile)? != profile.profile_digest
        || decode_fixed::<32>(sha)? != <[u8; 32]>::from(Sha256::digest(&outer))
    {
        return Err(TxAdmissionWalErrorV0::Malformed);
    }
    let built = BuiltCanonicalTxV0::from_exact_outer_bytes_v0(&outer)
        .map_err(|_| TxAdmissionWalErrorV0::Malformed)?;
    // Verify signatures independently of today's expiry while auditing history.
    built
        .envelope()
        .validate_at_strict(
            &built.envelope().chain_id,
            built.envelope().issued_at_unix_ms,
        )
        .map_err(|_| TxAdmissionWalErrorV0::Malformed)?;
    let expected = AdmissionRecordV0::from_transaction(
        &built,
        CanonicalSignerId::from_bytes(signer).map_err(|_| TxAdmissionWalErrorV0::Malformed)?,
    )?;
    let Some((persisted, state)) = read_row_v0(connection, namespace, signer, nonce)? else {
        return Err(TxAdmissionWalErrorV0::Malformed);
    };
    if expected.digest != digest || expected.nonce != nonce || !row_matches_v0(persisted, expected)
    {
        return Err(TxAdmissionWalErrorV0::Malformed);
    }
    if state == STATE_COMMITTED_V0
        && read_receipt_commitment_v0(connection, namespace, signer, nonce)?.is_none()
    {
        return Err(TxAdmissionWalErrorV0::CommitReadbackUnavailable);
    }
    let status = match (state, reason) {
        (STATE_RESERVED_V0, 0) => NativeAdmissionStatusV1::Pending,
        (STATE_HANDED_OFF_V0, 0) => NativeAdmissionStatusV1::InFlight,
        (STATE_COMMITTED_V0, 0) => NativeAdmissionStatusV1::Committed,
        (STATE_RELEASED_V0, 1) => NativeAdmissionStatusV1::Expired,
        (STATE_RELEASED_V0, 2) => NativeAdmissionStatusV1::Rejected,
        _ => return Err(TxAdmissionWalErrorV0::Malformed),
    };
    Ok(Some(NativeAdmissionRecordV1 {
        native_tx_hash: digest,
        exact_outer: outer,
        receive_sequence: sequence,
        status,
    }))
}

fn validate_native_body_inventory_v1(
    connection: &Connection,
    namespace: [u8; 32],
    profile: NativeAdmissionProfileV1,
) -> Result<(), TxAdmissionWalErrorV0> {
    native_inventory_bounds_v1(connection, namespace, profile)?;
    let foreign: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM native_admission_body_v1 WHERE namespace != ?1",
            params![namespace.as_slice()],
            |r| r.get(0),
        )
        .map_err(sqlite_error)?;
    let missing: i64 = connection.query_row("SELECT COUNT(*) FROM pending_nonce p LEFT JOIN native_admission_body_v1 b USING(namespace,signer,nonce) WHERE p.state IN (0,1) AND b.digest IS NULL", [], |r| r.get(0)).map_err(sqlite_error)?;
    if foreign != 0 || missing != 0 {
        return Err(TxAdmissionWalErrorV0::Malformed);
    }
    let last: Vec<u8> = connection
        .query_row(
            "SELECT last_sequence FROM native_admission_profile_v1 WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(sqlite_error)?;
    let last = u64::from_be_bytes(decode_fixed::<8>(last)?);
    let mut statement = connection
        .prepare("SELECT digest FROM native_admission_body_v1 ORDER BY receive_sequence")
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut maximum = 0;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let digest = decode_fixed::<32>(row.get(0).map_err(sqlite_error)?)?;
        let body = read_native_body_v1(connection, namespace, profile, digest)?
            .ok_or(TxAdmissionWalErrorV0::Malformed)?;
        if body.receive_sequence <= maximum || body.receive_sequence > last {
            return Err(TxAdmissionWalErrorV0::Malformed);
        }
        maximum = body.receive_sequence;
    }
    if maximum != last {
        return Err(TxAdmissionWalErrorV0::Malformed);
    }
    Ok(())
}

fn persist_native_body_v1(
    connection: &Connection,
    namespace: [u8; 32],
    profile: NativeAdmissionProfileV1,
    record: AdmissionRecordV0,
    outer: &[u8],
) -> Result<(), TxAdmissionWalErrorV0> {
    if outer.is_empty() || outer.len() > profile.maximum_outer_bytes {
        return Err(TxAdmissionWalErrorV0::TooLarge);
    }
    let built = BuiltCanonicalTxV0::from_exact_outer_bytes_v0(outer)
        .map_err(|_| TxAdmissionWalErrorV0::Malformed)?;
    let derived = AdmissionRecordV0::from_transaction(
        &built,
        CanonicalSignerId::from_bytes(record.signer)
            .map_err(|_| TxAdmissionWalErrorV0::Malformed)?,
    )?;
    if !row_matches_v0(record, derived) {
        return Err(TxAdmissionWalErrorV0::Malformed);
    }
    if let Some(existing) = read_native_body_v1(connection, namespace, profile, record.digest)? {
        if existing.exact_outer_bytes() != outer {
            return Err(TxAdmissionWalErrorV0::Replay);
        }
        return Ok(());
    }
    let last: Vec<u8> = connection
        .query_row(
            "SELECT last_sequence FROM native_admission_profile_v1 WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(sqlite_error)?;
    let next = u64::from_be_bytes(decode_fixed::<8>(last)?)
        .checked_add(1)
        .ok_or(TxAdmissionWalErrorV0::TooLarge)?;
    let sha: [u8; 32] = Sha256::digest(outer).into();
    connection
        .execute(
            "INSERT INTO native_admission_body_v1 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,0)",
            params![
                namespace.as_slice(),
                record.signer.as_slice(),
                record.nonce.to_be_bytes().as_slice(),
                record.digest.as_slice(),
                outer,
                sha.as_slice(),
                next.to_be_bytes().as_slice(),
                profile.profile_digest.as_slice()
            ],
        )
        .map_err(map_insert_error_v0)?;
    connection
        .execute(
            "UPDATE native_admission_profile_v1 SET last_sequence=?1 WHERE singleton=1",
            params![next.to_be_bytes().as_slice()],
        )
        .map_err(sqlite_error)?;
    native_inventory_bounds_v1(connection, namespace, profile)?;
    Ok(())
}

impl NodeOwnedTxAdmissionBoundaryV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn open_native_candidate_v1<R, C>(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        profile: NativeAdmissionProfileV1,
        signer_resolver: R,
        context_resolver: C,
        recovery: bool,
    ) -> Result<Self, NativeAdmissionErrorV1>
    where
        R: CanonicalSignerIdentityResolverV0 + 'static,
        C: CanonicalAdmissionContextResolverV0 + 'static,
    {
        profile.validate()?;
        let authority = SqlitePendingNonceAuthorityV0::open_with_native_profile_v1(
            path,
            namespace,
            recovery,
            Some(profile),
        )?;
        let mut boundary = Self {
            gate: TypedAdmissionGate::new(
                profile.maximum_pending,
                0,
                profile.maximum_outer_bytes as u64,
            ),
            authority,
            signer_resolver: Some(Box::new(signer_resolver)),
            context_resolver: Some(Box::new(context_resolver)),
            allow_handed_off_recovery: recovery,
            native_recovery_required: false,
        };
        if !boundary.authority.has_unresolved_handoff_v0()? {
            boundary.restore_native_pending_v1()?;
        }
        Ok(boundary)
    }

    pub fn native_record_v1(
        &self,
        digest: [u8; 32],
    ) -> Result<Option<NativeAdmissionRecordV1>, NativeAdmissionErrorV1> {
        self.authority.ensure_identity()?;
        let profile = self
            .authority
            .native_profile
            .ok_or(NativeAdmissionErrorV1::UnsupportedProfile)?;
        let connection = self
            .authority
            .connection
            .try_borrow()
            .map_err(|_| NativeAdmissionErrorV1::Uncertain)?;
        let result = read_native_body_v1(&connection, self.authority.namespace, profile, digest)?;
        drop(connection);
        self.authority.ensure_identity()?;
        Ok(result)
    }

    pub fn native_pending_inventory_v1(
        &self,
    ) -> Result<Vec<NativeAdmissionRecordV1>, NativeAdmissionErrorV1> {
        self.authority.ensure_identity()?;
        let profile = self
            .authority
            .native_profile
            .ok_or(NativeAdmissionErrorV1::UnsupportedProfile)?;
        let connection = self
            .authority
            .connection
            .try_borrow()
            .map_err(|_| NativeAdmissionErrorV1::Uncertain)?;
        native_inventory_bounds_v1(&connection, self.authority.namespace, profile)?;
        let mut statement = connection.prepare("SELECT b.digest FROM native_admission_body_v1 b JOIN pending_nonce p USING(namespace,signer,nonce) WHERE p.state IN (0,1) ORDER BY b.receive_sequence").map_err(sqlite_error)?;
        let mut rows = statement.query([]).map_err(sqlite_error)?;
        let mut results = Vec::new();
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let digest = decode_fixed::<32>(row.get(0).map_err(sqlite_error)?)?;
            results.push(
                read_native_body_v1(&connection, self.authority.namespace, profile, digest)?
                    .ok_or(TxAdmissionWalErrorV0::Malformed)?,
            );
        }
        Ok(results)
    }

    /// Atomic body+nonce admission. Exact retry survives expiry and ACK loss,
    /// returning the original durable facts without requeueing or resigning.
    pub fn submit_native_bytes_v1(
        &mut self,
        bytes: &[u8],
    ) -> Result<NativeAdmissionRecordV1, NativeAdmissionErrorV1> {
        if self.native_recovery_required {
            return Err(NativeAdmissionErrorV1::Uncertain);
        }
        let result = self.submit_native_bytes_inner_v1(bytes);
        if matches!(&result, Err(NativeAdmissionErrorV1::Uncertain)) {
            self.native_recovery_required = true;
        }
        result
    }

    fn submit_native_bytes_inner_v1(
        &mut self,
        bytes: &[u8],
    ) -> Result<NativeAdmissionRecordV1, NativeAdmissionErrorV1> {
        let profile = self
            .authority
            .native_profile
            .ok_or(NativeAdmissionErrorV1::UnsupportedProfile)?;
        if bytes.is_empty() || bytes.len() > profile.maximum_outer_bytes {
            return Err(NativeAdmissionErrorV1::Decode);
        }
        if self.authority.has_unresolved_handoff_v0()? {
            return Err(TxAdmissionWalErrorV0::AmbiguousHandoff.into());
        }
        let built = BuiltCanonicalTxV0::from_exact_outer_bytes_v0(bytes)
            .map_err(|_| NativeAdmissionErrorV1::Decode)?;
        let signer = self
            .resolve_signer_id_v0(&built)
            .map_err(NativeAdmissionErrorV1::Rejected)?;
        let expected = AdmissionRecordV0::from_transaction(&built, signer)?;
        if let Some(record) = self.native_record_v1(expected.digest)? {
            if record.exact_outer_bytes() != bytes {
                return Err(TxAdmissionWalErrorV0::Replay.into());
            }
            return Ok(record);
        }
        {
            let connection = self
                .authority
                .connection
                .try_borrow()
                .map_err(|_| NativeAdmissionErrorV1::Uncertain)?;
            let (count, total) =
                native_inventory_bounds_v1(&connection, self.authority.namespace, profile)?;
            if count >= profile.maximum_pending
                || total
                    .checked_add(bytes.len())
                    .is_none_or(|n| n > profile.maximum_pending_bytes)
            {
                return Err(NativeAdmissionErrorV1::Backpressure);
            }
        }
        if built
            .envelope()
            .expires_at_unix_ms
            .checked_sub(built.envelope().issued_at_unix_ms)
            .is_none_or(|ttl| ttl > 600_000)
        {
            return Err(NativeAdmissionErrorV1::Decode);
        }
        self.authority.pending_native_body = Some(bytes.to_vec());
        let outcome = self.check_tx_candidate_with_authorities(&built, IngressClass::Normal);
        self.authority.pending_native_body = None;
        match outcome {
            TypedAdmitOutcome::Accepted | TypedAdmitOutcome::Duplicate => self
                .native_record_v1(expected.digest)?
                .ok_or(NativeAdmissionErrorV1::Uncertain),
            TypedAdmitOutcome::Backpressured => Err(NativeAdmissionErrorV1::Backpressure),
            TypedAdmitOutcome::Rejected(reason) => {
                if self.native_record_v1(expected.digest)?.is_some() {
                    return Err(NativeAdmissionErrorV1::Uncertain);
                }
                Err(NativeAdmissionErrorV1::Rejected(reason))
            }
        }
    }

    pub fn restore_native_pending_v1(&mut self) -> Result<(), NativeAdmissionErrorV1> {
        if self.native_recovery_required {
            return Err(NativeAdmissionErrorV1::Uncertain);
        }
        if self.authority.has_unresolved_handoff_v0()? {
            return Err(TxAdmissionWalErrorV0::AmbiguousHandoff.into());
        }
        let records = self.native_pending_inventory_v1()?;
        for record in records {
            if record.status != NativeAdmissionStatusV1::Pending {
                continue;
            }
            let built = BuiltCanonicalTxV0::from_exact_outer_bytes_v0(&record.exact_outer)
                .map_err(|_| NativeAdmissionErrorV1::Decode)?;
            let now = self
                .context_resolver
                .as_ref()
                .ok_or(NativeAdmissionErrorV1::UnsupportedProfile)?
                .now_unix_ms_v0();
            if now > built.envelope().expires_at_unix_ms {
                self.reject_native_pending_v1(record.native_tx_hash, true)?;
                continue;
            }
            self.authority.pending_native_body = Some(record.exact_outer);
            let outcome = self.check_tx_candidate_with_authorities(&built, IngressClass::Normal);
            self.authority.pending_native_body = None;
            if !matches!(
                outcome,
                TypedAdmitOutcome::Accepted | TypedAdmitOutcome::Duplicate
            ) {
                return Err(NativeAdmissionErrorV1::Uncertain);
            }
        }
        Ok(())
    }

    /// Explicit local rejection only before handoff. An in-flight transaction
    /// requires authenticated chain reconciliation, never local cancellation.
    pub fn reject_native_pending_v1(
        &mut self,
        digest: [u8; 32],
        expired: bool,
    ) -> Result<(), NativeAdmissionErrorV1> {
        self.authority.ensure_identity()?;
        let profile = self
            .authority
            .native_profile
            .ok_or(NativeAdmissionErrorV1::UnsupportedProfile)?;
        let mut connection = self
            .authority
            .connection
            .try_borrow_mut()
            .map_err(|_| NativeAdmissionErrorV1::Uncertain)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let record = read_native_body_v1(&transaction, self.authority.namespace, profile, digest)?
            .ok_or(TxAdmissionWalErrorV0::Malformed)?;
        if record.status != NativeAdmissionStatusV1::Pending {
            return Err(TxAdmissionWalErrorV0::ReservationConflict.into());
        }
        let changed = transaction
            .execute(
                "UPDATE pending_nonce SET state=3 WHERE namespace=?1 AND digest=?2 AND state=0",
                params![self.authority.namespace.as_slice(), digest.as_slice()],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(TxAdmissionWalErrorV0::ReservationConflict.into());
        }
        transaction.execute("UPDATE native_admission_body_v1 SET local_reason=?1 WHERE namespace=?2 AND digest=?3",
            params![if expired { 1 } else { 2 }, self.authority.namespace.as_slice(), digest.as_slice()]).map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        drop(connection);
        self.authority.ensure_identity()?;
        Ok(())
    }

    pub fn pop_native_ready_v1(
        &mut self,
    ) -> Result<Option<NativePendingAdmissionV1>, NativeAdmissionErrorV1> {
        if self.native_recovery_required {
            return Err(NativeAdmissionErrorV1::Uncertain);
        }
        while let Some(admission) = self.pop_ready_with_lifecycle() {
            let record = self
                .native_record_v1(admission.metadata().digest().as_bytes())?
                .ok_or(TxAdmissionWalErrorV0::Malformed)?;
            if matches!(
                record.status,
                NativeAdmissionStatusV1::Expired | NativeAdmissionStatusV1::Rejected
            ) {
                continue;
            }
            if record.status != NativeAdmissionStatusV1::Pending {
                return Err(NativeAdmissionErrorV1::Uncertain);
            }
            let transaction = BuiltCanonicalTxV0::from_exact_outer_bytes_v0(&record.exact_outer)
                .map_err(|_| NativeAdmissionErrorV1::Decode)?;
            return Ok(Some(NativePendingAdmissionV1 {
                admission,
                transaction,
                receive_sequence: record.receive_sequence,
            }));
        }
        Ok(None)
    }

    pub fn commit_native_with_readback_v1(
        &mut self,
        admission: &mut NativePendingAdmissionV1,
        evidence: NativeCommitReceiptEvidenceV0,
        application: &DurableNativeApplicationV0,
        finality: &FinalityProofV0,
        parent_timestamp_ms: u64,
    ) -> Result<(), AdmissionReject> {
        self.commit_candidate_with_native_readback(
            &mut admission.admission,
            &admission.transaction,
            evidence,
            application,
            finality,
            parent_timestamp_ms,
        )
    }
}

impl NodeOwnedTxAdmissionBoundaryV0 {
    /// Explicit, exclusive, all-or-nothing schema-2 migration. No body can be
    /// reconstructed from a digest: callers must supply every Reserved exact
    /// preimage, and an unresolved HandedOff row blocks this operation.
    /// Historical terminal rows/receipts/tombstones are preserved verbatim.
    pub fn migrate_legacy_native_candidate_v1<R, C>(
        path: impl AsRef<Path>,
        namespace: [u8; 32],
        profile: NativeAdmissionProfileV1,
        exact_preimages: &[Vec<u8>],
        signer_resolver: &R,
        context: &C,
    ) -> Result<[u8; 32], NativeAdmissionErrorV1>
    where
        R: CanonicalSignerIdentityResolverV0,
        C: CanonicalAdmissionContextResolverV0,
    {
        profile.validate()?;
        if exact_preimages.len() > profile.maximum_pending {
            return Err(NativeAdmissionErrorV1::Backpressure);
        }
        // Opening the existing authority acquires its process/file identity
        // fences and audits the complete old catalog and terminal evidence.
        if !path.as_ref().exists() {
            return Err(TxAdmissionWalErrorV0::InvalidPath.into());
        }
        let legacy = SqlitePendingNonceAuthorityV0::open(path, namespace)?;
        let mut supplied = BTreeMap::new();
        let mut total = 0usize;
        for bytes in exact_preimages {
            total = total
                .checked_add(bytes.len())
                .ok_or(NativeAdmissionErrorV1::Backpressure)?;
            if bytes.is_empty()
                || bytes.len() > profile.maximum_outer_bytes
                || total > profile.maximum_pending_bytes
            {
                return Err(NativeAdmissionErrorV1::Backpressure);
            }
            let built = BuiltCanonicalTxV0::from_exact_outer_bytes_v0(bytes)
                .map_err(|_| NativeAdmissionErrorV1::Decode)?;
            built
                .envelope()
                .validate_at_strict(context.chain_id_v0(), built.envelope().issued_at_unix_ms)
                .map_err(|_| NativeAdmissionErrorV1::Decode)?;
            let signer = signer_resolver
                .resolve_canonical_signer_id_v0(&built)
                .map_err(NativeAdmissionErrorV1::Rejected)?;
            let record = AdmissionRecordV0::from_transaction(&built, signer)?;
            let expired = context.now_unix_ms_v0() > built.envelope().expires_at_unix_ms;
            if supplied
                .insert(
                    (record.signer, record.nonce, record.digest),
                    (record, bytes, expired),
                )
                .is_some()
            {
                return Err(TxAdmissionWalErrorV0::Replay.into());
            }
        }
        legacy.ensure_identity()?;
        let mut connection = legacy
            .connection
            .try_borrow_mut()
            .map_err(|_| NativeAdmissionErrorV1::Uncertain)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .map_err(sqlite_error)?;
        let reserved: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM pending_nonce WHERE state=0",
                [],
                |r| r.get(0),
            )
            .map_err(sqlite_error)?;
        if reserved < 0 || reserved as usize != supplied.len() {
            return Err(TxAdmissionWalErrorV0::Malformed.into());
        }
        for (record, _, _) in supplied.values() {
            let Some((persisted, state)) =
                read_row_v0(&transaction, namespace, record.signer, record.nonce)?
            else {
                return Err(TxAdmissionWalErrorV0::Malformed.into());
            };
            if state != STATE_RESERVED_V0 || !row_matches_v0(persisted, *record) {
                return Err(TxAdmissionWalErrorV0::Malformed.into());
            }
        }
        let mut commitment = Sha256::new();
        commitment.update(b"trnm.native-admission.schema2-to3.v1\0");
        commitment.update(namespace);
        commitment.update(profile.profile_digest);
        // Commit the complete pre-migration logical inventory, including
        // terminal evidence, with typed and length-framed SQL values.
        for query in [
            "SELECT * FROM tx_admission_meta ORDER BY singleton",
            "SELECT * FROM pending_nonce ORDER BY namespace,signer,nonce",
            "SELECT * FROM tx_commit_receipt_v0 ORDER BY namespace,signer,nonce",
            "SELECT * FROM tx_admission_tombstone_v1 ORDER BY namespace,signer,nonce",
        ] {
            commitment.update((query.len() as u64).to_be_bytes());
            commitment.update(query.as_bytes());
            let mut statement = transaction.prepare(query).map_err(sqlite_error)?;
            let column_count = statement.column_count();
            let mut rows = statement.query([]).map_err(sqlite_error)?;
            while let Some(row) = rows.next().map_err(sqlite_error)? {
                commitment.update([1]);
                for index in 0..column_count {
                    match row.get_ref(index).map_err(sqlite_error)? {
                        rusqlite::types::ValueRef::Integer(value) => {
                            commitment.update([0]);
                            commitment.update(value.to_be_bytes());
                        }
                        rusqlite::types::ValueRef::Blob(value) => {
                            commitment.update([1]);
                            commitment.update((value.len() as u64).to_be_bytes());
                            commitment.update(value);
                        }
                        _ => return Err(TxAdmissionWalErrorV0::Malformed.into()),
                    }
                }
            }
            commitment.update([0]);
        }
        transaction
            .execute_batch(NATIVE_BODY_SCHEMA_DDL_V1)
            .map_err(sqlite_error)?;
        initialize_or_validate_native_profile_v1(&transaction, profile, true)?;
        // This order is deterministic migration order, never a claim about
        // arrival ordering which schema 2 did not retain.
        for (record, bytes, expired) in supplied.values() {
            persist_native_body_v1(&transaction, namespace, profile, *record, bytes)?;
            commitment.update(record.signer);
            commitment.update(record.nonce.to_be_bytes());
            commitment.update(record.digest);
            commitment.update((bytes.len() as u64).to_be_bytes());
            commitment.update(bytes);
            if *expired {
                transaction.execute("UPDATE pending_nonce SET state=3 WHERE namespace=?1 AND signer=?2 AND nonce=?3",
                    params![namespace.as_slice(),record.signer.as_slice(),record.nonce.to_be_bytes().as_slice()]).map_err(sqlite_error)?;
                transaction.execute("UPDATE native_admission_body_v1 SET local_reason=1 WHERE namespace=?1 AND digest=?2",
                    params![namespace.as_slice(),record.digest.as_slice()]).map_err(sqlite_error)?;
            }
        }
        let digest: [u8; 32] = commitment.finalize().into();
        transaction
            .execute(
                "UPDATE native_admission_profile_v1 SET migration_digest=?1 WHERE singleton=1",
                params![digest.as_slice()],
            )
            .map_err(sqlite_error)?;
        transaction
            .execute(
                "UPDATE tx_admission_meta SET schema_version=3 WHERE singleton=1",
                [],
            )
            .map_err(sqlite_error)?;
        transaction
            .pragma_update(None, "user_version", NATIVE_BODY_SCHEMA_VERSION_V1)
            .map_err(sqlite_error)?;
        validate_native_body_inventory_v1(&transaction, namespace, profile)?;
        transaction.commit().map_err(sqlite_error)?;
        drop(connection);
        legacy.ensure_identity()?;
        Ok(digest)
    }
}
