use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};

use rusqlite::{params, Connection, OpenFlags, Transaction, TransactionBehavior};

use super::{
    files::Lease,
    types::{hash, proposal_retention_review, Decision},
    CellAdoptionActionV1, CellAdoptionPolicyV1, CellAdoptionReceiptV1, CellAdoptionSnapshotV1,
    CellCandidateEvidenceV1, CellCandidateObservationV1, CellProposalRetentionReceiptV1,
};
use crate::cell::{
    adoption_boundary::CellExecutionBoundaryV1, require, CellDigestV1, CellErrorV1, CellResultV1,
    CellVersionCommitmentV1, CellVersionManifestV1, MAX_CELL_VERSION_BYTES_V1,
};

const APPLICATION: i64 = 0x5443_4131;
const MAX_OBSERVATIONS: usize = 16;
const SCHEMA: &[(&str, &str)] = &[
    ("adoption_candidates", "CREATE TABLE adoption_candidates (commitment BLOB PRIMARY KEY NOT NULL CHECK(length(commitment)=64), parent BLOB CHECK(parent IS NULL OR length(parent)=64), version BLOB NOT NULL CHECK(length(version)>0 AND length(version)<=8388608)) STRICT"),
    ("adoption_decisions", "CREATE TABLE adoption_decisions (revision INTEGER PRIMARY KEY CHECK(revision>0), request_id BLOB NOT NULL UNIQUE CHECK(length(request_id)=32), request BLOB NOT NULL CHECK(length(request)<=512), evidence BLOB NOT NULL CHECK(length(evidence)>0 AND length(evidence)<=1024), after_state BLOB NOT NULL CHECK(length(after_state)<=256)) STRICT"),
    ("adoption_observations", "CREATE TABLE adoption_observations (candidate BLOB NOT NULL CHECK(length(candidate)=64), evidence BLOB NOT NULL CHECK(length(evidence)=64), material BLOB NOT NULL CHECK(length(material)<=264), PRIMARY KEY(candidate,evidence)) STRICT"),
    ("adoption_state", "CREATE TABLE adoption_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), policy BLOB NOT NULL CHECK(length(policy)=172), snapshot BLOB NOT NULL CHECK(length(snapshot)<=256)) STRICT"),
];

struct Candidate {
    parent: Option<CellVersionCommitmentV1>,
    version: CellVersionManifestV1,
    observations: BTreeSet<CellVersionCommitmentV1>,
}
type Catalog = BTreeMap<CellVersionCommitmentV1, Candidate>;

struct Audit {
    snapshot: CellAdoptionSnapshotV1,
    catalog: Catalog,
    selected_history: BTreeSet<CellVersionCommitmentV1>,
    receipts: BTreeMap<CellDigestV1, CellAdoptionReceiptV1>,
}

/// Durable local selection owner. It accepts only explicit local calls; it has
/// no network listener, provider-selected policy or automatic adoption loop.
/// The caller owns the private directory and preserves recovery-floor custody.
pub struct CellAdoptionOwnerV1 {
    connection: Connection,
    lease: Lease,
    policy: CellAdoptionPolicyV1,
    floor: CellAdoptionSnapshotV1,
}

impl CellAdoptionOwnerV1 {
    /// Create only. Existing, partial, foreign and already initialized files
    /// are never reset, upgraded or replaced. No version is selected yet.
    pub fn create(path: &Path, policy: &CellAdoptionPolicyV1) -> CellResultV1<Self> {
        let lease = Lease::open(path, true)?;
        let connection = connect(&lease)?;
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        connection.pragma_update(None, "synchronous", "EXTRA")?;
        let initial = policy.initial();
        let transaction = Transaction::new_unchecked(&connection, TransactionBehavior::Immediate)?;
        for (_, sql) in SCHEMA {
            transaction.execute_batch(sql)?;
        }
        transaction.pragma_update(None, "application_id", APPLICATION)?;
        transaction.pragma_update(None, "user_version", 1)?;
        transaction.execute(
            "INSERT INTO adoption_state VALUES(1,?1,?2)",
            params![policy.encode(), initial.encode()],
        )?;
        lease.check()?;
        transaction.commit()?;
        lease.check()?;
        let mut owner = Self {
            connection,
            lease,
            policy: policy.clone(),
            floor: initial,
        };
        owner.snapshot()?;
        Ok(owner)
    }

    /// Reopen against a separately retained lower bound. Every retained event
    /// is replayed and the exact floor must occur in that history. A stale floor
    /// cannot detect rollback after itself; its freshness is the caller's duty.
    pub fn open(
        path: &Path,
        policy: &CellAdoptionPolicyV1,
        recovery_floor: &CellAdoptionSnapshotV1,
    ) -> CellResultV1<Self> {
        require(
            recovery_floor.policy == policy.digest(),
            "adoption recovery policy",
        )?;
        let lease = Lease::open(path, false)?;
        let connection = connect(&lease)?;
        check_schema(&connection)?;
        connection.pragma_update(None, "synchronous", "EXTRA")?;
        let mut owner = Self {
            connection,
            lease,
            policy: policy.clone(),
            floor: recovery_floor.clone(),
        };
        owner.snapshot()?;
        Ok(owner)
    }

    pub fn snapshot(&mut self) -> CellResultV1<CellAdoptionSnapshotV1> {
        self.lease.check()?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let audit = audit(&transaction, &self.policy, &self.floor)?;
        self.floor = audit.snapshot.clone();
        self.lease.check()?;
        transaction.commit()?;
        Ok(audit.snapshot)
    }

    /// Record exact complete-version metadata and external evidence references.
    /// Multiple observations may reference the same immutable candidate. None
    /// changes the selected version, local revision or decision journal.
    /// This first profile admits only a complete single-parent lineage.
    pub fn observe_candidate(
        &mut self,
        version: &CellVersionManifestV1,
        parent: Option<CellVersionCommitmentV1>,
        evidence: CellCandidateEvidenceV1,
    ) -> CellResultV1<CellCandidateObservationV1> {
        self.policy.boundary.verify_version(version)?;
        evidence.validate()?;
        let candidate = version.commitment();
        let evidence_id = evidence.commitment();
        self.lease.check()?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let audit = audit(&transaction, &self.policy, &self.floor)?;
        // This snapshot was already committed before the current operation.
        // A later refusal cannot erase the fact that we observed its history.
        self.floor = audit.snapshot.clone();
        validate_parent(&self.policy, version, parent, &audit.catalog)?;
        if let Some(previous) = audit.catalog.get(&candidate) {
            require(
                previous.parent == parent && previous.version == *version,
                "adoption immutable candidate",
            )?;
            if previous.observations.contains(&evidence_id) {
                self.lease.check()?;
                transaction.commit()?;
                return Ok(CellCandidateObservationV1 {
                    candidate,
                    parent,
                    evidence: evidence_id,
                });
            }
            require(
                previous.observations.len() < MAX_OBSERVATIONS,
                "adoption evidence capacity",
            )?;
        } else {
            require(
                audit.catalog.len() < self.policy.candidates as usize,
                "adoption candidate capacity",
            )?;
            transaction.execute(
                "INSERT INTO adoption_candidates VALUES(?1,?2,?3)",
                params![
                    candidate.as_slice(),
                    parent.as_ref().map(|v| v.as_slice()),
                    version.encode()
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO adoption_observations VALUES(?1,?2,?3)",
            params![
                candidate.as_slice(),
                evidence_id.as_slice(),
                evidence.encode()
            ],
        )?;
        self.lease.check()?;
        transaction.commit()?;
        self.lease.check()?;
        Ok(CellCandidateObservationV1 {
            candidate,
            parent,
            evidence: evidence_id,
        })
    }

    /// Commit one explicit local decision using the exact expected snapshot.
    /// Same request/same bytes returns its old receipt even after later choices;
    /// same request/different bytes always refuses. That replay is not current
    /// permission. A nonzero review reference records the local owner's review,
    /// never authenticates or evaluates the referenced external evidence.
    pub fn decide(
        &mut self,
        request_id: CellDigestV1,
        expected: &CellAdoptionSnapshotV1,
        action: CellAdoptionActionV1,
        candidate: CellVersionCommitmentV1,
        review_commitment: CellVersionCommitmentV1,
    ) -> CellResultV1<CellAdoptionReceiptV1> {
        let decision = Decision {
            request: request_id,
            before: expected.clone(),
            action,
            candidate,
            review: review_commitment,
        };
        self.decide_checked(decision, None)
    }

    /// Retain the current version while binding the separate proposal that the
    /// local owner reviewed. The proposal must already be observed, name the
    /// current direct parent and contain the exact retained evidence reference.
    /// Those checks and the ordinary Retain(current) commit share one transaction.
    /// No qualification, signature, payment, NoUpdate or FinalUse is inferred.
    ///
    /// TCA1/TAD1 bytes and the original Retain action are unchanged. A fresh
    /// domain binds the full request into the existing review commitment.
    /// Preserve these original inputs for an exact cold-recovery retry; an old
    /// successful receipt remains historical and never grants current use.
    /// A replay verifies the currently retained proposal observation. It does
    /// not attest that this typed method validated the historical event: the
    /// trusted owner can also submit the same bound review through raw decide.
    pub fn retain_proposal(
        &mut self,
        request_id: CellDigestV1,
        expected: &CellAdoptionSnapshotV1,
        proposal: &CellCandidateObservationV1,
        local_review_commitment: CellVersionCommitmentV1,
    ) -> CellResultV1<CellProposalRetentionReceiptV1> {
        let review =
            proposal_retention_review(request_id, expected, proposal, local_review_commitment)?;
        let retained = expected
            .selected
            .ok_or(CellErrorV1::Invalid("adoption proposal retention parent"))?;
        let decision = Decision {
            request: request_id,
            before: expected.clone(),
            action: CellAdoptionActionV1::Retain,
            candidate: retained,
            review,
        };
        let retention = self.decide_checked(decision, Some(proposal))?;
        Ok(CellProposalRetentionReceiptV1 {
            proposal: proposal.clone(),
            local_review: local_review_commitment,
            retention,
        })
    }

    fn decide_checked(
        &mut self,
        decision: Decision,
        proposal: Option<&CellCandidateObservationV1>,
    ) -> CellResultV1<CellAdoptionReceiptV1> {
        decision.validate()?;
        let expected = decision.before.clone();
        let request_id = decision.request;
        let candidate = decision.candidate;
        require(
            expected.policy == self.policy.digest(),
            "adoption decision policy",
        )?;
        self.lease.check()?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let audit = audit(&transaction, &self.policy, &self.floor)?;
        self.floor = audit.snapshot.clone();
        if let Some(proposal) = proposal {
            let retained = audit
                .catalog
                .get(&proposal.candidate)
                .ok_or(CellErrorV1::Invalid("adoption proposal missing"))?;
            require(
                decision.action == CellAdoptionActionV1::Retain
                    && expected.selected == Some(candidate)
                    && proposal.candidate != candidate
                    && proposal.parent == Some(candidate)
                    && retained.parent == proposal.parent,
                "adoption proposal current parent required",
            )?;
            require(
                retained.observations.contains(&proposal.evidence),
                "adoption proposal evidence missing",
            )?;
        }
        if let Some(previous) = audit.receipts.get(&request_id) {
            require(
                previous.decision == decision,
                "adoption request identity conflict",
            )?;
            let previous = previous.clone();
            self.lease.check()?;
            transaction.commit()?;
            return Ok(previous);
        }
        require(audit.snapshot == expected, "adoption stale local snapshot")?;
        require(
            audit.snapshot.revision < u64::from(self.policy.decisions),
            "adoption decision capacity",
        )?;
        let selected = transition(&decision, &audit.catalog, &audit.selected_history)?;
        let observations = &audit
            .catalog
            .get(&candidate)
            .ok_or(CellErrorV1::Invalid("adoption candidate missing"))?
            .observations;
        let evidence = observation_bytes(observations);
        let evidence_set = evidence_set(candidate, &evidence);
        let receipt = CellAdoptionReceiptV1::new(decision, selected, evidence_set)?;
        transaction.execute(
            "INSERT INTO adoption_decisions VALUES(?1,?2,?3,?4,?5)",
            params![
                receipt.after.revision as i64,
                request_id.as_slice(),
                receipt.decision.encode(),
                evidence,
                receipt.after.encode()
            ],
        )?;
        let changed = transaction.execute(
            "UPDATE adoption_state SET snapshot=?1 WHERE singleton=1 AND policy=?2 AND snapshot=?3",
            params![
                receipt.after.encode(),
                self.policy.encode(),
                expected.encode()
            ],
        )?;
        require(changed == 1, "adoption snapshot CAS")?;
        self.lease.check()?;
        #[cfg(test)]
        super::tests::before_decision_commit()?;
        transaction.commit()?;
        // Successful COMMIT establishes this event even if its subsequent
        // acknowledgement fails. Before COMMIT, only the prior audit was a
        // known committed floor; an uncommitted proposal never becomes one.
        self.floor = receipt.after.clone();
        // If a late filesystem observation fails, the exact request remains
        // reconcilable after reopening; do not manufacture a new request ID.
        self.lease.check()?;
        #[cfg(test)]
        super::tests::after_decision_commit()?;
        Ok(receipt)
    }

    pub fn with_selected_guard<T>(
        &mut self,
        expected: &CellAdoptionSnapshotV1,
        version: &CellVersionManifestV1,
        current_execution: &CellExecutionBoundaryV1,
        consume: impl FnOnce() -> CellResultV1<T>,
    ) -> CellResultV1<T> {
        self.policy.boundary.verify_version(version)?;
        self.with_selected_commitment_guard(
            expected,
            version.commitment(),
            current_execution,
            consume,
        )
    }

    /// Re-read the selected complete TCV1 and immutable execution boundary,
    /// then hold the SQLite writer reservation through actual consumption.
    /// Contending writers refuse immediately; this never waits for a callback
    /// that could itself be trying to make a decision through another owner.
    /// The callback must retain its ordinary authorization/resource guard. Its
    /// external effects cannot be rolled back by a later callback/commit error.
    pub fn with_selected_commitment_guard<T>(
        &mut self,
        expected: &CellAdoptionSnapshotV1,
        commitment: CellVersionCommitmentV1,
        current_execution: &CellExecutionBoundaryV1,
        consume: impl FnOnce() -> CellResultV1<T>,
    ) -> CellResultV1<T> {
        self.policy.boundary.verify_execution(current_execution)?;
        self.lease.check()?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let audit = audit(&transaction, &self.policy, &self.floor)?;
        self.floor = audit.snapshot.clone();
        require(
            audit.snapshot == *expected && audit.snapshot.selected == Some(commitment),
            "adoption selected use snapshot",
        )?;
        let selected = audit
            .catalog
            .get(&commitment)
            .ok_or(CellErrorV1::Invalid("adoption selected metadata missing"))?;
        self.policy.boundary.verify_version(&selected.version)?;
        self.lease.check()?;
        let value = consume()?;
        self.lease.check()?;
        transaction.commit()?;
        Ok(value)
    }
}

fn connect(lease: &Lease) -> CellResultV1<Connection> {
    lease.check()?;
    let connection = Connection::open_with_flags(
        &lease.path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.busy_timeout(Duration::ZERO)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "cache_size", -2048)?;
    connection.pragma_update(None, "cache_spill", false)?;
    lease.check()?;
    Ok(connection)
}

fn check_schema(connection: &Connection) -> CellResultV1<()> {
    let app: i64 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let journal: String = connection.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    require(
        app == APPLICATION && version == 1 && journal == "delete",
        "adoption database namespace",
    )?;
    let mut statement = connection.prepare(
        "SELECT type,name,sql FROM sqlite_schema WHERE substr(name,1,7)!='sqlite_' ORDER BY name",
    )?;
    let entries = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    require(
        entries.len() == SCHEMA.len(),
        "adoption exact schema objects",
    )?;
    for ((kind, name, sql), (expected_name, expected_sql)) in entries.iter().zip(SCHEMA) {
        require(
            kind == "table" && name == expected_name && sql == expected_sql,
            "adoption exact schema",
        )?;
    }
    Ok(())
}

fn catalog(connection: &Connection, policy: &CellAdoptionPolicyV1) -> CellResultV1<Catalog> {
    let count: u64 =
        connection.query_row("SELECT count(*) FROM adoption_candidates", [], |r| r.get(0))?;
    require(
        count <= u64::from(policy.candidates),
        "adoption retained candidate count",
    )?;
    let mut statement = connection.prepare("SELECT commitment,parent,CASE WHEN length(version)<=8388608 THEN version ELSE NULL END FROM adoption_candidates ORDER BY commitment")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Option<Vec<u8>>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut result = Catalog::new();
    for row in rows {
        let (commitment, parent, wire) = row?;
        let commitment = digest64(&commitment)?;
        let parent = parent.as_deref().map(digest64).transpose()?;
        require(
            wire.len() <= MAX_CELL_VERSION_BYTES_V1,
            "adoption complete metadata size",
        )?;
        let version = CellVersionManifestV1::decode(&wire)?;
        policy.boundary.verify_version(&version)?;
        require(
            version.commitment() == commitment,
            "adoption complete metadata identity",
        )?;
        result.insert(
            commitment,
            Candidate {
                parent,
                version,
                observations: BTreeSet::new(),
            },
        );
    }
    for candidate in result.values() {
        validate_parent(policy, &candidate.version, candidate.parent, &result)?;
    }
    let count: u64 =
        connection.query_row("SELECT count(*) FROM adoption_observations", [], |r| {
            r.get(0)
        })?;
    require(
        count <= u64::from(policy.candidates) * MAX_OBSERVATIONS as u64,
        "adoption retained observation count",
    )?;
    let mut statement = connection.prepare("SELECT candidate,evidence,CASE WHEN length(material)<=264 THEN material ELSE NULL END FROM adoption_observations ORDER BY candidate,evidence")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    for row in rows {
        let (candidate, evidence, material) = row?;
        let candidate = result
            .get_mut(&digest64(&candidate)?)
            .ok_or(CellErrorV1::Invalid("adoption orphan evidence"))?;
        let evidence = digest64(&evidence)?;
        require(
            CellCandidateEvidenceV1::decode(&material)?.commitment() == evidence,
            "adoption evidence identity",
        )?;
        candidate.observations.insert(evidence);
    }
    require(
        result
            .values()
            .all(|v| !v.observations.is_empty() && v.observations.len() <= MAX_OBSERVATIONS),
        "adoption candidate evidence count",
    )?;
    Ok(result)
}

fn validate_parent(
    policy: &CellAdoptionPolicyV1,
    version: &CellVersionManifestV1,
    parent: Option<CellVersionCommitmentV1>,
    catalog: &Catalog,
) -> CellResultV1<()> {
    if let Some(parent) = parent {
        let parent = &catalog
            .get(&parent)
            .ok_or(CellErrorV1::Invalid("adoption parent missing"))?
            .version;
        require(
            version.model().closure().release().context().parent == parent.model().id(),
            "adoption parent context",
        )?;
        version
            .model()
            .verify_parent_roots(&[parent.model().clone()])
    } else {
        require(
            version.commitment() == policy.boundary.anchor_commitment(),
            "adoption unpinned origin",
        )
        // The exact independently approved anchor is a bootstrap checkpoint.
        // Preserve its earlier declared lineage without claiming to have
        // replayed that history. Every later local candidate has a fully
        // checked parent above; the anchor's prior review remains external.
    }
}

fn transition(
    decision: &Decision,
    catalog: &Catalog,
    history: &BTreeSet<CellVersionCommitmentV1>,
) -> CellResultV1<Option<CellVersionCommitmentV1>> {
    let candidate = catalog
        .get(&decision.candidate)
        .ok_or(CellErrorV1::Invalid("adoption candidate missing"))?;
    let selected = decision.before.selected;
    match decision.action {
        CellAdoptionActionV1::Adopt => {
            require(
                selected != Some(decision.candidate),
                "adoption requires a different selected candidate",
            )?;
            require(
                candidate.parent == selected,
                "adoption current parent required",
            )?;
            Ok(Some(decision.candidate))
        }
        CellAdoptionActionV1::Defer => {
            require(
                selected != Some(decision.candidate),
                "adoption defer selected candidate",
            )?;
            Ok(selected)
        }
        CellAdoptionActionV1::Retain => {
            require(
                selected == Some(decision.candidate),
                "adoption retain current required",
            )?;
            Ok(selected)
        }
        CellAdoptionActionV1::Rollback => {
            require(
                selected.is_some()
                    && selected != Some(decision.candidate)
                    && history.contains(&decision.candidate),
                "adoption rollback retained selection required",
            )?;
            Ok(Some(decision.candidate))
        }
    }
}

fn audit(
    connection: &Connection,
    policy: &CellAdoptionPolicyV1,
    floor: &CellAdoptionSnapshotV1,
) -> CellResultV1<Audit> {
    check_schema(connection)?;
    require(
        floor.policy == policy.digest(),
        "adoption local floor policy",
    )?;
    let count: u64 =
        connection.query_row("SELECT count(*) FROM adoption_state", [], |r| r.get(0))?;
    require(count == 1, "adoption singleton state")?;
    let (stored_policy, stored): (Vec<u8>, Vec<u8>) = connection.query_row(
        "SELECT policy,snapshot FROM adoption_state WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    require(
        stored_policy == policy.encode(),
        "adoption immutable local policy",
    )?;
    let stored = CellAdoptionSnapshotV1::decode(&stored)?;
    let catalog = catalog(connection, policy)?;
    let count: u64 =
        connection.query_row("SELECT count(*) FROM adoption_decisions", [], |r| r.get(0))?;
    require(
        count <= u64::from(policy.decisions),
        "adoption retained decision count",
    )?;
    let mut snapshot = policy.initial();
    let mut observed_floor = snapshot == *floor;
    let mut history = BTreeSet::new();
    let mut receipts = BTreeMap::new();
    let mut statement = connection.prepare("SELECT revision,request_id,request,evidence,after_state FROM adoption_decisions ORDER BY revision")?;
    let rows = statement.query_map([], |r| {
        Ok((
            r.get::<_, u64>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, Vec<u8>>(2)?,
            r.get::<_, Vec<u8>>(3)?,
            r.get::<_, Vec<u8>>(4)?,
        ))
    })?;
    for row in rows {
        let (revision, request_id, request, evidence, after) = row?;
        require(
            request.len() <= 512 && after.len() <= 256,
            "adoption retained encoding size",
        )?;
        let decision = Decision::decode(&request)?;
        require(
            decision.before == snapshot
                && decision.request.as_slice() == request_id
                && revision == snapshot.revision + 1,
            "adoption ordered decision history",
        )?;
        let candidate = catalog
            .get(&decision.candidate)
            .ok_or(CellErrorV1::Invalid("adoption decision metadata missing"))?;
        check_evidence(&evidence, &candidate.observations)?;
        let selected = transition(&decision, &catalog, &history)?;
        // The catalog already rehashed this complete version once. Replaying
        // each decision must not hash up to eight MiB of metadata again.
        let evidence_commitment = evidence_set(decision.candidate, &evidence);
        let receipt = CellAdoptionReceiptV1::new(decision, selected, evidence_commitment)?;
        require(
            receipt.after.encode() == after,
            "adoption decision state commitment",
        )?;
        snapshot = receipt.after.clone();
        if let Some(selected) = snapshot.selected {
            history.insert(selected);
        }
        observed_floor |= snapshot == *floor;
        require(
            receipts.insert(receipt.decision.request, receipt).is_none(),
            "adoption duplicate request",
        )?;
    }
    require(
        snapshot == stored && observed_floor,
        "adoption state/recovery floor mismatch",
    )?;
    Ok(Audit {
        snapshot,
        catalog,
        selected_history: history,
        receipts,
    })
}

fn observation_bytes(values: &BTreeSet<CellVersionCommitmentV1>) -> Vec<u8> {
    values.iter().flat_map(|v| v.iter().copied()).collect()
}

fn check_evidence(bytes: &[u8], retained: &BTreeSet<CellVersionCommitmentV1>) -> CellResultV1<()> {
    require(
        !bytes.is_empty() && bytes.len().is_multiple_of(64) && bytes.len() <= MAX_OBSERVATIONS * 64,
        "adoption decision evidence count",
    )?;
    let mut previous = None;
    for chunk in bytes.chunks_exact(64) {
        let current = digest64(chunk)?;
        require(
            previous.is_none_or(|v| v < current) && retained.contains(&current),
            "adoption decision evidence membership/order",
        )?;
        previous = Some(current);
    }
    Ok(())
}

fn evidence_set(candidate: CellVersionCommitmentV1, values: &[u8]) -> CellVersionCommitmentV1 {
    let mut bytes = candidate.to_vec();
    bytes.extend(values);
    hash(b"TRNM/Cell/LocalCandidateEvidenceSet/v1\0", &bytes)
}

fn digest64(bytes: &[u8]) -> CellResultV1<CellVersionCommitmentV1> {
    bytes
        .try_into()
        .map_err(|_| CellErrorV1::Invalid("adoption commitment width"))
}
