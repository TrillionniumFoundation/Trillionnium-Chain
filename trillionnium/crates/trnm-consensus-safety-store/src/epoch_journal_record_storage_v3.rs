//! Closed physical record strategies; logical codec2 authority is unchanged.
use super::*;
use trnm_consensus_core::{EpochSafetyRecordPartsV2, MAX_EPOCH_PREPARATION_RECORD_BYTES_V2};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecordStorageV3 {
    Full,
    PrefixOnce,
}
pub(super) type RecordCoordinatesV3 = (u64, [u8; 32], [u8; 32], i64, i64);

impl RecordStorageV3 {
    pub(super) fn layout(self) -> JournalLayoutV2 {
        match self {
            Self::Full => JournalLayoutV2::Codec2,
            Self::PrefixOnce => JournalLayoutV2::Codec2PrefixOnce,
        }
    }
    pub(super) fn profile_domain(self) -> &'static [u8] {
        match self {
            Self::Full => b"trnm.journal10.epoch.profile.v2",
            Self::PrefixOnce => b"trnm.journal11.epoch.profile.v3",
        }
    }
    pub(super) fn origin_domain(self) -> &'static [u8] {
        match self {
            Self::Full => b"trnm.journal10.epoch.origin.v2",
            Self::PrefixOnce => b"trnm.journal11.epoch.origin.v3",
        }
    }
    pub(super) fn chain_domain(self) -> &'static [u8] {
        match self {
            Self::Full => b"trnm.journal10.epoch.chain.v2",
            Self::PrefixOnce => b"trnm.journal11.epoch.chain.v3",
        }
    }
    pub(super) fn initialize_prefix(
        self,
        connection: &Connection,
        parts: &EpochSafetyRecordPartsV2,
    ) -> Result<()> {
        if self == Self::PrefixOnce {
            connection.execute(
                "INSERT INTO epoch_provenance VALUES(1,?1)",
                [parts.provenance()],
            )?;
        }
        Ok(())
    }
    pub(super) fn insert_record(
        self,
        connection: &Connection,
        coordinates: (u64, [u8; 32], [u8; 32]),
        parts: &EpochSafetyRecordPartsV2,
        transition: &[u8],
    ) -> Result<()> {
        let (revision, predecessor, chain) = coordinates;
        match self {
            Self::Full => connection.execute(
                "INSERT INTO epoch_records VALUES(?1,?2,?3,?4,?5)",
                params![
                    revision,
                    predecessor.as_slice(),
                    chain.as_slice(),
                    parts.record_bytes(),
                    transition
                ],
            )?,
            Self::PrefixOnce => {
                // The fresh read validated the prefix before the transaction.
                // Recheck its exact bytes under the writer transaction; never
                // update it and never interpret a hash as the original prefix.
                let same: bool = connection.query_row(
                    "SELECT count(*)=1 AND coalesce(min(typeof(provenance)='blob' AND provenance=?1 AND singleton=1),0) FROM epoch_provenance",
                    [parts.provenance()], |r| r.get(0),
                )?;
                if !same {
                    return invalid("journal11 immutable provenance changed");
                }
                connection.execute(
                    "INSERT INTO epoch_records VALUES(?1,?2,?3,1,?4,?5,?6)",
                    params![
                        revision,
                        predecessor.as_slice(),
                        chain.as_slice(),
                        parts.before_provenance(),
                        parts.after_provenance(),
                        transition
                    ],
                )?
            }
        };
        Ok(())
    }
    pub(super) fn screen_source(
        self,
        connection: &Connection,
        maximum_record: usize,
    ) -> Result<()> {
        if self == Self::Full {
            return Ok(());
        }
        let (record, transition): (i64,i64) = connection.query_row(
            "SELECT CASE WHEN typeof(source_record)='blob' THEN length(source_record) ELSE -1 END,CASE WHEN typeof(source_transition)='blob' THEN length(source_transition) ELSE -1 END FROM epoch_metadata WHERE singleton=1", [], |r| Ok((r.get(0)?,r.get(1)?)))?;
        if record <= 0
            || record as u64 > maximum_record as u64
            || transition <= 0
            || transition as u64 > MAX_CONTEXT as u64
        {
            return invalid("journal11 source blob bounds");
        }
        Ok(())
    }
    pub(super) fn read_prefix(
        self,
        connection: &Connection,
        context: &EpochSafetyStateRecordContextV2<'_>,
    ) -> Result<Vec<u8>> {
        if self == Self::Full {
            return Ok(Vec::new());
        }
        let count: i64 =
            connection.query_row("SELECT count(*) FROM epoch_provenance", [], |r| r.get(0))?;
        if count != 1 {
            return invalid("journal11 provenance inventory");
        }
        let length: i64 = connection.query_row(
            "SELECT CASE WHEN typeof(provenance)='blob' THEN length(provenance) ELSE -1 END FROM epoch_provenance WHERE singleton=1",
            [], |r| r.get(0),
        )?;
        if length <= 0 || length as u64 > MAX_EPOCH_PREPARATION_RECORD_BYTES_V2 as u64 {
            return invalid("journal11 provenance bounds");
        }
        let bytes: Vec<u8> = connection.query_row(
            "SELECT provenance FROM epoch_provenance WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        let expected =
            context
                .epoch()
                .preparation_record_v2()
                .ok_or(EpochJournalErrorV2::Invalid(
                    "journal11 missing independent preparation",
                ))?;
        if bytes.as_slice() != expected.as_bytes_v2() {
            return invalid("journal11 provenance differs from independent context");
        }
        Ok(bytes)
    }
    pub(super) fn coordinates(
        self,
        connection: &Connection,
        prefix_len: usize,
        maximum_record: usize,
    ) -> Result<Vec<RecordCoordinatesV3>> {
        if self == Self::Full {
            let mut statement = connection.prepare("SELECT revision,predecessor,chain,length(record),length(transition) FROM epoch_records ORDER BY revision")?;
            let rows = statement
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            return Ok(rows);
        }
        let mut statement = connection.prepare(
            "SELECT revision,predecessor,chain,provenance_id,CASE WHEN typeof(record_before)='blob' THEN length(record_before) ELSE -1 END,CASE WHEN typeof(record_after)='blob' THEN length(record_after) ELSE -1 END,CASE WHEN typeof(transition)='blob' THEN length(transition) ELSE -1 END FROM epoch_records ORDER BY revision",
        )?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, [u8; 32]>(1)?,
                    r.get::<_, [u8; 32]>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(revision, predecessor, chain, prefix_id, before, after, transition)| {
                    if prefix_id != 1
                        || before <= 0
                        || after < 32
                        || transition <= 0
                        || transition as u64 > MAX_CONTEXT as u64
                    {
                        return invalid("journal11 record segment bounds");
                    }
                    let total = usize::try_from(before)
                        .ok()
                        .and_then(|n| n.checked_add(prefix_len))
                        .and_then(|n| {
                            usize::try_from(after)
                                .ok()
                                .and_then(|after| n.checked_add(after))
                        })
                        .filter(|n| *n <= maximum_record)
                        .ok_or(EpochJournalErrorV2::Invalid(
                            "journal11 reconstructed record capacity",
                        ))?;
                    Ok((revision, predecessor, chain, total as i64, transition))
                },
            )
            .collect()
    }
    pub(super) fn verify_exact_parts(
        self,
        connection: &Connection,
        revision: u64,
        state: &SafetyState,
        context: &EpochSafetyStateRecordContextV2<'_>,
    ) -> Result<()> {
        if self == Self::Full {
            return Ok(());
        }
        // Canonical physical boundaries come from the same opaque Core encoder,
        // not a byte search or a second cryptographic verification loop.
        let parts = encode_epoch_safety_record_parts_v2(state, context)?;
        let exact: bool = connection.query_row(
            "SELECT r.record_before=?1 AND p.provenance=?2 AND r.record_after=?3 FROM epoch_records r JOIN epoch_provenance p ON p.singleton=r.provenance_id WHERE r.revision=?4 AND p.singleton=1",
            params![parts.before_provenance(),parts.provenance(),parts.after_provenance(),revision], |r| r.get(0))?;
        if !exact {
            return invalid("journal11 noncanonical record split");
        }
        Ok(())
    }
    pub(super) fn read_record(
        self,
        connection: &Connection,
        revision: u64,
        prefix: &[u8],
        expected_length: usize,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if self == Self::Full {
            return Ok(connection.query_row(
                "SELECT record,transition FROM epoch_records WHERE revision=?1",
                [revision],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?);
        }
        let (before, after, transition): (Vec<u8>, Vec<u8>, Vec<u8>) = connection.query_row(
            "SELECT record_before,record_after,transition FROM epoch_records WHERE revision=?1 AND provenance_id=1",
            [revision], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        )?;
        if before
            .len()
            .checked_add(prefix.len())
            .and_then(|n| n.checked_add(after.len()))
            != Some(expected_length)
        {
            return invalid("journal11 record length changed");
        }
        let mut bytes = Vec::with_capacity(expected_length);
        bytes.extend_from_slice(&before);
        bytes.extend_from_slice(prefix);
        bytes.extend_from_slice(&after);
        Ok((bytes, transition))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inert_sql() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        RecordStorageV3::PrefixOnce
            .layout()
            .initialize_schema(&c)
            .unwrap();
        c.execute("INSERT INTO epoch_records VALUES(1,zeroblob(32),zeroblob(32),1,x'00',zeroblob(32),x'00')", []).unwrap();
        c
    }
    #[test]
    fn journal11_scalar_segment_caps_precede_materialization() {
        // Deliberately inert SQL only; this function returns scalar coordinates,
        // never a decoded record or any Core persistence/recovery authority.
        let c = inert_sql();
        let storage = RecordStorageV3::PrefixOnce;
        assert_eq!(storage.coordinates(&c, 2, 35).unwrap()[0].3, 35);
        assert!(storage.coordinates(&c, 2, 34).is_err());
        assert!(storage.coordinates(&c, usize::MAX, usize::MAX).is_err());
        assert!(c
            .execute("UPDATE epoch_records SET record_before='bad SQL type'", [])
            .is_err());
        c.execute(
            "UPDATE epoch_records SET transition=zeroblob(?1)",
            [MAX_CONTEXT],
        )
        .unwrap();
        assert_eq!(
            storage.coordinates(&c, 2, 35).unwrap()[0].4,
            MAX_CONTEXT as i64
        );
        c.execute(
            "UPDATE epoch_records SET transition=zeroblob(?1)",
            [MAX_CONTEXT + 1],
        )
        .unwrap();
        assert!(storage.coordinates(&c, 2, 35).is_err());
        c.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE epoch_records SET transition=x'00',record_after=zeroblob(31)").unwrap();
        assert!(storage.coordinates(&c, 2, 35).is_err());
    }
    #[test]
    fn journal11_scalar_source_caps_preserve_original_record_bounds() {
        let c = inert_sql();
        c.execute("INSERT INTO epoch_metadata VALUES(1,zeroblob(32),zeroblob(32),0,zeroblob(32),zeroblob(32),zeroblob(64),x'00',zeroblob(32),1)", []).unwrap();
        let storage = RecordStorageV3::PrefixOnce;
        storage.screen_source(&c, 64).unwrap();
        assert!(storage.screen_source(&c, 63).is_err());
        assert!(c
            .execute("UPDATE epoch_metadata SET source_record='bad SQL type'", [])
            .is_err());
        c.execute(
            "UPDATE epoch_metadata SET source_transition=zeroblob(?1)",
            [MAX_CONTEXT + 1],
        )
        .unwrap();
        assert!(storage.screen_source(&c, 64).is_err());
    }
}
