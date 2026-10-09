
#[cfg(test)]
mod cached_owner_read_tests {
    use super::*;
    use crate::Node;

    fn open(path: &std::path::Path) -> Node {
        let settings = Settings::development_with_profiles(
            Some(1),
            "native-public-evaluation-dev-v1",
            trnm_mvcc_fee::continuity_v1::PROFILE,
        )
        .unwrap();
        Node::open_with_authenticated_state(path, settings, 1).unwrap()
    }

    #[test]
    fn cached_block_reads_do_not_hide_genesis_damage_or_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let node = open(directory.path());
        let id = node.settings.genesis();
        for capacity in [0, 1, 16] {
            node.db.set_prepared_statement_cache_capacity(capacity);
            let original = native_block(&node.db, &node.settings, id).unwrap();
            node.db.execute_batch("SAVEPOINT damaged_block").unwrap();
            node.db
                .execute("UPDATE blocks SET height=1 WHERE id=?", [id.as_slice()])
                .unwrap();
            let error = native_block(&node.db, &node.settings, id).err().unwrap();
            assert_eq!(error.to_string(), "NATIVE_STATE_GENESIS");
            assert!(error.requires_owner_stop());
            node.db
                .execute_batch("ROLLBACK TO damaged_block; RELEASE damaged_block")
                .unwrap();
            let recovered = native_block(&node.db, &node.settings, id).unwrap();
            assert_eq!(
                (recovered.parent, recovered.height, recovered.root, recovered.packet_digest),
                (original.parent, original.height, original.root, original.packet_digest)
            );
        }
    }

    #[test]
    fn cached_parent_reads_observe_changed_work_then_exact_restore() {
        let directory = tempfile::tempdir().unwrap();
        let mut node = open(directory.path());
        let genesis = node.settings.genesis();
        let miner = crate::development_public(0).unwrap();
        let packet = node
            .make_consensus_maintenance(genesis, vec![], miner, 11, 4096)
            .unwrap();
        let id = node.admit(&packet, 100_000).unwrap();
        let expected = native_block(&node.db, &node.settings, id).unwrap();
        node.db.execute_batch("SAVEPOINT damaged_parent").unwrap();
        node.db
            .execute(
                "UPDATE blocks SET chainwork=? WHERE id=?",
                params![vec![255u8; 64], genesis.as_slice()],
            )
            .unwrap();
        assert!(native_block(&node.db, &node.settings, id)
            .err()
            .unwrap()
            .requires_owner_stop());
        node.db
            .execute_batch("ROLLBACK TO damaged_parent; RELEASE damaged_parent")
            .unwrap();
        let actual = native_block(&node.db, &node.settings, id).unwrap();
        assert_eq!(
            (actual.parent, actual.height, actual.root, actual.packet_digest),
            (expected.parent, expected.height, expected.root, expected.packet_digest)
        );
    }

    #[test]
    fn cached_commitment_reads_preserve_limits_missing_and_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let node = open(directory.path());
        let id = node.settings.genesis();
        let expected = load(&node.db, id).unwrap();
        for length in [MAX_RECORD_BYTES + 1, MAX_RECORD_BYTES * 8] {
            node.db.execute_batch("SAVEPOINT damaged_record").unwrap();
            node.db
                .execute(
                    "UPDATE native_state_commitments SET data=? WHERE block=?",
                    params![vec![b'x'; length], id.as_slice()],
                )
                .unwrap();
            let error = load(&node.db, id).unwrap_err();
            assert_eq!(error.to_string(), "NATIVE_STATE_RECORD_LIMIT");
            assert!(error.requires_owner_stop());
            node.db
                .execute_batch("ROLLBACK TO damaged_record; RELEASE damaged_record")
                .unwrap();
            assert_eq!(load(&node.db, id).unwrap(), expected);
        }
        node.db.execute_batch("SAVEPOINT removed_record").unwrap();
        node.db
            .execute("DELETE FROM native_state_commitments WHERE block=?", [id.as_slice()])
            .unwrap();
        let missing = load(&node.db, id).unwrap_err();
        assert_eq!(missing.to_string(), "NATIVE_STATE_MISSING");
        assert!(missing.requires_owner_stop());
        node.db
            .execute_batch("ROLLBACK TO removed_record; RELEASE removed_record")
            .unwrap();
        assert_eq!(load(&node.db, id).unwrap(), expected);
    }

    #[test]
    fn cached_genesis_snapshot_is_reread_and_survives_cold_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let node = open(directory.path());
        let id = node.settings.genesis();
        let expected = node.read_active().unwrap();
        verify_history(&node.db, &node.settings, id, &mut || Ok(())).unwrap();
        node.db.execute_batch("SAVEPOINT damaged_snapshot").unwrap();
        node.db
            .execute(
                "UPDATE snapshots SET state=? WHERE block=?",
                params![b"{}".as_slice(), id.as_slice()],
            )
            .unwrap();
        let error = verify_history(&node.db, &node.settings, id, &mut || Ok(())).unwrap_err();
        assert_eq!(error.to_string(), "NATIVE_STATE_GENESIS");
        assert!(error.requires_owner_stop());
        node.db
            .execute_batch("ROLLBACK TO damaged_snapshot; RELEASE damaged_snapshot")
            .unwrap();
        verify_history(&node.db, &node.settings, id, &mut || Ok(())).unwrap();
        drop(node);
        let reopened = open(directory.path());
        assert_eq!(reopened.read_active().unwrap(), expected);
        verify_history(&reopened.db, &reopened.settings, id, &mut || Ok(())).unwrap();
    }
}
