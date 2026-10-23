use super::*;

fn populated(path: &Path) -> (CellManifestV1, Vec<u8>) {
    let bytes = vec![37_u8; 16_384];
    let digest = Sha256::digest(&bytes).into();
    let manifest = CellManifestV1::new(
        context(),
        bytes.len() as u64,
        digest,
        16_384,
        vec![CellChunkV1 {
            size: bytes.len() as u32,
            sha256: digest,
        }],
    )
    .unwrap();
    let cache = CellStoreV1::open(path, cache_config()).unwrap();
    cache
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    cache.put_chunk(&manifest.chunks()[0], &bytes).unwrap();
    (manifest, bytes)
}

#[test]
fn reserved_prefix_trigger_is_not_hidden_from_exact_cold_catalog_validation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("owned.sqlite");
    let (manifest, bytes) = populated(&path);
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "PRAGMA writable_schema=ON;
        INSERT INTO sqlite_schema(type,name,tbl_name,rootpage,sql)
        VALUES('trigger','sqlite_hidden','cell_chunks_v1',0,
        'CREATE TRIGGER sqlite_hidden AFTER INSERT ON cell_chunks_v1 BEGIN SELECT 1; END');
        PRAGMA writable_schema=OFF;",
    )
    .unwrap();
    drop(db);
    let before = std::fs::read(&path).unwrap();
    assert!(CellStoreV1::open_read_only(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(CellStoreV1::open(&path, cache_config()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row::<Vec<u8>, _, _>(
            "SELECT bytes FROM cell_chunks_v1 WHERE hash=?1",
            [manifest.chunks()[0].sha256.as_slice()],
            |row| row.get(0)
        )
        .unwrap(),
        bytes
    );
    assert_eq!(
        db.query_row::<u64, _, _>(
            "SELECT count(*) FROM sqlite_schema WHERE name='sqlite_hidden'",
            [],
            |row| row.get(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn foreign_database_containing_only_an_internal_sequence_is_not_claimed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("foreign.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE retired(id INTEGER PRIMARY KEY AUTOINCREMENT);
        DROP TABLE retired;",
    )
    .unwrap();
    let names = db
        .prepare("SELECT name FROM sqlite_schema")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(names, vec!["sqlite_sequence"]);
    drop(db);
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        CellStoreV1::open(&path, cache_config()),
        Err(CellErrorV1::Invalid("foreign cache database"))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn legitimate_two_automatic_indexes_and_payload_survive_both_cold_open_modes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("legitimate.sqlite");
    let (manifest, bytes) = populated(&path);
    let db = Connection::open(&path).unwrap();
    let indexes = db
        .prepare(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE type='index' ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        indexes,
        vec![
            (
                "index".into(),
                "sqlite_autoindex_cell_chunks_v1_1".into(),
                "cell_chunks_v1".into(),
                None
            ),
            (
                "index".into(),
                "sqlite_autoindex_cell_manifests_v1_1".into(),
                "cell_manifests_v1".into(),
                None
            )
        ]
    );
    drop(db);
    for cache in [
        CellStoreV1::open_read_only(&path).unwrap(),
        CellStoreV1::open(&path, cache_config()).unwrap(),
    ] {
        assert_eq!(
            cache.manifest(manifest.id()).unwrap(),
            Some(manifest.clone())
        );
        assert_eq!(
            cache.chunk(manifest.chunks()[0].sha256).unwrap(),
            Some(bytes.clone())
        );
        cache.verify_complete(&manifest).unwrap();
        assert_eq!(cache.cache_usage().unwrap().chunk_rows, 1);
    }
}

#[test]
fn automatic_index_metadata_and_oversized_non_null_sql_are_not_accepted_as_null() {
    for damage in ["table", "name", "short-sql", "oversized-sql"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("index.sqlite");
        let cache = CellStoreV1::open(&path, cache_config()).unwrap();
        let db = Connection::open(&path).unwrap();
        db.execute_batch("PRAGMA writable_schema=ON").unwrap();
        match damage {
            "table" => db
                .execute(
                    "UPDATE sqlite_schema SET tbl_name='cell_manifests_v1'
                WHERE name='sqlite_autoindex_cell_chunks_v1_1'",
                    [],
                )
                .unwrap(),
            "name" => db
                .execute(
                    "UPDATE sqlite_schema SET name='sqlite_autoindex_other_1'
                WHERE name='sqlite_autoindex_cell_chunks_v1_1'",
                    [],
                )
                .unwrap(),
            _ => db
                .execute(
                    "UPDATE sqlite_schema SET sql=?1
                WHERE name='sqlite_autoindex_cell_chunks_v1_1'",
                    [if damage == "short-sql" {
                        String::new()
                    } else {
                        "x".repeat(65_536)
                    }],
                )
                .unwrap(),
        };
        db.execute_batch("PRAGMA writable_schema=OFF").unwrap();
        drop(db);
        // The already-parsed original connection reads the actual changed
        // catalog without a schema-cookie bump: this exercises our bounded
        // validation, including the NULL-vs-oversized guard, rather than relying
        // on SQLite's later cold parser to reject a malformed definition.
        assert!(
            matches!(
                cache.cache_usage(),
                Err(CellErrorV1::Invalid("cache schema definition"))
            ),
            "{damage}"
        );
        drop(cache);
        let before = std::fs::read(&path).unwrap();
        assert!(CellStoreV1::open_read_only(&path).is_err(), "{damage}");
        assert_eq!(std::fs::read(&path).unwrap(), before, "{damage}");
        assert!(
            CellStoreV1::open(&path, cache_config()).is_err(),
            "{damage}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before, "{damage}");
    }
}
