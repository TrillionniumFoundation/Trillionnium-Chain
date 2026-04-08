#[derive(Debug)]
pub struct SqliteReliabilityStore {
    conn: Connection,
    config: InMemoryReliabilityStoreConfig,
}

impl SqliteReliabilityStore {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, ReliabilityStoreError> {
        Self::open_with_config(path, Self::default_persistent_config())
    }

    pub fn open_with_config(
        path: impl AsRef<std::path::Path>,
        config: InMemoryReliabilityStoreConfig,
    ) -> Result<Self, ReliabilityStoreError> {
        let conn = Connection::open(path).map_err(|e| ReliabilityStoreError::InvalidState {
            detail: format!("open sqlite failed: {e}"),
        })?;
        Self::configure_connection(&conn)?;
        Self::apply_migrations(&conn)?;
        Ok(Self {
            conn,
            config: sanitize_store_config(config),
        })
    }

    fn default_persistent_config() -> InMemoryReliabilityStoreConfig {
        InMemoryReliabilityStoreConfig {
            max_sessions: Some(4_096),
            max_pending_per_session: Some(1_024),
            max_pending_total: Some(65_536),
            max_dedup_entries: Some(65_536),
            empty_session_cleanup: EmptySessionCleanupPolicy::RemoveImmediately,
        }
    }

    fn configure_connection(conn: &Connection) -> Result<(), ReliabilityStoreError> {
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA busy_timeout = 5000;
            ",
        )
        .map_err(|e| ReliabilityStoreError::InvalidState {
            detail: format!("configure sqlite pragmas failed: {e}"),
        })
    }

    fn apply_migrations(conn: &Connection) -> Result<(), ReliabilityStoreError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);",
        )
        .map_err(|e| ReliabilityStoreError::InvalidState {
            detail: format!("init migration table failed: {e}"),
        })?;

        let current: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version),0) FROM schema_migrations",
                [],
                |r| r.get(0),
            )
            .map_err(|e| ReliabilityStoreError::InvalidState {
                detail: format!("read migration version failed: {e}"),
            })?;

        if current < 1 {
            conn.execute_batch(
                "
                CREATE TABLE IF NOT EXISTS reliability_sessions (
                    session_id TEXT PRIMARY KEY,
                    session_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reliability_dedup (
                    from_addr TEXT NOT NULL,
                    seq_or_nonce INTEGER NOT NULL,
                    seen_at_unix_ms INTEGER NOT NULL,
                    PRIMARY KEY(from_addr, seq_or_nonce)
                );
                INSERT INTO schema_migrations(version) VALUES(1);
                ",
            )
            .map_err(|e| ReliabilityStoreError::InvalidState {
                detail: format!("apply migration v1 failed: {e}"),
            })?;
        }

        if current < 2 {
            let _ = conn.execute(
                "ALTER TABLE reliability_sessions ADD COLUMN updated_at_unix_ms INTEGER NOT NULL DEFAULT 0",
                [],
            );
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version) VALUES(2)",
                [],
            )
            .map_err(|e| ReliabilityStoreError::InvalidState {
                detail: format!("apply migration v2 failed: {e}"),
            })?;
        }

        Ok(())
    }

    fn total_pending_items(&self) -> usize {
        self.list_session_ids()
            .into_iter()
            .filter_map(|sid| self.get_session(&sid))
            .map(|session| session.pending.len())
            .sum()
    }

    fn cleanup_expired_sessions_only(&mut self, now_unix_ms: u128, retention: &RetentionConfig) {
        let pending_cutoff = now_unix_ms.saturating_sub(retention.pending_ttl_ms as u128);
        for sid in self.list_session_ids() {
            let Some(mut session) = self.get_session(&sid) else {
                continue;
            };
            session
                .pending
                .retain(|_, item| item.created_at_unix_ms >= pending_cutoff);
            if session.pending.is_empty() {
                self.remove_session(&sid);
            } else {
                let _ = self.try_upsert_session_with_ts(session, now_unix_ms);
            }
        }
    }
}
