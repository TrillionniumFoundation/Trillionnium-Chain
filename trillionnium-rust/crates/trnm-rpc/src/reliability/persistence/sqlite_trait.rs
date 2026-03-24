impl ReliabilityStore for SqliteReliabilityStore {
    fn get_session(&self, session_id: &str) -> Option<SessionState> {
        let payload: String = self
            .conn
            .query_row(
                "SELECT session_json FROM reliability_sessions WHERE session_id=?1",
                [session_id],
                |r| r.get(0),
            )
            .ok()?;
        serde_json::from_str::<SessionState>(&payload).ok()
    }

    fn upsert_session(&mut self, session: SessionState) {
        let _ = self.try_upsert_session_with_ts(session, 0);
    }

    fn remove_session(&mut self, session_id: &str) {
        let _ = self.conn.execute(
            "DELETE FROM reliability_sessions WHERE session_id=?1",
            [session_id],
        );
    }

    fn list_session_ids(&self) -> Vec<String> {
        let mut stmt = match self
            .conn
            .prepare("SELECT session_id FROM reliability_sessions ORDER BY session_id")
        {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map([], |r| r.get::<_, String>(0)) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        rows.filter_map(Result::ok).collect()
    }

    fn contains_dedup_key(&self, key: &DedupKey) -> bool {
        self.conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM reliability_dedup WHERE from_addr=?1 AND seq_or_nonce=?2)",
                rusqlite::params![key.from, key.seq_or_nonce],
                |r| r.get::<_, i64>(0),
            )
            .map(|exists| exists != 0)
            .unwrap_or(false)
    }

    fn remember_dedup_key(&mut self, key: DedupKey) {
        self.remember_dedup_key_with_ts(key, 0);
    }

    fn remember_dedup_key_with_ts(&mut self, key: DedupKey, now_unix_ms: u128) {
        let seen = i64::try_from(now_unix_ms).unwrap_or(i64::MAX);
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO reliability_dedup(from_addr, seq_or_nonce, seen_at_unix_ms)
             VALUES(?1, ?2, ?3)",
            rusqlite::params![key.from, key.seq_or_nonce, seen],
        );
    }

    fn try_remember_dedup_key_with_ts(
        &mut self,
        key: DedupKey,
        now_unix_ms: u128,
    ) -> Result<(), ReliabilityStoreError> {
        if let Some(max) = self.config.max_dedup_entries {
            let existing: i64 = self
                .conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM reliability_dedup WHERE from_addr=?1 AND seq_or_nonce=?2)",
                    rusqlite::params![key.from, key.seq_or_nonce],
                    |r| r.get(0),
                )
                .map_err(|e| ReliabilityStoreError::InvalidState {
                    detail: format!("check dedup row failed: {e}"),
                })?;
            if existing == 0 {
                let count: i64 = self
                    .conn
                    .query_row("SELECT COUNT(*) FROM reliability_dedup", [], |r| r.get(0))
                    .map_err(|e| ReliabilityStoreError::InvalidState {
                        detail: format!("count dedup rows failed: {e}"),
                    })?;
                if usize::try_from(count).unwrap_or(usize::MAX) >= max {
                    return Err(ReliabilityStoreError::CapacityExceeded {
                        detail: format!("dedup limit reached ({max})"),
                    });
                }
            }
        }
        self.remember_dedup_key_with_ts(key, now_unix_ms);
        Ok(())
    }

    fn forget_dedup_key(&mut self, key: &DedupKey) {
        let _ = self.conn.execute(
            "DELETE FROM reliability_dedup WHERE from_addr=?1 AND seq_or_nonce=?2",
            rusqlite::params![key.from, key.seq_or_nonce],
        );
    }

    fn try_upsert_session_with_ts(
        &mut self,
        session: SessionState,
        now_unix_ms: u128,
    ) -> Result<(), ReliabilityStoreError> {
        let session_id = session.session_id.clone();
        let existing = self.get_session(&session_id);
        let old_len = existing.as_ref().map(|s| s.pending.len()).unwrap_or(0);
        let new_len = session.pending.len();
        let is_new_session = existing.is_none();

        if let Some(max) = self.config.max_sessions {
            if is_new_session && self.list_session_ids().len() >= max {
                return Err(ReliabilityStoreError::CapacityExceeded {
                    detail: format!("session limit reached ({max})"),
                });
            }
        }

        if let Some(max) = self.config.max_pending_per_session {
            if new_len > max {
                return Err(ReliabilityStoreError::CapacityExceeded {
                    detail: format!("pending per-session limit reached ({max})"),
                });
            }
        }

        if let Some(max) = self.config.max_pending_total {
            // Keep sqlite parity with in-memory hot path: non-growing updates on an
            // existing session cannot increase global pending pressure, so skip
            // O(session_count) total scans under sustained ingress.
            if is_new_session || new_len > old_len {
                let total = self.total_pending_items();
                let projected = total.saturating_sub(old_len).saturating_add(new_len);
                if projected > max {
                    return Err(ReliabilityStoreError::CapacityExceeded {
                        detail: format!("pending total limit reached ({max})"),
                    });
                }
            }
        }

        let payload =
            serde_json::to_string(&session).map_err(|e| ReliabilityStoreError::InvalidState {
                detail: format!("serialize session failed: {e}"),
            })?;
        let ts = i64::try_from(now_unix_ms).unwrap_or(i64::MAX);
        self.conn
            .execute(
                "INSERT INTO reliability_sessions(session_id, session_json, updated_at_unix_ms)
                 VALUES(?1, ?2, ?3)
                 ON CONFLICT(session_id) DO UPDATE SET
                   session_json=excluded.session_json,
                   updated_at_unix_ms=CASE
                     WHEN excluded.updated_at_unix_ms = 0 THEN reliability_sessions.updated_at_unix_ms
                     ELSE excluded.updated_at_unix_ms
                   END",
                rusqlite::params![session.session_id, payload, ts],
            )
            .map_err(|e| ReliabilityStoreError::InvalidState {
                detail: format!("upsert session failed: {e}"),
            })?;
        Ok(())
    }

    fn cleanup_expired(&mut self, now_unix_ms: u128, retention: &RetentionConfig) {
        let dedup_cutoff = now_unix_ms.saturating_sub(retention.dedup_ttl_ms as u128);
        let dedup_cutoff_i64 = i64::try_from(dedup_cutoff).unwrap_or(i64::MAX);
        let _ = self.conn.execute(
            "DELETE FROM reliability_dedup WHERE seen_at_unix_ms <> 0 AND seen_at_unix_ms < ?1",
            [dedup_cutoff_i64],
        );

        let pending_cutoff = now_unix_ms.saturating_sub(retention.pending_ttl_ms as u128);
        let pending_cutoff_i64 = i64::try_from(pending_cutoff).unwrap_or(i64::MAX);

        let mut stmt = match self.conn.prepare(
            "SELECT session_id, session_json, updated_at_unix_ms FROM reliability_sessions",
        ) {
            Ok(stmt) => stmt,
            Err(_) => return,
        };
        let rows = match stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        }) {
            Ok(rows) => rows,
            Err(_) => return,
        };

        let mut remove_ids = Vec::new();
        let mut updates = Vec::new();

        for row in rows.filter_map(Result::ok) {
            let (session_id, payload, updated_at_unix_ms) = row;
            let Ok(mut session) = serde_json::from_str::<SessionState>(&payload) else {
                remove_ids.push(session_id);
                continue;
            };

            let before_len = session.pending.len();
            session
                .pending
                .retain(|_, item| item.created_at_unix_ms >= pending_cutoff);

            if session.pending.is_empty() {
                if before_len != 0
                    || (updated_at_unix_ms != 0 && updated_at_unix_ms < pending_cutoff_i64)
                {
                    remove_ids.push(session_id);
                }
                continue;
            }

            if session.pending.len() != before_len {
                updates.push((
                    session_id,
                    session,
                    i64::try_from(now_unix_ms).unwrap_or(i64::MAX),
                ));
            }
        }
        drop(stmt);

        for session_id in remove_ids {
            let _ = self.conn.execute(
                "DELETE FROM reliability_sessions WHERE session_id=?1",
                [session_id],
            );
        }

        for (session_id, session, updated_at_unix_ms) in updates {
            if let Ok(payload) = serde_json::to_string(&session) {
                let _ = self.conn.execute(
                    "UPDATE reliability_sessions
                     SET session_json=?2, updated_at_unix_ms=?3
                     WHERE session_id=?1",
                    rusqlite::params![session_id, payload, updated_at_unix_ms],
                );
            }
        }
        self.cleanup_expired_sessions_only(now_unix_ms, retention);
    }
}
