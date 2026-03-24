#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex, OnceLock};
    use std::thread;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn mk_msg(from: &str, session_id: &str, seq: u64) -> ReliableMessage {
        ReliableMessage {
            from: from.to_string(),
            chain_id: "trnm-mainnet".to_string(),
            session_id: session_id.to_string(),
            seq: Some(seq),
            nonce: None,
            msg_type: "INPUT_CHUNK".to_string(),
            payload: "hello".to_string(),
        }
    }

    #[derive(Default)]
    struct FailingUpsertStore {
        inner: InMemoryReliabilityStore,
        fail_upsert: bool,
    }

    impl ReliabilityStore for FailingUpsertStore {
        fn get_session(&self, session_id: &str) -> Option<SessionState> {
            self.inner.get_session(session_id)
        }

        fn upsert_session(&mut self, session: SessionState) {
            self.inner.upsert_session(session);
        }

        fn remove_session(&mut self, session_id: &str) {
            self.inner.remove_session(session_id);
        }

        fn list_session_ids(&self) -> Vec<String> {
            self.inner.list_session_ids()
        }

        fn contains_dedup_key(&self, key: &DedupKey) -> bool {
            self.inner.contains_dedup_key(key)
        }

        fn remember_dedup_key(&mut self, key: DedupKey) {
            self.inner.remember_dedup_key(key);
        }

        fn remember_dedup_key_with_ts(&mut self, key: DedupKey, now_unix_ms: u128) {
            self.inner.remember_dedup_key_with_ts(key, now_unix_ms);
        }

        fn try_upsert_session_with_ts(
            &mut self,
            session: SessionState,
            now_unix_ms: u128,
        ) -> Result<(), ReliabilityStoreError> {
            if self.fail_upsert {
                return Err(ReliabilityStoreError::InvalidState {
                    detail: "injected upsert failure".to_string(),
                });
            }
            self.inner.try_upsert_session_with_ts(session, now_unix_ms)
        }

        fn try_remember_dedup_key_with_ts(
            &mut self,
            key: DedupKey,
            now_unix_ms: u128,
        ) -> Result<(), ReliabilityStoreError> {
            self.inner.try_remember_dedup_key_with_ts(key, now_unix_ms)
        }

        fn forget_dedup_key(&mut self, key: &DedupKey) {
            self.inner.forget_dedup_key(key);
        }

        fn should_remove_empty_session_immediately(&self) -> bool {
            self.inner.should_remove_empty_session_immediately()
        }

        fn cleanup_expired(&mut self, now_unix_ms: u128, retention: &RetentionConfig) {
            self.inner.cleanup_expired(now_unix_ms, retention);
        }
    }


    mod ingress {
        use super::*;
        include!("tests_ingress.rs");
    }

    mod retry_cleanup {
        use super::*;
        include!("tests_retry_cleanup.rs");
    }

    mod fairness_store {
        use super::*;
        include!("tests_fairness_store.rs");
    }
}
