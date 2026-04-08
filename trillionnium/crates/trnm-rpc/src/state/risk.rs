use anyhow::Result;
use std::collections::HashMap;

use super::{too_many_requests, RiskDomain};

pub(crate) const MAX_RISK_BUCKET_KEYS_PER_DOMAIN: usize = 4096;
pub(crate) const RISK_SOURCE_MAX_CHARS: usize = 64;
pub(crate) const RISK_ERROR_KEY_MAX_CHARS: usize = 96;

#[derive(Debug, Clone)]
pub struct RiskQuotaConfig {
    pub window_ms: u128,
    pub per_session_limit: u32,
    pub per_source_limit: u32,
}

impl Default for RiskQuotaConfig {
    fn default() -> Self {
        Self {
            window_ms: 1_000,
            per_session_limit: 64,
            per_source_limit: 64,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct WindowCounter {
    window_start_ms: u128,
    used: u32,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RiskQuotaState {
    by_session: HashMap<(RiskDomain, String), WindowCounter>,
    by_source: HashMap<(RiskDomain, String), WindowCounter>,
}

impl RiskQuotaState {
    pub(crate) fn consume(
        &mut self,
        now_ms: u128,
        domain: RiskDomain,
        session_id: &str,
        source: &str,
        cfg: &RiskQuotaConfig,
    ) -> Result<()> {
        Self::consume_bucket(
            &mut self.by_session,
            now_ms,
            domain,
            session_id,
            cfg.window_ms,
            cfg.per_session_limit,
            "session",
        )?;

        if let Err(e) = Self::consume_bucket(
            &mut self.by_source,
            now_ms,
            domain,
            source,
            cfg.window_ms,
            cfg.per_source_limit,
            "source",
        ) {
            Self::rollback_bucket(&mut self.by_session, domain, session_id);
            return Err(e);
        }

        Ok(())
    }

    fn consume_bucket(
        buckets: &mut HashMap<(RiskDomain, String), WindowCounter>,
        now_ms: u128,
        domain: RiskDomain,
        key: &str,
        window_ms: u128,
        limit: u32,
        dim: &str,
    ) -> Result<()> {
        let window_ms = window_ms.max(1);
        let limit = limit.max(1);
        Self::prune_expired_domain_buckets(buckets, now_ms, domain, window_ms);
        let bucket_key = (domain, key.to_string());
        if !buckets.contains_key(&bucket_key)
            && Self::domain_bucket_count(buckets, domain) >= MAX_RISK_BUCKET_KEYS_PER_DOMAIN
        {
            return Err(too_many_requests(
                "quota_exceeded",
                format!(
                    "domain={} dim={} keyspace_exhausted max_keys={} window_ms={}",
                    domain.as_str(),
                    dim,
                    MAX_RISK_BUCKET_KEYS_PER_DOMAIN,
                    window_ms
                ),
            ));
        }

        let bucket = buckets.entry(bucket_key).or_insert_with(|| WindowCounter {
            window_start_ms: now_ms,
            used: 0,
        });

        if now_ms.saturating_sub(bucket.window_start_ms) >= window_ms {
            bucket.window_start_ms = now_ms;
            bucket.used = 0;
        }

        if bucket.used >= limit {
            return Err(too_many_requests(
                "quota_exceeded",
                format!(
                    "domain={} dim={} key={} limit={} window_ms={}",
                    domain.as_str(),
                    dim,
                    elide_risk_error_key(key),
                    limit,
                    window_ms
                ),
            ));
        }
        bucket.used += 1;
        Ok(())
    }

    fn prune_expired_domain_buckets(
        buckets: &mut HashMap<(RiskDomain, String), WindowCounter>,
        now_ms: u128,
        domain: RiskDomain,
        window_ms: u128,
    ) {
        buckets.retain(|(d, _), bucket| {
            if *d != domain {
                return true;
            }
            now_ms.saturating_sub(bucket.window_start_ms) < window_ms
        });
    }

    fn domain_bucket_count(
        buckets: &HashMap<(RiskDomain, String), WindowCounter>,
        domain: RiskDomain,
    ) -> usize {
        buckets.keys().filter(|(d, _)| *d == domain).count()
    }

    fn rollback_bucket(
        buckets: &mut HashMap<(RiskDomain, String), WindowCounter>,
        domain: RiskDomain,
        key: &str,
    ) {
        let bucket_key = (domain, key.to_string());
        let mut should_remove = false;
        if let Some(bucket) = buckets.get_mut(&bucket_key) {
            if bucket.used > 0 {
                bucket.used -= 1;
            }
            should_remove = bucket.used == 0;
        }
        if should_remove {
            buckets.remove(&bucket_key);
        }
    }
}

pub(crate) fn elide_risk_error_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len().min(RISK_ERROR_KEY_MAX_CHARS));
    for ch in key.chars().take(RISK_ERROR_KEY_MAX_CHARS) {
        out.push(ch);
    }
    if key.chars().count() > RISK_ERROR_KEY_MAX_CHARS {
        out.push('…');
    }
    out
}

pub(crate) fn canonicalize_risk_source(source: Option<&str>) -> String {
    let source = source.unwrap_or("anon").trim();
    if source.is_empty() {
        return "anon".to_string();
    }

    if source.len() <= RISK_SOURCE_MAX_CHARS
        && source
            .chars()
            .all(|ch| !ch.is_whitespace() && !ch.is_uppercase())
    {
        return source.to_string();
    }

    let mut out = String::with_capacity(source.len().min(RISK_SOURCE_MAX_CHARS));
    let mut emitted = 0usize;
    let mut pending_space = false;

    for ch in source.chars() {
        if ch.is_whitespace() {
            if emitted > 0 {
                pending_space = true;
            }
            continue;
        }

        if pending_space {
            if emitted >= RISK_SOURCE_MAX_CHARS {
                break;
            }
            out.push(' ');
            emitted += 1;
            pending_space = false;
        }

        for lower in ch.to_lowercase() {
            if emitted >= RISK_SOURCE_MAX_CHARS {
                break;
            }
            out.push(lower);
            emitted += 1;
        }
    }

    if out.is_empty() {
        return "anon".to_string();
    }

    out
}
