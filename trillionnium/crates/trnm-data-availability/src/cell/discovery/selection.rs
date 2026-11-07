//! Choose among already verified, current hints within the original finite query.
//! Configured bootstrap sockets and advertised IP prefixes are only diversity
//! heuristics. Neither proves distinct operators, endpoint control or custody.

use super::{
    canonical_endpoint, ip_bytes, require, CellDigestV1, CellResultV1, MAX_DISCOVERED_PROVIDERS,
    MAX_DISCOVERY_BOOTSTRAPS, MAX_DISCOVERY_RECORDS,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    time::Instant,
};

pub(super) struct Candidate {
    pub owner: CellDigestV1,
    pub endpoint: SocketAddr,
    /// Bits denote the actual configured bootstrap positions that returned this
    /// exact current statement. A newer sequence must start a fresh source set.
    pub sources: u8,
    pub expires: Instant,
}

fn prefix(ip: IpAddr) -> [u8; 17] {
    let mut bytes = ip_bytes(ip);
    if ip.is_ipv4() {
        bytes[16] = 0; // /24, matching the directory's existing IPv4 grouping.
    } else {
        bytes[9..].fill(0); // /64, matching the existing IPv6 grouping.
    }
    bytes
}

/// Retain every bounded eligible identity until selection. First balance actual
/// bootstrap contributions; then prefer unused provider prefixes and IPs. A
/// single-source/one-network development deployment still retains its fallback
/// endpoints when no more diverse alternative exists. No additional query,
/// signature, lease extension or durable replay-state eviction is performed.
pub(super) fn select(candidates: Vec<Candidate>) -> CellResultV1<Vec<(SocketAddr, Instant)>> {
    require(
        candidates.len() <= MAX_DISCOVERY_RECORDS,
        "discovery candidate budget",
    )?;
    let source_mask = (1_u8 << MAX_DISCOVERY_BOOTSTRAPS) - 1;
    let mut owners = BTreeSet::new();
    let mut endpoints: BTreeMap<SocketAddr, Candidate> = BTreeMap::new();
    for candidate in candidates {
        require(
            candidate.sources != 0
                && candidate.sources & !source_mask == 0
                && canonical_endpoint(candidate.endpoint)
                && owners.insert(candidate.owner),
            "discovery candidate provenance/identity",
        )?;
        if let Some(prior) = endpoints.get_mut(&candidate.endpoint) {
            // One current, actually observed hint suffices for this endpoint.
            // Preserve the existing latest-eligible-expiry deduplication rule.
            prior.expires = prior.expires.max(candidate.expires);
            prior.sources |= candidate.sources;
            prior.owner = prior.owner.min(candidate.owner);
        } else {
            endpoints.insert(candidate.endpoint, candidate);
        }
    }
    let mut candidates: Vec<_> = endpoints.into_values().collect();
    let mut sources = [0_usize; MAX_DISCOVERY_BOOTSTRAPS];
    let mut prefixes: BTreeMap<[u8; 17], usize> = BTreeMap::new();
    let mut ips: BTreeMap<IpAddr, usize> = BTreeMap::new();
    let mut selected = Vec::new();
    while !candidates.is_empty() && selected.len() < MAX_DISCOVERED_PROVIDERS {
        let (index, source) = candidates
            .iter()
            .enumerate()
            .map(|(index, candidate)| {
                let source = (0..MAX_DISCOVERY_BOOTSTRAPS)
                    .filter(|source| candidate.sources & (1 << source) != 0)
                    .min_by_key(|source| (sources[*source], *source))
                    .expect("validated nonempty source mask");
                let score = (
                    sources[source],
                    prefixes
                        .get(&prefix(candidate.endpoint.ip()))
                        .copied()
                        .unwrap_or(0),
                    ips.get(&candidate.endpoint.ip()).copied().unwrap_or(0),
                    source,
                    candidate.owner,
                    candidate.endpoint,
                );
                (score, index, source)
            })
            .min_by_key(|(score, _, _)| *score)
            .map(|(_, index, source)| (index, source))
            .expect("nonempty bounded candidate set");
        let candidate = candidates.swap_remove(index);
        sources[source] += 1;
        *prefixes.entry(prefix(candidate.endpoint.ip())).or_default() += 1;
        *ips.entry(candidate.endpoint.ip()).or_default() += 1;
        selected.push((candidate.endpoint, candidate.expires));
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn candidate(owner: u8, endpoint: &str, sources: u8, expires: Instant) -> Candidate {
        Candidate {
            owner: [owner; 32],
            endpoint: endpoint.parse().unwrap(),
            sources,
            expires,
        }
    }

    #[test]
    fn bootstrap_flood_cannot_take_all_slots_from_later_observed_sources() {
        let expiry = Instant::now() + Duration::from_secs(10);
        let mut candidates = Vec::new();
        for owner in 1..=8 {
            candidates.push(candidate(
                owner,
                &format!("192.0.2.1:{}", 1000 + owner as u16),
                1,
                expiry,
            ));
        }
        for (owner, sources, endpoint) in [
            (100, 2, "192.0.2.2:1000"),
            (101, 4, "198.51.100.1:1000"),
            (102, 8, "203.0.113.1:1000"),
        ] {
            candidates.push(candidate(owner, endpoint, sources, expiry));
        }
        let selected = select(candidates).unwrap();
        assert_eq!(selected.len(), MAX_DISCOVERED_PROVIDERS);
        for endpoint in ["192.0.2.2:1000", "198.51.100.1:1000", "203.0.113.1:1000"] {
            assert!(selected
                .iter()
                .any(|(peer, _)| *peer == endpoint.parse::<SocketAddr>().unwrap()));
        }
    }

    #[test]
    fn ipv4_and_ipv6_prefixes_and_ips_precede_additional_ports_of_low_keys() {
        let expiry = Instant::now() + Duration::from_secs(10);
        for endpoints in [
            [
                "192.0.2.1:1000",
                "192.0.2.1:1001",
                "192.0.2.2:1000",
                "198.51.100.1:1000",
            ],
            [
                "[2001:db8:1::1]:1000",
                "[2001:db8:1::1]:1001",
                "[2001:db8:1::2]:1000",
                "[2001:db8:2::1]:1000",
            ],
        ] {
            let selected = select(
                endpoints
                    .iter()
                    .enumerate()
                    .map(|(i, endpoint)| candidate(i as u8 + 1, endpoint, 1, expiry))
                    .collect(),
            )
            .unwrap();
            let expected: Vec<SocketAddr> = [0, 3, 2, 1]
                .iter()
                .map(|i| endpoints[*i].parse().unwrap())
                .collect();
            assert_eq!(
                selected.iter().map(|(peer, _)| *peer).collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn dedup_uses_latest_current_expiry_without_losing_actual_source_provenance() {
        let expiry = Instant::now() + Duration::from_secs(10);
        let later = expiry + Duration::from_secs(1);
        let selected = select(vec![
            candidate(1, "192.0.2.1:1000", 1, expiry),
            candidate(2, "192.0.2.1:1000", 2, later),
            candidate(3, "192.0.2.2:1000", 1, expiry),
            candidate(4, "198.51.100.1:1000", 2, expiry),
        ])
        .unwrap();
        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0], ("192.0.2.1:1000".parse().unwrap(), later));
        assert_eq!(selected[1].0, "198.51.100.1:1000".parse().unwrap());
    }

    #[test]
    fn one_network_fallbacks_survive_and_candidate_identity_is_not_peer_chosen() {
        let expiry = Instant::now() + Duration::from_secs(10);
        let make = || {
            (1..=8)
                .map(|owner| {
                    candidate(
                        owner,
                        &format!("127.0.0.1:{}", 1000 + owner as u16),
                        1,
                        expiry,
                    )
                })
                .collect()
        };
        assert_eq!(select(make()).unwrap().len(), 8);
        for sources in [0, 16, 255] {
            assert!(select(vec![candidate(1, "127.0.0.1:1000", sources, expiry)]).is_err());
        }
        assert!(select(vec![
            candidate(1, "127.0.0.1:1000", 1, expiry),
            candidate(1, "127.0.0.1:1001", 2, expiry),
        ])
        .is_err());
        let too_many = (0..=MAX_DISCOVERY_RECORDS)
            .map(|i| candidate(i as u8, &format!("127.0.0.1:{}", 1000 + i), 1, expiry))
            .collect();
        assert!(select(too_many).is_err());
    }
}
