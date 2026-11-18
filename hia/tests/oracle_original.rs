//! Transport-only adapter for the complete unchanged trnm-oracle crate.
//! All validation, hashing, accounting and bridge decisions call actual APIs.
//! Two separate linked original libraries preserve checked and release arithmetic.

use std::io::{self, BufRead, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use trnm_oracle::{
    validate_snapshot_observed, OracleError, OraclePolicy, OracleSnapshot, OracleSourceId,
    OracleValidationMetrics, OracleValidationObservation, OracleValidationReport,
};

const MALFORMED: u32 = 100;
const ORIGINAL_PANIC: u32 = 250;
const MAX_FRAME_BYTES: usize = 1024 * 1024;
const PROFILE: u64 = if cfg!(oracle_checked) { 1 } else { 0 };
// Bind the JSON transport to the actual serde_json dependency feature graph.
const JSON_PROFILE: u64 = PROFILE + if cfg!(oracle_json_arbitrary_precision) { 2 } else { 0 };
type Parsed<T> = Result<T, u32>;

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn take(&mut self, count: usize) -> Parsed<&'a [u8]> {
        let end = self.at.checked_add(count).ok_or(MALFORMED)?;
        let value = self.bytes.get(self.at..end).ok_or(MALFORMED)?;
        self.at = end;
        Ok(value)
    }
    fn word(&mut self) -> Parsed<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| MALFORMED)?))
    }
    fn u32(&mut self) -> Parsed<u32> {
        u32::try_from(self.word()?).map_err(|_| MALFORMED)
    }
    fn size(&mut self) -> Parsed<usize> {
        usize::try_from(self.word()?).map_err(|_| MALFORMED)
    }
    fn boolean(&mut self) -> Parsed<bool> {
        match self.word()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(MALFORMED),
        }
    }
    fn i128(&mut self) -> Parsed<i128> {
        Ok(i128::from_le_bytes(self.take(16)?.try_into().map_err(|_| MALFORMED)?))
    }
    fn u128(&mut self) -> Parsed<u128> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().map_err(|_| MALFORMED)?))
    }
    fn text_bytes(&mut self, size: usize) -> Parsed<String> {
        String::from_utf8(self.take(size)?.to_vec()).map_err(|_| MALFORMED)
    }
    fn string(&mut self) -> Parsed<String> {
        let size = self.size()?;
        self.text_bytes(size)
    }
    fn finish(&self) -> Parsed<()> {
        if self.at == self.bytes.len() { Ok(()) } else { Err(MALFORMED) }
    }
    fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }
}

fn source_from_deserialize(raw: String) -> Parsed<OracleSourceId> {
    // The original public Deserialize implementation accepts a raw String.
    // Calling parse here would incorrectly erase part of that public domain.
    // serde_json's real newtype visitor is required. A bare StringDeserializer
    // does not implement the derived newtype boundary, even for an empty String.
    let encoded = serde_json::to_string(&raw).map_err(|_| MALFORMED)?;
    serde_json::from_str::<OracleSourceId>(&encoded).map_err(|_| MALFORMED)
}

fn snapshot(r: &mut Reader<'_>) -> Parsed<OracleSnapshot> {
    let value = r.i128()?;
    let sample_count = r.u32()?;
    let median_present = r.boolean()?;
    let median_value = r.i128()?;
    if !median_present && median_value != 0 { return Err(MALFORMED); }
    let mad_present = r.boolean()?;
    let mad_value = r.u128()?;
    if !mad_present && mad_value != 0 { return Err(MALFORMED); }
    let window_start_ms = r.word()?;
    let window_end_ms = r.word()?;
    let snapshot_ts_ms = r.word()?;
    let feed_size = r.size()?;
    let hash_size = r.size()?;
    let count = r.size()?;
    let feed_id = r.text_bytes(feed_size)?;
    let snapshot_hash = r.text_bytes(hash_size)?;
    if count > r.remaining() / 8 { return Err(MALFORMED); }
    let mut sources = Vec::with_capacity(count);
    for _ in 0..count {
        sources.push(source_from_deserialize(r.string()?)?);
    }
    Ok(OracleSnapshot {
        feed_id, value, sources, sample_count,
        median: median_present.then_some(median_value),
        mad: mad_present.then_some(mad_value),
        window_start_ms, window_end_ms, snapshot_ts_ms, snapshot_hash,
    })
}

fn policy(r: &mut Reader<'_>) -> Parsed<OraclePolicy> {
    Ok(OraclePolicy {
        min_sources: r.u32()?, max_staleness_ms: r.word()?,
        max_deviation_bps: r.u32()?, max_update_rate_per_window: r.u32()?,
    })
}

fn observation(r: &mut Reader<'_>) -> Parsed<OracleValidationObservation> {
    Ok(OracleValidationObservation {
        stale_reject_total: r.u32()?, quorum_reject_total: r.u32()?,
        drift_reject_total: r.u32()?, accepted_total: r.u32()?,
    })
}

fn metrics(r: &mut Reader<'_>) -> Parsed<OracleValidationMetrics> {
    Ok(OracleValidationMetrics {
        oracle_stale_reject_total: r.u32()?, oracle_quorum_reject_total: r.u32()?,
        oracle_drift_reject_total: r.u32()?, oracle_source_cardinality: r.u32()?,
        accepted_total: r.u32()?, sample_count: r.u32()?,
    })
}

fn report(r: &mut Reader<'_>) -> Parsed<OracleValidationReport> {
    let ok = r.boolean()?;
    let now_ts_ms = r.word()?;
    let observation = observation(r)?;
    let metrics = metrics(r)?;
    let error_present = r.boolean()?;
    let error_value = r.string()?;
    if !error_present && !error_value.is_empty() { return Err(MALFORMED); }
    Ok(OracleValidationReport {
        ok, now_ts_ms, observation, metrics,
        error: error_present.then_some(error_value),
    })
}

enum Command {
    ParseSource(String),
    NewSnapshot(OracleSnapshot),
    HashSnapshot(OracleSnapshot),
    ValidateHash(OracleSnapshot),
    ValidatePolicy(OraclePolicy),
    ValidateSnapshot(OraclePolicy, u64, OracleSnapshot),
    ObserveSnapshot(OraclePolicy, u64, OracleSnapshot),
    ObservationMethod(u64, u32, OracleValidationObservation),
    MetricsMethod(u64, OracleValidationMetrics),
    ReportMethod(u64, OracleValidationReport),
    SourceText(OracleSourceId),
    JsonDecode(u64, Vec<u8>),
    JsonEncode(JsonValue),
}

enum JsonValue {
    Source(OracleSourceId),
    Snapshot(OracleSnapshot),
    Policy(OraclePolicy),
    Observation(OracleValidationObservation),
    Metrics(OracleValidationMetrics),
    Report(OracleValidationReport),
}

fn parse_json(bytes: &[u8]) -> Parsed<Command> {
    let mut r = Reader::new(bytes);
    if r.take(8)? != b"ORJS0001" { return Err(MALFORMED); }
    let kind = r.word()?;
    let direction = r.word()?;
    if kind > 5 || direction > 1 || r.word()? != JSON_PROFILE { return Err(MALFORMED); }
    let command = if direction == 0 {
        let size = r.size()?;
        // Deliberately retain arbitrary raw bytes here. The original serde_json
        // decoder owns UTF-8, JSON grammar, number and derived-type rejection.
        Command::JsonDecode(kind, r.take(size)?.to_vec())
    } else {
        Command::JsonEncode(match kind {
            0 => JsonValue::Source(source_from_deserialize(r.string()?)?),
            1 => JsonValue::Snapshot(snapshot(&mut r)?),
            2 => JsonValue::Policy(policy(&mut r)?),
            3 => JsonValue::Observation(observation(&mut r)?),
            4 => JsonValue::Metrics(metrics(&mut r)?),
            5 => JsonValue::Report(report(&mut r)?),
            _ => unreachable!(),
        })
    };
    r.finish()?;
    Ok(command)
}

fn parse(bytes: &[u8]) -> Parsed<Command> {
    if bytes.len() > MAX_FRAME_BYTES { return Err(MALFORMED); }
    if bytes.starts_with(b"ORJS0001") { return parse_json(bytes); }
    let mut r = Reader::new(bytes);
    if r.take(8)? != b"ORAC0001" { return Err(MALFORMED); }
    let op = r.word()?;
    if r.word()? != PROFILE { return Err(MALFORMED); }
    let value = match op {
        0 => Command::ParseSource(r.string()?),
        1 => {
            let item = snapshot(&mut r)?;
            if !item.snapshot_hash.is_empty() { return Err(MALFORMED); }
            Command::NewSnapshot(item)
        }
        2 => Command::HashSnapshot(snapshot(&mut r)?),
        3 => Command::ValidateHash(snapshot(&mut r)?),
        4 => Command::ValidatePolicy(policy(&mut r)?),
        5 | 6 => {
            let policy = policy(&mut r)?;
            let now = r.word()?;
            let item = snapshot(&mut r)?;
            if op == 5 { Command::ValidateSnapshot(policy, now, item) }
            else { Command::ObserveSnapshot(policy, now, item) }
        }
        7 => {
            let method = r.word()?;
            if method > 2 { return Err(MALFORMED); }
            Command::ObservationMethod(method, r.u32()?, observation(&mut r)?)
        }
        8 => {
            let method = r.word()?;
            if method > 2 { return Err(MALFORMED); }
            Command::MetricsMethod(method, metrics(&mut r)?)
        }
        9 => {
            let method = r.word()?;
            if method > 7 { return Err(MALFORMED); }
            Command::ReportMethod(method, report(&mut r)?)
        }
        10 => Command::SourceText(source_from_deserialize(r.string()?)?),
        _ => return Err(MALFORMED),
    };
    r.finish()?;
    Ok(value)
}

fn word(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn string(out: &mut Vec<u8>, value: &str) {
    word(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn snapshot_bytes(item: &OracleSnapshot) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&item.value.to_le_bytes());
    word(&mut out, u64::from(item.sample_count));
    word(&mut out, u64::from(item.median.is_some()));
    out.extend_from_slice(&item.median.unwrap_or(0).to_le_bytes());
    word(&mut out, u64::from(item.mad.is_some()));
    out.extend_from_slice(&item.mad.unwrap_or(0).to_le_bytes());
    for value in [item.window_start_ms, item.window_end_ms, item.snapshot_ts_ms,
                  item.feed_id.len() as u64, item.snapshot_hash.len() as u64, item.sources.len() as u64] {
        word(&mut out, value);
    }
    out.extend_from_slice(item.feed_id.as_bytes());
    out.extend_from_slice(item.snapshot_hash.as_bytes());
    for source in &item.sources { string(&mut out, source.as_str()); }
    out
}

fn observation_bytes(out: &mut Vec<u8>, value: &OracleValidationObservation) {
    for value in [value.stale_reject_total, value.quorum_reject_total,
                  value.drift_reject_total, value.accepted_total] {
        word(out, u64::from(value));
    }
}

fn metrics_bytes(out: &mut Vec<u8>, value: &OracleValidationMetrics) {
    for value in [value.oracle_stale_reject_total, value.oracle_quorum_reject_total,
                  value.oracle_drift_reject_total, value.oracle_source_cardinality,
                  value.accepted_total, value.sample_count] {
        word(out, u64::from(value));
    }
}

fn report_bytes(value: &OracleValidationReport) -> Vec<u8> {
    let mut out = Vec::new();
    word(&mut out, u64::from(value.ok));
    word(&mut out, value.now_ts_ms);
    observation_bytes(&mut out, &value.observation);
    metrics_bytes(&mut out, &value.metrics);
    word(&mut out, u64::from(value.error.is_some()));
    string(&mut out, value.error.as_deref().unwrap_or(""));
    out
}

fn policy_bytes(value: &OraclePolicy) -> Vec<u8> {
    let mut out = Vec::new();
    for value in [u64::from(value.min_sources), value.max_staleness_ms,
                  u64::from(value.max_deviation_bps), u64::from(value.max_update_rate_per_window)] {
        word(&mut out, value);
    }
    out
}

fn response(code: u64, payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    word(&mut out, code);
    word(&mut out, payload.len() as u64);
    out.extend_from_slice(&payload);
    out
}

fn serde_response<T>(result: Result<T, serde_json::Error>, encode: impl FnOnce(T) -> Vec<u8>) -> Vec<u8> {
    match result {
        Ok(value) => response(0, encode(value)),
        Err(error) => {
            // This profile compares the real serde acceptance boundary and
            // values. Its original diagnostic is evidence, not a native error
            // string contract or a manufactured OracleError variant.
            eprintln!("{error}");
            response(1, Vec::new())
        }
    }
}

fn json_decode(kind: u64, raw: &[u8]) -> Vec<u8> {
    match kind {
        0 => serde_response(serde_json::from_slice::<OracleSourceId>(raw),
                            |value| text_bytes(value.as_str())),
        1 => serde_response(serde_json::from_slice::<OracleSnapshot>(raw),
                            |value| snapshot_bytes(&value)),
        2 => serde_response(serde_json::from_slice::<OraclePolicy>(raw),
                            |value| policy_bytes(&value)),
        3 => serde_response(serde_json::from_slice::<OracleValidationObservation>(raw), |value| {
            let mut out = Vec::new(); observation_bytes(&mut out, &value); out
        }),
        4 => serde_response(serde_json::from_slice::<OracleValidationMetrics>(raw), |value| {
            let mut out = Vec::new(); metrics_bytes(&mut out, &value); out
        }),
        5 => serde_response(serde_json::from_slice::<OracleValidationReport>(raw),
                            |value| report_bytes(&value)),
        _ => unreachable!(),
    }
}

fn json_encode(value: JsonValue) -> Vec<u8> {
    let encoded = match value {
        JsonValue::Source(value) => serde_json::to_vec(&value),
        JsonValue::Snapshot(value) => serde_json::to_vec(&value),
        JsonValue::Policy(value) => serde_json::to_vec(&value),
        JsonValue::Observation(value) => serde_json::to_vec(&value),
        JsonValue::Metrics(value) => serde_json::to_vec(&value),
        JsonValue::Report(value) => serde_json::to_vec(&value),
    };
    serde_response(encoded, |bytes| bytes)
}

fn error_response(error: OracleError) -> Vec<u8> {
    use OracleError::*;
    let mut values = [0u64; 3];
    let mut texts = ["", ""];
    let code = match &error {
        EmptySourceId => 1,
        NonCanonicalSourceId { raw, canonical } => { texts = [raw, canonical]; 2 },
        EmptyFeedId => 3,
        NonCanonicalFeedId { raw, canonical } => { texts = [raw, canonical]; 4 },
        InvalidWindow { start_ms, end_ms } => { values = [*start_ms, *end_ms, 0]; 5 },
        InvalidWindowTimestamp { window_end_ms, snapshot_ts_ms } => { values = [*window_end_ms, *snapshot_ts_ms, 0]; 6 },
        DuplicateSources => 7,
        NonCanonicalSourceOrdering { previous, current } => { texts = [previous, current]; 8 },
        EmptySnapshotHash => 9,
        NonCanonicalSnapshotHash { raw, canonical } => { texts = [raw, canonical]; 10 },
        SnapshotHashMismatch { expected, actual } => { texts = [expected, actual]; 11 },
        InvalidSnapshotHashFormat { raw } => { texts[0] = raw; 12 },
        InvalidPolicy(reason) => {
            values[0] = match *reason {
                "min_sources must be > 0" => 1,
                "max_staleness_ms must be > 0" => 2,
                "max_deviation_bps must be <= 10000" => 3,
                "max_update_rate_per_window must be > 0" => 4,
                "min_sources must be <= max_update_rate_per_window" => 5,
                other => panic!("unrecognized original policy reason: {other}"),
            };
            texts[0] = reason; 13
        }
        InvalidSampleCount => 14,
        FutureSnapshot { snapshot_ts_ms, now_ts_ms } => { values = [*snapshot_ts_ms, *now_ts_ms, 0]; 15 },
        StaleSnapshot { snapshot_ts_ms, now_ts_ms, max_staleness_ms } => {
            values = [*snapshot_ts_ms, *now_ts_ms, *max_staleness_ms]; 16
        }
        InsufficientSources { min_sources, actual_sources, sample_count } => {
            values = [u64::from(*min_sources), u64::from(*actual_sources), u64::from(*sample_count)]; 17
        }
        DeviationExceeded { deviation_bps, max_deviation_bps } => {
            values = [u64::from(*deviation_bps), u64::from(*max_deviation_bps), 0]; 18
        }
        InconsistentSampleCount { actual_sources, sample_count } => {
            values = [u64::from(*actual_sources), u64::from(*sample_count), 0]; 19
        }
        UpdateRateExceeded { sample_count, max_update_rate_per_window } => {
            values = [u64::from(*sample_count), u64::from(*max_update_rate_per_window), 0]; 20
        }
    };
    let mut payload = Vec::new();
    for value in values { word(&mut payload, value); }
    for text in texts { string(&mut payload, text); }
    string(&mut payload, &error.to_string());
    response(code, payload)
}

fn business<T>(result: Result<T, OracleError>, serialize: impl FnOnce(T) -> Vec<u8>) -> Vec<u8> {
    match result {
        Ok(value) => response(0, serialize(value)),
        Err(error) => error_response(error),
    }
}

fn text_bytes(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    string(&mut out, value);
    out
}

fn numeric(value: u64) -> Vec<u8> {
    response(0, value.to_le_bytes().to_vec())
}

fn original_call<T>(call: impl FnOnce() -> T) -> Parsed<T> {
    // Keep the original panic hook: exact arithmetic panic details remain on
    // stderr. Only an actual invoked original API is inside this boundary.
    catch_unwind(AssertUnwindSafe(call)).map_err(|_| ORIGINAL_PANIC)
}

fn execute(command: Command) -> Parsed<Vec<u8>> {
    Ok(match command {
        Command::ParseSource(raw) => business(original_call(|| OracleSourceId::parse(raw))?,
                                               |value| text_bytes(value.as_str())),
        Command::NewSnapshot(item) => {
            let result = original_call(|| OracleSnapshot::new(item.feed_id, item.value, item.sources,
                item.sample_count, item.median, item.mad, item.window_start_ms,
                item.window_end_ms, item.snapshot_ts_ms))?;
            business(result, |value| snapshot_bytes(&value))
        }
        Command::HashSnapshot(item) => response(0, text_bytes(&original_call(|| item.compute_hash())?)),
        Command::ValidateHash(item) => business(original_call(|| item.validate_hash())?, |_| Vec::new()),
        Command::ValidatePolicy(policy) => business(original_call(|| policy.validate())?, |_| Vec::new()),
        Command::ValidateSnapshot(policy, now, item) =>
            business(original_call(|| policy.validate_snapshot(&item, now))?, |_| Vec::new()),
        Command::ObserveSnapshot(policy, now, item) =>
            response(0, report_bytes(&original_call(|| validate_snapshot_observed(&policy, &item, now))?)),
        Command::ObservationMethod(method, sample, value) => numeric(match method {
            0 => u64::from(original_call(|| value.classified_reject_total())?),
            1 => u64::from(original_call(|| value.classified_outcome_total())?),
            2 => u64::from(original_call(|| value.classified_outcome_conserves_sample_count(sample))?),
            _ => unreachable!(),
        }),
        Command::MetricsMethod(method, value) => numeric(match method {
            0 => u64::from(original_call(|| value.classified_reject_total())?),
            1 => u64::from(original_call(|| value.classified_outcome_total())?),
            2 => u64::from(original_call(|| value.classified_outcome_conserves_sample_count())?),
            _ => unreachable!(),
        }),
        Command::ReportMethod(method, value) => numeric(match method {
            0 => u64::from(original_call(|| value.classified_reject_total())?),
            1 => u64::from(original_call(|| value.classified_outcome_total())?),
            2 => u64::from(original_call(|| value.classified_outcome_conserves_sample_count())?),
            3 => u64::from(original_call(|| value.observation_classified_reject_total())?),
            4 => u64::from(original_call(|| value.observation_classified_outcome_total())?),
            5 => u64::from(original_call(|| value.observation_classified_outcome_conserves_sample_count())?),
            6 => u64::from(original_call(|| value.observation_matches_metrics())?),
            7 => u64::from(original_call(|| value.bridge_contract_consistent())?),
            _ => unreachable!(),
        }),
        Command::SourceText(value) => response(0, text_bytes(original_call(|| value.as_str())?)),
        Command::JsonDecode(kind, raw) => json_decode(kind, &raw),
        Command::JsonEncode(value) => json_encode(value),
    })
}

fn decode(line: &str) -> Parsed<Vec<u8>> {
    if line.len() > MAX_FRAME_BYTES * 2 || line.len() % 2 != 0 { return Err(MALFORMED); }
    fn digit(value: u8) -> Parsed<u8> {
        match value { b'0'..=b'9' => Ok(value - b'0'), b'a'..=b'f' => Ok(value - b'a' + 10), _ => Err(MALFORMED) }
    }
    line.as_bytes().chunks_exact(2).map(|pair| Ok(digit(pair[0])? * 16 + digit(pair[1])?)).collect()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let expected = if PROFILE == 1 { "checked" } else { "release" };
    if arguments.len() != 1 || arguments[0] != expected {
        eprintln!("this original adapter requires arithmetic profile argument {expected}");
        std::process::exit(2);
    }
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let answer = line.map_err(|_| MALFORMED).and_then(|line| decode(&line))
            .and_then(|bytes| parse(&bytes)).and_then(execute);
        match answer {
            Ok(bytes) => writeln!(out, "0 {}", if bytes.is_empty() { "-".into() } else { hex(&bytes) }).unwrap(),
            Err(status) => writeln!(out, "{status} -").unwrap(),
        }
        out.flush().unwrap();
    }
}
