use serde::{Deserialize, Serialize};
use std::{hint::black_box, time::Instant};

const MAX_PACKET: usize = 1_048_576;
const PREFIX: &[u8] = br#"{"op":"submit","packet":""#;
const SUFFIX: &[u8] = br#""}"#;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Submit { packet: String },
    Head,
    History { tip: String, after: String },
    PoolSubmitBundle { pool_context: String, transactions: Vec<String> },
    PoolStatus,
    GrowthSubmitV1 { packet: String },
    GrowthPacketStatusV1 { packet: String },
    GrowthHeadV1,
}
fn lower_hex(text: &[u8]) -> bool {
    text.iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
fn vector_lower_hex(text: &[u8]) -> bool {
    text.chunks(64).all(|chunk| {
        chunk.iter().fold(true, |valid, &byte| {
            valid & ((byte.wrapping_sub(b'0') < 10) | (byte.wrapping_sub(b'a') < 6))
        })
    })
}
fn original(request: &Request) -> Vec<u8> {
    let bytes = serde_json::to_vec(request).unwrap();
    assert!(!bytes.is_empty() && bytes.len() <= 2 * MAX_PACKET + 64);
    let text = bytes.strip_prefix(PREFIX).unwrap().strip_suffix(SUFFIX).unwrap();
    assert!(text.len() <= 2 * MAX_PACKET && text.len().is_multiple_of(2) && lower_hex(text));
    let owned = Request::Submit { packet: std::str::from_utf8(text).unwrap().to_owned() };
    drop(owned);
    bytes
}
fn candidate(request: &Request, vector: bool) -> Vec<u8> {
    if let Request::Submit { packet } = request {
        let text = packet.as_bytes();
        if text.len() <= 2 * MAX_PACKET && text.len().is_multiple_of(2)
            && if vector { vector_lower_hex(text) } else { lower_hex(text) } {
            let mut bytes = Vec::with_capacity(PREFIX.len() + text.len() + SUFFIX.len());
            bytes.extend_from_slice(PREFIX);
            bytes.extend_from_slice(text);
            bytes.extend_from_slice(SUFFIX);
            return bytes;
        }
    }
    serde_json::to_vec(request).unwrap()
}
fn cpu() -> u128 {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::ThreadCPUTime);
    t.tv_sec as u128 * 1_000_000_000 + t.tv_nsec as u128
}
fn main() {
    let input_source="/workspace/scratch/b333277443cf/ci-originals/chain-c3-head-protocol/from-zero-native/confirmation/report.json";
    let report:serde_json::Value=serde_json::from_slice(&std::fs::read(input_source).unwrap()).unwrap();
    let requests:Vec<_>=report["from_zero_construction"].as_array().unwrap().iter().map(|row|Request::Submit{packet:row["packet"].as_str().unwrap().to_owned()}).collect();
    assert_eq!(requests.len(),16);
    let request=&requests[0];
    let exact = original(request);
    for request in &requests {
        assert_eq!(original(request), candidate(request, false));
        assert_eq!(original(request), candidate(request, true));
    }
    for byte in 0..=u8::MAX {
        assert_eq!(lower_hex(&[byte]), vector_lower_hex(&[byte]));
    }
    let len = exact.len();
    for _ in 0..100 { black_box(original(&request)); black_box(candidate(&request, false)); black_box(candidate(&request, true)); }
    let mut samples = Vec::new();
    let iterations = 1024;
    for round in 0..12 {
        let order = if round % 2 == 0 { [0, 1, 2] } else { [2, 1, 0] };
        for variant in order {
            let start_cpu = cpu();
            let start_wall = Instant::now();
            for index in 0..iterations {
                let request=&requests[index%requests.len()];
                black_box(match variant { 0 => original(black_box(request)), 1 => candidate(black_box(request),false), _ => candidate(black_box(request),true) });
            }
            samples.push(serde_json::json!({"round":round,"variant":match variant {0 => "original_serde_owned_validation",1 => "typed_canonical",_ => "typed_canonical_vector_hex"},"iterations":iterations,"cpu_ns":cpu()-start_cpu,"wall_ns":start_wall.elapsed().as_nanos()}));
        }
    }
    let mut hex_samples = Vec::new();
    for (label, invalid_at) in [("valid",None),("invalid_first",Some(0)),("invalid_middle",Some(MAX_PACKET)),("invalid_last",Some(2*MAX_PACKET-1))] {
        let mut bytes = vec![b'a';2*MAX_PACKET];
        if let Some(index)=invalid_at { bytes[index]=b'g'; }
        assert_eq!(lower_hex(&bytes),vector_lower_hex(&bytes));
        let iterations=if invalid_at==Some(0) {200_000} else {64};
        for round in 0..6 {
            let order=if round%2==0 {[false,true]}else{[true,false]};
            for vector in order {
                let start=cpu();
                for _ in 0..iterations { black_box(if vector {vector_lower_hex(black_box(&bytes))}else{lower_hex(black_box(&bytes))}); }
                hex_samples.push(serde_json::json!({"case":label,"variant":if vector {"chunked"}else{"original"},"round":round,"iterations":iterations,"input_bytes":bytes.len(),"cpu_ns":cpu()-start,"result":invalid_at.is_none()}));
            }
        }
    }
    println!("{}", serde_json::json!({"schema":"client-canonical-encoding-experiment-v1","scope":"pure client construction CPU comparison cycling all sixteen actual original head false payloads; profile identified by exact cargo command receipt; no network or Host callback changed; not confirmation qualification; faster clients may complete more false calls within the unchanged window","debug_assertions":cfg!(debug_assertions),"input_source":input_source,"input_payloads":requests.len(),"request_bytes":len,"exact_serde_byte_equality":true,"samples":samples,"hex_samples":hex_samples}));
}
