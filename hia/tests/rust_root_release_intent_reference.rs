use std::io::{self, Write};
use trnm_release_bundle::root_recovery_v3::{ReleaseIntentV3 as V, ReleaseUseV3 as Kind, RootErrorV3 as E};

fn example(w: &mut impl Write, wire: &[u8], bundle: &[u8], contract: &[u8], artifact: &[u8]) {
    let status: u32 = match V::decode(wire) {
        Ok(v) => {
            assert_eq!(v.encode().unwrap(), wire);
            if v.matches_bytes(bundle, contract, artifact) { 0 } else { 4 }
        }
        Err(E::Codec) => 1,
        Err(E::Capacity) => 2,
        Err(E::Intent) => 3,
        Err(e) => panic!("{e:?}"),
    };
    w.write_all(&status.to_le_bytes()).unwrap();
    let n = 24 + wire.len() + bundle.len() + contract.len() + artifact.len();
    w.write_all(&(n as u32).to_le_bytes()).unwrap();
    for part in [wire, bundle, contract] { w.write_all(&(part.len() as u64).to_le_bytes()).unwrap(); }
    for part in [wire, bundle, contract, artifact] { w.write_all(part).unwrap(); }
}
fn main() {
    let b = b"fixture release";
    let c = b"fixture contract";
    let a = b"fixture artifact";
    let mut w = io::stdout().lock();
    let made = V::from_bytes(Kind::Install, b, c, a, [12; 32]).unwrap();
    let good = made.encode().unwrap();
    example(&mut w, &good, b, c, a);
    // Same lengths but different first/last byte; no loss of field or hash identity.
    example(&mut w, &good, b"Fixture release", c, a);
    example(&mut w, &good, b, b"fixture contracT", a);
    example(&mut w, &good, b, c, b"fixture artifacT");
    example(&mut w, &good, b, c, b"fixture art");
    for (kind, n) in [(Kind::Launch, 255), (Kind::FinalUse, 256), (Kind::Install, 65536)] {
        let bfull = vec![0xBA; 8192];
        let cfull = vec![0xCE; 8192];
        let artifact: Vec<_> = (0..n).map(|i| (i % 251) as u8).collect();
        let valid = V::from_bytes(kind, &bfull, &cfull, &artifact, [9;32]).unwrap();
        example(&mut w, &valid.encode().unwrap(), &bfull, &cfull, &artifact);
    }
    let mut max = made.clone();
    max.artifact_size = 64 * 1024 * 1024;
    example(&mut w, &max.encode().unwrap(), b, c, a);
    let mut bad = good.clone();
    bad[35] = 9; // unknown typed kind
    example(&mut w, &bad, b, c, a);
    let mut bad = good.clone();
    bad[36..40].copy_from_slice(&8193u32.to_be_bytes());
    example(&mut w, &bad, b, c, a);
    example(&mut w, &good[..good.len()-1], b, c, a);
    let mut bad = good.clone();
    bad.extend([0]);
    example(&mut w, &bad, b, c, a);
    let size_at = good.len()-40;
    let mut bad = good.clone();
    bad[size_at..size_at+8].copy_from_slice(&(64*1024*1024u64 + 1).to_be_bytes());
    example(&mut w, &bad, b, c, a);
    let mut bad = good.clone();
    let attempt_at = bad.len()-32;
    bad[attempt_at..].fill(0);
    example(&mut w, &bad, b, c, a);
    bad.extend([0]); // trailing framing precedes invalid typed value
    example(&mut w, &bad, b, c, a);
    let mut bad = good.clone();
    bad[size_at-64..size_at].fill(0);
    example(&mut w, &bad, b, c, a);
}
