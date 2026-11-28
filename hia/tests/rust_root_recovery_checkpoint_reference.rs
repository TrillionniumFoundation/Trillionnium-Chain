//! Public original RootRecovery V3 value methods; never signs or applies an operation.
use std::io::{self, Write};
use trnm_crypto_primitives::pq_root_v3::{DualFamilyRosterV3, RootCryptoErrorV3, RootPublicKeyV3, RootSuiteV3};
use trnm_release_bundle::root_recovery_v3::{RootErrorV3, RootPolicyV3, RootStateV3};

fn roster(seed:u8) -> DualFamilyRosterV3 {
    let ml = b"\x30\x82\x0a\x32\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x13\x03\x82\x0a\x21\x00";
    let slh = b"\x30\x50\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x18\x03\x41\x00";
    let mut out = Vec::new();
    for (suite, header, extent) in [(RootSuiteV3::MlDsa87,ml.as_slice(),2592),
                                   (RootSuiteV3::SlhDsaSha2_256s,slh.as_slice(),64)] {
        for symbol in 1..=3u8 {
            // Inert public values only: even the original only checks canonical SPKI
            // shape/identity here; it does not expand/validate signing keys.
            let mut spki = header.to_vec();
            spki.extend((0..extent).map(|i| (i as u8).wrapping_mul(symbol+1)^symbol^seed));
            out.push(RootPublicKeyV3 {suite,spki});
        }
    }
    out.reverse(); // Original constructor orders these by exact derived SHA-512 identity.
    DualFamilyRosterV3::from_keys(out).unwrap()
}

fn status(e:RootErrorV3) -> u32 {
    match e {
        RootErrorV3::Codec => 1, RootErrorV3::Policy => 2, RootErrorV3::Capacity => 3,
        RootErrorV3::Crypto(s) => {
            for (i, which) in [RootCryptoErrorV3::RosterEncoding,RootCryptoErrorV3::Suite,
                   RootCryptoErrorV3::PublicKeyEncoding,RootCryptoErrorV3::RosterFamilies,
                   RootCryptoErrorV3::DuplicateKey].into_iter().enumerate() {
                if s==which.to_string() { return 4 + i as u32; }
            }
            panic!("unexpected original crypto value error {s}")
        }
        other => panic!("unexpected original value error {other:?}"),
    }
}

fn row(w:&mut impl Write, scope:[u8;64], now:u64, policy: &[u8]) {
    let result = RootPolicyV3::decode(policy).and_then(|p| {
        let digest = p.commitment()?;
        let state = RootStateV3::bootstrap(scope,p,now)?;
        Ok((digest,state.checkpoint()))
    });
    let (ret,body) = match result {
        Ok((a,b)) => {let mut data=Vec::from(a); data.extend(b); (0,data)}
        Err(err) => (status(err),vec![]),
    };
    w.write_all(&ret.to_le_bytes()).unwrap();
    w.write_all(&((72+policy.len()) as u32).to_le_bytes()).unwrap();
    w.write_all(&scope).unwrap();
    w.write_all(&now.to_be_bytes()).unwrap();
    w.write_all(policy).unwrap();
    w.write_all(&body).unwrap();
}

fn main() {
    let mut w = io::stdout().lock();
    let first = RootPolicyV3{roster:roster(0),expires_at_unix:20}.encode().unwrap();
    let second = RootPolicyV3{roster:roster(67),expires_at_unix:u64::MAX}.encode().unwrap();
    assert_eq!(first.len(),8192);
    row(&mut w,[1;64],0,&first);
    row(&mut w,[2;64],19,&first);
    row(&mut w,[3;64],u64::MAX-1,&second);
    row(&mut w,[0;64],0,&first);
    row(&mut w,[1;64],20,&first);
    row(&mut w,[1;64],21,&first);

    let mut bad=first.clone();
    bad[0]^=1;
    row(&mut w,[1;64],1,&bad); // wrong policy domain
    bad=first.clone();
    bad[36..40].copy_from_slice(&16001u32.to_be_bytes());
    row(&mut w,[1;64],1,&bad); // capacity before body availability
    row(&mut w,[1;64],1,&first[..8191]); // actual original truncated outer blob
    bad=first.clone();
    bad.push(0);                       // trailing policy bytes, after roster acceptance
    row(&mut w,[1;64],1,&bad);
    bad=first.clone();
    bad[40+26]^=1;
    row(&mut w,[1;64],1,&bad); // fixed roster rule mismatch
    bad=first.clone();
    bad[74]=3;
    row(&mut w,[1;64],1,&bad); // suite tag
    bad=first.clone();
    bad[78]^=1;
    row(&mut w,[1;64],1,&bad); // suite length
    bad=first.clone();
    bad[79]^=1;
    row(&mut w,[1;64],1,&bad); // public DER prefix
    bad=first.clone();
    bad[79+2619..79+2619+2614].copy_from_slice(&first[79..79+2614]);
    row(&mut w,[1;64],1,&bad); // distinct hash identities
    bad=first.clone();
    bad[79..79+2614].copy_from_slice(&first[79+2619..79+2619+2614]);
    bad[79+2619..79+2619+2614].copy_from_slice(&first[79..79+2614]);
    row(&mut w,[1;64],1,&bad); // comparator rejects wrong original key ID order
    bad=first.clone();
    bad[28..36].fill(0);
    row(&mut w,[1;64],0,&bad); // original typed zero-expiry check
    bad[74]=3;
    bad.push(0);
    row(&mut w,[1;64],0,&bad); // original roster error before trailing and expiry
    // Ordinary unsigned Unix second values around adjacent byte transitions.
    let r = roster(0);
    for (expires, now) in [(255,254), (256,255), (256,256), (257,256), (65536,65535)] {
        let policy = RootPolicyV3{roster:r.clone(),expires_at_unix:expires}.encode().unwrap();
        row(&mut w,[1;64],now,&policy);
    }
}
