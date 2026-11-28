//! Exact typed adapter to the legacy research metadata constructor; no Node.
use std::io::{self, BufRead};
use trnm_pon_node::research_work_schedule::{NativeWire, Policy, Profile, ProfileInputs};

fn fixed<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    data[offset..offset + N].try_into().unwrap()
}

fn main() -> io::Result<()> {
    for line in io::stdin().lock().lines() {
        let line = line?;
        assert!(matches!(line.len(), 404 | 436));
        let data: Vec<u8> = line
            .as_bytes()
            .chunks_exact(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(&data[..8], b"NWSP0001");
        let wire = match data[200] {
            1 => NativeWire::Pnh1,
            2 => NativeWire::Pgh2,
            _ => panic!("not a typed wire fixture"),
        };
        let policy = match (data[201], data.len()) {
            (0, 202) => Policy::FixedTarget,
            (1, 218) => Policy::AnchoredAsert {
                activation_height: u64::from_le_bytes(fixed(&data, 202)),
                half_life_seconds: u64::from_le_bytes(fixed(&data, 210)),
            },
            _ => panic!("not a typed policy fixture"),
        };
        let inputs = ProfileInputs {
            network: fixed(&data, 8),
            parameters: fixed(&data, 40),
            genesis: fixed(&data, 72),
            initial_target: fixed(&data, 104),
            pow_limit: fixed(&data, 136),
            genesis_time: u64::from_le_bytes(fixed(&data, 168)),
            legacy_interval: u64::from_le_bytes(fixed(&data, 176)),
            spacing_seconds: u64::from_le_bytes(fixed(&data, 184)),
            future_skew_seconds: u64::from_le_bytes(fixed(&data, 192)),
            wire,
            policy,
        };
        match Profile::new(inputs) {
            Ok(profile) => {
                print!("OK ");
                for byte in profile.id() {
                    print!("{byte:02x}");
                }
                println!();
            }
            Err(error) => println!("ERR {error}"),
        }
    }
    Ok(())
}
