//! Ordinary typed resource-profile metadata only; no resource owner or ledger.
use std::io::{self, BufRead};
use trnm_pon_node::resource_owner_v1::{ResourceProfileV1, ResourcesV1};

fn fixed<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    data[offset..offset + N].try_into().unwrap()
}

fn resources(data: &[u8], pos: usize) -> ResourcesV1 {
    ResourcesV1 {
        cpu_ns: u64::from_le_bytes(fixed(data, pos)),
        io_bytes: u64::from_le_bytes(fixed(data, pos + 8)),
    }
}

fn print_hex(data: &[u8]) {
    for x in data {
        print!("{x:02x}");
    }
}

fn main() -> io::Result<()> {
    for line in io::stdin().lock().lines() {
        let line = line?;
        assert_eq!(line.len(), 256);
        let data: Vec<u8> = line
            .as_bytes()
            .chunks_exact(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(&data[..8], b"NRPF0001");
        let profile = ResourceProfileV1 {
            owner_id: fixed(&data, 8),
            grants: std::array::from_fn(|i| resources(&data, 40 + 16 * i)),
            max_operations: std::array::from_fn(|i| u32::from_le_bytes(fixed(&data, 88 + 4 * i))),
            max_inflight: std::array::from_fn(|i| u32::from_le_bytes(fixed(&data, 100 + 4 * i))),
            overshoot: resources(&data, 112),
        };
        match (profile.validate(), profile.id()) {
            (Ok(()), Ok(value)) => {
                print!("OK ");
                print_hex(&value);
                print!(" ");
                print_hex(&serde_json::to_vec(&profile).unwrap());
                println!();
            }
            (Err(validation), Err(id)) => {
                assert_eq!(validation.to_string(), id.to_string());
                println!("ERR {id}");
            }
            _ => panic!("original validate/id disagreed"),
        }
    }
    Ok(())
}
