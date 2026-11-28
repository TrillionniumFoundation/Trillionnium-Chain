//! Independent frozen typed serializer for inert descriptor fixtures.
#[allow(dead_code)]
#[path = "frozen_tile_material.rs"]
mod original;
use std::io::{self, Read, Write};

fn word(p: &mut &[u8]) -> u64 {
    let n = u64::from_le_bytes(p[..8].try_into().unwrap());
    *p = &p[8..];
    n
}

fn string(p: &mut &[u8]) -> String {
    let n = word(p) as usize;
    let s = std::str::from_utf8(&p[..n]).unwrap().to_owned();
    *p = &p[n..];
    s
}

fn main() {
    let mut stream = Vec::new();
    io::stdin().read_to_end(&mut stream).unwrap();
    let mut raw = &stream[..];
    let mut out = io::stdout().lock();
    while !raw.is_empty() {
        let size = word(&mut raw) as usize;
        let mut p = &raw[8..size];
        assert_eq!(&raw[..8], b"TDV1\0\0\0\0");
        let d = original::TileMaterialDescriptorV1 {
            a_nonzero: word(&mut p) as usize,
            a_sha256: string(&mut p),
            activation_clip: word(&mut p) as i64,
            activation_clipped: word(&mut p) as usize,
            activation_scale_power: word(&mut p) as u8,
            activation_sha256: string(&mut p),
            activation_width: word(&mut p),
            b_nonzero: word(&mut p) as usize,
            b_sha256: string(&mut p),
            chain_authority: false,
            checkpoint_bytes: word(&mut p),
            checkpoint_sha256: string(&mut p),
            dense_base_product_multiplications: word(&mut p) as usize,
            full_forward_verified: false,
            genuine_demand_verified: false,
            hardness_accepted: false,
            header_bytes: word(&mut p),
            header_sha256: string(&mut p),
            input: string(&mut p),
            input_coordinates: [word(&mut p),word(&mut p)],
            marginal_contribution_accepted: false,
            matrix_task: string(&mut p),
            model: string(&mut p),
            network: string(&mut p),
            output_coordinates: [word(&mut p),word(&mut p)],
            padded_token_columns: word(&mut p) as usize,
            parameters: string(&mut p),
            policy: string(&mut p),
            real_token_columns: word(&mut p) as usize,
            schema: string(&mut p),
            sparse_b_base_product_multiplications: word(&mut p) as usize,
            tensor: string(&mut p),
            tensor_count: word(&mut p) as usize,
            tensor_dtype: string(&mut p),
            tensor_offsets: [word(&mut p),word(&mut p)],
            tensor_shape: [word(&mut p),word(&mut p)],
            weight_clip: word(&mut p) as i64,
            weight_clipped: word(&mut p) as usize,
            weight_scale_power: word(&mut p) as u8,
        };
        assert!(p.is_empty());
        let result = original::tile_descriptor_value_witness(&d).unwrap();
        out.write_all(&(result.len() as u64).to_le_bytes()).unwrap();
        out.write_all(&result).unwrap();
        raw = &raw[size..];
    }
}
