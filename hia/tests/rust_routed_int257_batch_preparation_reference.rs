use std::io::{self, Read, Write};
use trnm_crypto_primitives::pon_routed_int257_grouped::{
    Context, Model, PreparedModel, Request, DIM,
};

fn field(bytes: &[u8], at: usize) -> [u8; 32] {
    bytes[at..at + 32].try_into().unwrap()
}

fn dispatch(raw: &[u8]) -> (u8, Vec<u8>) {
    // Independent actual model identity; the native framing's 32 bytes are
    // checked against this original accessor, never supplied to Rust as proof.
    let mut base = [[0; DIM]; 3];
    base[0][1] = 7;
    let model = [197, 198]
        .into_iter()
        .map(|version| {
            PreparedModel::new(Model {
                version: [version; 32],
                base,
                router: [[0; DIM]; 3],
                deltas: [[[0; DIM]; 3]; 3],
            })
            .unwrap()
        })
        .find(|model| field(raw, 12) == model.commitment())
        .expect("caller fixture must select one of the two original model commitments");
    let n = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
    let now = u64::from_le_bytes(raw[4..12].try_into().unwrap());
    assert_eq!(raw.len(), 172 + 1108 * n);
    let context = Context {
        chain: field(raw, 44),
        parent: field(raw, 76),
        challenge: field(raw, 108),
        batch_id: field(raw, 140),
    };
    let requests = raw[172..]
        .chunks_exact(1108)
        .map(|r| Request {
            id: field(r, 0),
            scope: field(r, 32),
            arrival_ns: u64::from_le_bytes(r[64..72].try_into().unwrap()),
            deadline_ns: u64::from_le_bytes(r[72..80].try_into().unwrap()),
            x: std::array::from_fn(|i| {
                let start = 80 + i * 4;
                i32::from_le_bytes(r[start..start + 4].try_into().unwrap())
            }),
        })
        .collect::<Vec<_>>();
    match model.prepare_batch(&context, &requests, now) {
        Ok((batch, _)) => {
            // No getter on PreparedBatch. Read only this field of the
            // nondispatching original arithmetic observation.
            let (observed, _) = model.observe_direct(&batch).unwrap();
            (0, observed.input_commitment.to_vec())
        }
        Err("BATCH_SIZE") => (4, Vec::new()),
        Err("REQUEST_DEADLINE") => (5, Vec::new()),
        Err("DUPLICATE_REQUEST") => (6, Vec::new()),
        Err("INPUT_RANGE_BIAS") => (7, Vec::new()),
        Err(s) => panic!("unexpected original preparation status: {s}"),
    }
}

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();
    let mut input = input.as_slice();
    let mut output = io::stdout().lock();
    while !input.is_empty() {
        let n = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
        assert!(n <= 172 + 1108 * 65);
        let (s, data) = dispatch(&input[4..4 + n]);
        input = &input[4 + n..];
        output.write_all(&[s]).unwrap();
        output.write_all(&data).unwrap();
    }
}
