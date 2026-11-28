//! Synthetic fixture data, frozen original numeric and detached replay/pin comparison.
#[allow(dead_code)]
#[path = "frozen_tile_material.rs"]
mod original;
use std::io::{self, Read, Write};

fn main() {
    let mut stream = Vec::new();
    io::stdin().read_to_end(&mut stream).unwrap();
    let mut at = 0;
    let mut out = io::stdout().lock();
    while at < stream.len() {
        let mode = u16::from_le_bytes(stream[at..at+2].try_into().unwrap());
        let n = u32::from_le_bytes(stream[at+2..at+6].try_into().unwrap()) as usize;
        at += 6;
        let frame = &stream[at..at+n];
        at += n;
        let foot = n-48;
        let mut actpin: [u8;32] = frame[8..40].try_into().unwrap();
        let mut cppin: [u8;32] = frame[foot..foot+32].try_into().unwrap();
        let cpsz = u64::from_le_bytes(frame[foot+32..foot+40].try_into().unwrap());
        let actn = u64::from_le_bytes(frame[foot+40..].try_into().unwrap()) as usize;
        let activation = &frame[40..40+actn];
        let checkpoint = &frame[40+actn..foot];
        let (mut a,mut b,mut model,mut input) = match original::tile_model_numeric_witness(
            activation, checkpoint, actpin, cppin, cpsz,
        ) {
            Ok((a,b,_,_)) => {
                let (model,input) = original::binding_fixture_pins(&a,&b);
                (a,b,model,input)
            }
            Err(_) => (vec![0;16384],vec![0;16384],[7;32],[8;32]),
        };
        if mode & 1 != 0 { a[0] ^= 1; }
        if mode & 2 != 0 { b[16383] ^= 1; }
        if mode & 4 != 0 { model[17] ^= 1; }
        if mode & 8 != 0 { input[31] ^= 1; }
        let mut network = [1;32];
        let mut parameters = [2;32];
        // Exercise all six independently supplied fields.
        if mode & 16 != 0 { network = [0;32]; }
        if mode & 32 != 0 { parameters = [0;32]; }
        if mode & 64 != 0 { cppin = [0;32]; }
        if mode & 128 != 0 { actpin = [0;32]; }
        if mode & 256 != 0 { model = [0;32]; }
        if mode & 512 != 0 { input = [0;32]; }
        let result = original::tile_context_binding_witness(
            activation,checkpoint,actpin,cppin,cpsz,&a,&b,model,input,network,parameters,
        );
        let (status,payload) = match result {
            Ok((model,input)) => (0u32,[model,input].concat()),
            Err(e) => (match e {
                "ACTIVATION_PIN" => 1,
                "NONFINITE" => 15,
                "CHECKPOINT_PIN" => 34,
                "MATRIX_REPLAY" => 40,
                "MATERIAL_PIN" => 41,
                "CHECKPOINT_LIMIT" => 42,
                "PINNED_CONTEXT" => 43,
                "CHECKPOINT_SIZE" => 21,
                "CHECKPOINT_IO" => 32,
                _ => panic!("unexpected original stage {e}"),
            },vec![]),
        };
        out.write_all(&status.to_le_bytes()).unwrap();
        out.write_all(&(payload.len() as u32).to_le_bytes()).unwrap();
        out.write_all(&payload).unwrap();
        out.write_all(&a).unwrap(); out.write_all(&b).unwrap();
        out.write_all(&model).unwrap(); out.write_all(&input).unwrap();
        out.write_all(&network).unwrap(); out.write_all(&parameters).unwrap();
        out.write_all(&actpin).unwrap(); out.write_all(&cppin).unwrap();
    }
}
