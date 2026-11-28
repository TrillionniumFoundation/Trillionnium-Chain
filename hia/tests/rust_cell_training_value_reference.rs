use std::io::{self, Write};
use trnm_pon_node::cell_native_v1::{canonical, TrainableMask, Training, DIM};

fn mask(f: impl Fn(usize, usize, usize) -> bool) -> TrainableMask {
    let matrix = |m| (0..3).map(|r| (0..DIM).map(|c| f(m,r,c)).collect()).collect();
    TrainableMask { base: matrix(0), deltas: (1..4).map(matrix).collect() }
}

fn row(out: &mut impl Write, mask: &TrainableMask, cfg: Option<[u64;5]>) {
    let mut frame = if cfg.is_some() { b"CTr1\0\0\0\0".to_vec() } else { b"CTm1\0\0\0\0".to_vec() };
    let wire = if let Some([clip_abs, learning_rate_den, learning_rate_num, momentum_den, momentum_num]) = cfg {
        for x in cfg.unwrap() { frame.extend_from_slice(&x.to_le_bytes()); }
        canonical(&Training { learning_rate_num, learning_rate_den, momentum_num, momentum_den,
                              clip_abs, trainable_mask: mask.clone() }).unwrap()
    } else { canonical(mask).unwrap() };
    for m in std::iter::once(&mask.base).chain(&mask.deltas) {
        assert_eq!(m.len(), 3);
        for r in m {
            assert_eq!(r.len(), DIM);
            frame.extend(r.iter().map(|v| u8::from(*v)));
        }
    }
    out.write_all(&(frame.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&(wire.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&frame).unwrap();
    out.write_all(&wire).unwrap();
}

fn main() {
    let full = mask(|_,_,_| true);
    let empty = mask(|_,_,_| false);
    let mixed = mask(|m,r,c| (m+2*r+3*c)%11 < 5);
    let mut out = io::stdout().lock();
    row(&mut out, &full, None);
    row(&mut out, &empty, None);
    row(&mut out, &mixed, None);
    row(&mut out, &mixed, Some([9,100,3,10,7]));
    row(&mut out, &empty, Some([u64::MAX;5]));
    row(&mut out, &full, Some([0;5]));
    let mut swapped = mixed.clone();
    swapped.deltas.swap(0,2);
    row(&mut out, &swapped, Some([9,100,3,10,7]));
}
