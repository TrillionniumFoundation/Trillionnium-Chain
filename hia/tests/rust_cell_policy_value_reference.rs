use std::io::{self, Write};
use trnm_pon_node::cell_native_v1::{canonical, Action, Policy, Sampler, TrainableMask, Training, DIM};

fn write_row(out: &mut impl Write, value: &Policy) {
    let mut frame = b"CPV1\0\0\0\0".to_vec();
    for x in [value.abstain_margin, value.allowed_actions.len() as u64,
              value.expert_mask.len() as u64, match value.sampler {
                  Sampler::ArgmaxLowest => 0, Sampler::Sha256PositiveShift => 1,
              }, value.training.is_some() as u64] {
        frame.extend_from_slice(&x.to_le_bytes());
    }
    for name in &value.tool_names {
        frame.extend_from_slice(&name.as_ref().map_or(u64::MAX, |n| n.len() as u64).to_le_bytes());
    }
    frame.extend(value.allowed_actions.iter().map(|a| match a {
        Action::Emit => 0, Action::Stop => 1, Action::Abstain => 2, Action::ProposeTool => 3,
    }));
    assert_eq!(value.feature_mask.len(), DIM);
    frame.extend(value.feature_mask.iter().map(|b| u8::from(*b)));
    for r in &value.expert_mask {
        assert_eq!(r.len(),3);
        frame.extend(r.iter().map(|b| u8::from(*b)));
    }
    for name in value.tool_names.iter().flatten() { frame.extend_from_slice(name.as_bytes()); }
    if let Some(t) = &value.training {
        for u in [t.clip_abs, t.learning_rate_den, t.learning_rate_num, t.momentum_den, t.momentum_num] {
            frame.extend_from_slice(&u.to_le_bytes());
        }
        for m in std::iter::once(&t.trainable_mask.base).chain(&t.trainable_mask.deltas) {
            assert_eq!(m.len(),3);
            for r in m {
                assert_eq!(r.len(),DIM);
                frame.extend(r.iter().map(|b| u8::from(*b)));
            }
        }
    }
    let bytes = match canonical(value) {
        Ok(bytes) => bytes,
        Err(e) => { assert_eq!(e.to_string(),"CELL_JSON_ASCII"); Vec::new() },
    };
    out.write_all(&(frame.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&frame).unwrap();
    out.write_all(&bytes).unwrap();
}

fn main() {
    let mut out = io::stdout().lock();
    let base = Policy {
        feature_mask: (0..DIM).map(|i| i%3==0).collect(), expert_mask: vec![vec![true,false,true]],
        allowed_actions: vec![Action::Emit, Action::ProposeTool, Action::Abstain, Action::Stop],
        sampler: Sampler::ArgmaxLowest, abstain_margin: 7,
        tool_names: vec![None, Some("".to_owned()), Some((0..=127).map(char::from).collect())],
        training: None,
    };
    write_row(&mut out,&base);
    let mut reordered = base.clone();
    reordered.allowed_actions.reverse();
    reordered.expert_mask.push(vec![false,true,false]);
    reordered.sampler = Sampler::Sha256PositiveShift;
    write_row(&mut out,&reordered);
    let mut minimal = base.clone();
    minimal.allowed_actions.clear();
    minimal.expert_mask.clear();
    minimal.tool_names=vec![None;3];
    write_row(&mut out,&minimal);

    let mixed = |m| (0..3).map(|r| (0..DIM).map(|i| (i+2*r+m)%7 < 3).collect()).collect();
    let mut some = reordered;
    some.training = Some(Training {
        learning_rate_num: 4, learning_rate_den: u64::MAX,
        momentum_num: 2, momentum_den: 0, clip_abs: 900,
        trainable_mask: TrainableMask {base:mixed(0), deltas:(1..4).map(mixed).collect()},
    });
    write_row(&mut out,&some);
    let mut max = some.clone();
    max.feature_mask=vec![false;DIM];
    max.expert_mask=vec![vec![false;3];64];
    max.tool_names=vec![Some("\0".repeat(128));3];
    max.abstain_margin=u64::MAX;
    max.training=Some(Training {
        learning_rate_num:u64::MAX,learning_rate_den:u64::MAX,
        momentum_num:u64::MAX,momentum_den:u64::MAX,clip_abs:u64::MAX,
        trainable_mask:TrainableMask {base:vec![vec![false;DIM];3],
            deltas:vec![vec![vec![false;DIM];3];3]},
    });
    write_row(&mut out,&max);
    let mut rejected=some;
    rejected.tool_names[0]=Some("λ".to_owned());
    write_row(&mut out,&rejected);
}
