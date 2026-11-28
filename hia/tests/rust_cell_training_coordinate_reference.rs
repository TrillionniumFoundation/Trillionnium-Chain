use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, Read, Write};

// Pure carrier for the original diagnostic strings, not the Node error graph.
type Error = String;
type Result<T> = std::result::Result<T, Error>;
// EXACT_ORIGINAL_TRAIN

fn coordinate_rows(want: i64) -> Vec<ActiveRow> {
    let mut out=Vec::new();
    let max_error=LOGIT_BOUND+8192;
    let mut left=want.abs()/2;
    let sgn=if want<0 { 1 } else { -1 };
    let mut add=|error: i64,feature: i64| {
        let mut features=vec![0;DIM];
        features[13]=feature;
        features[DIM-1]=8;
        let logit=8192-error;
        assert!((-LOGIT_BOUND..=LOGIT_BOUND).contains(&logit));
        assert!((-8..=8).contains(&feature));
        out.push(ActiveRow {row:out.len(),route:0,logits:vec![logit,0,0],features,label:0});
    };
    while left>=8*max_error {
        add(max_error,8*sgn);
        left-=8*max_error;
    }
    if left>=8 { add(left/8,8*sgn); }
    if left%8!=0 { add(left%8,sgn); }
    if want==0 { add(0,0); }
    assert!((1..=MAX_BATCH).contains(&out.len()));
    out
}

fn read_word(data:&[u8], index:usize) -> u64 {
    u64::from_le_bytes(data[index*8..(index+1)*8].try_into().unwrap())
}

fn observe(frame:&[u8], out:&mut impl Write) -> io::Result<()> {
    let word=|j|read_word(frame,j);
    let mask=word(0);
    let step=word(1);
    let weight=word(2) as i64;
    let old=word(3) as i64;
    let raw=word(4) as i64;
    assert!(mask<=1 && (-32767..=32767).contains(&weight) && old!=i64::MIN);
    assert!(raw%2==0 && raw.abs()<=2*(LOGIT_BOUND+8192)*8*MAX_BATCH as i64);
    let mut model=Model {schema:MODEL_SCHEMA.into(),base:zero_matrix(),router:zero_matrix(),
                         deltas:vec![zero_matrix();3]};
    let mut opt=Optimizer {schema:OPTIMIZER_SCHEMA.into(),step,base:zero_matrix(),deltas:vec![zero_matrix();3]};
    model.base[0][13]=weight;
    opt.base[0][13]=old;
    // Frozen nonzero control in another group must not undergo hidden decay.
    opt.deltas[0][1][21]=-53;
    let mut base_mask=vec![vec![false;DIM];3];
    base_mask[0][13]=mask==1;
    let spec=Training {learning_rate_num:word(5),learning_rate_den:word(6),
                       momentum_num:word(7),momentum_den:word(8),clip_abs:word(9),
                       trainable_mask:TrainableMask {base:base_mask,deltas:vec![vec![vec![false;DIM];3];3]}};
    assert!(spec.learning_rate_num<=1<<20 && (1..=1<<32).contains(&spec.learning_rate_den)
            && spec.momentum_num<spec.momentum_den && spec.momentum_den<=1<<16
            && (1..=1<<40).contains(&spec.clip_abs));
    let rows=coordinate_rows(raw);
    match train(&model,&rows,&Some(opt),&spec) {
        Ok((m,opt2,summary,stages)) => {
            let opt=opt2.unwrap();
            assert_eq!(opt.deltas[0][1][21],-53);
            assert_eq!(summary["optimizer_step"].as_u64(),Some(opt.step));
            assert_eq!(stages[1].stage,"training-backward");
            assert_eq!(stages[1].outputs["gradients"]["base"][0][13].as_i64(),Some(raw));
            assert_eq!(stages[2].stage,"training-update");
            let fields=&stages[2].outputs;
            let staged=|k:&str|fields[k]["base"][0][13].as_i64().unwrap();
            out.write_all(&[0])?;
            out.write_all(&opt.step.to_le_bytes())?;
            for v in [m.base[0][13],opt.base[0][13],staged("masked_gradients"),
                      staged("clipped_gradients"),staged("updates")] {
                out.write_all(&v.to_le_bytes())?;
            }
        }
        Err(e) => out.write_all(&[match e.as_str() {
            "CELL_OPTIMIZER_STEP_OVERFLOW"=>201,
            "CELL_MOMENT_OVERFLOW"=>202,
            "CELL_TRAINED_WEIGHT_RANGE"=>203,
            _=>panic!("Unexpected original train diagnostic {e:?}"),
        }])?,
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let mut raw=Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    assert_eq!(raw.len()%80,0);
    let mut out=io::BufWriter::new(io::stdout().lock());
    for frame in raw.chunks_exact(80) { observe(frame,&mut out)?; }
    out.flush()
}
