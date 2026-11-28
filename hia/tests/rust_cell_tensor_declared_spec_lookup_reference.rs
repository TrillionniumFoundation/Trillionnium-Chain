// This observer is appended to the source-bound synthetic fixture setup from
// rust_cell_tensor_view_bytes_reference.rs. No production source is extracted.
fn row(name: &str, dtype: CellTensorDTypeV1, shape: &[u64]) -> Vec<u8> {
    let mut w = (name.len() as u16).to_be_bytes().to_vec();
    w.extend(name.as_bytes());
    w.push(dtype as u8);
    w.push(shape.len() as u8);
    for dim in shape {
        w.extend(dim.to_be_bytes());
    }
    w
}

fn frame(w: &mut impl Write, tag: u8, bytes: &[u8]) -> io::Result<()> {
    w.write_all(&[tag])?;
    w.write_all(&(bytes.len() as u32).to_le_bytes())?;
    w.write_all(bytes)
}

fn main() -> io::Result<()> {
    let temp = std::env::temp_dir().join(format!("trnm-hia-tensor-spec-{}", std::process::id()));
    fs::create_dir(&temp)?;
    let _remove = RemoveOwned(temp.clone());
    let payload = synthetic_container();
    let (resident, model, expected) = obtain(&temp.join("owned.sqlite"), &payload, WIDTH);
    let cancel = AtomicBool::new(false);
    let view = resident.admit_local_tensor_model(
        &model, model.id(), &expected, Instant::now() + Duration::from_secs(10), &cancel,
    ).unwrap();
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let mut out = io::BufWriter::new(io::stdout().lock());
    frame(&mut out, 0, &model.contract().encode())?;
    for (file, query) in [(0, "a"), (0, "b"), (0, "c"), (0, "z"), (0, "A"), (1, "a")] {
        if let Some(t) = view.tensor(file, query) {
            let mut info = t.byte_length().to_le_bytes().to_vec();
            info.extend(row(t.name(), t.dtype(), t.shape()));
            frame(&mut out, 0, &info)?;
        } else {
            frame(&mut out, 2, &[])?;
        }
    }
    // The exact legacy native view entry already supports every admissible
    // width. This observed original case extends its previously checked
    // one/two-chunk geometry without editing or duplicating its code.
    let tensor = view.tensor(0, "a").unwrap();
    let slices: Vec<_> = tensor.segments().collect();
    assert_eq!(slices.len(), 4);
    frame(&mut out, 0, &payload)?;
    let mut bytes = (slices.len() as u32).to_le_bytes().to_vec();
    for slice in &slices {
        bytes.extend((slice.len() as u32).to_le_bytes());
    }
    for slice in &slices {
        bytes.extend(*slice);
    }
    frame(&mut out, 0, &bytes)?;
    let mut copy = vec![0; tensor.byte_length() as usize - 2];
    tensor.copy_bytes(1, &mut copy).unwrap();
    frame(&mut out, 0, &copy)?;
    let mut before = 0u64;
    for slice in &slices[..3] {
        before += slice.len() as u64;
        assert_ne!(before % 4, 0);
        let float = tensor.read_f32(before / 4).unwrap();
        frame(&mut out, 0, &float.to_bits().to_le_bytes())?;
    }
    // All other rows independently exercise public declared TMT1 decode/files.
    let mut remaining = input.as_slice();
    while !remaining.is_empty() {
        let n = u32::from_le_bytes(remaining[..4].try_into().unwrap()) as usize;
        let (query, rest) = remaining[4..].split_at(n);
        remaining = rest;
        let file = u16::from_be_bytes(query[..2].try_into().unwrap());
        let name_len = u16::from_be_bytes(query[2..4].try_into().unwrap()) as usize;
        let (name, wire) = query[4..].split_at(name_len);
        let name = std::str::from_utf8(name).unwrap();
        match CellTensorContractV1::decode(wire) {
            Ok(original) => {
                assert_eq!(original.encode(), wire);
                let item = original.files().iter().find(|f| f.file_index == file)
                    .and_then(|f| f.tensors.iter().find(|s| s.name == name));
                if let Some(t) = item {
                    frame(&mut out, 0, &row(&t.name, t.dtype, &t.shape))?;
                } else {
                    frame(&mut out, 2, &[])?;
                }
            }
            Err(CellErrorV1::Invalid(reason)) => frame(&mut out, 1, reason.as_bytes())?,
            Err(CellErrorV1::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                frame(&mut out, 1, b"unexpected eof")?;
            }
            Err(_) => panic!("non-declaration error from TMT1 decode"),
        }
    }
    out.flush()
}
