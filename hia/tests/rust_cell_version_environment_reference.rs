// Fixture-only outer frame; actual unchanged Rust owns the child parsing and relation.
fn split(wire: &[u8]) -> Option<(&[u8], &[u8])> {
    if !(12..=1 << 20).contains(&wire.len()) || &wire[..4] != b"EVB1" {
        return None;
    }
    let root_size = u32::from_be_bytes(wire[4..8].try_into().ok()?) as usize;
    let end = 8usize.checked_add(root_size)?;
    let after = end.checked_add(4)?;
    let env_size = u32::from_be_bytes(wire.get(end..after)?.try_into().ok()?) as usize;
    let environment = wire.get(after..)?;
    (environment.len() == env_size).then(|| (&wire[8..end], environment))
}

fn stage(wire: &[u8]) -> (u8, Option<CellDigestV1>) {
    let Some((a, b)) = split(wire) else {
        return (100, None);
    };
    let model = match CellModelReleaseRootV1::decode(a) {
        Ok(value) => value,
        Err(error) => return (model_root_status(error), None),
    };
    let environment = match CellReleaseClosureV1::decode(b) {
        Ok(value) => value,
        Err(error) => return (closure_observer::closure_error_status(error), None),
    };
    assert_eq!(model.encode(), a);
    assert_eq!(environment.encode(), b);
    // Only the private shell supplies an empty roster. The extracted original
    // prefix performs its actual input validations and lexical relation.
    let probe = CellVersionManifestV1 {
        model,
        environment,
        manifests: vec![],
    };
    match probe.declared_environment() {
        Ok(()) => (0, Some(probe.environment.id())),
        Err(CellErrorV1::Invalid("version environment binding")) => (84, None),
        Err(CellErrorV1::Invalid("version environment data role")) => (85, None),
        Err(other) => panic!("unexpected original declared-stage error: {other:?}"),
    }
}

fn main() -> io::Result<()> {
    let mut capture = Vec::new();
    io::stdin().read_to_end(&mut capture)?;
    let mut frames = capture.as_slice();
    let mut out = io::stdout().lock();
    while !frames.is_empty() {
        let (header, tail) = frames.split_at(5);
        let extent = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let (wire, rest) = tail.split_at(extent);
        frames = rest;
        if header[0] == 0 {
            let (status, identity) = stage(wire);
            out.write_all(&[status])?;
            if let Some(identity) = identity {
                out.write_all(&identity)?;
            }
        } else {
            assert_eq!(header[0], 1);
            // The genuine full decode includes the genuine complete constructor;
            // no filesystem, loader, signature or payload functions are linked.
            match CellVersionManifestV1::decode(wire) {
                Ok(value) => {
                    assert_eq!(value.encode(), wire);
                    out.write_all(&[0])?;
                    out.write_all(&value.commitment())?;
                }
                Err(CellErrorV1::Invalid("version environment binding")) => out.write_all(&[84])?,
                Err(CellErrorV1::Invalid("version environment data role")) => {
                    out.write_all(&[85])?
                }
                Err(CellErrorV1::Invalid("version manifest coverage")) => out.write_all(&[86])?,
                Err(CellErrorV1::Invalid("version manifest count")) => out.write_all(&[87])?,
                Err(CellErrorV1::Invalid("version trailing bytes")) => out.write_all(&[88])?,
                Err(CellErrorV1::Invalid("version canonical manifests")) => out.write_all(&[89])?,
                Err(error) => panic!("unexpected full original control: {error:?}"),
            }
        }
    }
    Ok(())
}
