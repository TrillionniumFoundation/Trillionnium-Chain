// Prefix supplied by Python: original V0 code, original fixture and the
// independent SHA-256 implementation at the original external sha2 seam.
use std::io::Read;

fn text(slot: &[u8], index: usize, start: usize) -> Vec<u8> {
    let width = usize::from(u16::from_le_bytes(slot[index..index + 2].try_into().unwrap()));
    slot[start..start + width].to_vec()
}

fn main() -> io::Result<()> {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut input = raw.as_slice();
    let mut out = io::stdout().lock();
    while !input.is_empty() {
        let count = usize::from(u16::from_le_bytes(input[..2].try_into().unwrap()));
        let end = 2 + count * 1351;
        let mut bundle = bundle(20, 7);
        bundle.sbom_packages = input[2..end]
            .chunks_exact(1351)
            .map(|slot| SbomPackageV0 {
                package_name: text(slot, 0, 71),
                package_version: text(slot, 2, 583),
                source_digest: Digest32V0(slot[7..39].try_into().unwrap()),
                package_checksum: Digest32V0(slot[39..71].try_into().unwrap()),
                license_expression: text(slot, 4, 839),
                direct_production_dependency: match slot[6] {
                    0 => false,
                    1 => true,
                    _ => panic!("non-Boolean typed input"),
                },
            })
            .collect();

        // Call the original aggregate method on the unsorted vector, not on
        // the harness's sorted output. Report native sort comparison bytes.
        out.write_all(&bundle.sbom_digest().0)?;
        let mut sorted = bundle.sbom_packages.clone();
        sorted.sort_unstable();
        for entry in sorted {
            out.write_all(&entry.canonical_digest().0)?;
        }
        input = &input[end..];
    }
    Ok(())
}
