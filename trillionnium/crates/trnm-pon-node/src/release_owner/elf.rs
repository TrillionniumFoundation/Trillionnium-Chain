//! Strict native static ELF profile; no interpreter or external dynamic objects.
use super::frontier::{hash, invalid, Digest32, Result};
use std::fs::File;
use std::os::unix::fs::FileExt;

pub(super) fn platform() -> Result<Digest32> {
    let value: &[u8] = match std::env::consts::ARCH {
        "x86_64" => b"linux-x86_64-static-elf64-le",
        "aarch64" => b"linux-aarch64-static-elf64-le",
        _ => return Err(invalid("M15 sealed ELF platform unsupported")),
    };
    Ok(hash(b"TRNM/M15/SealedExecutablePlatform/v1\0", value))
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("fixed ELF field"))
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed ELF field"))
}
fn within(offset: u64, length: u64, size: u64) -> Result<()> {
    if offset.checked_add(length).is_none_or(|end| end > size) {
        return Err(invalid("M15 ELF offset/length bound"));
    }
    Ok(())
}

pub(super) fn verify(file: &File, size: u64, expected_platform: Digest32) -> Result<()> {
    if size < 64 || expected_platform != platform()? {
        return Err(invalid("M15 actual ELF platform"));
    }
    let mut header = [0; 64];
    file.read_exact_at(&mut header, 0)?;
    let machine = match std::env::consts::ARCH {
        "x86_64" => 62,
        "aarch64" => 183,
        _ => 0,
    };
    if &header[..4] != b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || !matches!(header[7], 0 | 3)
        || !matches!(u16_at(&header, 16), 2 | 3)
        || u16_at(&header, 18) != machine
        || u32_at(&header, 20) != 1
        || u16_at(&header, 52) != 64
        || u16_at(&header, 54) != 56
    {
        return Err(invalid("M15 native ELF header rejected"));
    }
    let count = u16_at(&header, 56);
    let offset = u64_at(&header, 32);
    let entry = u64_at(&header, 24);
    if count == 0 || count > 128 {
        return Err(invalid("M15 ELF program-header count"));
    }
    within(offset, u64::from(count) * 56, size)?;
    let mut executable_entry = false;
    for i in 0..count {
        let mut segment = [0; 56];
        file.read_exact_at(&mut segment, offset + u64::from(i) * 56)?;
        let kind = u32_at(&segment, 0);
        let flags = u32_at(&segment, 4);
        let start = u64_at(&segment, 8);
        let address = u64_at(&segment, 16);
        let length = u64_at(&segment, 32);
        let memory = u64_at(&segment, 40);
        within(start, length, size)?;
        if kind == 3 {
            return Err(invalid(
                "M15 PT_INTERP is outside the sealed static profile",
            ));
        }
        if kind == 1 {
            if memory < length || flags & 3 == 3 {
                return Err(invalid("M15 ELF writable executable load"));
            }
            let end = address
                .checked_add(memory)
                .ok_or_else(|| invalid("M15 ELF address overflow"))?;
            executable_entry |= flags & 1 != 0 && entry >= address && entry < end;
        }
        if kind == 2 {
            if length > 65536 || !length.is_multiple_of(16) {
                return Err(invalid("M15 ELF dynamic table bound"));
            }
            let mut terminated = false;
            for n in 0..length / 16 {
                let mut dynamic = [0; 16];
                file.read_exact_at(&mut dynamic, start + n * 16)?;
                let tag = u64_at(&dynamic, 0);
                if tag == 0 {
                    terminated = true;
                    break;
                }
                if matches!(
                    tag,
                    1 | 15 | 29 | 0x6ffffefb | 0x6ffffefc | 0x7ffffffd | 0x7fffffff
                ) {
                    return Err(invalid(
                        "M15 external dynamic dependency/search/audit path rejected",
                    ));
                }
            }
            if !terminated {
                return Err(invalid("M15 ELF dynamic table lacks terminator"));
            }
        }
    }
    if !executable_entry {
        return Err(invalid(
            "M15 ELF entry is not in a sealed executable segment",
        ));
    }
    Ok(())
}
