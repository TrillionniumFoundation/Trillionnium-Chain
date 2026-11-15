//! Exact typed byte views admitted from already resident immutable chunks.
//! No cache, transport, device or execution-authority capability is acquired.

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use super::{checkpoint, CellResidencyV1, CellResidentFileV1};
use crate::cell::{
    require, CellDigestV1, CellErrorV1, CellLoaderContextV1, CellResultV1, CellTensorDTypeV1,
    CellTensorFileV1, CellTensorModelManifestV1, CellTensorReadbackV1, CellTensorSpecV1,
};

/// Complete declared tensor admission over the exact borrowed resident bytes.
/// This handle retains no owned payload buffer and cannot outlive its residency
/// manager or independently supplied TMA1 plan. The borrow prevents eviction or
/// local switching while the handle or one of its tensor views is still in use.
/// CURRENT, withdrawal, resource admission, device installation and FinalUse
/// remain the real execution owner's responsibilities. Admission is not a token.
///
/// ```compile_fail
/// use std::{sync::atomic::AtomicBool, time::Instant};
/// use trnm_data_availability::cell::*;
/// fn evict_borrowed(
///     pool: &mut CellResidencyV1, model: &CellTensorModelManifestV1,
///     pin: CellDigestV1, expected: &CellLoaderContextV1, deadline: Instant,
///     cancelled: &AtomicBool,
/// ) {
///     let tensors = pool.admit_local_tensor_model(model, pin, expected, deadline, cancelled).unwrap();
///     pool.evict(expected.closure_id).unwrap();
///     let _ = tensors.files();
/// }
/// ```
pub struct CellResidentTensorModelV1<'a> {
    manifest_id: CellDigestV1,
    model_root: CellDigestV1,
    contract_id: CellDigestV1,
    closure_id: CellDigestV1,
    files: Vec<CellResidentTensorFileV1<'a>>,
}

impl<'a> CellResidentTensorModelV1<'a> {
    pub fn manifest_id(&self) -> CellDigestV1 {
        self.manifest_id
    }

    pub fn model_root(&self) -> CellDigestV1 {
        self.model_root
    }

    pub fn contract_id(&self) -> CellDigestV1 {
        self.contract_id
    }

    pub fn closure_id(&self) -> CellDigestV1 {
        self.closure_id
    }

    pub fn files(&self) -> &[CellResidentTensorFileV1<'a>] {
        &self.files
    }

    pub fn tensor(&self, file_index: u16, name: &str) -> Option<CellResidentTensorV1<'_>> {
        self.files
            .binary_search_by_key(&file_index, |file| file.spec.file_index)
            .ok()
            .and_then(|index| self.files[index].tensor(name))
    }
}

/// One fully verified safetensors container; tensor order is the TMT1 order.
pub struct CellResidentTensorFileV1<'a> {
    file: &'a CellResidentFileV1,
    spec: &'a CellTensorFileV1,
    ranges: Vec<(u64, u64)>,
    readback: CellTensorReadbackV1,
}

impl CellResidentTensorFileV1<'_> {
    pub fn file_index(&self) -> u16 {
        self.spec.file_index
    }

    pub fn path(&self) -> &str {
        self.file.path()
    }

    pub fn readback(&self) -> &CellTensorReadbackV1 {
        &self.readback
    }

    pub fn tensors(&self) -> impl ExactSizeIterator<Item = CellResidentTensorV1<'_>> {
        self.spec
            .tensors
            .iter()
            .zip(&self.ranges)
            .map(|(spec, &(start, length))| CellResidentTensorV1 {
                file: self.file,
                spec,
                start,
                length,
            })
    }

    pub fn tensor(&self, name: &str) -> Option<CellResidentTensorV1<'_>> {
        let index = self
            .spec
            .tensors
            .binary_search_by(|spec| spec.name.as_str().cmp(name))
            .ok()?;
        let (start, length) = self.ranges[index];
        Some(CellResidentTensorV1 {
            file: self.file,
            spec: &self.spec.tensors[index],
            start,
            length,
        })
    }
}

/// An exact dense tensor range. Bytes retain the safetensors little-endian
/// representation. A range can cross chunk boundaries and need not be aligned
/// for a native typed pointer; no pointer cast or payload allocation is used.
#[derive(Clone, Copy)]
pub struct CellResidentTensorV1<'a> {
    file: &'a CellResidentFileV1,
    spec: &'a CellTensorSpecV1,
    start: u64,
    length: u64,
}

impl<'a> CellResidentTensorV1<'a> {
    pub fn name(self) -> &'a str {
        &self.spec.name
    }

    pub fn dtype(self) -> CellTensorDTypeV1 {
        self.spec.dtype
    }

    pub fn shape(self) -> &'a [u64] {
        &self.spec.shape
    }

    pub fn byte_length(self) -> u64 {
        self.length
    }

    /// Borrow only this tensor's data, excluding the container/header and other
    /// tensors. Underlying Arc ownership stays private to the resident pool.
    pub fn segments(self) -> impl ExactSizeIterator<Item = &'a [u8]> {
        let width = self.file.chunks[0].len() as u64;
        let first = (self.start / width) as usize;
        let end = self.start + self.length;
        let last = ((end - 1) / width) as usize;
        self.file.chunks[first..=last]
            .iter()
            .enumerate()
            .map(move |(index, chunk)| {
                let chunk_start = (first + index) as u64 * width;
                let begin = self.start.saturating_sub(chunk_start) as usize;
                let finish = (end - chunk_start).min(chunk.len() as u64) as usize;
                &chunk[begin..finish]
            })
    }

    /// Copy a caller-sized byte range without allocating or fetching. The
    /// execution owner bounds its own subsequent computation and output buffers.
    pub fn copy_bytes(self, offset: u64, output: &mut [u8]) -> CellResultV1<()> {
        require(
            offset <= self.length && output.len() as u64 <= self.length - offset,
            "resident tensor byte range",
        )?;
        copy_resident_bytes(self.file, self.start + offset, output);
        Ok(())
    }

    /// Decode one F32 element, including an unaligned element split across two
    /// chunks. F16/BF16 require an explicitly chosen numerical backend; their
    /// exact dense bytes remain available through `segments` and `copy_bytes`.
    /// NaN/Inf representation is preserved, not promoted to numerical safety.
    pub fn read_f32(self, index: u64) -> CellResultV1<f32> {
        require(
            self.dtype() == CellTensorDTypeV1::F32,
            "resident tensor F32 dtype",
        )?;
        let offset = index
            .checked_mul(4)
            .ok_or(CellErrorV1::Invalid("resident tensor element range"))?;
        let mut bytes = [0; 4];
        self.copy_bytes(offset, &mut bytes)?;
        Ok(f32::from_le_bytes(bytes))
    }
}

impl CellResidencyV1 {
    /// Validate every TMT1 file against the independent TMA1 pin and current
    /// caller-supplied loader context, directly over the immutable resident
    /// bytes. Every admission repeats the existing strict parser and complete
    /// payload hashes under one original deadline and cancellation token. A
    /// missing resident, wrong plan, cancellation or invalid later file returns
    /// no typed handle and changes no byte residency, usage or local selection.
    /// No store or transport capability exists on this path.
    pub fn admit_local_tensor_model<'a>(
        &'a self,
        model: &'a CellTensorModelManifestV1,
        pinned: CellDigestV1,
        expected: &CellLoaderContextV1,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> CellResultV1<CellResidentTensorModelV1<'a>> {
        checkpoint(deadline, cancelled)?;
        require(model.id() == pinned, "resident tensor manifest pin")?;
        model.validate()?;
        let model_root = model.root().id();
        model.root().verify_for_loader(model_root, expected)?;
        let resident = self.resident(expected)?;
        require(
            &resident.closure == model.root().closure(),
            "resident tensor closure",
        )?;
        let contract_id = model.contract().id();
        let mut files = Vec::with_capacity(model.contract().files().len());
        for spec in model.contract().files() {
            checkpoint(deadline, cancelled)?;
            let file = &resident.files[usize::from(spec.file_index)];
            let mut reader = ResidentPayloadReader {
                file,
                size: resident.closure.files()[usize::from(spec.file_index)].payload_bytes,
                position: 0,
                deadline,
                cancelled,
            };
            let layout = model.contract().verify_reader_layout(
                model.root(),
                contract_id,
                spec.file_index,
                &mut reader,
                deadline,
            )?;
            #[cfg(test)]
            tests::after_file(spec.file_index);
            checkpoint(deadline, cancelled)?;
            files.push(CellResidentTensorFileV1 {
                file,
                spec,
                ranges: layout.ranges,
                readback: layout.readback,
            });
        }
        checkpoint(deadline, cancelled)?;
        Ok(CellResidentTensorModelV1 {
            manifest_id: pinned,
            model_root,
            contract_id,
            closure_id: resident.id,
            files,
        })
    }

    /// Also require the manager's existing local selection. This is a byte
    /// selection check, not the ordinary Hepta owner's CURRENT or FinalUse gate.
    pub fn admit_selected_tensor_model<'a>(
        &'a self,
        model: &'a CellTensorModelManifestV1,
        pinned: CellDigestV1,
        expected: &CellLoaderContextV1,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> CellResultV1<CellResidentTensorModelV1<'a>> {
        require(
            self.selection()
                .is_some_and(|selection| selection.closure_id == expected.closure_id),
            "resident local selection mismatch",
        )?;
        self.admit_local_tensor_model(model, pinned, expected, deadline, cancelled)
    }
}

fn copy_resident_bytes(file: &CellResidentFileV1, mut position: u64, mut output: &mut [u8]) {
    let width = file.chunks[0].len() as u64;
    while !output.is_empty() {
        let chunk = &file.chunks[(position / width) as usize];
        let offset = (position % width) as usize;
        let length = output.len().min(chunk.len() - offset);
        output[..length].copy_from_slice(&chunk[offset..offset + length]);
        output = &mut output[length..];
        position += length as u64;
    }
}

struct ResidentPayloadReader<'a> {
    file: &'a CellResidentFileV1,
    size: u64,
    position: u64,
    deadline: Instant,
    cancelled: &'a AtomicBool,
}

impl Read for ResidentPayloadReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        checkpoint(self.deadline, self.cancelled).map_err(io::Error::other)?;
        if output.is_empty() || self.position >= self.size {
            return Ok(0);
        }
        let length = (self.size - self.position).min(output.len() as u64) as usize;
        copy_resident_bytes(self.file, self.position, &mut output[..length]);
        self.position += length as u64;
        checkpoint(self.deadline, self.cancelled).map_err(io::Error::other)?;
        Ok(length)
    }
}

impl Seek for ResidentPayloadReader<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        checkpoint(self.deadline, self.cancelled).map_err(io::Error::other)?;
        let position = match from {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::End(offset) => i128::from(self.size) + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };
        self.position = u64::try_from(position)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "resident tensor seek"))?;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests;
