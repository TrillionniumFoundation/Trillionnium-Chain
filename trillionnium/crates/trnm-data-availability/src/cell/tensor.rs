//! Owner-pinned tensor metadata admission over immutable TMR1 file identities.
//!
//! TMT1 uses SHA-256 v1 and a deliberately bounded safetensors dense profile:
//! F32/F16/BF16, scalar or rank <= 8, positive dimensions <= u32::MAX, and no
//! quantization. It checks the complete expected tensor roster and actual file
//! bytes. It does not infer architecture, expert ABI, numerical quality,
//! CURRENT, publisher authority or FinalUse. NaN/Inf tensor values retain the
//! safetensors representation; this is not a numerical-safety assessment.
//!
//! Format reference: https://github.com/safetensors/safetensors#format
//! A reader must expose a stable, owner-controlled byte source. Reads/seeks are
//! cooperative, not preemptible I/O. Successful admission is not a use token;
//! the existing use owner must still reject changed or revoked source state.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, Cursor, Read, Seek, SeekFrom},
    time::Instant,
};

use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use sha2::{Digest, Sha256};

use super::{
    require, CellDigestV1, CellErrorV1, CellFileRoleV1, CellModelReleaseRootV1, CellResultV1,
    MAX_CELL_BYTES, MAX_CELL_CLOSURE_FILES_V1, MAX_MODEL_RELEASE_ROOT_BYTES_V1,
};

pub const MAX_CELL_TENSOR_CONTRACT_BYTES_V1: usize = 1024 * 1024;
pub const MAX_CELL_TENSOR_HEADER_BYTES_V1: usize = 1024 * 1024;
pub const MAX_CELL_TENSOR_MODEL_MANIFEST_BYTES_V1: usize =
    12 + MAX_MODEL_RELEASE_ROOT_BYTES_V1 + MAX_CELL_TENSOR_CONTRACT_BYTES_V1;
const HASH_PROFILE_SHA256_V1: u8 = 1;
const CODEC_SAFETENSORS_DENSE_V1: u8 = 1;
const MAX_TENSORS: usize = 16_384;
const MAX_TENSOR_NAME_BYTES: usize = 255;
const MAX_RANK: usize = 8;
const MAX_METADATA_ENTRIES: usize = 1024;
const MAX_METADATA_VALUE_BYTES: usize = 16_384;
const STREAM_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CellTensorDTypeV1 {
    F32 = 1,
    F16 = 2,
    Bf16 = 3,
}

impl CellTensorDTypeV1 {
    fn decode(value: u8) -> CellResultV1<Self> {
        match value {
            1 => Ok(Self::F32),
            2 => Ok(Self::F16),
            3 => Ok(Self::Bf16),
            _ => Err(CellErrorV1::Invalid("tensor dtype")),
        }
    }

    fn bytes(self) -> u64 {
        match self {
            Self::F32 => 4,
            Self::F16 | Self::Bf16 => 2,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::F32 => "F32",
            Self::F16 => "F16",
            Self::Bf16 => "BF16",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellTensorSpecV1 {
    pub name: String,
    pub dtype: CellTensorDTypeV1,
    /// Empty shape denotes a scalar. Empty tensors are outside this profile.
    pub shape: Vec<u64>,
}

impl CellTensorSpecV1 {
    fn byte_length(&self) -> CellResultV1<u64> {
        require(valid_name(&self.name), "tensor name")?;
        require(self.shape.len() <= MAX_RANK, "tensor rank")?;
        let mut bytes = self.dtype.bytes();
        for dimension in &self.shape {
            require(
                (1..=u64::from(u32::MAX)).contains(dimension),
                "tensor dimension",
            )?;
            bytes = bytes
                .checked_mul(*dimension)
                .ok_or(CellErrorV1::Invalid("tensor shape overflow"))?;
        }
        require(bytes <= MAX_CELL_BYTES, "tensor byte bound")?;
        Ok(bytes)
    }
}

/// Files use their immutable TCD1 index; names are canonical within each file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellTensorFileV1 {
    pub file_index: u16,
    pub tensors: Vec<CellTensorSpecV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellTensorContractV1 {
    model_root: CellDigestV1,
    files: Vec<CellTensorFileV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellTensorReadbackV1 {
    pub contract_id: CellDigestV1,
    pub model_root: CellDigestV1,
    pub file_index: u16,
    pub tensor_count: usize,
    pub payload_bytes: u64,
    pub payload_sha256: CellDigestV1,
}

impl CellTensorContractV1 {
    pub fn new(model_root: CellDigestV1, files: Vec<CellTensorFileV1>) -> CellResultV1<Self> {
        let value = Self { model_root, files };
        value.validate()?;
        Ok(value)
    }

    pub fn model_root(&self) -> CellDigestV1 {
        self.model_root
    }

    pub fn files(&self) -> &[CellTensorFileV1] {
        &self.files
    }

    pub fn validate(&self) -> CellResultV1<()> {
        require(self.model_root != [0; 32], "tensor model root")?;
        require(
            !self.files.is_empty() && self.files.len() <= MAX_CELL_CLOSURE_FILES_V1,
            "tensor file count",
        )?;
        require(
            self.files
                .windows(2)
                .all(|pair| pair[0].file_index < pair[1].file_index),
            "tensor canonical files",
        )?;
        let mut count = 0usize;
        // Bound the encoding before allocating it. Private fields prevent an
        // admitted contract from later growing behind its content address.
        let mut encoded_bytes = 40usize;
        for file in &self.files {
            require(
                usize::from(file.file_index) < MAX_CELL_CLOSURE_FILES_V1
                    && !file.tensors.is_empty()
                    && file.tensors.len() <= MAX_TENSORS,
                "tensor file roster",
            )?;
            count = count
                .checked_add(file.tensors.len())
                .ok_or(CellErrorV1::Invalid("tensor count"))?;
            require(count <= MAX_TENSORS, "tensor count")?;
            require(
                file.tensors
                    .windows(2)
                    .all(|pair| pair[0].name < pair[1].name),
                "tensor canonical names",
            )?;
            encoded_bytes += 4;
            let mut file_bytes = 0u64;
            for tensor in &file.tensors {
                file_bytes = file_bytes
                    .checked_add(tensor.byte_length()?)
                    .ok_or(CellErrorV1::Invalid("tensor file bytes"))?;
                require(file_bytes <= MAX_CELL_BYTES, "tensor file bytes")?;
                encoded_bytes = encoded_bytes
                    .checked_add(4 + tensor.name.len() + 8 * tensor.shape.len())
                    .ok_or(CellErrorV1::Invalid("tensor contract length"))?;
                require(
                    encoded_bytes <= MAX_CELL_TENSOR_CONTRACT_BYTES_V1,
                    "tensor contract length",
                )?;
            }
        }
        Ok(())
    }

    /// Verify the independent owner pin and all Base/Adapter coverage before
    /// reading any tensor payload. Other files may explicitly be tensor files,
    /// but their role does not imply a model architecture or expert interface.
    pub fn verify_for_model(
        &self,
        root: &CellModelReleaseRootV1,
        pinned: CellDigestV1,
    ) -> CellResultV1<()> {
        self.validate()?;
        root.validate()?;
        require(self.id() == pinned, "tensor contract pin")?;
        require(self.model_root == root.id(), "tensor model root")?;
        let closure = root.closure();
        for file in &self.files {
            let member = closure
                .files()
                .get(usize::from(file.file_index))
                .ok_or(CellErrorV1::Invalid("tensor closure file index"))?;
            let data_bytes = file.tensors.iter().try_fold(0u64, |sum, tensor| {
                sum.checked_add(tensor.byte_length()?)
                    .ok_or(CellErrorV1::Invalid("tensor file bytes"))
            })?;
            require(
                data_bytes
                    .checked_add(10)
                    .is_some_and(|minimum| minimum <= member.payload_bytes),
                "tensor closure payload size",
            )?;
        }
        for (index, file) in closure.files().iter().enumerate() {
            if matches!(file.role, CellFileRoleV1::Base | CellFileRoleV1::Adapter) {
                require(
                    self.files
                        .binary_search_by_key(&(index as u16), |entry| entry.file_index)
                        .is_ok(),
                    "tensor missing required file",
                )?;
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"TMT1");
        out.push(HASH_PROFILE_SHA256_V1);
        out.push(CODEC_SAFETENSORS_DENSE_V1);
        out.extend_from_slice(&self.model_root);
        out.extend_from_slice(&(self.files.len() as u16).to_be_bytes());
        for file in &self.files {
            out.extend_from_slice(&file.file_index.to_be_bytes());
            out.extend_from_slice(&(file.tensors.len() as u16).to_be_bytes());
            for tensor in &file.tensors {
                out.extend_from_slice(&(tensor.name.len() as u16).to_be_bytes());
                out.extend_from_slice(tensor.name.as_bytes());
                out.push(tensor.dtype as u8);
                out.push(tensor.shape.len() as u8);
                for dimension in &tensor.shape {
                    out.extend_from_slice(&dimension.to_be_bytes());
                }
            }
        }
        out
    }

    pub fn id(&self) -> CellDigestV1 {
        let mut hash = Sha256::new();
        hash.update(b"trnm.cell-tensor-contract.v1\0");
        hash.update(self.encode());
        hash.finalize().into()
    }

    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(
            (40..=MAX_CELL_TENSOR_CONTRACT_BYTES_V1).contains(&bytes.len()),
            "tensor contract length",
        )?;
        let mut input = Cursor::new(bytes);
        require(
            read::<4>(&mut input)? == *b"TMT1",
            "tensor contract version",
        )?;
        require(
            read::<1>(&mut input)?[0] == HASH_PROFILE_SHA256_V1,
            "tensor hash profile",
        )?;
        require(
            read::<1>(&mut input)?[0] == CODEC_SAFETENSORS_DENSE_V1,
            "tensor codec",
        )?;
        let model_root = read(&mut input)?;
        let count = usize::from(u16::from_be_bytes(read(&mut input)?));
        require(
            (1..=MAX_CELL_CLOSURE_FILES_V1).contains(&count),
            "tensor file count",
        )?;
        let mut files = Vec::with_capacity(count);
        let mut total = 0usize;
        for _ in 0..count {
            let file_index = u16::from_be_bytes(read(&mut input)?);
            let count = usize::from(u16::from_be_bytes(read(&mut input)?));
            total += count;
            require(count > 0 && total <= MAX_TENSORS, "tensor count")?;
            require(
                bytes.len() as u64 - input.position() >= count as u64 * 5,
                "tensor truncated roster",
            )?;
            let mut tensors = Vec::with_capacity(count);
            for _ in 0..count {
                let length = usize::from(u16::from_be_bytes(read(&mut input)?));
                require(
                    (1..=MAX_TENSOR_NAME_BYTES).contains(&length),
                    "tensor name length",
                )?;
                let mut name = vec![0; length];
                input.read_exact(&mut name)?;
                let name = String::from_utf8(name)
                    .map_err(|_| CellErrorV1::Invalid("tensor name encoding"))?;
                let dtype = CellTensorDTypeV1::decode(read::<1>(&mut input)?[0])?;
                let rank = usize::from(read::<1>(&mut input)?[0]);
                require(rank <= MAX_RANK, "tensor rank")?;
                let mut shape = Vec::with_capacity(rank);
                for _ in 0..rank {
                    shape.push(u64::from_be_bytes(read(&mut input)?));
                }
                tensors.push(CellTensorSpecV1 { name, dtype, shape });
            }
            files.push(CellTensorFileV1 {
                file_index,
                tensors,
            });
        }
        require(
            input.position() == bytes.len() as u64,
            "tensor contract suffix",
        )?;
        let value = Self::new(model_root, files)?;
        require(
            value.encode() == bytes,
            "tensor contract canonical encoding",
        )?;
        Ok(value)
    }

    /// Re-read one complete real container through a bounded header and a
    /// 64 KiB streaming buffer. Success covers both metadata and payload SHA.
    pub fn verify_reader<R: Read + Seek>(
        &self,
        root: &CellModelReleaseRootV1,
        pinned: CellDigestV1,
        file_index: u16,
        reader: &mut R,
        deadline: Instant,
    ) -> CellResultV1<CellTensorReadbackV1> {
        check_deadline(deadline)?;
        self.verify_for_model(root, pinned)?;
        let spec = self
            .files
            .binary_search_by_key(&file_index, |file| file.file_index)
            .ok()
            .map(|index| &self.files[index])
            .ok_or(CellErrorV1::Invalid("tensor undeclared file"))?;
        let file = &root.closure().files()[usize::from(file_index)];
        check_deadline(deadline)?;
        require(
            reader.seek(SeekFrom::End(0))? == file.payload_bytes,
            "tensor actual file length",
        )?;
        check_deadline(deadline)?;
        require(
            reader.seek(SeekFrom::Start(0))? == 0,
            "tensor reader position",
        )?;
        let mut prefix = [0; 8];
        read_exact_until(reader, &mut prefix, deadline)?;
        let header_bytes = u64::from_le_bytes(prefix);
        require(
            (2..=MAX_CELL_TENSOR_HEADER_BYTES_V1 as u64).contains(&header_bytes)
                && header_bytes + 8 <= file.payload_bytes,
            "tensor header length",
        )?;
        let mut header = vec![0; header_bytes as usize];
        read_exact_until(reader, &mut header, deadline)?;
        require(header.first() == Some(&b'{'), "tensor header prefix")?;
        require(
            header.iter().rfind(|byte| **byte != b' ') == Some(&b'}'),
            "tensor header padding",
        )?;
        let decoded: TensorHeader = serde_json::from_slice(&header)
            .map_err(|_| CellErrorV1::Invalid("tensor header JSON"))?;
        check_deadline(deadline)?;
        require(
            decoded.tensors.len() == spec.tensors.len(),
            "tensor roster coverage",
        )?;
        let data_bytes = file.payload_bytes - header_bytes - 8;
        let mut intervals = Vec::with_capacity(spec.tensors.len());
        for (expected, (name, actual)) in spec.tensors.iter().zip(&decoded.tensors) {
            require(
                &expected.name == name
                    && actual.dtype == expected.dtype.name()
                    && actual.shape == expected.shape,
                "tensor roster metadata",
            )?;
            let [start, end] = actual.data_offsets;
            require(
                start < end && end <= data_bytes && end - start == expected.byte_length()?,
                "tensor data range",
            )?;
            intervals.push((start, end));
        }
        intervals.sort_unstable();
        let mut covered = 0u64;
        for (start, end) in intervals {
            require(start == covered, "tensor overlap or hole")?;
            covered = end;
        }
        require(covered == data_bytes, "tensor trailing data")?;
        let mut hash = Sha256::new();
        hash.update(prefix);
        hash.update(&header);
        // Drop parsed metadata and raw header before streaming the weights.
        drop(decoded);
        drop(header);
        let mut buffer = [0; STREAM_BYTES];
        let mut remaining = data_bytes;
        while remaining != 0 {
            let length = remaining.min(STREAM_BYTES as u64) as usize;
            read_exact_until(reader, &mut buffer[..length], deadline)?;
            hash.update(&buffer[..length]);
            remaining -= length as u64;
        }
        let mut extra = [0];
        loop {
            check_deadline(deadline)?;
            match reader.read(&mut extra) {
                Ok(0) => break,
                Ok(_) => return Err(CellErrorV1::Invalid("tensor actual file length")),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        check_deadline(deadline)?;
        require(
            reader.seek(SeekFrom::End(0))? == file.payload_bytes,
            "tensor changed file length",
        )?;
        check_deadline(deadline)?;
        let payload_sha256: CellDigestV1 = hash.finalize().into();
        require(
            payload_sha256 == file.payload_sha256,
            "tensor payload digest",
        )?;
        Ok(CellTensorReadbackV1 {
            contract_id: pinned,
            model_root: self.model_root,
            file_index,
            tensor_count: spec.tensors.len(),
            payload_bytes: file.payload_bytes,
            payload_sha256,
        })
    }
}

/// TMA1 is a self-contained byte/metadata plan, never a CURRENT or FinalUse grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellTensorModelManifestV1 {
    root: CellModelReleaseRootV1,
    contract: CellTensorContractV1,
}

impl CellTensorModelManifestV1 {
    pub fn new(root: CellModelReleaseRootV1, contract: CellTensorContractV1) -> CellResultV1<Self> {
        let value = Self { root, contract };
        value.validate()?;
        Ok(value)
    }

    pub fn root(&self) -> &CellModelReleaseRootV1 {
        &self.root
    }

    pub fn contract(&self) -> &CellTensorContractV1 {
        &self.contract
    }

    pub fn validate(&self) -> CellResultV1<()> {
        self.contract
            .verify_for_model(&self.root, self.contract.id())
    }

    pub fn encode(&self) -> Vec<u8> {
        let root = self.root.encode();
        let contract = self.contract.encode();
        let mut out = Vec::with_capacity(12 + root.len() + contract.len());
        out.extend_from_slice(b"TMA1");
        out.extend_from_slice(&(root.len() as u32).to_be_bytes());
        out.extend_from_slice(&root);
        out.extend_from_slice(&(contract.len() as u32).to_be_bytes());
        out.extend_from_slice(&contract);
        out
    }

    pub fn id(&self) -> CellDigestV1 {
        let mut hash = Sha256::new();
        hash.update(b"trnm.cell-tensor-model-manifest.v1\0");
        hash.update(self.encode());
        hash.finalize().into()
    }

    pub fn decode(bytes: &[u8]) -> CellResultV1<Self> {
        require(
            (12..=MAX_CELL_TENSOR_MODEL_MANIFEST_BYTES_V1).contains(&bytes.len()),
            "tensor model manifest length",
        )?;
        let mut input = Cursor::new(bytes);
        require(
            read::<4>(&mut input)? == *b"TMA1",
            "tensor model manifest version",
        )?;
        let root = CellModelReleaseRootV1::decode(read_section(
            &mut input,
            MAX_MODEL_RELEASE_ROOT_BYTES_V1,
        )?)?;
        let contract = CellTensorContractV1::decode(read_section(
            &mut input,
            MAX_CELL_TENSOR_CONTRACT_BYTES_V1,
        )?)?;
        require(
            input.position() == bytes.len() as u64,
            "tensor model manifest suffix",
        )?;
        let value = Self::new(root, contract)?;
        require(value.encode() == bytes, "tensor model canonical encoding")?;
        Ok(value)
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TENSOR_NAME_BYTES
        && name != "__metadata__"
        && !name.chars().any(char::is_control)
}

fn read<const N: usize>(input: &mut Cursor<&[u8]>) -> CellResultV1<[u8; N]> {
    let mut value = [0; N];
    input.read_exact(&mut value)?;
    Ok(value)
}

fn read_section<'a>(input: &mut Cursor<&'a [u8]>, maximum: usize) -> CellResultV1<&'a [u8]> {
    let count = u32::from_be_bytes(read(input)?) as usize;
    let start = input.position() as usize;
    require(
        count <= maximum && count <= input.get_ref().len() - start,
        "tensor model section length",
    )?;
    let bytes = *input.get_ref();
    input.set_position((start + count) as u64);
    Ok(&bytes[start..start + count])
}

fn check_deadline(deadline: Instant) -> CellResultV1<()> {
    require(Instant::now() < deadline, "tensor deadline")
}

fn read_exact_until<R: Read>(
    reader: &mut R,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> CellResultV1<()> {
    while !bytes.is_empty() {
        check_deadline(deadline)?;
        match reader.read(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    check_deadline(deadline)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TensorEntry {
    dtype: String,
    #[serde(deserialize_with = "bounded_shape")]
    shape: Vec<u64>,
    data_offsets: [u64; 2],
}

fn bounded_shape<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u64>, D::Error> {
    struct ShapeVisitor;
    impl<'de> Visitor<'de> for ShapeVisitor {
        type Value = Vec<u64>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded tensor shape")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut shape = Vec::new();
            while let Some(dimension) = sequence.next_element::<u64>()? {
                if shape.len() == MAX_RANK {
                    return Err(de::Error::custom("tensor rank"));
                }
                shape.push(dimension);
            }
            Ok(shape)
        }
    }
    deserializer.deserialize_seq(ShapeVisitor)
}

struct TensorHeader {
    tensors: BTreeMap<String, TensorEntry>,
}

impl<'de> Deserialize<'de> for TensorHeader {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HeaderVisitor;
        impl<'de> Visitor<'de> for HeaderVisitor {
            type Value = TensorHeader;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a safetensors header with unique names")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut tensors = BTreeMap::new();
                let mut metadata_seen = false;
                while let Some(name) = map.next_key::<String>()? {
                    if name == "__metadata__" {
                        if metadata_seen {
                            return Err(de::Error::custom("duplicate metadata"));
                        }
                        map.next_value::<Metadata>()?;
                        metadata_seen = true;
                    } else {
                        if !valid_name(&name)
                            || tensors.len() == MAX_TENSORS
                            || tensors.contains_key(&name)
                        {
                            return Err(de::Error::custom("tensor name/count/duplicate"));
                        }
                        let entry = map.next_value::<TensorEntry>()?;
                        tensors.insert(name, entry);
                    }
                }
                Ok(TensorHeader { tensors })
            }
        }
        deserializer.deserialize_map(HeaderVisitor)
    }
}

struct Metadata;

impl<'de> Deserialize<'de> for Metadata {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MetadataVisitor;
        impl<'de> Visitor<'de> for MetadataVisitor {
            type Value = Metadata;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded unique metadata strings")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut keys = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if keys.len() == MAX_METADATA_ENTRIES
                        || key.len() > MAX_TENSOR_NAME_BYTES
                        || !keys.insert(key)
                    {
                        return Err(de::Error::custom("metadata key/count/duplicate"));
                    }
                    let value = map.next_value::<String>()?;
                    if value.len() > MAX_METADATA_VALUE_BYTES {
                        return Err(de::Error::custom("metadata value length"));
                    }
                }
                Ok(Metadata)
            }
        }
        deserializer.deserialize_map(MetadataVisitor)
    }
}
