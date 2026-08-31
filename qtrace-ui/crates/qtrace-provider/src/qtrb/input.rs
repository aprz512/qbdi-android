use std::{hash::Hasher, io::Read, sync::Arc};

use twox_hash::XxHash32;

use crate::{ByteSource, ProviderError, WorkDelta, WorkGuard, allocation};

const STANDARD_FRAME_MAGIC: [u8; 4] = 0x184d_2204_u32.to_le_bytes();
const RAW_CHUNK_BYTES: usize = 64 * 1024;
const LINKED_DICTIONARY_BYTES: usize = 64 * 1024;

enum InputEncoding {
    Raw,
    Lz4,
}

/// A one-shot raw or standard-LZ4 QTRB input.
pub struct QtrbInput {
    reader: Box<dyn Read + Send>,
    encoding: InputEncoding,
}

impl QtrbInput {
    pub fn raw(reader: impl Read + Send + 'static) -> Self {
        Self {
            reader: Box::new(reader),
            encoding: InputEncoding::Raw,
        }
    }

    pub fn lz4(reader: impl Read + Send + 'static) -> Self {
        Self {
            reader: Box::new(reader),
            encoding: InputEncoding::Lz4,
        }
    }

    /// Consumes this input and returns a bounded in-memory random-access source.
    ///
    /// LZ4 input is consumed frame-by-frame and block-by-block, retaining only
    /// the current compressed block and bounded decode workspace. A successful
    /// stream is charged one extra input byte for the final EOF probe, regardless
    /// of the underlying reader's short-read behavior.
    pub fn into_source(self, guard: &dyn WorkGuard) -> Result<Arc<ByteSource>, ProviderError> {
        let mut reader = CountingReader::new(self.reader);
        let bytes = match self.encoding {
            InputEncoding::Raw => reader.read_raw(guard)?,
            InputEncoding::Lz4 => ConcatenatedFrameReader::decode(&mut reader, guard)?,
        };
        Ok(Arc::new(ByteSource::new(bytes)))
    }
}

struct CountingReader {
    inner: Box<dyn Read + Send>,
    offset: u64,
}

impl CountingReader {
    fn new(inner: Box<dyn Read + Send>) -> Self {
        Self { inner, offset: 0 }
    }

    fn read_raw(&mut self, guard: &dyn WorkGuard) -> Result<Vec<u8>, ProviderError> {
        let mut bytes = Vec::new();
        loop {
            guard.consume(WorkDelta {
                input_bytes: 1,
                ..WorkDelta::default()
            })?;
            let mut byte = [0_u8; 1];
            match self.inner.read(&mut byte) {
                Ok(0) => return Ok(bytes),
                Ok(1) => self.advance(1, input_error)?,
                Ok(_) => return Err(input_error(self.offset, "raw reader over-reported bytes")),
                Err(error) => return Err(input_error(self.offset, &error.to_string())),
            }
            if bytes.len() == bytes.capacity() {
                let capacity = bytes
                    .capacity()
                    .checked_mul(2)
                    .map(|capacity| capacity.max(RAW_CHUNK_BYTES))
                    .ok_or_else(|| input_error(self.offset, "raw input capacity overflow"))?;
                allocation::try_reserve_vec_exact(
                    &mut bytes,
                    capacity,
                    guard,
                    "raw input allocation failed",
                )?;
            }
            bytes.push(byte[0]);
        }
    }

    fn read_optional_magic(
        &mut self,
        guard: &dyn WorkGuard,
    ) -> Result<Option<([u8; 4], u64)>, ProviderError> {
        let start = self.offset;
        guard.consume(WorkDelta {
            input_bytes: 1,
            ..WorkDelta::default()
        })?;
        let mut magic = [0_u8; 4];
        match self.inner.read(&mut magic[..1]) {
            Ok(0) => return Ok(None),
            Ok(1) => self.advance(1, compression_error)?,
            Ok(_) => {
                return Err(compression_error(
                    self.offset,
                    "compressed reader over-reported bytes",
                ));
            }
            Err(error) => return Err(compression_error(self.offset, &error.to_string())),
        }
        self.read_lz4_exact(&mut magic[1..], guard, "truncated LZ4 frame magic")?;
        Ok(Some((magic, start)))
    }

    fn read_lz4_exact(
        &mut self,
        output: &mut [u8],
        guard: &dyn WorkGuard,
        truncated: &str,
    ) -> Result<(), ProviderError> {
        guard.consume(WorkDelta {
            input_bytes: output.len() as u64,
            ..WorkDelta::default()
        })?;
        let mut filled = 0;
        while filled < output.len() {
            match self.inner.read(&mut output[filled..]) {
                Ok(0) => return Err(compression_error(self.offset, truncated)),
                Ok(count) if count <= output.len() - filled => {
                    filled = filled.checked_add(count).ok_or_else(|| {
                        compression_error(self.offset, "compressed input length overflow")
                    })?;
                    self.advance(count, compression_error)?;
                }
                Ok(_) => {
                    return Err(compression_error(
                        self.offset,
                        "compressed reader over-reported bytes",
                    ));
                }
                Err(error) => return Err(compression_error(self.offset, &error.to_string())),
            }
        }
        Ok(())
    }

    fn advance(
        &mut self,
        count: usize,
        error: fn(u64, &str) -> ProviderError,
    ) -> Result<(), ProviderError> {
        self.offset = self
            .offset
            .checked_add(count as u64)
            .ok_or_else(|| error(self.offset, "input offset overflow"))?;
        Ok(())
    }
}

struct ConcatenatedFrameReader;

impl ConcatenatedFrameReader {
    fn decode(
        reader: &mut CountingReader,
        guard: &dyn WorkGuard,
    ) -> Result<Vec<u8>, ProviderError> {
        let mut output = Vec::new();
        let mut frames = 0_u64;
        while let Some((magic, frame_start)) = reader.read_optional_magic(guard)? {
            if magic != STANDARD_FRAME_MAGIC {
                return Err(compression_error(
                    frame_start,
                    "expected standard LZ4 frame magic",
                ));
            }
            guard.consume(WorkDelta {
                nodes: 1,
                ..WorkDelta::default()
            })?;
            decode_frame(reader, guard, &mut output, frame_start)?;
            frames = frames
                .checked_add(1)
                .ok_or_else(|| compression_error(frame_start, "LZ4 frame count overflow"))?;
        }
        if frames == 0 {
            return Err(compression_error(
                0,
                "compressed input contains zero frames",
            ));
        }
        Ok(output)
    }
}

#[derive(Clone, Copy)]
struct FrameDescriptor {
    independent: bool,
    block_checksum: bool,
    content_checksum: bool,
    content_size: Option<u64>,
    dictionary_id: Option<u32>,
    block_maximum: usize,
}

fn decode_frame(
    reader: &mut CountingReader,
    guard: &dyn WorkGuard,
    output: &mut Vec<u8>,
    frame_start: u64,
) -> Result<(), ProviderError> {
    let descriptor = read_descriptor(reader, guard, frame_start)?;
    let frame_output_start = output.len();
    let mut content_hasher = XxHash32::with_seed(0);
    loop {
        guard.consume(WorkDelta {
            nodes: 1,
            ..WorkDelta::default()
        })?;
        let mut encoded_header = [0_u8; 4];
        reader.read_lz4_exact(
            &mut encoded_header,
            guard,
            "truncated LZ4 frame block header",
        )?;
        let encoded_header = u32::from_le_bytes(encoded_header);
        if encoded_header == 0 {
            if descriptor.content_checksum {
                let expected = read_checksum(reader, guard, "truncated LZ4 content checksum")?;
                if expected != content_hasher.finish_32() {
                    return Err(compression_error(
                        reader.offset.saturating_sub(4),
                        "invalid LZ4 content checksum",
                    ));
                }
            }
            let decoded = output
                .len()
                .checked_sub(frame_output_start)
                .ok_or_else(|| compression_error(frame_start, "LZ4 frame output offset overflow"))?
                as u64;
            if descriptor.content_size.is_some_and(|size| size != decoded) {
                return Err(compression_error(
                    frame_start,
                    "LZ4 frame content size mismatch",
                ));
            }
            return Ok(());
        }

        let raw = encoded_header & 0x8000_0000 != 0;
        let encoded_size = usize::try_from(encoded_header & 0x7fff_ffff)
            .map_err(|_| compression_error(reader.offset, "LZ4 block length overflow"))?;
        if encoded_size > descriptor.block_maximum {
            return Err(compression_error(
                reader.offset.saturating_sub(4),
                "invalid LZ4 frame block length",
            ));
        }

        guard.consume(WorkDelta {
            input_bytes: encoded_size as u64,
            ..WorkDelta::default()
        })?;
        let mut encoded = Vec::new();
        allocation::try_reserve_vec_exact(
            &mut encoded,
            encoded_size,
            guard,
            "compressed block allocation failed",
        )?;
        encoded.resize(encoded_size, 0);
        read_pre_authorized(reader, &mut encoded, "truncated LZ4 frame block")?;

        if descriptor.block_checksum {
            let expected = read_checksum(reader, guard, "truncated LZ4 block checksum")?;
            if expected != checksum(&encoded) {
                return Err(compression_error(
                    reader.offset.saturating_sub(4),
                    "invalid LZ4 block checksum",
                ));
            }
        }

        let decoded = if raw {
            guard.consume(WorkDelta {
                decompressed_bytes: encoded_size as u64,
                ..WorkDelta::default()
            })?;
            encoded
        } else {
            guard.consume(WorkDelta {
                decompressed_bytes: descriptor.block_maximum as u64,
                ..WorkDelta::default()
            })?;
            let mut decoded = Vec::new();
            allocation::try_reserve_vec_exact(
                &mut decoded,
                descriptor.block_maximum,
                guard,
                "decompression workspace allocation failed",
            )?;
            decoded.resize(descriptor.block_maximum, 0);
            let dictionary = if descriptor.independent {
                &[][..]
            } else {
                let history_start = output
                    .len()
                    .saturating_sub(LINKED_DICTIONARY_BYTES)
                    .max(frame_output_start);
                &output[history_start..]
            };
            let decoded_size = lz4_flex::block::decompress_into_with_dict(
                &encoded,
                &mut decoded,
                dictionary,
            )
            .map_err(|error| {
                if let Some(dictionary_id) = descriptor.dictionary_id {
                    compression_error(
                        reader.offset,
                        &format!(
                            "LZ4 block cannot decode without unavailable dictionary {dictionary_id}: {error}"
                        ),
                    )
                } else {
                    compression_error(reader.offset, &format!("invalid LZ4 block: {error}"))
                }
            })?;
            decoded.truncate(decoded_size);
            decoded
        };

        let frame_size = output
            .len()
            .checked_sub(frame_output_start)
            .and_then(|size| size.checked_add(decoded.len()))
            .ok_or_else(|| compression_error(frame_start, "decompressed output size overflow"))?;
        if descriptor
            .content_size
            .is_some_and(|declared| frame_size as u64 > declared)
        {
            return Err(compression_error(
                frame_start,
                "LZ4 frame exceeds declared content size",
            ));
        }
        let output_capacity = output
            .len()
            .checked_add(decoded.len())
            .ok_or_else(|| compression_error(reader.offset, "decompressed output overflow"))?;
        allocation::try_reserve_vec_exact(
            output,
            output_capacity,
            guard,
            "decompressed output allocation failed",
        )?;
        content_hasher.write(&decoded);
        output.extend_from_slice(&decoded);
    }
}

fn read_descriptor(
    reader: &mut CountingReader,
    guard: &dyn WorkGuard,
    frame_start: u64,
) -> Result<FrameDescriptor, ProviderError> {
    let mut descriptor = [0_u8; 14];
    reader.read_lz4_exact(
        &mut descriptor[..2],
        guard,
        "truncated LZ4 frame descriptor",
    )?;
    let flg = descriptor[0];
    let bd = descriptor[1];
    if flg >> 6 != 1 || flg & 0x02 != 0 {
        return Err(compression_error(frame_start, "invalid LZ4 frame flags"));
    }
    if bd & 0x8f != 0 {
        return Err(compression_error(
            frame_start,
            "invalid LZ4 frame block descriptor",
        ));
    }
    let block_maximum = match (bd >> 4) & 0x07 {
        4 => 64 * 1024,
        5 => 256 * 1024,
        6 => 1024 * 1024,
        7 => 4 * 1024 * 1024,
        _ => {
            return Err(compression_error(
                frame_start,
                "invalid LZ4 frame block size",
            ));
        }
    };

    let mut descriptor_len = 2;
    let content_size = if flg & 0x08 != 0 {
        reader.read_lz4_exact(
            &mut descriptor[descriptor_len..descriptor_len + 8],
            guard,
            "truncated LZ4 content size",
        )?;
        let value = u64::from_le_bytes(
            descriptor[descriptor_len..descriptor_len + 8]
                .try_into()
                .map_err(|_| compression_error(frame_start, "invalid LZ4 content size"))?,
        );
        descriptor_len += 8;
        Some(value)
    } else {
        None
    };
    let dictionary_id = if flg & 0x01 != 0 {
        reader.read_lz4_exact(
            &mut descriptor[descriptor_len..descriptor_len + 4],
            guard,
            "truncated LZ4 dictionary ID",
        )?;
        let value = u32::from_le_bytes(
            descriptor[descriptor_len..descriptor_len + 4]
                .try_into()
                .map_err(|_| compression_error(frame_start, "invalid LZ4 dictionary ID"))?,
        );
        descriptor_len += 4;
        Some(value)
    } else {
        None
    };
    let mut header_checksum = [0_u8; 1];
    reader.read_lz4_exact(&mut header_checksum, guard, "truncated LZ4 header checksum")?;
    if header_checksum[0] != (checksum(&descriptor[..descriptor_len]) >> 8) as u8 {
        return Err(compression_error(
            frame_start,
            "invalid LZ4 header checksum",
        ));
    }
    Ok(FrameDescriptor {
        independent: flg & 0x20 != 0,
        block_checksum: flg & 0x10 != 0,
        content_checksum: flg & 0x04 != 0,
        content_size,
        dictionary_id,
        block_maximum,
    })
}

fn read_checksum(
    reader: &mut CountingReader,
    guard: &dyn WorkGuard,
    truncated: &str,
) -> Result<u32, ProviderError> {
    let mut bytes = [0_u8; 4];
    reader.read_lz4_exact(&mut bytes, guard, truncated)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_pre_authorized(
    reader: &mut CountingReader,
    output: &mut [u8],
    truncated: &str,
) -> Result<(), ProviderError> {
    let mut filled = 0;
    while filled < output.len() {
        match reader.inner.read(&mut output[filled..]) {
            Ok(0) => return Err(compression_error(reader.offset, truncated)),
            Ok(count) if count <= output.len() - filled => {
                filled = filled.checked_add(count).ok_or_else(|| {
                    compression_error(reader.offset, "compressed input length overflow")
                })?;
                reader.advance(count, compression_error)?;
            }
            Ok(_) => {
                return Err(compression_error(
                    reader.offset,
                    "compressed reader over-reported bytes",
                ));
            }
            Err(error) => return Err(compression_error(reader.offset, &error.to_string())),
        }
    }
    Ok(())
}

fn checksum(bytes: &[u8]) -> u32 {
    let mut hasher = XxHash32::with_seed(0);
    hasher.write(bytes);
    hasher.finish_32()
}

fn input_error(offset: u64, detail: &str) -> ProviderError {
    ProviderError::new(
        "source.qtrb.io",
        "qtrb.input",
        Some(crate::SourceCoordinate {
            offset,
            record_ordinal: None,
        }),
        false,
        detail,
    )
}

fn compression_error(offset: u64, detail: &str) -> ProviderError {
    ProviderError::new(
        "source.qtrb.compression",
        "qtrb.compression",
        Some(crate::SourceCoordinate {
            offset,
            record_ordinal: None,
        }),
        false,
        detail,
    )
}
