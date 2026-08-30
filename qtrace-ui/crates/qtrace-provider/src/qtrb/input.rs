use std::io::{Cursor, Read};
use std::sync::Arc;

use lz4_flex::frame::FrameDecoder;

use crate::{ByteSource, ProviderError, WorkDelta, WorkGuard};

const STANDARD_FRAME_MAGIC: [u8; 4] = 0x184d_2204_u32.to_le_bytes();
const INPUT_CHUNK_BYTES: usize = 16 * 1024;
const OUTPUT_CHUNK_BYTES: usize = 64 * 1024;

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
    /// Compressed input is read and decoded incrementally; no intermediate trace
    /// file is created. The returned bytes use one cumulative decompressed offset
    /// across every concatenated frame.
    pub fn into_source(self, guard: &dyn WorkGuard) -> Result<Arc<ByteSource>, ProviderError> {
        let compressed = CountingReader::new(self.reader).read_all(guard)?;
        let bytes = match self.encoding {
            InputEncoding::Raw => compressed,
            InputEncoding::Lz4 => ConcatenatedFrameReader::decode(&compressed, guard)?,
        };
        Ok(Arc::new(ByteSource::new(bytes)))
    }
}

struct CountingReader {
    inner: Box<dyn Read + Send>,
    total: u64,
}

impl CountingReader {
    fn new(inner: Box<dyn Read + Send>) -> Self {
        Self { inner, total: 0 }
    }

    fn read_all(mut self, guard: &dyn WorkGuard) -> Result<Vec<u8>, ProviderError> {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; INPUT_CHUNK_BYTES];
        loop {
            guard.consume(WorkDelta {
                input_bytes: INPUT_CHUNK_BYTES as u64,
                resident_bytes: INPUT_CHUNK_BYTES as u64,
                ..WorkDelta::default()
            })?;
            bytes
                .try_reserve_exact(INPUT_CHUNK_BYTES)
                .map_err(|_| compression_error(self.total, "compressed input allocation failed"))?;
            let count = self
                .inner
                .read(&mut chunk)
                .map_err(|error| compression_error(self.total, &error.to_string()))?;
            if count == 0 {
                return Ok(bytes);
            }
            self.total = self
                .total
                .checked_add(count as u64)
                .ok_or_else(|| compression_error(self.total, "compressed input offset overflow"))?;
            bytes.extend_from_slice(&chunk[..count]);
        }
    }
}

struct ConcatenatedFrameReader;

impl ConcatenatedFrameReader {
    fn decode(compressed: &[u8], guard: &dyn WorkGuard) -> Result<Vec<u8>, ProviderError> {
        if compressed.is_empty() {
            return Err(compression_error(
                0,
                "compressed input contains zero frames",
            ));
        }

        let mut output = Vec::new();
        let mut compressed_offset = 0_usize;
        let mut frames = 0_u64;
        while compressed_offset < compressed.len() {
            let layout = frame_layout(compressed, compressed_offset)?;
            guard.consume(WorkDelta {
                nodes: 1,
                resident_bytes: layout.workspace_bytes,
                ..WorkDelta::default()
            })?;
            let frame = &compressed[compressed_offset..layout.end];
            let mut decoder = FrameDecoder::new(Cursor::new(frame));
            let mut chunk = [0_u8; OUTPUT_CHUNK_BYTES];
            loop {
                guard.consume(WorkDelta {
                    decompressed_bytes: OUTPUT_CHUNK_BYTES as u64,
                    resident_bytes: OUTPUT_CHUNK_BYTES as u64,
                    ..WorkDelta::default()
                })?;
                output.try_reserve_exact(OUTPUT_CHUNK_BYTES).map_err(|_| {
                    compression_error(
                        compressed_offset as u64,
                        "decompressed output allocation failed",
                    )
                })?;
                let count = decoder.read(&mut chunk).map_err(|error| {
                    compression_error(compressed_offset as u64, &error.to_string())
                })?;
                if count == 0 {
                    let consumed = usize::try_from(decoder.get_ref().position()).map_err(|_| {
                        compression_error(compressed_offset as u64, "frame offset overflow")
                    })?;
                    if consumed == frame.len() {
                        break;
                    }
                    continue;
                }
                output.extend_from_slice(&chunk[..count]);
            }
            let consumed = usize::try_from(decoder.into_inner().position()).map_err(|_| {
                compression_error(compressed_offset as u64, "frame offset overflow")
            })?;
            if consumed != frame.len() {
                return Err(compression_error(
                    compressed_offset as u64,
                    "decoder did not consume exactly one complete frame",
                ));
            }
            compressed_offset = layout.end;
            frames = frames.saturating_add(1);
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

struct FrameLayout {
    end: usize,
    workspace_bytes: u64,
}

fn frame_layout(bytes: &[u8], start: usize) -> Result<FrameLayout, ProviderError> {
    let magic = bytes.get(start..start.saturating_add(4));
    if magic != Some(STANDARD_FRAME_MAGIC.as_slice()) {
        return Err(compression_error(
            start as u64,
            "expected standard LZ4 frame magic",
        ));
    }
    let flg = *bytes
        .get(start.saturating_add(4))
        .ok_or_else(|| compression_error(start as u64, "truncated LZ4 frame header"))?;
    let bd = *bytes
        .get(start.saturating_add(5))
        .ok_or_else(|| compression_error(start as u64, "truncated LZ4 frame header"))?;
    let descriptor_bytes = 7_usize
        .saturating_add(if flg & 0x08 != 0 { 8 } else { 0 })
        .saturating_add(if flg & 0x01 != 0 { 4 } else { 0 });
    let mut offset = start
        .checked_add(descriptor_bytes)
        .ok_or_else(|| compression_error(start as u64, "LZ4 frame offset overflow"))?;
    if offset > bytes.len() {
        return Err(compression_error(
            start as u64,
            "truncated LZ4 frame descriptor",
        ));
    }
    let block_bytes = match (bd >> 4) & 0x07 {
        4 => 64 * 1024,
        5 => 256 * 1024,
        6 => 1024 * 1024,
        7 => 4 * 1024 * 1024,
        _ => {
            return Err(compression_error(
                start as u64,
                "invalid LZ4 frame block size",
            ));
        }
    };
    loop {
        let header = bytes
            .get(offset..offset.saturating_add(4))
            .ok_or_else(|| compression_error(start as u64, "truncated LZ4 frame block header"))?;
        let encoded =
            u32::from_le_bytes(header.try_into().map_err(|_| {
                compression_error(start as u64, "truncated LZ4 frame block header")
            })?);
        offset = offset
            .checked_add(4)
            .ok_or_else(|| compression_error(start as u64, "LZ4 frame offset overflow"))?;
        if encoded == 0 {
            if flg & 0x04 != 0 {
                offset = offset
                    .checked_add(4)
                    .ok_or_else(|| compression_error(start as u64, "LZ4 frame offset overflow"))?;
            }
            if offset > bytes.len() {
                return Err(compression_error(
                    start as u64,
                    "truncated LZ4 frame checksum",
                ));
            }
            let workspace_bytes = if flg & 0x20 == 0 {
                (block_bytes as u64)
                    .saturating_mul(3)
                    .saturating_add(64 * 1024)
            } else {
                (block_bytes as u64).saturating_mul(2)
            };
            return Ok(FrameLayout {
                end: offset,
                workspace_bytes,
            });
        }
        let payload_bytes = usize::try_from(encoded & 0x7fff_ffff)
            .map_err(|_| compression_error(start as u64, "LZ4 block length overflow"))?;
        if payload_bytes > block_bytes {
            return Err(compression_error(
                start as u64,
                "invalid LZ4 frame block length",
            ));
        }
        offset = offset
            .checked_add(payload_bytes)
            .and_then(|value| value.checked_add(if flg & 0x10 != 0 { 4 } else { 0 }))
            .ok_or_else(|| compression_error(start as u64, "LZ4 frame offset overflow"))?;
        if offset > bytes.len() {
            return Err(compression_error(start as u64, "truncated LZ4 frame block"));
        }
    }
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
