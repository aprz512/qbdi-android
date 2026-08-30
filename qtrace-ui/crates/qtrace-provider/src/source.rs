use std::sync::Arc;

use crate::{
    EventRecord, ProviderCapabilities, ProviderError, ProviderSummary, SourceCoordinate,
    SourceIdentity, TimelineDescriptor, WorkGuard,
};

#[allow(clippy::len_without_is_empty)]
pub trait ReadAtSource: Send + Sync {
    fn len(&self) -> u64;
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), ProviderError>;
}

pub trait EventCursor {
    fn next_event(&mut self, guard: &dyn WorkGuard) -> Result<Option<EventRecord>, ProviderError>;
    fn finish(self: Box<Self>) -> Result<ProviderSummary, ProviderError>;
}

pub trait TraceProvider: Send + Sync {
    fn identity(&self) -> &SourceIdentity;
    fn capabilities(&self) -> &ProviderCapabilities;
    fn timelines(&self) -> &[TimelineDescriptor];
    fn into_cursor(self: Box<Self>) -> Result<Box<dyn EventCursor>, ProviderError>;
}

#[derive(Clone, Debug)]
pub struct ByteSource {
    bytes: Arc<[u8]>,
}

impl ByteSource {
    pub fn new(bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }
}

impl ReadAtSource for ByteSource {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), ProviderError> {
        let requested = output.len() as u64;
        let Some(end) = offset.checked_add(requested) else {
            return Err(short_read(offset, requested, self.len()));
        };
        if end > self.len() {
            return Err(short_read(offset, requested, self.len()));
        }

        let start =
            usize::try_from(offset).map_err(|_| short_read(offset, requested, self.len()))?;
        let end = usize::try_from(end).map_err(|_| short_read(offset, requested, self.len()))?;
        output.copy_from_slice(&self.bytes[start..end]);
        Ok(())
    }
}

fn short_read(offset: u64, requested: u64, source_len: u64) -> ProviderError {
    ProviderError::new(
        "source.short_read",
        "read",
        Some(SourceCoordinate {
            offset,
            record_ordinal: None,
        }),
        false,
        format!(
            "requested {requested} bytes at offset {offset}, but only {} remain",
            source_len.saturating_sub(offset)
        ),
    )
}
