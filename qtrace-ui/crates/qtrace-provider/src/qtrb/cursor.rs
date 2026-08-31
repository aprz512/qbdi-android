use crate::{ProviderError, SourceCoordinate, WorkGuard, allocation};

pub(super) struct PayloadCursor<'a> {
    bytes: &'a [u8],
    position: usize,
    label: &'static str,
    coordinate: SourceCoordinate,
}

impl<'a> PayloadCursor<'a> {
    pub(super) const fn new(
        bytes: &'a [u8],
        label: &'static str,
        coordinate: SourceCoordinate,
    ) -> Self {
        Self {
            bytes,
            position: 0,
            label,
            coordinate,
        }
    }

    pub(super) fn take(&mut self, size: usize) -> Result<&'a [u8], ProviderError> {
        let Some(end) = self.position.checked_add(size) else {
            return Err(self.invalid_length());
        };
        let Some(result) = self.bytes.get(self.position..end) else {
            return Err(self.invalid_length());
        };
        self.position = end;
        Ok(result)
    }

    pub(super) fn u8(&mut self) -> Result<u8, ProviderError> {
        Ok(self.take(1)?[0])
    }

    pub(super) fn u16_le(&mut self) -> Result<u16, ProviderError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(super) fn u32_le(&mut self) -> Result<u32, ProviderError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(super) fn u64_le(&mut self) -> Result<u64, ProviderError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(super) fn i64_le(&mut self) -> Result<i64, ProviderError> {
        let bytes = self.take(8)?;
        Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(super) fn bounded_utf8_guarded(
        &mut self,
        maximum: usize,
        field: &'static str,
        guard: &dyn WorkGuard,
    ) -> Result<String, ProviderError> {
        let size = usize::from(self.u16_le()?);
        if size > maximum {
            return Err(ProviderError::new(
                "source.invalid_payload",
                "qtrb.payload",
                Some(self.coordinate),
                false,
                format!("{field} exceeds {maximum} bytes"),
            ));
        }
        let raw = self.take(size)?;
        let value = std::str::from_utf8(raw).map_err(|_| {
            ProviderError::new(
                "source.invalid_utf8",
                "qtrb.payload",
                Some(self.coordinate),
                false,
                format!("{field} is not valid UTF-8"),
            )
        })?;
        allocation::try_copy_string(value, guard, "QTRB string allocation failed")
    }

    pub(super) fn finish(self) -> Result<(), ProviderError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(self.invalid_length())
        }
    }

    fn invalid_length(&self) -> ProviderError {
        ProviderError::new(
            "source.invalid_payload",
            "qtrb.payload",
            Some(self.coordinate),
            false,
            format!("invalid {} payload length", self.label),
        )
    }
}
