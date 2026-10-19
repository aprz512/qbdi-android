//! Strict canonical discontinuity payload decoding. No heap-backed JSON tree is built.

use qtrace_provider::Provenance;

use super::{AnalysisError, ParsedDiscontinuity};

pub(crate) fn decode_discontinuity_payload(
    payload: &[u8],
) -> Result<ParsedDiscontinuity, AnalysisError> {
    parse_discontinuity_payload(payload).map_err(discontinuity_parse_error)
}

fn discontinuity_parse_error(error: RawDiscontinuityTagError) -> AnalysisError {
    match error {
        RawDiscontinuityTagError::WrongVariant => {
            AnalysisError::store_shape("discontinuity row payload has the wrong event kind")
        }
        RawDiscontinuityTagError::Malformed => {
            AnalysisError::store_shape("invalid discontinuity payload tag")
        }
        RawDiscontinuityTagError::Escape => {
            AnalysisError::store_shape("discontinuity payload must use canonical unescaped JSON")
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RawDiscontinuityTagError {
    WrongVariant,
    Malformed,
    Escape,
}

struct CanonicalJsonCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CanonicalJsonCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn skip_whitespace(&mut self) {
        while self
            .bytes
            .get(self.offset)
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.offset += 1;
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), RawDiscontinuityTagError> {
        self.skip_whitespace();
        if self.bytes.get(self.offset) != Some(&expected) {
            return Err(RawDiscontinuityTagError::Malformed);
        }
        self.offset += 1;
        Ok(())
    }

    fn token(&mut self) -> Result<&'a [u8], RawDiscontinuityTagError> {
        self.skip_whitespace();
        if self.bytes.get(self.offset) != Some(&b'"') {
            return Err(RawDiscontinuityTagError::Malformed);
        }
        self.offset += 1;
        let start = self.offset;
        while let Some(byte) = self.bytes.get(self.offset).copied() {
            match byte {
                b'"' => {
                    let token = &self.bytes[start..self.offset];
                    self.offset += 1;
                    return Ok(token);
                }
                b'\\' => return Err(RawDiscontinuityTagError::Escape),
                0x20..=0x7f => self.offset += 1,
                _ => return Err(RawDiscontinuityTagError::Malformed),
            }
        }
        Err(RawDiscontinuityTagError::Malformed)
    }

    fn member(&mut self, first: &mut bool) -> Result<Option<&'a [u8]>, RawDiscontinuityTagError> {
        self.skip_whitespace();
        if self.bytes.get(self.offset) == Some(&b'}') {
            self.offset += 1;
            return Ok(None);
        }
        if !*first {
            self.expect(b',')?;
        }
        *first = false;
        let key = self.token()?;
        self.expect(b':')?;
        Ok(Some(key))
    }

    fn number(&mut self) -> Result<u64, RawDiscontinuityTagError> {
        self.skip_whitespace();
        let start = self.offset;
        let first = self
            .bytes
            .get(self.offset)
            .copied()
            .filter(u8::is_ascii_digit)
            .ok_or(RawDiscontinuityTagError::Malformed)?;
        self.offset += 1;
        if first == b'0' && self.bytes.get(self.offset).is_some_and(u8::is_ascii_digit) {
            return Err(RawDiscontinuityTagError::Malformed);
        }
        let mut value = u64::from(first - b'0');
        while let Some(byte) = self
            .bytes
            .get(self.offset)
            .copied()
            .filter(u8::is_ascii_digit)
        {
            if self.offset - start == 20 {
                return Err(RawDiscontinuityTagError::Malformed);
            }
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(u64::from(byte - b'0')))
                .ok_or(RawDiscontinuityTagError::Malformed)?;
            self.offset += 1;
        }
        Ok(value)
    }

    fn finish(mut self) -> Result<(), RawDiscontinuityTagError> {
        self.skip_whitespace();
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(RawDiscontinuityTagError::Malformed)
        }
    }
}

fn parse_discontinuity_payload(
    payload: &[u8],
) -> Result<ParsedDiscontinuity, RawDiscontinuityTagError> {
    let mut cursor = CanonicalJsonCursor::new(payload);
    cursor.expect(b'{')?;
    let mut first = true;
    let key = cursor
        .member(&mut first)?
        .ok_or(RawDiscontinuityTagError::Malformed)?;
    if key != b"discontinuity" {
        return Err(RawDiscontinuityTagError::WrongVariant);
    }
    let discontinuity = parse_discontinuity_object(&mut cursor)?;
    if cursor.member(&mut first)?.is_some() {
        return Err(RawDiscontinuityTagError::Malformed);
    }
    cursor.finish()?;
    Ok(discontinuity)
}

fn parse_discontinuity_object(
    cursor: &mut CanonicalJsonCursor<'_>,
) -> Result<ParsedDiscontinuity, RawDiscontinuityTagError> {
    cursor.expect(b'{')?;
    let mut first = true;
    let mut fields = 0_u8;
    let mut cause = None;
    let mut evidence = None;
    while let Some(key) = cursor.member(&mut first)? {
        match key {
            b"cause" => {
                set_field(&mut fields, 1)?;
                cause = Some(parse_discontinuity_cause(cursor.token()?)?);
            }
            b"evidence" => {
                set_field(&mut fields, 2)?;
                evidence = Some(parse_completeness_range(cursor)?);
            }
            _ => return Err(RawDiscontinuityTagError::Malformed),
        }
    }
    if fields != 3 {
        return Err(RawDiscontinuityTagError::Malformed);
    }
    Ok(ParsedDiscontinuity {
        cause: cause.ok_or(RawDiscontinuityTagError::Malformed)?,
        evidence: evidence.ok_or(RawDiscontinuityTagError::Malformed)?,
    })
}

fn parse_completeness_range(
    cursor: &mut CanonicalJsonCursor<'_>,
) -> Result<qtrace_provider::CompletenessRange, RawDiscontinuityTagError> {
    cursor.expect(b'{')?;
    let mut first = true;
    let mut fields = 0_u8;
    let mut domain = None;
    let mut bounds = None;
    let mut provenance = None;
    let mut cause = None;
    while let Some(key) = cursor.member(&mut first)? {
        match key {
            b"domain" => {
                set_field(&mut fields, 1)?;
                domain = Some(parse_range_domain(cursor.token()?)?);
            }
            b"bounds" => {
                set_field(&mut fields, 2)?;
                bounds = Some(parse_range_bounds(cursor)?);
            }
            b"provenance" => {
                set_field(&mut fields, 4)?;
                provenance = Some(parse_provenance(cursor.token()?)?);
            }
            b"cause" => {
                set_field(&mut fields, 8)?;
                cause = Some(parse_completeness_cause(cursor.token()?)?);
            }
            _ => return Err(RawDiscontinuityTagError::Malformed),
        }
    }
    if fields != 15 {
        return Err(RawDiscontinuityTagError::Malformed);
    }
    let domain = domain.ok_or(RawDiscontinuityTagError::Malformed)?;
    let bounds = bounds.ok_or(RawDiscontinuityTagError::Malformed)?;
    let provenance = provenance.ok_or(RawDiscontinuityTagError::Malformed)?;
    let cause = cause.ok_or(RawDiscontinuityTagError::Malformed)?;
    match (domain, bounds) {
        (
            qtrace_provider::RangeDomain::CapturedSequence,
            qtrace_provider::RangeBounds::InclusiveSequence { first, last },
        ) => qtrace_provider::CompletenessRange::captured_sequence_with_cause(
            first, last, provenance, cause,
        ),
        (
            qtrace_provider::RangeDomain::SourceBytes,
            qtrace_provider::RangeBounds::HalfOpen {
                start,
                end_exclusive,
            },
        ) => qtrace_provider::CompletenessRange::source_bytes_with_cause(
            start,
            end_exclusive,
            provenance,
            cause,
        ),
        (
            qtrace_provider::RangeDomain::MemoryAddresses,
            qtrace_provider::RangeBounds::HalfOpen {
                start,
                end_exclusive,
            },
        ) => qtrace_provider::CompletenessRange::memory_addresses_with_cause(
            start,
            end_exclusive,
            provenance,
            cause,
        ),
        _ => None,
    }
    .ok_or(RawDiscontinuityTagError::Malformed)
}

fn parse_range_bounds(
    cursor: &mut CanonicalJsonCursor<'_>,
) -> Result<qtrace_provider::RangeBounds, RawDiscontinuityTagError> {
    cursor.expect(b'{')?;
    let mut first = true;
    let key = cursor
        .member(&mut first)?
        .ok_or(RawDiscontinuityTagError::Malformed)?;
    let endpoints = match key {
        b"inclusive_sequence" => parse_number_pair(cursor, b"first", b"last")?,
        b"half_open" => parse_number_pair(cursor, b"start", b"end_exclusive")?,
        _ => return Err(RawDiscontinuityTagError::Malformed),
    };
    if cursor.member(&mut first)?.is_some() {
        return Err(RawDiscontinuityTagError::Malformed);
    }
    qtrace_provider::RangeBounds::from_wire_parts(key, endpoints)
        .ok_or(RawDiscontinuityTagError::Malformed)
}

fn parse_number_pair(
    cursor: &mut CanonicalJsonCursor<'_>,
    left_key: &[u8],
    right_key: &[u8],
) -> Result<(u64, u64), RawDiscontinuityTagError> {
    cursor.expect(b'{')?;
    let mut first = true;
    let mut fields = 0_u8;
    let mut left = None;
    let mut right = None;
    while let Some(key) = cursor.member(&mut first)? {
        if key == left_key {
            set_field(&mut fields, 1)?;
            left = Some(cursor.number()?);
        } else if key == right_key {
            set_field(&mut fields, 2)?;
            right = Some(cursor.number()?);
        } else {
            return Err(RawDiscontinuityTagError::Malformed);
        }
    }
    if fields != 3 {
        return Err(RawDiscontinuityTagError::Malformed);
    }
    Ok((
        left.ok_or(RawDiscontinuityTagError::Malformed)?,
        right.ok_or(RawDiscontinuityTagError::Malformed)?,
    ))
}

fn set_field(fields: &mut u8, bit: u8) -> Result<(), RawDiscontinuityTagError> {
    if *fields & bit != 0 {
        return Err(RawDiscontinuityTagError::Malformed);
    }
    *fields |= bit;
    Ok(())
}

fn parse_discontinuity_cause(
    token: &[u8],
) -> Result<qtrace_provider::DiscontinuityCause, RawDiscontinuityTagError> {
    qtrace_provider::DiscontinuityCause::from_wire_name(token)
        .ok_or(RawDiscontinuityTagError::Malformed)
}

fn parse_range_domain(
    token: &[u8],
) -> Result<qtrace_provider::RangeDomain, RawDiscontinuityTagError> {
    qtrace_provider::RangeDomain::from_wire_name(token).ok_or(RawDiscontinuityTagError::Malformed)
}

fn parse_provenance(token: &[u8]) -> Result<Provenance, RawDiscontinuityTagError> {
    Provenance::from_wire_name(token).ok_or(RawDiscontinuityTagError::Malformed)
}

fn parse_completeness_cause(
    token: &[u8],
) -> Result<qtrace_provider::CompletenessCause, RawDiscontinuityTagError> {
    qtrace_provider::CompletenessCause::from_wire_name(token)
        .ok_or(RawDiscontinuityTagError::Malformed)
}
