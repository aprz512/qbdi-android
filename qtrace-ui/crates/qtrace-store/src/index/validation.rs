use qtrace_provider::EventKind;

use super::IndexError;

const fn invalid(detail: &'static str) -> &'static str {
    detail
}

pub(super) fn validate_external_payload_tag(
    bytes: &[u8],
    expected: EventKind,
) -> Result<(), IndexError> {
    scan_external_payload_tag(bytes, expected).map_err(IndexError::corrupt)
}

pub(super) fn scan_external_payload_tag(
    bytes: &[u8],
    expected: EventKind,
) -> Result<(), &'static str> {
    let mut scanner = JsonScanner { bytes, cursor: 0 };
    scanner.skip_whitespace();
    scanner.expect_byte(b'{')?;
    scanner.skip_whitespace();
    let tag = scanner.external_tag()?;
    if tag != expected {
        return Err(invalid(
            "canonical payload external tag disagrees with base kind",
        ));
    }
    scanner.skip_whitespace();
    scanner.expect_byte(b':')?;
    scanner.skip_whitespace();
    scanner.value(0)?;
    scanner.skip_whitespace();
    scanner.expect_byte(b'}')?;
    scanner.skip_whitespace();
    if scanner.cursor != bytes.len() {
        return Err(invalid(
            "canonical payload contains trailing or extra fields",
        ));
    }
    Ok(())
}

struct JsonScanner<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl JsonScanner<'_> {
    fn skip_whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.cursor),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.cursor += 1;
        }
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), &'static str> {
        if self.bytes.get(self.cursor).copied() != Some(expected) {
            return Err(invalid("canonical payload has malformed JSON structure"));
        }
        self.cursor += 1;
        Ok(())
    }

    fn external_tag(&mut self) -> Result<EventKind, &'static str> {
        self.expect_byte(b'"')?;
        let start = self.cursor;
        while let Some(byte) = self.bytes.get(self.cursor).copied() {
            match byte {
                b'"' => {
                    let tag = &self.bytes[start..self.cursor];
                    self.cursor += 1;
                    return EventKind::from_external_tag(tag)
                        .ok_or_else(|| invalid("canonical payload has an unknown external tag"));
                }
                b'\\' | 0..=0x1f | 0x80..=0xff => {
                    return Err(invalid(
                        "canonical payload external tag must be literal ASCII",
                    ));
                }
                _ => self.cursor += 1,
            }
        }
        Err(invalid("canonical payload external tag is unterminated"))
    }

    fn value(&mut self, depth: u8) -> Result<(), &'static str> {
        if depth >= 64 {
            return Err(invalid("canonical payload JSON nesting exceeds its bound"));
        }
        match self.bytes.get(self.cursor).copied() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string(),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(invalid("canonical payload has a malformed JSON value")),
        }
    }

    fn object(&mut self, depth: u8) -> Result<(), &'static str> {
        self.expect_byte(b'{')?;
        self.skip_whitespace();
        if self.bytes.get(self.cursor) == Some(&b'}') {
            self.cursor += 1;
            return Ok(());
        }
        loop {
            self.string()?;
            self.skip_whitespace();
            self.expect_byte(b':')?;
            self.skip_whitespace();
            self.value(depth)?;
            self.skip_whitespace();
            match self.bytes.get(self.cursor).copied() {
                Some(b',') => {
                    self.cursor += 1;
                    self.skip_whitespace();
                }
                Some(b'}') => {
                    self.cursor += 1;
                    return Ok(());
                }
                _ => {
                    return Err(invalid("canonical payload has a malformed JSON object"));
                }
            }
        }
    }

    fn array(&mut self, depth: u8) -> Result<(), &'static str> {
        self.expect_byte(b'[')?;
        self.skip_whitespace();
        if self.bytes.get(self.cursor) == Some(&b']') {
            self.cursor += 1;
            return Ok(());
        }
        loop {
            self.value(depth)?;
            self.skip_whitespace();
            match self.bytes.get(self.cursor).copied() {
                Some(b',') => {
                    self.cursor += 1;
                    self.skip_whitespace();
                }
                Some(b']') => {
                    self.cursor += 1;
                    return Ok(());
                }
                _ => {
                    return Err(invalid("canonical payload has a malformed JSON array"));
                }
            }
        }
    }

    fn string(&mut self) -> Result<(), &'static str> {
        self.expect_byte(b'"')?;
        let mut raw_start = self.cursor;
        while let Some(byte) = self.bytes.get(self.cursor).copied() {
            match byte {
                b'"' => {
                    self.validate_raw_utf8(raw_start, self.cursor)?;
                    self.cursor += 1;
                    return Ok(());
                }
                b'\\' => {
                    self.validate_raw_utf8(raw_start, self.cursor)?;
                    self.cursor += 1;
                    self.escape()?;
                    raw_start = self.cursor;
                }
                0..=0x1f => {
                    return Err(invalid(
                        "canonical payload has a control byte in a JSON string",
                    ));
                }
                _ => self.cursor += 1,
            }
        }
        Err(invalid("canonical payload has an unterminated JSON string"))
    }

    fn validate_raw_utf8(&self, start: usize, end: usize) -> Result<(), &'static str> {
        std::str::from_utf8(&self.bytes[start..end])
            .map(|_| ())
            .map_err(|_| invalid("canonical payload string is not valid UTF-8"))
    }

    fn escape(&mut self) -> Result<(), &'static str> {
        match self.bytes.get(self.cursor).copied() {
            Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                self.cursor += 1;
                Ok(())
            }
            Some(b'u') => {
                self.cursor += 1;
                let first = self.hex_quad()?;
                if (0xd800..=0xdbff).contains(&first) {
                    if self.bytes.get(self.cursor..self.cursor.saturating_add(2)) != Some(b"\\u") {
                        return Err(invalid("canonical payload has an unpaired high surrogate"));
                    }
                    self.cursor += 2;
                    let second = self.hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(invalid("canonical payload has an invalid surrogate pair"));
                    }
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err(invalid("canonical payload has an unpaired low surrogate"));
                }
                Ok(())
            }
            _ => Err(invalid("canonical payload has a malformed JSON escape")),
        }
    }

    fn hex_quad(&mut self) -> Result<u16, &'static str> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let digit = match self.bytes.get(self.cursor).copied() {
                Some(b'0'..=b'9') => u16::from(self.bytes[self.cursor] - b'0'),
                Some(b'a'..=b'f') => u16::from(self.bytes[self.cursor] - b'a') + 10,
                Some(b'A'..=b'F') => u16::from(self.bytes[self.cursor] - b'A') + 10,
                _ => {
                    return Err(invalid("canonical payload has a malformed JSON escape"));
                }
            };
            value = (value << 4) | digit;
            self.cursor += 1;
        }
        Ok(value)
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), &'static str> {
        let end = self
            .cursor
            .checked_add(literal.len())
            .ok_or_else(|| invalid("canonical payload JSON offset overflow"))?;
        if self.bytes.get(self.cursor..end) != Some(literal) {
            return Err(invalid("canonical payload has a malformed JSON literal"));
        }
        self.cursor = end;
        Ok(())
    }

    fn number(&mut self) -> Result<(), &'static str> {
        if self.bytes.get(self.cursor) == Some(&b'-') {
            self.cursor += 1;
        }
        match self.bytes.get(self.cursor).copied() {
            Some(b'0') => self.cursor += 1,
            Some(b'1'..=b'9') => {
                self.cursor += 1;
                while matches!(self.bytes.get(self.cursor), Some(b'0'..=b'9')) {
                    self.cursor += 1;
                }
            }
            _ => {
                return Err(invalid("canonical payload has a malformed JSON number"));
            }
        }
        if self.bytes.get(self.cursor) == Some(&b'.') {
            self.cursor += 1;
            let start = self.cursor;
            while matches!(self.bytes.get(self.cursor), Some(b'0'..=b'9')) {
                self.cursor += 1;
            }
            if self.cursor == start {
                return Err(invalid("canonical payload has a malformed JSON fraction"));
            }
        }
        if matches!(self.bytes.get(self.cursor), Some(b'e' | b'E')) {
            self.cursor += 1;
            if matches!(self.bytes.get(self.cursor), Some(b'+' | b'-')) {
                self.cursor += 1;
            }
            let start = self.cursor;
            while matches!(self.bytes.get(self.cursor), Some(b'0'..=b'9')) {
                self.cursor += 1;
            }
            if self.cursor == start {
                return Err(invalid("canonical payload has a malformed JSON exponent"));
            }
        }
        Ok(())
    }
}
