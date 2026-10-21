//! Compact, lossless JSON payloads and borrowed semantic text.
use qtrace_provider::EventPayload;
use serde::{Serialize, Serializer};

pub(super) const DETAIL_ROW_BIT: u32 = 1 << 31;

pub(super) struct Payload<'a>(pub &'a EventPayload);

impl Serialize for Payload<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let EventPayload::StringDefinition(value) = self.0
            && let Ok(bytes) = std::str::from_utf8(&value.bytes)
        {
            #[derive(Serialize)]
            struct Definition<'a> {
                id: u32,
                bytes: &'a str,
            }
            #[derive(Serialize)]
            #[serde(rename_all = "snake_case")]
            enum Compact<'a> {
                StringDefinition(Definition<'a>),
            }
            return Compact::StringDefinition(Definition {
                id: value.id,
                bytes,
            })
            .serialize(serializer);
        }
        self.0.serialize(serializer)
    }
}

// Only literal JSON text can be borrowed. Escaped text keeps its ordinary blob
// entry, so callers always receive the exact decoded UTF-8 bytes.
pub(super) fn literal_detail(bytes: &[u8]) -> Option<&[u8]> {
    if ![
        b"{\"semantic_call\":".as_slice(),
        b"{\"semantic_rule\":",
        b"{\"semantic_error\":",
    ]
    .iter()
    .any(|prefix| bytes.starts_with(prefix))
    {
        return None;
    }
    let marker = b",\"detail\":\"";
    let start = bytes
        .windows(marker.len())
        .position(|part| part == marker)?
        + marker.len();
    let rest = &bytes[start..];
    let end = rest.iter().position(|byte| matches!(byte, b'"' | b'\\'))?;
    (rest[end] == b'"').then_some(&rest[..end])
}
