//! Resource limits shared by application services and IPC deserializers.

use std::{fmt, io};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{SeqAccess, Visitor},
};

use crate::{AppError, EventFilterDto};

pub const MAX_FILTER_TERMS: usize = 256;
pub const MAX_FILTER_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_TEXT_BYTES: usize = 4096;
pub const MAX_COMMENT_BYTES: usize = 64 * 1024;
pub const MAX_CURSOR_BYTES: usize = 8192;
pub const MAX_SYMBOL_QUERIES: usize = 2000;
pub const MAX_MEMORY_DIRECTIONS: usize = 4;
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_WORKSPACE_EVENTS: u64 = u32::MAX as u64;

pub(crate) fn event_count(value: usize) -> Result<u32, AppError> {
    u32::try_from(value).map_err(|_| AppError::new(
        "workspace.event_limit_exceeded", "open",
        "artifact event count exceeds the supported maximum of 4294967295; workspace was not published",
    ))
}

pub(crate) fn view_event_count(view: &dyn qtrace_store::TraceStoreView) -> Result<u32, AppError> {
    event_count(view.event_count())
}

pub(crate) fn text(value: &str, maximum: usize, label: &str) -> Result<(), AppError> {
    if value.len() > maximum {
        return Err(AppError::new(
            "ipc.input_too_large",
            "ipc",
            format!("{label} exceeds {maximum} bytes"),
        ));
    }
    Ok(())
}

pub(crate) fn items(count: usize, maximum: usize, label: &str) -> Result<(), AppError> {
    if count > maximum {
        return Err(AppError::new(
            "ipc.input_too_large",
            "ipc",
            format!("{label} exceeds {maximum} items"),
        ));
    }
    Ok(())
}

pub(crate) fn filter(value: &EventFilterDto) -> Result<(), AppError> {
    let lengths = [
        value.tids.len(),
        value.kinds.len(),
        value.modules.len(),
        value.relative_pc.len(),
        value.absolute_pc.len(),
        value.sequence.len(),
        value.mnemonic.len(),
        value.register_reads.len(),
        value.register_writes.len(),
        value.memory.len(),
        value.semantic_categories.len(),
        value.semantic_names.len(),
        value.semantic_detail_contains.len(),
    ];
    let count = lengths
        .into_iter()
        .try_fold(0usize, |total, length| total.checked_add(length))
        .ok_or_else(|| AppError::new("ipc.input_too_large", "ipc", "filter item count overflow"))?;
    items(count, MAX_FILTER_TERMS, "filter")?;
    let mut bytes = 0usize;
    let mut add = |value: &str| -> Result<(), AppError> {
        text(value, MAX_TEXT_BYTES, "filter text")?;
        bytes = bytes.checked_add(value.len()).ok_or_else(|| {
            AppError::new("ipc.input_too_large", "ipc", "filter text size overflow")
        })?;
        if bytes > MAX_FILTER_TEXT_BYTES {
            return Err(AppError::new(
                "ipc.input_too_large",
                "ipc",
                "filter text exceeds 65536 bytes",
            ));
        }
        Ok(())
    };
    for values in [
        &value.kinds,
        &value.register_reads,
        &value.register_writes,
        &value.semantic_categories,
        &value.semantic_names,
        &value.semantic_detail_contains,
    ] {
        for value in values {
            add(value)?;
        }
    }
    for matcher in &value.mnemonic {
        add(&matcher.mode)?;
        add(&matcher.value)?;
    }
    for memory in &value.memory {
        items(
            memory.directions.len(),
            MAX_MEMORY_DIRECTIONS,
            "memory directions",
        )?;
        for direction in &memory.directions {
            add(direction)?;
        }
    }
    Ok(())
}

pub(crate) fn output<T: Serialize>(value: T) -> Result<T, AppError> {
    check_output(&value)?;
    Ok(value)
}

pub(crate) fn check_output(value: &impl Serialize) -> Result<(), AppError> {
    struct Counter(usize);
    impl io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|total| *total <= MAX_RESPONSE_BYTES)
                .ok_or_else(|| io::Error::other("IPC response exceeds byte limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Counter(0), value).map_err(|error| {
        AppError::new(
            "ipc.response_too_large",
            "ipc",
            format!("response exceeds {MAX_RESPONSE_BYTES} serialized bytes: {error}"),
        )
    })
}

fn strings<'de, D: Deserializer<'de>, const MAXIMUM: usize>(d: D) -> Result<String, D::Error> {
    struct Text<const MAXIMUM: usize>;
    impl<'de, const MAXIMUM: usize> Visitor<'de> for Text<MAXIMUM> {
        type Value = String;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "a string of at most {MAXIMUM} bytes")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<String, E> {
            if value.len() > MAXIMUM {
                return Err(E::custom("IPC string exceeds byte limit"));
            }
            Ok(value.to_owned())
        }
        fn visit_string<E: serde::de::Error>(self, value: String) -> Result<String, E> {
            if value.len() > MAXIMUM {
                return Err(E::custom("IPC string exceeds byte limit"));
            }
            Ok(value)
        }
    }
    d.deserialize_string(Text::<MAXIMUM>)
}

fn values<'de, D: Deserializer<'de>, T: Deserialize<'de>, const MAXIMUM: usize>(
    d: D,
) -> Result<Vec<T>, D::Error> {
    struct Values<T, const MAXIMUM: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const MAXIMUM: usize> Visitor<'de> for Values<T, MAXIMUM> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "an array of at most {MAXIMUM} items")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Vec<T>, A::Error> {
            if sequence.size_hint().is_some_and(|length| length > MAXIMUM) {
                return Err(serde::de::Error::custom("IPC array exceeds item limit"));
            }
            let mut output = Vec::new();
            while let Some(value) = sequence.next_element()? {
                if output.len() == MAXIMUM {
                    return Err(serde::de::Error::custom("IPC array exceeds item limit"));
                }
                output.push(value);
            }
            Ok(output)
        }
    }
    d.deserialize_seq(Values::<T, MAXIMUM>(std::marker::PhantomData))
}

pub fn deserialize_filter_items<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Vec<T>, D::Error> {
    values::<D, T, MAX_FILTER_TERMS>(d)
}
pub fn deserialize_symbol_queries<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Vec<T>, D::Error> {
    values::<D, T, MAX_SYMBOL_QUERIES>(d)
}
pub fn deserialize_filter_strings<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<String>, D::Error> {
    text_values::<D, MAX_FILTER_TERMS>(d)
}
pub fn deserialize_memory_directions<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<String>, D::Error> {
    text_values::<D, MAX_MEMORY_DIRECTIONS>(d)
}
fn text_values<'de, D: Deserializer<'de>, const MAXIMUM: usize>(
    d: D,
) -> Result<Vec<String>, D::Error> {
    struct Text(String);
    impl<'de> Deserialize<'de> for Text {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            deserialize_text(d).map(Text)
        }
    }
    values::<D, Text, MAXIMUM>(d).map(|values| values.into_iter().map(|value| value.0).collect())
}
pub fn deserialize_text<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    strings::<D, MAX_TEXT_BYTES>(d)
}
pub fn deserialize_identifier<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    strings::<D, 256>(d)
}
pub fn deserialize_comment<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    strings::<D, MAX_COMMENT_BYTES>(d)
}
pub fn deserialize_highlight<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    strings::<D, 256>(d)
}
pub fn deserialize_cursor<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    struct Cursor(String);
    impl<'de> Deserialize<'de> for Cursor {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            strings::<D, MAX_CURSOR_BYTES>(d).map(Cursor)
        }
    }
    Option::<Cursor>::deserialize(d).map(|value| value.map(|value| value.0))
}
pub fn deserialize_optional_identifier<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<String>, D::Error> {
    struct Identifier(String);
    impl<'de> Deserialize<'de> for Identifier {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            deserialize_identifier(d).map(Identifier)
        }
    }
    Option::<Identifier>::deserialize(d).map(|value| value.map(|value| value.0))
}
pub fn deserialize_build_id<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    struct BuildId(Vec<u8>);
    impl<'de> Deserialize<'de> for BuildId {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            values::<D, u8, MAX_TEXT_BYTES>(d).map(BuildId)
        }
    }
    Option::<BuildId>::deserialize(d).map(|value| value.map(|value| value.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_event_count_boundary_needs_no_large_trace() {
        assert_eq!(event_count(u32::MAX as usize).unwrap(), u32::MAX);
        if let Ok(too_many) = usize::try_from(u64::from(u32::MAX) + 1) {
            let error = event_count(too_many).unwrap_err();
            assert_eq!(error.code, "workspace.event_limit_exceeded");
            assert_eq!(error.stage, "open");
        }
    }

    #[test]
    fn filter_limits_apply_to_aggregate_terms_and_text() {
        let mut filter = EventFilterDto {
            tids: vec![1; MAX_FILTER_TERMS],
            ..Default::default()
        };
        super::filter(&filter).unwrap();
        filter.modules.push(1);
        assert_eq!(
            super::filter(&filter).unwrap_err().code,
            "ipc.input_too_large"
        );
        filter = EventFilterDto {
            semantic_detail_contains: vec!["x".repeat(MAX_TEXT_BYTES); 17],
            ..Default::default()
        };
        assert_eq!(
            super::filter(&filter).unwrap_err().code,
            "ipc.input_too_large"
        );
    }

    #[test]
    fn filter_deserialization_stops_excess_arrays_and_strings() {
        let input = serde_json::json!({ "tids": vec![1; MAX_FILTER_TERMS + 1] });
        assert!(serde_json::from_value::<EventFilterDto>(input).is_err());
        let input = serde_json::json!({ "semantic_names": ["x".repeat(MAX_TEXT_BYTES + 1)] });
        assert!(serde_json::from_value::<EventFilterDto>(input).is_err());
        let input = serde_json::json!({ "memory": [{ "range": { "start": "0x1", "end_exclusive": "0x2" }, "directions": vec!["read"; MAX_FILTER_TERMS + 1] }] });
        assert!(serde_json::from_value::<EventFilterDto>(input).is_err());
        assert_eq!(
            serde_json::from_str::<EventFilterDto>("{}").unwrap(),
            EventFilterDto::default()
        );
    }

    #[test]
    fn memory_filter_retains_all_four_existing_direction_variants() {
        let input = serde_json::json!({ "memory": [{
            "range": { "start": "0x1", "end_exclusive": "0x2" },
            "directions": ["read", "write", "readwrite", "unknown"],
        }] });
        let filter: EventFilterDto = serde_json::from_value(input).unwrap();
        super::filter(&filter).unwrap();
    }

    #[test]
    fn an_untrusted_array_size_hint_is_rejected_before_reading_elements() {
        struct HugeHint;
        impl Iterator for HugeHint {
            type Item = u32;
            fn next(&mut self) -> Option<u32> {
                panic!("oversized array should not be read")
            }
            fn size_hint(&self) -> (usize, Option<usize>) {
                (usize::MAX, Some(usize::MAX))
            }
        }
        let sequence =
            serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(HugeHint);
        assert!(deserialize_filter_items::<_, u32>(sequence).is_err());
    }

    #[test]
    fn response_limit_counts_json_escaping_without_an_encoded_copy() {
        check_output(&vec!["bounded"; 100]).unwrap();
        let escaped = "\0".repeat(MAX_RESPONSE_BYTES / 6 + 1);
        assert_eq!(
            check_output(&escaped).unwrap_err().code,
            "ipc.response_too_large"
        );
    }
}

#[cfg(test)]
mod row_limit_tests;
