use std::path::{Path, PathBuf};

use qtrace_service::{EventFilterDto, QtraceService};
use qtrace_store::AuthorizedPath;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fixtures/sessions")
        .join(name)
}

#[test]
fn real_mixed_session_crosses_provider_store_analysis_and_persistent_annotations() {
    let data = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let service = QtraceService::with_cache_root(cache.path().join("indexes"));
    let opened = service
        .open_session(AuthorizedPath::new(fixture("valid-mixed")))
        .unwrap();
    assert_eq!(opened.artifacts.len(), 3);
    let context = opened.context.as_ref().unwrap();
    assert_eq!(context.package.as_deref(), Some("com.example.fixture"));
    assert_eq!(context.device_serial.as_deref(), Some("fixture-device"));
    assert_eq!(context.device_access_mode.as_deref(), Some("run-as"));
    assert_eq!(context.target_module.as_deref(), Some("libtarget.so"));
    assert!(
        opened
            .missing_capabilities
            .contains(&"effective_config".to_owned())
    );
    assert!(
        opened
            .artifacts
            .iter()
            .all(|artifact| artifact.status == "indexed")
    );
    assert!(
        opened
            .artifacts
            .iter()
            .any(|artifact| !artifact.completeness.is_empty())
    );
    let artifact_tids = opened.artifacts[0].tids.clone();
    let workspace = opened.workspace.id;
    let projection = service
        .create_projection(&workspace, 0, EventFilterDto::default())
        .unwrap();
    let page = service
        .query_timeline(&workspace, &projection.projection_id, None, 2_000)
        .unwrap();
    assert!(page.rows.len() <= 2_000 && !page.rows.is_empty());
    let row = &page.rows[0];
    if let Some(tid) = row.key.tid {
        assert!(artifact_tids.contains(&tid));
    }
    let location = service
        .locate_timeline(&workspace, &projection.projection_id, row.source_row, 2_000)
        .unwrap()
        .expect("visible row location");
    assert_eq!(location.start, 0);
    assert!(location.cursor.is_none());
    let offset_location = service
        .locate_timeline_offset(&workspace, &projection.projection_id, 0, 2_000)
        .unwrap()
        .expect("visible offset location");
    assert_eq!(offset_location, location);
    service
        .get_event_detail(&workspace, 0, row.source_row)
        .unwrap();
    service
        .get_register_state(&workspace, 0, row.source_row)
        .unwrap();
    service
        .get_memory_state(&workspace, 0, row.source_row, 0, 1)
        .unwrap();
    service
        .upsert_annotation(
            &workspace,
            AuthorizedPath::new(data.path().to_owned()),
            0,
            row.source_row,
            "persistent".into(),
        )
        .unwrap();

    drop(service);
    assert!(
        cache
            .path()
            .join("indexes")
            .read_dir()
            .unwrap()
            .next()
            .is_some()
    );
    let restarted = QtraceService::with_cache_root(cache.path().join("indexes"));
    let reopened = restarted
        .open_session(AuthorizedPath::new(fixture("valid-mixed")))
        .unwrap();
    let annotation = restarted
        .get_annotation(
            &reopened.workspace.id,
            AuthorizedPath::new(data.path().to_owned()),
            0,
            row.source_row,
        )
        .unwrap()
        .unwrap();
    assert_eq!(annotation.comment, "persistent");
}

#[test]
fn selecting_report_file_matches_selecting_its_session_directory() {
    let cache = tempfile::tempdir().unwrap();
    let directory_service = QtraceService::with_cache_root(cache.path().join("directory"));
    let directory = directory_service
        .open_session(AuthorizedPath::new(fixture("valid-mixed")))
        .unwrap();
    let file_service = QtraceService::with_cache_root(cache.path().join("report"));
    let report = file_service
        .open_session(AuthorizedPath::new(
            fixture("valid-mixed").join("report.json"),
        ))
        .unwrap();
    assert_eq!(report.artifacts, directory.artifacts);
    assert_eq!(report.context, directory.context);
    assert_eq!(report.warnings, directory.warnings);
    assert_eq!(report.missing_capabilities, directory.missing_capabilities);
}

#[test]
fn compressed_capture_opens_cold_and_cached_as_file_or_report() {
    use lz4_flex::frame::FrameEncoder;
    use sha2::{Digest, Sha256};
    use std::{fs, io::Write};

    let raw_path = fixture("valid-mixed").join("artifacts/main.trace.bin");
    let cache = tempfile::tempdir().unwrap();
    let reference = QtraceService::with_cache_root(cache.path().join("raw"))
        .open_artifact(AuthorizedPath::new(raw_path.clone()))
        .unwrap();
    let mut encoder = FrameEncoder::new(Vec::new());
    encoder.write_all(&fs::read(raw_path).unwrap()).unwrap();
    let mut compressed = encoder.finish().unwrap();
    compressed.extend_from_slice(&0x184d_2a50_u32.to_le_bytes());
    compressed.extend_from_slice(&41_u32.to_le_bytes());
    compressed.extend_from_slice(&[0; 41]);
    let capture = tempfile::tempdir().unwrap();
    let name = "main.trace.bin.lz4";
    fs::write(capture.path().join(name), &compressed).unwrap();
    let mut report: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture("valid-mixed").join("report.json")).unwrap())
            .unwrap();
    let mut artifact = report["artifacts"][0].clone();
    artifact["local_path"] = name.into();
    artifact["remote_name"] = name.into();
    artifact["destination_size"] = compressed.len().into();
    artifact["source_size"] = compressed.len().into();
    artifact["sha256"] = format!("{:x}", Sha256::digest(&compressed)).into();
    report["artifacts"] = serde_json::json!([artifact]);
    report["outputs"] = serde_json::json!([name]);
    fs::write(
        capture.path().join("report.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    for report_selected in [false, true] {
        for _ in 0..2 {
            let service = QtraceService::with_cache_root(cache.path().join(if report_selected {
                "report"
            } else {
                "file"
            }));
            let opened = if report_selected {
                service.open_session(AuthorizedPath::new(capture.path().join("report.json")))
            } else {
                service.open_artifact(AuthorizedPath::new(capture.path().join(name)))
            }
            .unwrap();
            assert_eq!(opened.artifacts.len(), 1);
            assert_eq!(
                opened.artifacts[0].event_count,
                reference.artifacts[0].event_count
            );
        }
    }
}

fn repeated_memory_capture(copies: usize) -> Vec<u8> {
    let raw = std::fs::read(fixture("valid-mixed").join("artifacts/main.trace.bin")).unwrap();
    let mut offset = 16;
    while offset < raw.len() {
        let kind = u16::from_le_bytes(raw[offset..offset + 2].try_into().unwrap());
        let length = u32::from_le_bytes(raw[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let end = offset + 8 + length;
        if kind == 5 {
            let mut capture = raw[..offset].to_vec();
            for _ in 0..copies {
                capture.extend_from_slice(&raw[offset..end]);
            }
            capture.extend_from_slice(&raw[end..]);
            let terminal = capture.len() - (8 + 97);
            let encoded_bytes = terminal + 8 + (1 + 8 + 8) + 8;
            let length = capture.len() as u64;
            capture[encoded_bytes..encoded_bytes + 8].copy_from_slice(&length.to_le_bytes());
            return capture;
        }
        offset = end;
    }
    panic!("fixture has no memory observation");
}

#[test]
fn budget_memory_queries_separate_posting_work_from_returned_rows() {
    let capture = tempfile::tempdir().unwrap();
    let path = capture.path().join("memory.trace.bin");
    std::fs::write(&path, repeated_memory_capture(2_001)).unwrap();
    let cache = tempfile::tempdir().unwrap();
    let service = QtraceService::with_cache_root(cache.path().join("indexes"));
    let opened = service.open_artifact(AuthorizedPath::new(path)).unwrap();
    let workspace = &opened.workspace.id;
    let projection = service
        .create_projection(
            workspace,
            0,
            EventFilterDto {
                kinds: vec!["memory".into()],
                ..EventFilterDto::default()
            },
        )
        .unwrap();
    let first = service
        .query_timeline(workspace, &projection.projection_id, None, 1)
        .unwrap()
        .rows[0]
        .source_row;
    let state = service
        .get_memory_state(workspace, 0, first, 0x2000, 0x2004)
        .unwrap();
    assert_eq!(state.observed.len(), 4);
    assert!(state.observed.iter().all(|byte| byte.value.is_some()));
    assert_eq!(
        service
            .get_memory_history(workspace, 0, first + 1_999, 0x2000, 0x2004)
            .unwrap()
            .len(),
        2_000
    );
    let error = service
        .get_memory_history(workspace, 0, first + 2_000, 0x2000, 0x2004)
        .unwrap_err();
    assert!(error.detail.contains("Rows budget exceeded"), "{error:?}");
}

#[test]
fn ordered_memory_candidates_fit_interactive_work_budget() {
    let capture = tempfile::tempdir().unwrap();
    let path = capture.path().join("memory.trace.bin");
    std::fs::write(&path, repeated_memory_capture(8_192)).unwrap();
    let cache = tempfile::tempdir().unwrap();
    let service = QtraceService::with_cache_root(cache.path().join("indexes"));
    let opened = service.open_artifact(AuthorizedPath::new(path)).unwrap();
    let workspace = &opened.workspace.id;
    let projection = service
        .create_projection(
            workspace,
            0,
            EventFilterDto {
                kinds: vec!["memory".into()],
                ..EventFilterDto::default()
            },
        )
        .unwrap();
    let first = service
        .query_timeline(workspace, &projection.projection_id, None, 1)
        .unwrap()
        .rows[0]
        .source_row;
    let state = service
        .get_memory_state(workspace, 0, first, 0x2000, 0x2004)
        .unwrap();
    assert_eq!(state.observed.len(), 4);
    assert!(state.observed.iter().all(|byte| byte.value.is_some()));
    let history = service
        .get_memory_history(workspace, 0, first, 0x2000, 0x2004)
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].key, state.key);
}

fn dense_flight_capture(damaged_prefix: bool) -> Vec<u8> {
    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn checksum(bytes: &[u8]) -> u32 {
        bytes.iter().fold(2_166_136_261_u32, |value, byte| {
            (value ^ u32::from(*byte)).wrapping_mul(16_777_619)
        })
    }
    let raw = std::fs::read(fixture("valid-mixed").join("artifacts/capture.flight.bin")).unwrap();
    let chunk_start = u64::from_le_bytes(raw[40..48].try_into().unwrap()) as usize;
    let chunk_bytes = u32::from_le_bytes(raw[48..52].try_into().unwrap()) as usize;
    let chunks = 32;
    let mut cursor = chunk_start + 64;
    let mut prefix = Vec::new();
    for _ in 0..4 {
        let length = u32::from_le_bytes(raw[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        let end = cursor + ((length + 7) & !7);
        prefix.push(raw[cursor..end].to_vec());
        cursor = end;
    }
    let instruction_length =
        u32::from_le_bytes(raw[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
    let instruction = raw[cursor..cursor + ((instruction_length + 7) & !7)].to_vec();
    let committed =
        u32::from_le_bytes(raw[chunk_start + 40..chunk_start + 44].try_into().unwrap()) as usize;
    let end = raw[chunk_start + 64 + committed - 32..chunk_start + 64 + committed].to_vec();
    let prefix_bytes: usize = prefix.iter().map(Vec::len).sum();
    let repeated = (chunk_bytes - 64 - prefix_bytes - end.len()) / instruction.len();
    let records = prefix.len() + repeated + 1;
    let mut capture = vec![0; chunk_start + chunks * chunk_bytes];
    capture[..chunk_start].copy_from_slice(&raw[..chunk_start]);
    let length = capture.len() as u64;
    put_u64(&mut capture, 16, length);
    put_u32(&mut capture, 52, chunks as u32);
    capture[4096 + 64..4096 + 128].fill(0);
    put_u64(&mut capture, 4096 + 8, 1);
    put_u64(&mut capture, 4096 + 16, (chunks * records) as u64);
    put_u32(&mut capture, 4096 + 24, (chunks - 1) as u32);
    for index in 0..chunks {
        let start = chunk_start + index * chunk_bytes;
        let chunk = &mut capture[start..start + chunk_bytes];
        chunk[..64].copy_from_slice(&raw[chunk_start..chunk_start + 64]);
        put_u32(chunk, 8, index as u32);
        put_u64(chunk, 24, (index * records + 1) as u64);
        put_u64(chunk, 32, ((index + 1) * records) as u64);
        let mut offset = 64;
        for (record, template) in prefix
            .iter()
            .chain(std::iter::repeat_n(&instruction, repeated))
            .chain(std::iter::once(&end))
            .enumerate()
        {
            chunk[offset..offset + template.len()].copy_from_slice(template);
            put_u64(chunk, offset + 8, (index * records + record + 1) as u64);
            let length = u32::from_le_bytes(template[4..8].try_into().unwrap()) as usize;
            let mut record_bytes = chunk[offset..offset + 16].to_vec();
            record_bytes.extend_from_slice(&chunk[offset + 24..offset + length]);
            put_u32(chunk, offset + 16, checksum(&record_bytes));
            offset += template.len();
        }
        put_u32(chunk, 40, (offset - 64) as u32);
        put_u32(chunk, 44, records as u32);
        let chunk_checksum = checksum(&chunk[64..offset]);
        put_u32(chunk, 48, chunk_checksum);
    }
    if damaged_prefix {
        let chunk = &mut capture[chunk_start..chunk_start + chunk_bytes];
        let record_length = u32::from_le_bytes(chunk[68..72].try_into().unwrap()) as usize;
        chunk[64 + 24] = 0xff;
        let mut record_bytes = chunk[64..80].to_vec();
        record_bytes.extend_from_slice(&chunk[88..64 + record_length]);
        put_u32(chunk, 64 + 16, checksum(&record_bytes));
        let committed = u32::from_le_bytes(chunk[40..44].try_into().unwrap()) as usize;
        let chunk_checksum = checksum(&chunk[64..64 + committed]);
        put_u32(chunk, 48, chunk_checksum);
    }
    capture
}

#[test]
fn budget_flight_opens_cold_and_cached_with_checksum_and_record_reads() {
    let capture = tempfile::tempdir().unwrap();
    let path = capture.path().join("dense.flight.bin");
    std::fs::write(&path, dense_flight_capture(false)).unwrap();
    let cache = tempfile::tempdir().unwrap();
    for _ in 0..2 {
        let service = QtraceService::with_cache_root(cache.path().join("indexes"));
        let opened = service
            .open_artifact(AuthorizedPath::new(path.clone()))
            .unwrap();
        assert_eq!(opened.artifacts.len(), 1);
        assert!(opened.artifacts[0].event_count > 32 * 4);
    }
}

#[test]
fn damaged_flight_proofs_match_merged_completeness_after_cache_reopen() {
    let capture = tempfile::tempdir().unwrap();
    let path = capture.path().join("damaged.flight.bin");
    std::fs::write(&path, dense_flight_capture(true)).unwrap();
    let cache = tempfile::tempdir().unwrap();
    for _ in 0..2 {
        let service = QtraceService::with_cache_root(cache.path().join("indexes"));
        let opened = service
            .open_artifact(AuthorizedPath::new(path.clone()))
            .unwrap();
        assert!(
            opened.artifacts[0]
                .completeness
                .iter()
                .any(|range| range.provenance == "damaged")
        );
    }
}

#[test]
fn invalid_artifact_is_isolated_while_healthy_timelines_remain_queryable() {
    let service = QtraceService::new();
    let opened = service
        .open_session(AuthorizedPath::new(fixture("one-invalid-artifact")))
        .unwrap();
    assert!(!opened.warnings.is_empty());
    assert!(!opened.artifacts.is_empty());
    let projection = service
        .create_projection(&opened.workspace.id, 0, EventFilterDto::default())
        .unwrap();
    let page = service
        .query_timeline(&opened.workspace.id, &projection.projection_id, None, 32)
        .unwrap();
    assert!(!page.rows.is_empty());
}

#[test]
fn single_artifact_exposes_missing_session_context() {
    let service = QtraceService::new();
    let opened = service
        .open_artifact(AuthorizedPath::new(
            fixture("valid-mixed").join("artifacts/main.trace.bin"),
        ))
        .unwrap();
    assert!(opened.context.is_none());
    assert_eq!(
        opened.missing_capabilities,
        ["package", "device", "target", "effective_config"]
    );
    assert_eq!(opened.artifacts.len(), 1);
    assert_eq!(opened.artifacts[0].status, "indexed");
}
