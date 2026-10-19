#[path = "../fuzz_targets/storage_support.rs"]
mod storage_support;
#[path = "../fuzz_targets/support.rs"]
mod support;

use proptest::prelude::*;
use qtrace_provider::{WorkDelta, WorkGuard};
use storage_support::{Outcome, fuzz_annotations, fuzz_cache_manifest, fuzz_session_report};

#[test]
fn cache_corpus_reaches_valid_manifest_and_rejects_semantic_corruption() {
    assert_eq!(fuzz_cache_manifest(b"cache:valid\n"), Outcome::Accepted);
    for name in [
        "overlap",
        "overflow",
        "identity",
        "section-count",
        "unknown-field",
        "truncated",
    ] {
        assert_eq!(
            fuzz_cache_manifest(format!("cache:{name}\n").as_bytes()),
            Outcome::Rejected,
            "{name}"
        );
    }
}

#[test]
fn session_corpus_reaches_real_artifacts_and_rejects_unsafe_root_reports() {
    assert_eq!(fuzz_session_report(b"session:valid\n"), Outcome::Accepted);
    for name in [
        "path-escape",
        "collection-limit",
        "unknown-field",
        "deep-json",
        "nul-path",
    ] {
        assert_eq!(
            fuzz_session_report(format!("session:{name}\n").as_bytes()),
            Outcome::Rejected,
            "{name}"
        );
    }
    assert_eq!(
        fuzz_session_report(b"session:size-overflow\n"),
        Outcome::Accepted,
        "artifact failure remains isolated"
    );
}

#[test]
fn annotation_corpus_covers_current_legacy_malformed_and_expensive_schema() {
    for name in ["valid", "legacy-v1", "legacy-v2"] {
        assert_eq!(
            fuzz_annotations(format!("annotation:{name}\n").as_bytes()),
            Outcome::Accepted,
            "{name}"
        );
    }
    for name in ["oversized-text", "wrong-type", "recursive-view"] {
        assert_eq!(
            fuzz_annotations(format!("annotation:{name}\n").as_bytes()),
            Outcome::Rejected,
            "{name}"
        );
    }
}

#[test]
fn storage_entry_points_and_guards_keep_all_work_dimensions_bounded() {
    let oversized = vec![0; storage_support::STORAGE_INPUT_LIMIT + 1];
    assert_eq!(fuzz_cache_manifest(&oversized), Outcome::Budget);
    assert_eq!(fuzz_session_report(&oversized), Outcome::Budget);
    assert_eq!(fuzz_annotations(&oversized), Outcome::Budget);
    for delta in [
        WorkDelta {
            input_bytes: u64::MAX,
            ..WorkDelta::default()
        },
        WorkDelta {
            decompressed_bytes: u64::MAX,
            ..WorkDelta::default()
        },
        WorkDelta {
            events: u64::MAX,
            ..WorkDelta::default()
        },
        WorkDelta {
            rows: u64::MAX,
            ..WorkDelta::default()
        },
        WorkDelta {
            nodes: u64::MAX,
            ..WorkDelta::default()
        },
        WorkDelta {
            resident_bytes: u64::MAX,
            ..WorkDelta::default()
        },
    ] {
        assert!(
            support::StrictGuard::new().consume(delta).is_err(),
            "{delta:?}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        max_shrink_iters: 128,
        rng_seed: proptest::test_runner::RngSeed::Fixed(0x2026_1019),
        ..ProptestConfig::default()
    })]

    #[test]
    fn untrusted_storage_bytes_and_structural_seed_mutations_never_panic(
        data in proptest::collection::vec(any::<u8>(), 0..4096),
        target in 0u8..3,
        seeded in any::<bool>(),
    ) {
        let prefix: &[u8] = match target {
            0 => b"cache:valid\n",
            1 => b"session:valid\n",
            _ => b"annotation:valid\n",
        };
        let input = if seeded { [prefix, &data].concat() } else { data };
        match target {
            0 => { fuzz_cache_manifest(&input); }
            1 => { fuzz_session_report(&input); }
            _ => { fuzz_annotations(&input); }
        }
    }
}
