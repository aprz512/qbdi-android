use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    fs,
    path::Path,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

use qtrace_provider::{AllocationScope, BudgetDimension, OperationAbort, WorkDelta, WorkGuard};
use qtrace_store::{AuthorizedPath, BuildOptions, OpenPolicy, SessionLoader, TraceStore};
use tempfile::TempDir;

const CHILD_ENV: &str = "QTRACE_ALLOCATION_ORACLE_CHILD";
const ABORT_CHILD_ENV: &str = "QTRACE_ALLOCATION_ABORT_ORACLE_CHILD";
const COLD_CHILD_ENV: &str = "QTRACE_ALLOCATION_COLD_ORACLE_CHILD";
const COLD_ABORT_CHILD_ENV: &str = "QTRACE_ALLOCATION_COLD_ABORT_ORACLE_CHILD";
const FLIGHT_COLD_CHILD_ENV: &str = "QTRACE_ALLOCATION_FLIGHT_COLD_ORACLE_CHILD";

#[derive(Clone, Copy)]
struct OracleState {
    active: bool,
    scope_active: bool,
    authorized: u64,
    allowed_slack: u64,
    allocations: u64,
    unauthorized: u64,
    scope_violations: u64,
    nested_scopes: u64,
    post_reject: u64,
    rejected: bool,
    unauthorized_sizes: [usize; 64],
    unauthorized_ordinals: [usize; 64],
    resident_bytes: [u64; 256],
    unauthorized_len: usize,
    resident_ordinal: usize,
}

impl Default for OracleState {
    fn default() -> Self {
        Self {
            active: false,
            scope_active: false,
            authorized: 0,
            allowed_slack: 0,
            allocations: 0,
            unauthorized: 0,
            scope_violations: 0,
            nested_scopes: 0,
            post_reject: 0,
            rejected: false,
            unauthorized_sizes: [0; 64],
            unauthorized_ordinals: [0; 64],
            resident_bytes: [0; 256],
            unauthorized_len: 0,
            resident_ordinal: 0,
        }
    }
}

thread_local! {
    static ORACLE: Cell<OracleState> = const { Cell::new(OracleState {
        active: false,
        scope_active: false,
        authorized: 0,
        allowed_slack: 0,
        allocations: 0,
        unauthorized: 0,
        scope_violations: 0,
        nested_scopes: 0,
        post_reject: 0,
        rejected: false,
        unauthorized_sizes: [0; 64],
        unauthorized_ordinals: [0; 64],
        resident_bytes: [0; 256],
        unauthorized_len: 0,
        resident_ordinal: 0,
    }) };
}

struct TrackingAllocator;

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_growth(layout.size());
        // SAFETY: forwards the allocation request unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_growth(layout.size());
        // SAFETY: forwards the allocation request unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forwards the matching deallocation to the system allocator.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_growth(new_size);
        // SAFETY: forwards the matching reallocation to the system allocator.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn record_growth(bytes: usize) {
    if bytes == 0 {
        return;
    }
    let _ = ORACLE.try_with(|slot| {
        let mut state = slot.get();
        if !state.active {
            return;
        }
        state.allocations = state.allocations.saturating_add(1);
        if state.rejected {
            state.post_reject = state.post_reject.saturating_add(1);
            if state.unauthorized_len < state.unauthorized_sizes.len() {
                state.unauthorized_sizes[state.unauthorized_len] = bytes;
                state.unauthorized_ordinals[state.unauthorized_len] = state.resident_ordinal;
                state.unauthorized_len += 1;
            }
        } else if let Ok(bytes) = u64::try_from(bytes) {
            if state.scope_active && state.authorized >= bytes {
                state.authorized -= bytes;
            } else {
                state.unauthorized = state.unauthorized.saturating_add(1);
                if state.unauthorized_len < state.unauthorized_sizes.len() {
                    state.unauthorized_sizes[state.unauthorized_len] = bytes as usize;
                    state.unauthorized_ordinals[state.unauthorized_len] = state.resident_ordinal;
                    state.unauthorized_len += 1;
                }
            }
        } else {
            state.unauthorized = state.unauthorized.saturating_add(1);
        }
        slot.set(state);
    });
}

struct OracleGuard {
    reject_resident: Option<usize>,
    resident_ordinal: AtomicUsize,
}

impl WorkGuard for OracleGuard {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.resident_bytes == 0 {
            return Ok(());
        }
        let ordinal = self.resident_ordinal.fetch_add(1, Ordering::Relaxed) + 1;
        ORACLE.with(|slot| {
            let mut state = slot.get();
            state.resident_ordinal = ordinal;
            if ordinal < state.resident_bytes.len() {
                state.resident_bytes[ordinal] = delta.resident_bytes;
            }
            slot.set(state);
        });
        if self.reject_resident == Some(ordinal) {
            ORACLE.with(|slot| {
                let mut state = slot.get();
                state.rejected = true;
                slot.set(state);
            });
            return Err(OperationAbort::budget_exceeded(
                BudgetDimension::ResidentBytes,
                0x1122,
                0x3344,
            ));
        }
        Ok(())
    }

    fn begin_allocation_scope(
        &self,
        delta: WorkDelta,
        allowed_slack: u64,
    ) -> Result<(), OperationAbort> {
        self.consume(delta)?;
        ORACLE.with(|slot| {
            let mut state = slot.get();
            if state.scope_active {
                state.nested_scopes = state.nested_scopes.saturating_add(1);
            }
            state.scope_active = true;
            state.authorized = delta.resident_bytes;
            state.allowed_slack = allowed_slack;
            slot.set(state);
        });
        Ok(())
    }

    fn end_allocation_scope(&self) {
        ORACLE.with(|slot| {
            let mut state = slot.get();
            if !state.scope_active || state.authorized > state.allowed_slack {
                state.scope_violations = state.scope_violations.saturating_add(1);
            }
            state.scope_active = false;
            state.authorized = 0;
            state.allowed_slack = 0;
            slot.set(state);
        });
    }
}

fn active_oracle_state() -> OracleState {
    OracleState {
        active: true,
        ..OracleState::default()
    }
}

fn assert_scopes_closed(state: &OracleState, context: &str) {
    assert!(!state.scope_active, "{context}: allocation scope leaked");
    assert_eq!(state.authorized, 0, "{context}: stale credit survived");
    assert_eq!(
        state.nested_scopes, 0,
        "{context}: allocation scopes nested"
    );
    assert_eq!(
        state.scope_violations, 0,
        "{context}: allocation scope exceeded its slack formula"
    );
}

#[test]
fn allocator_oracle_binds_credit_to_one_scope_and_counts_full_realloc_requests() {
    let guard = OracleGuard {
        reject_resident: None,
        resident_ordinal: AtomicUsize::new(0),
    };

    let mut values = Vec::with_capacity(8);
    values.extend_from_slice(&[0_u8; 8]);
    ORACLE.with(|slot| slot.set(active_oracle_state()));
    {
        let _scope = AllocationScope::begin(&guard, 16, 0).expect("realloc token");
        values.try_reserve_exact(8).expect("grow to sixteen");
    }
    let full_request = ORACLE.with(|slot| {
        let mut state = slot.get();
        state.active = false;
        slot.set(state);
        state
    });
    assert_eq!(values.capacity(), 16);
    assert_eq!(full_request.unauthorized, 0);
    assert_eq!(
        full_request.authorized, 0,
        "realloc consumes its full new layout"
    );

    ORACLE.with(|slot| slot.set(active_oracle_state()));
    drop(AllocationScope::begin(&guard, 1_024, 1_024).expect("old scope"));
    let mut second = Vec::<u8>::new();
    {
        let _scope = AllocationScope::begin(&guard, 1, 1).expect("replacement scope");
        second.try_reserve_exact(2).expect("two-byte request");
    }
    let scoped = ORACLE.with(|slot| {
        let mut state = slot.get();
        state.active = false;
        slot.set(state);
        state
    });
    assert_eq!(scoped.unauthorized, 1, "stale 1KiB credit must not pool");
    assert_eq!(scoped.authorized, 0, "scope drop clears unused credit");
    assert_eq!(scoped.scope_violations, 0);
    assert_eq!(scoped.nested_scopes, 0);
    assert_scopes_closed(&scoped, "manual full-request scope");
}

#[test]
fn warm_deep_validation_heap_growth_requires_prior_resident_authorization() {
    if std::env::var_os(CHILD_ENV).is_none() {
        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("warm_deep_validation_heap_growth_requires_prior_resident_authorization")
            .arg("--nocapture")
            .env(CHILD_ENV, "1")
            .status()
            .expect("allocation oracle child");
        assert!(status.success(), "allocation oracle child failed: {status}");
        return;
    }

    let session = SessionLoader::open_report(
        AuthorizedPath::new(fixture()),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("mixed fixture");
    let source = session
        .artifacts()
        .iter()
        .find(|artifact| artifact.local_path().ends_with("main.trace.bin"))
        .expect("QTRB artifact");
    let root = private_root();
    TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &AllowAll)
        .expect("initial cache");

    ORACLE.with(|slot| {
        slot.set(active_oracle_state());
    });
    let guard = OracleGuard {
        reject_resident: None,
        resident_ordinal: AtomicUsize::new(0),
    };
    TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &guard)
        .expect("warm open");
    let state = ORACLE.with(|slot| {
        let mut state = slot.get();
        state.active = false;
        slot.set(state);
        state
    });
    assert!(state.allocations > 0, "oracle must observe heap growth");
    assert_eq!(
        state.unauthorized,
        0,
        "every heap growth needs prior unconsumed resident authorization; sizes={:?}, ordinals={:?}",
        &state.unauthorized_sizes[..state.unauthorized_len],
        &state.unauthorized_ordinals[..state.unauthorized_len]
    );
    assert_scopes_closed(&state, "warm validation");
}

#[test]
fn cold_build_heap_growth_requires_prior_resident_authorization() {
    if std::env::var_os(COLD_CHILD_ENV).is_none() {
        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("cold_build_heap_growth_requires_prior_resident_authorization")
            .arg("--nocapture")
            .env(COLD_CHILD_ENV, "1")
            .status()
            .expect("cold allocation oracle child");
        assert!(
            status.success(),
            "cold allocation oracle child failed: {status}"
        );
        return;
    }

    let session = SessionLoader::open_report(
        AuthorizedPath::new(fixture()),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("mixed fixture");
    let source = session
        .artifacts()
        .iter()
        .find(|artifact| artifact.local_path().ends_with("main.trace.bin"))
        .expect("QTRB artifact");
    let root = private_root();
    ORACLE.with(|slot| {
        slot.set(active_oracle_state());
    });
    let guard = OracleGuard {
        reject_resident: None,
        resident_ordinal: AtomicUsize::new(0),
    };
    TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &guard)
        .expect("cold build");
    let state = ORACLE.with(|slot| {
        let mut state = slot.get();
        state.active = false;
        slot.set(state);
        state
    });
    assert!(
        state.allocations > 0,
        "oracle must observe cold heap growth"
    );
    assert_eq!(
        state.unauthorized,
        0,
        "every cold heap growth needs prior unconsumed resident authorization; sizes={:?}, ordinals={:?}, resident_bytes={:?}",
        &state.unauthorized_sizes[..state.unauthorized_len],
        &state.unauthorized_ordinals[..state.unauthorized_len],
        &state.resident_bytes[..=guard.resident_ordinal.load(Ordering::Relaxed).min(255)]
    );
    assert_scopes_closed(&state, "cold build");
}

#[test]
fn cold_flight_build_heap_growth_requires_explicit_scopes() {
    if std::env::var_os(FLIGHT_COLD_CHILD_ENV).is_none() {
        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("cold_flight_build_heap_growth_requires_explicit_scopes")
            .arg("--nocapture")
            .env(FLIGHT_COLD_CHILD_ENV, "1")
            .status()
            .expect("Flight allocation oracle child");
        assert!(status.success(), "Flight oracle child failed: {status}");
        return;
    }

    let session = SessionLoader::open_report(
        AuthorizedPath::new(fixture()),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("mixed fixture");
    let source = session
        .artifacts()
        .iter()
        .find(|artifact| artifact.local_path().ends_with("capture.flight.bin"))
        .expect("Flight artifact");
    let root = private_root();
    ORACLE.with(|slot| slot.set(active_oracle_state()));
    let guard = OracleGuard {
        reject_resident: None,
        resident_ordinal: AtomicUsize::new(0),
    };
    TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &guard)
        .expect("cold Flight build");
    let state = ORACLE.with(|slot| {
        let mut state = slot.get();
        state.active = false;
        slot.set(state);
        state
    });
    assert_eq!(
        state.unauthorized,
        0,
        "Flight growth escaped explicit scope: sizes={:?}, ordinals={:?}",
        &state.unauthorized_sizes[..state.unauthorized_len],
        &state.unauthorized_ordinals[..state.unauthorized_len]
    );
    assert_scopes_closed(&state, "cold Flight build");
}

#[test]
fn every_warm_resident_rejection_preserves_the_original_abort_without_later_growth() {
    if std::env::var_os(ABORT_CHILD_ENV).is_none() {
        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("every_warm_resident_rejection_preserves_the_original_abort_without_later_growth")
            .arg("--nocapture")
            .env(ABORT_CHILD_ENV, "1")
            .status()
            .expect("allocation abort oracle child");
        assert!(
            status.success(),
            "allocation abort oracle child failed: {status}"
        );
        return;
    }

    let session = SessionLoader::open_report(
        AuthorizedPath::new(fixture()),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("mixed fixture");
    let source = session
        .artifacts()
        .iter()
        .find(|artifact| artifact.local_path().ends_with("main.trace.bin"))
        .expect("QTRB artifact");
    let root = private_root();
    TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &AllowAll)
        .expect("initial cache");
    let final_path = only_cache(root.path());
    let original = fs::read(&final_path).expect("original final");

    let count = OracleGuard {
        reject_resident: None,
        resident_ordinal: AtomicUsize::new(0),
    };
    TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &count)
        .expect("count resident ordinals");
    let resident_calls = count.resident_ordinal.load(Ordering::Relaxed);
    assert!(
        resident_calls > 8,
        "deep validation needs resident checkpoints"
    );

    for reject_at in 1..=resident_calls {
        ORACLE.with(|slot| {
            slot.set(active_oracle_state());
        });
        let reject = OracleGuard {
            reject_resident: Some(reject_at),
            resident_ordinal: AtomicUsize::new(0),
        };
        let error =
            TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &reject)
                .expect_err("resident rejection");
        let state = ORACLE.with(|slot| {
            let mut state = slot.get();
            state.active = false;
            slot.set(state);
            state
        });
        assert_eq!(
            error.code(),
            "control.budget_exceeded",
            "ordinal {reject_at}"
        );
        let detail = error.to_string();
        assert!(
            detail.contains("ResidentBytes"),
            "ordinal {reject_at}: {detail}"
        );
        assert!(detail.contains("4386"), "ordinal {reject_at}: {detail}");
        assert!(detail.contains("13124"), "ordinal {reject_at}: {detail}");
        assert_eq!(
            state.post_reject,
            0,
            "ordinal {reject_at} allocated after rejection: sizes={:?}",
            &state.unauthorized_sizes[..state.unauthorized_len]
        );
        assert_scopes_closed(&state, "warm rejection");
        assert_eq!(fs::read(&final_path).expect("retained final"), original);
        assert_no_transient_cache_entries(root.path());
    }
}

#[test]
fn every_cold_resident_rejection_stops_growth_and_leaves_no_cache_object() {
    if std::env::var_os(COLD_ABORT_CHILD_ENV).is_none() {
        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("every_cold_resident_rejection_stops_growth_and_leaves_no_cache_object")
            .arg("--nocapture")
            .env(COLD_ABORT_CHILD_ENV, "1")
            .status()
            .expect("cold allocation abort oracle child");
        assert!(
            status.success(),
            "cold allocation abort oracle child failed: {status}"
        );
        return;
    }

    let session = SessionLoader::open_report(
        AuthorizedPath::new(fixture()),
        OpenPolicy::default(),
        &AllowAll,
    )
    .expect("mixed fixture");
    for (label, suffix) in [("QTRB", "main.trace.bin"), ("Flight", "capture.flight.bin")] {
        let source = session
            .artifacts()
            .iter()
            .find(|artifact| artifact.local_path().ends_with(suffix))
            .unwrap_or_else(|| panic!("{label} artifact"));
        let count_root = private_root();
        let count = OracleGuard {
            reject_resident: None,
            resident_ordinal: AtomicUsize::new(0),
        };
        TraceStore::open_or_build(count_root.path(), source, &BuildOptions::default(), &count)
            .unwrap_or_else(|error| panic!("count {label} resident ordinals: {error}"));
        let resident_calls = count.resident_ordinal.load(Ordering::Relaxed);
        assert!(
            resident_calls > 128,
            "{label} cold build needs all allocation phases"
        );

        for reject_at in 1..=resident_calls {
            let root = private_root();
            ORACLE.with(|slot| {
                slot.set(active_oracle_state());
            });
            let reject = OracleGuard {
                reject_resident: Some(reject_at),
                resident_ordinal: AtomicUsize::new(0),
            };
            let error =
                TraceStore::open_or_build(root.path(), source, &BuildOptions::default(), &reject)
                    .expect_err("resident rejection");
            let state = ORACLE.with(|slot| {
                let mut state = slot.get();
                state.active = false;
                slot.set(state);
                state
            });
            assert_eq!(
                error.code(),
                "control.budget_exceeded",
                "{label} ordinal {reject_at}"
            );
            let detail = error.to_string();
            assert!(
                detail.contains("ResidentBytes"),
                "{label} ordinal {reject_at}: {detail}"
            );
            assert!(
                detail.contains("4386"),
                "{label} ordinal {reject_at}: {detail}"
            );
            assert!(
                detail.contains("13124"),
                "{label} ordinal {reject_at}: {detail}"
            );
            assert_eq!(
                state.post_reject,
                0,
                "{label} ordinal {reject_at} allocated after rejection: sizes={:?}",
                &state.unauthorized_sizes[..state.unauthorized_len]
            );
            assert_scopes_closed(&state, "cold rejection");
            assert!(
                !contains_name(root.path(), "index.qtc"),
                "{label} ordinal {reject_at}"
            );
            assert_no_transient_cache_entries(root.path());
        }
    }
}

struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("fixtures/sessions/valid-mixed")
}

fn private_root() -> TempDir {
    let root = TempDir::new().expect("root");
    fs::set_permissions(
        root.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("private root");
    root
}

fn only_cache(root: &Path) -> std::path::PathBuf {
    let app = root.join("qtrace-ui");
    let digest = fs::read_dir(app)
        .expect("cache app")
        .filter_map(Result::ok)
        .find(|entry| entry.path().is_dir())
        .expect("digest");
    digest.path().join("index.qtc")
}

fn assert_no_transient_cache_entries(root: &Path) {
    fn walk(path: &Path, bad: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let child = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".tmp") || name.starts_with(".qtrace-dir-") {
                bad.push(child.clone());
            }
            if child.is_dir() {
                walk(&child, bad);
            }
        }
    }
    let mut bad = Vec::new();
    walk(root, &mut bad);
    assert!(bad.is_empty(), "transient cache entries: {bad:?}");
}

fn contains_name(root: &Path, expected: &str) -> bool {
    let Ok(entries) = fs::read_dir(root) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        entry.file_name() == expected
            || (entry.path().is_dir() && contains_name(&entry.path(), expected))
    })
}
