use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use qtrace_provider::{
    ArtifactDigest, BudgetDimension, EventKey, OperationAbort, TimelineId, WorkDelta, WorkGuard,
};
use qtrace_store::{AnnotationOpenRequest, AnnotationStore, AuthorizedPath, EventAnnotation};
use rusqlite::Connection;
use tempfile::TempDir;

struct Guard {
    cancelled: AtomicBool,
    nodes: AtomicU64,
    node_limit: u64,
    resident: AtomicU64,
}

impl WorkGuard for Guard {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(OperationAbort::Cancelled);
        }
        self.resident
            .fetch_add(delta.resident_bytes, Ordering::Relaxed);
        let nodes = self.nodes.fetch_add(delta.nodes, Ordering::Relaxed) + delta.nodes;
        if nodes > self.node_limit {
            return Err(OperationAbort::budget_exceeded(
                BudgetDimension::Nodes,
                self.node_limit,
                nodes,
            ));
        }
        Ok(())
    }
}

fn guard(node_limit: u64) -> Arc<Guard> {
    Arc::new(Guard {
        cancelled: AtomicBool::new(false),
        nodes: AtomicU64::new(0),
        node_limit,
        resident: AtomicU64::new(0),
    })
}

fn request(root: &TempDir) -> AnnotationOpenRequest {
    AnnotationOpenRequest::new(
        AuthorizedPath::new(root.path().to_owned()),
        ArtifactDigest::new([0xa1; 32]),
    )
}

fn event() -> EventKey {
    EventKey::new(
        ArtifactDigest::new([0x11; 32]),
        TimelineId(1),
        1,
        1,
        None,
        None,
    )
}

#[test]
fn cancelled_open_creates_no_database_or_directories() {
    let root = TempDir::new().unwrap();
    let budget = guard(u64::MAX);
    budget.cancelled.store(true, Ordering::Relaxed);
    let error = AnnotationStore::open_guarded(request(&root), budget).unwrap_err();
    assert_eq!(error.code(), "control.cancelled");
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn sqlite_vm_budget_interrupts_untrusted_migration_and_preserves_schema() {
    let root = TempDir::new().unwrap();
    let path = AnnotationStore::open(request(&root))
        .unwrap()
        .database_path()
        .to_owned();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "UPDATE schema_version SET version=2;
         DROP TABLE event_annotations;
         CREATE VIEW event_annotations AS
           WITH RECURSIVE work(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM work WHERE x<1000000)
           SELECT zeroblob(70) AS event_key, 'x'||x AS comment FROM work;",
        )
        .unwrap();
    drop(connection);
    let budget = guard(10_000);
    let error = AnnotationStore::open_guarded(request(&root), budget.clone()).unwrap_err();
    assert_eq!(error.code(), "control.budget_exceeded", "{error}");
    assert!(budget.nodes.load(Ordering::Relaxed) > 10_000);
    let connection = Connection::open(path).unwrap();
    let version: i64 = connection
        .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        version, 2,
        "interrupted migration must not commit a schema update"
    );
}

#[test]
fn annotation_reads_charge_output_and_cancelled_transactions_do_not_commit() {
    let root = TempDir::new().unwrap();
    let budget = guard(u64::MAX);
    let mut store = AnnotationStore::open_guarded(request(&root), budget.clone()).unwrap();
    let value = EventAnnotation::new(event(), "bounded output").unwrap();
    let mut transaction = store.begin_transaction().unwrap();
    transaction.put_event_annotation(&value).unwrap();
    transaction.commit().unwrap();
    let before = budget.resident.load(Ordering::Relaxed);
    assert_eq!(store.event_annotation(&event()).unwrap(), Some(value));
    assert!(budget.resident.load(Ordering::Relaxed) >= before + 14);
    let mut transaction = store.begin_transaction().unwrap();
    transaction.delete_event_annotation(&event()).unwrap();
    budget.cancelled.store(true, Ordering::Relaxed);
    assert_eq!(
        transaction.commit().unwrap_err().code(),
        "control.cancelled"
    );
    drop(store);
    let reopened = AnnotationStore::open(request(&root)).unwrap();
    assert!(reopened.event_annotation(&event()).unwrap().is_some());
}
