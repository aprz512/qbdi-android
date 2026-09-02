use std::{
    fs,
    os::unix::{
        fs::{MetadataExt, PermissionsExt, symlink},
        net::UnixListener,
    },
};

use qtrace_provider::{ArtifactDigest, EventKey, TimelineId};
use qtrace_store::{
    AnnotationOpenRequest, AnnotationStore, AuthorizedPath, EventAnnotation, Highlight,
    LocalSymbolName,
};
use tempfile::TempDir;

fn digest(byte: u8) -> ArtifactDigest {
    ArtifactDigest::new([byte; 32])
}

fn event() -> EventKey {
    EventKey::new(digest(0x11), TimelineId(7), 19, 0x240, Some(91), Some(42))
}

fn request(root: &TempDir, session: ArtifactDigest) -> AnnotationOpenRequest {
    AnnotationOpenRequest::new(AuthorizedPath::new(root.path().to_owned()), session)
}

#[test]
fn transactions_persist_delete_and_rollback_all_annotation_kinds() {
    let root = TempDir::new().unwrap();
    let mut store = AnnotationStore::open(request(&root, digest(1))).unwrap();
    let annotation = EventAnnotation::new(event(), "inspect return value").unwrap();
    let local = LocalSymbolName::new(digest(2), 0x120, "decrypt_round").unwrap();
    let highlight = Highlight::new(event(), "#ffcc00").unwrap();

    {
        let mut tx = store.begin_transaction().unwrap();
        tx.put_event_annotation(&annotation).unwrap();
        tx.put_local_symbol_name(&local).unwrap();
        tx.put_highlight(&highlight).unwrap();
        tx.commit().unwrap();
    }
    drop(store);

    let mut reopened = AnnotationStore::open(request(&root, digest(1))).unwrap();
    assert_eq!(
        reopened.event_annotation(&event()).unwrap(),
        Some(annotation.clone())
    );
    assert_eq!(
        reopened.local_symbol_name(digest(2), 0x120).unwrap(),
        Some(local.clone())
    );
    assert_eq!(
        reopened.highlight(&event()).unwrap(),
        Some(highlight.clone())
    );

    {
        let mut tx = reopened.begin_transaction().unwrap();
        tx.delete_event_annotation(&event()).unwrap();
        tx.delete_local_symbol_name(digest(2), 0x120).unwrap();
        tx.delete_highlight(&event()).unwrap();
        tx.rollback().unwrap();
    }
    assert_eq!(
        reopened.event_annotation(&event()).unwrap(),
        Some(annotation)
    );
    assert!(
        reopened
            .local_symbol_name(digest(2), 0x120)
            .unwrap()
            .is_some()
    );
    assert!(reopened.highlight(&event()).unwrap().is_some());

    {
        let mut tx = reopened.begin_transaction().unwrap();
        tx.delete_event_annotation(&event()).unwrap();
        tx.delete_local_symbol_name(digest(2), 0x120).unwrap();
        tx.delete_highlight(&event()).unwrap();
        tx.commit().unwrap();
    }
    drop(reopened);
    let deleted = AnnotationStore::open(request(&root, digest(1))).unwrap();
    assert_eq!(deleted.event_annotation(&event()).unwrap(), None);
    assert_eq!(deleted.local_symbol_name(digest(2), 0x120).unwrap(), None);
    assert_eq!(deleted.highlight(&event()).unwrap(), None);
}

#[test]
fn session_identity_isolates_databases_and_private_permissions() {
    let root = TempDir::new().unwrap();
    let mut first = AnnotationStore::open(request(&root, digest(1))).unwrap();
    {
        let mut tx = first.begin_transaction().unwrap();
        tx.put_event_annotation(&EventAnnotation::new(event(), "first").unwrap())
            .unwrap();
        tx.commit().unwrap();
    }
    let second = AnnotationStore::open(request(&root, digest(2))).unwrap();
    assert_eq!(second.event_annotation(&event()).unwrap(), None);
    assert_ne!(first.database_path(), second.database_path());
    assert_eq!(
        fs::metadata(first.database_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let data_dir = first.database_path().parent().unwrap();
    assert_eq!(
        fs::metadata(data_dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for suffix in ["-wal", "-shm"] {
        let metadata =
            fs::metadata(format!("{}{}", first.database_path().display(), suffix)).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
    assert!(
        !std::path::PathBuf::from(format!("{}-journal", first.database_path().display())).exists()
    );
}

#[test]
fn migrates_empty_schema_one_database() {
    let root = TempDir::new().unwrap();
    let request = request(&root, digest(3));
    let path = root
        .path()
        .join("qtrace-ui")
        .join(digest(3).to_hex())
        .join("annotations.sqlite3");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::set_permissions(
        root.path().join("qtrace-ui"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE schema_version(version INTEGER NOT NULL);\n\
             INSERT INTO schema_version(version) VALUES(1);",
        )
        .unwrap();
    drop(connection);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let mut store = AnnotationStore::open(request).unwrap();
    let mut tx = store.begin_transaction().unwrap();
    tx.put_event_annotation(&EventAnnotation::new(event(), "migrated").unwrap())
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        store.event_annotation(&event()).unwrap().unwrap().comment(),
        "migrated"
    );
}

#[test]
fn rejects_symlinked_data_root_database_leaf_and_root_replacement() {
    let temp = TempDir::new().unwrap();
    let real = temp.path().join("real");
    fs::create_dir(&real).unwrap();
    let linked = temp.path().join("linked");
    symlink(&real, &linked).unwrap();
    let error = AnnotationStore::open(AnnotationOpenRequest::new(
        AuthorizedPath::new(linked),
        digest(4),
    ))
    .unwrap_err();
    assert_eq!(error.code(), "annotation.path_escape");

    let root = TempDir::new().unwrap();
    let leaf_request = request(&root, digest(5));
    let database = root
        .path()
        .join("qtrace-ui")
        .join(digest(5).to_hex())
        .join("annotations.sqlite3");
    fs::create_dir_all(database.parent().unwrap()).unwrap();
    fs::set_permissions(
        root.path().join("qtrace-ui"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(
        database.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let target = root.path().join("elsewhere.sqlite3");
    fs::write(&target, b"not sqlite").unwrap();
    symlink(&target, &database).unwrap();
    assert_eq!(
        AnnotationStore::open(leaf_request).unwrap_err().code(),
        "annotation.path_escape"
    );

    let replacement = TempDir::new().unwrap();
    let original = replacement.path().join("data");
    fs::create_dir(&original).unwrap();
    let mut store = AnnotationStore::open(AnnotationOpenRequest::new(
        AuthorizedPath::new(original.clone()),
        digest(6),
    ))
    .unwrap();
    let held = replacement.path().join("held");
    fs::rename(&original, &held).unwrap();
    fs::create_dir(&original).unwrap();
    let error = match store.begin_transaction() {
        Ok(mut tx) => tx
            .put_event_annotation(&EventAnnotation::new(event(), "must not redirect").unwrap())
            .unwrap_err(),
        Err(error) => error,
    };
    assert_eq!(error.code(), "annotation.identity_changed");

    // Ensure this assertion really observed distinct directory identities.
    assert_ne!(
        fs::metadata(&original).unwrap().ino(),
        fs::metadata(&held).unwrap().ino()
    );

    let root = TempDir::new().unwrap();
    let mut store = AnnotationStore::open(request(&root, digest(10))).unwrap();
    let database = store.database_path().to_owned();
    fs::rename(&database, database.with_extension("held")).unwrap();
    fs::write(&database, b"replacement").unwrap();
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
    let error = match store.begin_transaction() {
        Ok(_) => panic!("replaced database leaf was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "annotation.identity_changed");
}

#[test]
fn never_touches_cache_or_source_files() {
    let root = TempDir::new().unwrap();
    let source = root.path().join("source.trace.bin");
    let cache = root.path().join("index.qtc");
    fs::write(&source, b"source").unwrap();
    fs::write(&cache, b"cache").unwrap();
    let before_source = fs::read(&source).unwrap();
    let before_cache = fs::read(&cache).unwrap();
    let mut store = AnnotationStore::open(request(&root, digest(7))).unwrap();
    let mut tx = store.begin_transaction().unwrap();
    tx.put_event_annotation(&EventAnnotation::new(event(), "local only").unwrap())
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(fs::read(source).unwrap(), before_source);
    assert_eq!(fs::read(cache).unwrap(), before_cache);
}

#[test]
fn rejects_untrusted_sqlite_sidecars_before_the_vfs_can_follow_them() {
    for suffix in ["-wal", "-shm", "-journal"] {
        let root = TempDir::new().unwrap();
        let session = root.path().join("qtrace-ui").join(digest(8).to_hex());
        fs::create_dir_all(&session).unwrap();
        fs::set_permissions(
            root.path().join("qtrace-ui"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(&session, fs::Permissions::from_mode(0o700)).unwrap();
        let outside = root.path().join("outside");
        fs::write(&outside, b"must remain untouched").unwrap();
        symlink(
            &outside,
            session.join(format!("annotations.sqlite3{suffix}")),
        )
        .unwrap();

        let error = AnnotationStore::open(request(&root, digest(8))).unwrap_err();
        assert_eq!(error.code(), "annotation.path_escape", "sidecar {suffix}");
        assert_eq!(fs::read(&outside).unwrap(), b"must remain untouched");
    }

    let root = TempDir::new().unwrap();
    let session = root.path().join("qtrace-ui").join(digest(9).to_hex());
    fs::create_dir_all(&session).unwrap();
    fs::set_permissions(
        root.path().join("qtrace-ui"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&session, fs::Permissions::from_mode(0o700)).unwrap();
    let socket_path = root.path().join("socket");
    let _socket = UnixListener::bind(&socket_path).unwrap();
    fs::hard_link(socket_path, session.join("annotations.sqlite3-wal")).unwrap();
    assert_eq!(
        AnnotationStore::open(request(&root, digest(9)))
            .unwrap_err()
            .code(),
        "annotation.path_escape"
    );
}

#[test]
fn rejects_insecure_existing_database_mode_without_chmodding_the_leaf() {
    let root = TempDir::new().unwrap();
    let session = root.path().join("qtrace-ui").join(digest(12).to_hex());
    fs::create_dir_all(&session).unwrap();
    fs::set_permissions(
        root.path().join("qtrace-ui"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&session, fs::Permissions::from_mode(0o700)).unwrap();
    let database = session.join("annotations.sqlite3");
    fs::write(&database, []).unwrap();
    fs::set_permissions(&database, fs::Permissions::from_mode(0o644)).unwrap();

    let error = AnnotationStore::open(request(&root, digest(12))).unwrap_err();
    assert_eq!(error.code(), "annotation.permission_denied");
    assert_eq!(
        fs::metadata(database).unwrap().permissions().mode() & 0o777,
        0o644
    );
}
