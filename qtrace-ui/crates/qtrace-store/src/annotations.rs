use std::{
    error::Error,
    fmt,
    fs::File,
    os::unix::{fs::PermissionsExt, io::AsRawFd},
    path::{Path, PathBuf},
};

use qtrace_provider::{ArtifactDigest, EventKey, OperationAbort, WorkDelta, WorkGuard};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use rustix::fs::{Mode, OFlags, openat};
use rustix::io::Errno;

use crate::{
    AuthorizedPath,
    cache::{CacheDirectory, CacheError, ObjectIdentity},
};

const DATABASE_NAME: &str = "annotations.sqlite3";
const SIDECAR_NAMES: [&str; 3] = [
    "annotations.sqlite3-wal",
    "annotations.sqlite3-shm",
    "annotations.sqlite3-journal",
];
const CURRENT_SCHEMA: i64 = 2;
const MAX_COMMENT_BYTES: usize = 64 * 1024;
const MAX_LOCAL_NAME_BYTES: usize = 4 * 1024;
const MAX_HIGHLIGHT_BYTES: usize = 256;

struct AllowAll;

impl WorkGuard for AllowAll {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnotationOpenRequest {
    data_home: AuthorizedPath,
    session_identity: ArtifactDigest,
}

impl AnnotationOpenRequest {
    pub const fn new(data_home: AuthorizedPath, session_identity: ArtifactDigest) -> Self {
        Self {
            data_home,
            session_identity,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventAnnotation {
    event: EventKey,
    comment: String,
}

impl EventAnnotation {
    pub fn new(event: EventKey, comment: impl Into<String>) -> Result<Self, AnnotationError> {
        let comment = comment.into();
        validate_text(&comment, MAX_COMMENT_BYTES, "event comment")?;
        Ok(Self { event, comment })
    }

    pub const fn event(&self) -> &EventKey {
        &self.event
    }

    pub fn comment(&self) -> &str {
        &self.comment
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalSymbolName {
    module_digest: ArtifactDigest,
    relative_pc: u64,
    name: String,
}

impl LocalSymbolName {
    pub fn new(
        module_digest: ArtifactDigest,
        relative_pc: u64,
        name: impl Into<String>,
    ) -> Result<Self, AnnotationError> {
        let name = name.into();
        validate_text(&name, MAX_LOCAL_NAME_BYTES, "local symbol name")?;
        Ok(Self {
            module_digest,
            relative_pc,
            name,
        })
    }

    pub const fn module_digest(&self) -> ArtifactDigest {
        self.module_digest
    }

    pub const fn relative_pc(&self) -> u64 {
        self.relative_pc
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Highlight {
    event: EventKey,
    value: String,
}

impl Highlight {
    pub fn new(event: EventKey, value: impl Into<String>) -> Result<Self, AnnotationError> {
        let value = value.into();
        validate_text(&value, MAX_HIGHLIGHT_BYTES, "highlight")?;
        Ok(Self { event, value })
    }

    pub const fn event(&self) -> &EventKey {
        &self.event
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

pub struct AnnotationStore {
    directory: CacheDirectory,
    database: File,
    database_identity: ObjectIdentity,
    sidecar_identities: [Option<ObjectIdentity>; 3],
    connection: Connection,
    database_path: PathBuf,
}

impl fmt::Debug for AnnotationStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnnotationStore")
            .field("database_path", &self.database_path)
            .finish_non_exhaustive()
    }
}

impl AnnotationStore {
    pub fn open(request: AnnotationOpenRequest) -> Result<Self, AnnotationError> {
        let key = request.session_identity.to_hex();
        let directory =
            CacheDirectory::open_data(request.data_home.as_path(), &key, true, &AllowAll)
                .map_err(AnnotationError::from_initial_cache)?
                .ok_or_else(|| AnnotationError::io("annotation data directory was not created"))?;
        let (database, identity) = open_database_leaf(&directory)?;
        inspect_sidecars(&directory)?;
        let proc_path = PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            directory.file.as_raw_fd(),
            DATABASE_NAME
        ));
        let mut connection = Connection::open_with_flags(
            &proc_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(AnnotationError::sqlite)?;
        verify_database_binding(&directory, identity)
            .map_err(|_| AnnotationError::identity("database binding changed while opening"))?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(AnnotationError::sqlite)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(AnnotationError::sqlite)?;
        let journal: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .map_err(AnnotationError::sqlite)?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(AnnotationError::io("SQLite refused WAL journal mode"));
        }
        migrate(&mut connection)?;
        verify_database_binding(&directory, identity)
            .map_err(|_| AnnotationError::identity("database binding changed during migration"))?;
        let sidecar_identities = inspect_sidecars(&directory)?;
        let database_path = request
            .data_home
            .as_path()
            .join("qtrace-ui")
            .join(key)
            .join(DATABASE_NAME);
        Ok(Self {
            directory,
            database,
            database_identity: identity,
            sidecar_identities,
            connection,
            database_path,
        })
    }

    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub fn begin_transaction(&mut self) -> Result<AnnotationTransaction<'_>, AnnotationError> {
        self.verify_bindings()?;
        let directory = &self.directory;
        let database = &self.database;
        let database_identity = self.database_identity;
        let sidecar_identities = self.sidecar_identities;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(AnnotationError::sqlite)?;
        Ok(AnnotationTransaction {
            transaction,
            directory,
            database,
            database_identity,
            sidecar_identities,
        })
    }

    pub fn event_annotation(
        &self,
        event: &EventKey,
    ) -> Result<Option<EventAnnotation>, AnnotationError> {
        self.verify_bindings()?;
        let key = encode_event_key(event);
        let comment = self
            .connection
            .query_row(
                "SELECT comment FROM event_annotations WHERE event_key=?1",
                [key.as_slice()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(AnnotationError::sqlite)?;
        comment
            .map(|comment| EventAnnotation::new(event.clone(), comment))
            .transpose()
    }

    pub fn local_symbol_name(
        &self,
        module_digest: ArtifactDigest,
        relative_pc: u64,
    ) -> Result<Option<LocalSymbolName>, AnnotationError> {
        self.verify_bindings()?;
        let pc = relative_pc.to_le_bytes();
        let name = self
            .connection
            .query_row(
                "SELECT name FROM local_symbol_names WHERE module_digest=?1 AND relative_pc=?2",
                params![module_digest.as_bytes().as_slice(), pc.as_slice()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(AnnotationError::sqlite)?;
        name.map(|name| LocalSymbolName::new(module_digest, relative_pc, name))
            .transpose()
    }

    pub fn highlight(&self, event: &EventKey) -> Result<Option<Highlight>, AnnotationError> {
        self.verify_bindings()?;
        let key = encode_event_key(event);
        let value = self
            .connection
            .query_row(
                "SELECT value FROM highlights WHERE event_key=?1",
                [key.as_slice()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(AnnotationError::sqlite)?;
        value
            .map(|value| Highlight::new(event.clone(), value))
            .transpose()
    }

    fn verify_bindings(&self) -> Result<(), AnnotationError> {
        self.directory
            .verify()
            .map_err(|_| AnnotationError::identity("annotation data directory was replaced"))?;
        let held = ObjectIdentity::regular_file(&self.database)
            .map_err(|_| AnnotationError::identity("held annotation database changed type"))?;
        if held != self.database_identity {
            return Err(AnnotationError::identity(
                "held annotation database identity changed",
            ));
        }
        verify_database_binding(&self.directory, self.database_identity)
            .map_err(|_| AnnotationError::identity("annotation database was replaced"))?;
        verify_sidecars(&self.directory, self.sidecar_identities)
    }
}

pub struct AnnotationTransaction<'store> {
    transaction: Transaction<'store>,
    directory: &'store CacheDirectory,
    database: &'store File,
    database_identity: ObjectIdentity,
    sidecar_identities: [Option<ObjectIdentity>; 3],
}

impl AnnotationTransaction<'_> {
    pub fn put_event_annotation(&mut self, value: &EventAnnotation) -> Result<(), AnnotationError> {
        self.verify_bindings()?;
        let key = encode_event_key(value.event());
        self.transaction
            .execute(
                "INSERT INTO event_annotations(event_key, comment) VALUES(?1, ?2)\n\
                 ON CONFLICT(event_key) DO UPDATE SET comment=excluded.comment",
                params![key.as_slice(), value.comment()],
            )
            .map_err(AnnotationError::sqlite)?;
        Ok(())
    }

    pub fn delete_event_annotation(&mut self, event: &EventKey) -> Result<(), AnnotationError> {
        self.verify_bindings()?;
        let key = encode_event_key(event);
        self.transaction
            .execute(
                "DELETE FROM event_annotations WHERE event_key=?1",
                [key.as_slice()],
            )
            .map_err(AnnotationError::sqlite)?;
        Ok(())
    }

    pub fn put_local_symbol_name(
        &mut self,
        value: &LocalSymbolName,
    ) -> Result<(), AnnotationError> {
        self.verify_bindings()?;
        let pc = value.relative_pc().to_le_bytes();
        self.transaction
            .execute(
                "INSERT INTO local_symbol_names(module_digest, relative_pc, name) VALUES(?1, ?2, ?3)\n\
                 ON CONFLICT(module_digest, relative_pc) DO UPDATE SET name=excluded.name",
                params![value.module_digest().as_bytes().as_slice(), pc.as_slice(), value.name()],
            )
            .map_err(AnnotationError::sqlite)?;
        Ok(())
    }

    pub fn delete_local_symbol_name(
        &mut self,
        module_digest: ArtifactDigest,
        relative_pc: u64,
    ) -> Result<(), AnnotationError> {
        self.verify_bindings()?;
        let pc = relative_pc.to_le_bytes();
        self.transaction
            .execute(
                "DELETE FROM local_symbol_names WHERE module_digest=?1 AND relative_pc=?2",
                params![module_digest.as_bytes().as_slice(), pc.as_slice()],
            )
            .map_err(AnnotationError::sqlite)?;
        Ok(())
    }

    pub fn put_highlight(&mut self, value: &Highlight) -> Result<(), AnnotationError> {
        self.verify_bindings()?;
        let key = encode_event_key(value.event());
        self.transaction
            .execute(
                "INSERT INTO highlights(event_key, value) VALUES(?1, ?2)\n\
                 ON CONFLICT(event_key) DO UPDATE SET value=excluded.value",
                params![key.as_slice(), value.value()],
            )
            .map_err(AnnotationError::sqlite)?;
        Ok(())
    }

    pub fn delete_highlight(&mut self, event: &EventKey) -> Result<(), AnnotationError> {
        self.verify_bindings()?;
        let key = encode_event_key(event);
        self.transaction
            .execute(
                "DELETE FROM highlights WHERE event_key=?1",
                [key.as_slice()],
            )
            .map_err(AnnotationError::sqlite)?;
        Ok(())
    }

    pub fn commit(self) -> Result<(), AnnotationError> {
        self.verify_bindings()?;
        self.transaction.commit().map_err(AnnotationError::sqlite)
    }

    pub fn rollback(self) -> Result<(), AnnotationError> {
        self.transaction.rollback().map_err(AnnotationError::sqlite)
    }

    fn verify_bindings(&self) -> Result<(), AnnotationError> {
        self.directory
            .verify()
            .map_err(|_| AnnotationError::identity("annotation data directory was replaced"))?;
        let held = ObjectIdentity::regular_file(self.database)
            .map_err(|_| AnnotationError::identity("held annotation database changed type"))?;
        if held != self.database_identity {
            return Err(AnnotationError::identity(
                "held annotation database identity changed",
            ));
        }
        verify_database_binding(self.directory, self.database_identity)
            .map_err(|_| AnnotationError::identity("annotation database was replaced"))?;
        verify_sidecars(self.directory, self.sidecar_identities)
    }
}

fn migrate(connection: &mut Connection) -> Result<(), AnnotationError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(AnnotationError::sqlite)?;
    let version_table: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version')",
            [],
            |row| row.get(0),
        )
        .map_err(AnnotationError::sqlite)?;
    if !version_table {
        create_schema(&transaction)?;
        transaction
            .execute(
                "INSERT INTO schema_version(version) VALUES(?1)",
                [CURRENT_SCHEMA],
            )
            .map_err(AnnotationError::sqlite)?;
    } else {
        let version: i64 = transaction
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .map_err(AnnotationError::sqlite)?;
        match version {
            1 => {
                create_annotation_tables(&transaction)?;
                transaction
                    .execute("UPDATE schema_version SET version=?1", [CURRENT_SCHEMA])
                    .map_err(AnnotationError::sqlite)?;
            }
            CURRENT_SCHEMA => create_annotation_tables(&transaction)?,
            _ => {
                return Err(AnnotationError::new(
                    "annotation.schema_unsupported",
                    format!("unsupported annotation schema {version}"),
                ));
            }
        }
    }
    transaction.commit().map_err(AnnotationError::sqlite)
}

fn create_schema(transaction: &Transaction<'_>) -> Result<(), AnnotationError> {
    transaction
        .execute_batch("CREATE TABLE schema_version(version INTEGER NOT NULL);")
        .map_err(AnnotationError::sqlite)?;
    create_annotation_tables(transaction)
}

fn create_annotation_tables(transaction: &Transaction<'_>) -> Result<(), AnnotationError> {
    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS event_annotations(\n\
                 event_key BLOB PRIMARY KEY NOT NULL CHECK(length(event_key)=70),\n\
                 comment TEXT NOT NULL\n\
             );\n\
             CREATE TABLE IF NOT EXISTS local_symbol_names(\n\
                 module_digest BLOB NOT NULL CHECK(length(module_digest)=32),\n\
                 relative_pc BLOB NOT NULL CHECK(length(relative_pc)=8),\n\
                 name TEXT NOT NULL,\n\
                 PRIMARY KEY(module_digest, relative_pc)\n\
             );\n\
             CREATE TABLE IF NOT EXISTS highlights(\n\
                 event_key BLOB PRIMARY KEY NOT NULL CHECK(length(event_key)=70),\n\
                 value TEXT NOT NULL\n\
             );",
        )
        .map_err(AnnotationError::sqlite)
}

fn encode_event_key(key: &EventKey) -> [u8; 70] {
    let mut out = [0_u8; 70];
    out[..32].copy_from_slice(key.artifact.as_bytes());
    out[32..40].copy_from_slice(&key.timeline.0.to_le_bytes());
    out[40..48].copy_from_slice(&key.record_ordinal.to_le_bytes());
    out[48..56].copy_from_slice(&key.source_offset.to_le_bytes());
    if let Some(sequence) = key.sequence {
        out[56] = 1;
        out[57..65].copy_from_slice(&sequence.to_le_bytes());
    }
    if let Some(tid) = key.tid {
        out[65] = 1;
        out[66..70].copy_from_slice(&tid.to_le_bytes());
    }
    out
}

fn verify_database_binding(
    directory: &CacheDirectory,
    expected: ObjectIdentity,
) -> Result<(), CacheError> {
    let descriptor = openat(
        &directory.file,
        DATABASE_NAME,
        OFlags::RDWR.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC),
        Mode::empty(),
    )
    .map_err(|error| CacheError::path(format!("annotation database binding changed: {error}")))?;
    let actual = ObjectIdentity::regular_file(&File::from(descriptor))?;
    if actual != expected {
        return Err(CacheError::identity(
            "annotation database identity changed during operation",
        ));
    }
    Ok(())
}

fn open_database_leaf(
    directory: &CacheDirectory,
) -> Result<(File, ObjectIdentity), AnnotationError> {
    for _ in 0..8 {
        let expected = inspect_database_leaf(directory)?;
        let (descriptor, created) = if expected.is_some() {
            (
                openat(
                    &directory.file,
                    DATABASE_NAME,
                    OFlags::RDWR
                        .union(OFlags::NONBLOCK)
                        .union(OFlags::NOFOLLOW)
                        .union(OFlags::CLOEXEC),
                    Mode::empty(),
                ),
                false,
            )
        } else {
            (
                openat(
                    &directory.file,
                    DATABASE_NAME,
                    OFlags::RDWR
                        .union(OFlags::NONBLOCK)
                        .union(OFlags::CREATE)
                        .union(OFlags::EXCL)
                        .union(OFlags::NOFOLLOW)
                        .union(OFlags::CLOEXEC),
                    Mode::RUSR | Mode::WUSR,
                ),
                true,
            )
        };
        let descriptor = match descriptor {
            Ok(descriptor) => descriptor,
            Err(Errno::EXIST) if expected.is_none() => continue,
            Err(error) => {
                return Err(AnnotationError::path(format!(
                    "cannot open annotation database: {error}"
                )));
            }
        };
        let database = File::from(descriptor);
        if created {
            database
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    AnnotationError::permission(format!(
                        "cannot secure created annotation database: {error}"
                    ))
                })?;
        }
        let actual = ObjectIdentity::regular_file(&database)
            .map_err(|_| AnnotationError::path("annotation database is not a regular file"))?;
        let mode = database
            .metadata()
            .map_err(|error| {
                AnnotationError::io(format!("cannot stat annotation database: {error}"))
            })?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            return Err(AnnotationError::permission(
                "annotation database mode is not 0600",
            ));
        }
        if expected.is_some_and(|identity| identity != actual) {
            return Err(AnnotationError::identity(
                "annotation database was replaced while opening",
            ));
        }
        return Ok((database, actual));
    }
    Err(AnnotationError::identity(
        "annotation database binding raced repeatedly while opening",
    ))
}

fn inspect_database_leaf(
    directory: &CacheDirectory,
) -> Result<Option<ObjectIdentity>, AnnotationError> {
    let descriptor = match openat(
        &directory.file,
        DATABASE_NAME,
        OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC),
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(AnnotationError::path(format!(
                "cannot inspect annotation database: {error}"
            )));
        }
    };
    let file = File::from(descriptor);
    let identity = ObjectIdentity::regular_file(&file)
        .map_err(|_| AnnotationError::path("annotation database is not a regular file"))?;
    let mode = file
        .metadata()
        .map_err(|error| AnnotationError::io(format!("cannot stat annotation database: {error}")))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err(AnnotationError::permission(
            "existing annotation database mode is not 0600",
        ));
    }
    Ok(Some(identity))
}

fn inspect_sidecars(
    directory: &CacheDirectory,
) -> Result<[Option<ObjectIdentity>; 3], AnnotationError> {
    let mut identities = [None; 3];
    for (slot, name) in identities.iter_mut().zip(SIDECAR_NAMES) {
        let descriptor = match openat(
            &directory.file,
            name,
            OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC),
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(Errno::NOENT) => continue,
            Err(error) => {
                return Err(AnnotationError::path(format!(
                    "cannot inspect SQLite sidecar {name}: {error}"
                )));
            }
        };
        let file = File::from(descriptor);
        let identity = ObjectIdentity::regular_file(&file).map_err(|_| {
            AnnotationError::path(format!("SQLite sidecar {name} is not a regular file"))
        })?;
        let mode = file
            .metadata()
            .map_err(|error| {
                AnnotationError::io(format!("cannot stat SQLite sidecar {name}: {error}"))
            })?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            return Err(AnnotationError::path(format!(
                "SQLite sidecar {name} does not have mode 0600"
            )));
        }
        *slot = Some(identity);
    }
    Ok(identities)
}

fn verify_sidecars(
    directory: &CacheDirectory,
    expected: [Option<ObjectIdentity>; 3],
) -> Result<(), AnnotationError> {
    let actual = inspect_sidecars(directory)?;
    if actual != expected {
        return Err(AnnotationError::identity(
            "SQLite sidecar identity changed during operation",
        ));
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize, label: &str) -> Result<(), AnnotationError> {
    if value.is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(AnnotationError::new(
            "annotation.invalid_argument",
            format!("{label} is empty, too long, or contains NUL"),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnotationError {
    code: &'static str,
    detail: String,
}

impl AnnotationError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn path(detail: impl Into<String>) -> Self {
        Self::new("annotation.path_escape", detail)
    }

    fn identity(detail: impl Into<String>) -> Self {
        Self::new("annotation.identity_changed", detail)
    }

    fn permission(detail: impl Into<String>) -> Self {
        Self::new("annotation.permission_denied", detail)
    }

    fn io(detail: impl Into<String>) -> Self {
        Self::new("annotation.io", detail)
    }

    fn sqlite(error: rusqlite::Error) -> Self {
        Self::new("annotation.sqlite", error.to_string())
    }

    fn from_initial_cache(error: CacheError) -> Self {
        let code = match error.code() {
            "control.resource_exhausted" => "control.resource_exhausted",
            "job.cancelled" => "job.cancelled",
            "cache.permission_denied" => "annotation.permission_denied",
            _ => "annotation.path_escape",
        };
        Self::new(code, error.to_string())
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for AnnotationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl Error for AnnotationError {}
