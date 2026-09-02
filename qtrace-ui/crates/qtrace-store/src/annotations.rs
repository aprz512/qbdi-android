use std::{
    error::Error,
    fmt,
    fs::File,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use qtrace_provider::{ArtifactDigest, EventKey, OperationAbort, WorkDelta, WorkGuard};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use rustix::fs::{Mode, OFlags, openat};
use rustix::io::Errno;

#[cfg(test)]
use std::sync::{Mutex, OnceLock};

use crate::{
    AuthorizedPath,
    annotation_vfs::DescriptorVfs,
    cache::{CacheDirectory, CacheError, ObjectIdentity},
};

const DATABASE_NAME: &str = "annotations.sqlite3";
const SIDECAR_NAMES: [&str; 3] = [
    "annotations.sqlite3-wal",
    "annotations.sqlite3-shm",
    "annotations.sqlite3-journal",
];
const CURRENT_SCHEMA: i64 = 3;
const MAX_COMMENT_BYTES: usize = 64 * 1024;
const MAX_LOCAL_NAME_BYTES: usize = 4 * 1024;
const MAX_HIGHLIGHT_BYTES: usize = 256;

#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) enum OpenHookPhase {
    BeforeSqliteOpen,
    AfterSqliteOpen,
}

#[cfg(test)]
type OpenHook = Box<dyn Fn(OpenHookPhase) + Send>;

#[cfg(test)]
static OPEN_HOOK: OnceLock<Mutex<Option<OpenHook>>> = OnceLock::new();

#[cfg(test)]
pub(super) fn run_open_hook(phase: OpenHookPhase) {
    if let Some(hook) = OPEN_HOOK
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("annotation open hook lock poisoned")
        .as_ref()
    {
        hook(phase);
    }
}

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
    vfs: DescriptorVfs,
    connection: Option<Connection>,
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
        let (database, _) = open_database_leaf(&directory)?;
        let sidecars = inspect_sidecars(&directory)?;
        if sidecars[1].is_some() {
            return Err(AnnotationError::path(
                "preexisting SQLite shared-memory sidecar is forbidden",
            ));
        }
        let database_path = request
            .data_home
            .as_path()
            .join("qtrace-ui")
            .join(key)
            .join(DATABASE_NAME);
        let vfs = DescriptorVfs::register(&directory.file, database)?;
        let mut connection = Connection::open_with_flags_and_vfs(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            vfs.name(),
        )
        .map_err(AnnotationError::sqlite)?;
        configure_sqlite_limits(&connection)?;
        let locking: String = connection
            .query_row("PRAGMA locking_mode=EXCLUSIVE", [], |row| row.get(0))
            .map_err(AnnotationError::sqlite)?;
        if !locking.eq_ignore_ascii_case("exclusive") {
            return Err(AnnotationError::vfs(
                "SQLite refused exclusive locking mode",
            ));
        }
        configure_sqlite_pragmas(&connection)?;
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
        vfs.verify_bindings()?;
        Ok(Self {
            directory,
            vfs,
            connection: Some(connection),
            database_path,
        })
    }

    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub fn begin_transaction(&mut self) -> Result<AnnotationTransaction<'_>, AnnotationError> {
        self.verify_bindings()?;
        let directory = &self.directory;
        let vfs = &self.vfs;
        let transaction = self
            .connection
            .as_mut()
            .expect("annotation connection is present until drop")
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(AnnotationError::sqlite)?;
        Ok(AnnotationTransaction {
            transaction,
            directory,
            vfs,
        })
    }

    pub fn event_annotation(
        &self,
        event: &EventKey,
    ) -> Result<Option<EventAnnotation>, AnnotationError> {
        self.verify_bindings()?;
        let key = encode_event_key(event);
        let connection = self
            .connection
            .as_ref()
            .expect("annotation connection is present until drop");
        let parameters: [&dyn rusqlite::ToSql; 1] = [&key.as_slice()];
        let comment = read_bounded_text(
            connection,
            "event_annotations",
            "comment",
            "event_key=?1",
            &parameters,
            MAX_COMMENT_BYTES,
        )?;
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
        let connection = self
            .connection
            .as_ref()
            .expect("annotation connection is present until drop");
        let digest = module_digest.as_bytes();
        let parameters: [&dyn rusqlite::ToSql; 2] = [&digest.as_slice(), &pc.as_slice()];
        let name = read_bounded_text(
            connection,
            "local_symbol_names",
            "name",
            "module_digest=?1 AND relative_pc=?2",
            &parameters,
            MAX_LOCAL_NAME_BYTES,
        )?;
        name.map(|name| LocalSymbolName::new(module_digest, relative_pc, name))
            .transpose()
    }

    pub fn highlight(&self, event: &EventKey) -> Result<Option<Highlight>, AnnotationError> {
        self.verify_bindings()?;
        let key = encode_event_key(event);
        let connection = self
            .connection
            .as_ref()
            .expect("annotation connection is present until drop");
        let parameters: [&dyn rusqlite::ToSql; 1] = [&key.as_slice()];
        let value = read_bounded_text(
            connection,
            "highlights",
            "value",
            "event_key=?1",
            &parameters,
            MAX_HIGHLIGHT_BYTES,
        )?;
        value
            .map(|value| Highlight::new(event.clone(), value))
            .transpose()
    }

    fn verify_bindings(&self) -> Result<(), AnnotationError> {
        self.directory
            .verify()
            .map_err(|_| AnnotationError::identity("annotation data directory was replaced"))?;
        self.vfs.verify_bindings()
    }
}

impl Drop for AnnotationStore {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            let _ = connection.close();
        }
    }
}

pub struct AnnotationTransaction<'store> {
    transaction: Transaction<'store>,
    directory: &'store CacheDirectory,
    vfs: &'store DescriptorVfs,
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
        self.vfs.verify_bindings()
    }
}

fn configure_sqlite_limits(connection: &Connection) -> Result<(), AnnotationError> {
    // SAFETY: the connection is live and exclusively borrowed during initialization.
    let handle = unsafe { connection.handle() };
    for (category, limit) in [
        (rusqlite::ffi::SQLITE_LIMIT_LENGTH, 128 * 1024),
        (rusqlite::ffi::SQLITE_LIMIT_SQL_LENGTH, 64 * 1024),
        (rusqlite::ffi::SQLITE_LIMIT_COLUMN, 32),
        (rusqlite::ffi::SQLITE_LIMIT_VARIABLE_NUMBER, 16),
        (rusqlite::ffi::SQLITE_LIMIT_ATTACHED, 0),
    ] {
        // SAFETY: sqlite3_limit accepts these documented categories and retains no pointers.
        unsafe { rusqlite::ffi::sqlite3_limit(handle, category, limit) };
    }
    Ok(())
}

fn configure_sqlite_pragmas(connection: &Connection) -> Result<(), AnnotationError> {
    for statement in [
        "PRAGMA page_size=4096",
        "PRAGMA max_page_count=262144",
        "PRAGMA temp_store=MEMORY",
        "PRAGMA recursive_triggers=OFF",
        "PRAGMA journal_size_limit=67108864",
        "PRAGMA wal_autocheckpoint=1000",
    ] {
        connection.execute_batch(statement).map_err(|error| {
            AnnotationError::vfs(format!("SQLite limit setup `{statement}` failed: {error}"))
        })?;
    }
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(AnnotationError::sqlite)?;
    let max_pages: i64 = connection
        .query_row("PRAGMA max_page_count", [], |row| row.get(0))
        .map_err(AnnotationError::sqlite)?;
    if page_size != 4096 || max_pages <= 0 || max_pages > 262_144 {
        return Err(AnnotationError::resource(
            "SQLite page-size or page-count hard limit was not applied",
        ));
    }
    Ok(())
}

fn read_bounded_text(
    connection: &Connection,
    table: &str,
    column: &str,
    predicate: &str,
    parameters: &[&dyn rusqlite::ToSql],
    maximum: usize,
) -> Result<Option<String>, AnnotationError> {
    let metadata_sql = format!(
        "SELECT typeof({column}), length(CAST({column} AS BLOB)) FROM {table} WHERE {predicate}"
    );
    let metadata = connection
        .query_row(&metadata_sql, parameters, |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .optional()
        .map_err(AnnotationError::sqlite)?;
    let Some((kind, length)) = metadata else {
        return Ok(None);
    };
    if kind != "text" || length < 0 {
        return Err(AnnotationError::schema(
            "annotation text has an invalid SQLite storage class",
        ));
    }
    let length = usize::try_from(length)
        .map_err(|_| AnnotationError::resource("annotation text length overflow"))?;
    if length == 0 || length > maximum {
        return Err(AnnotationError::resource(
            "annotation text exceeds its UTF-8 byte limit",
        ));
    }
    let value_sql = format!("SELECT {column} FROM {table} WHERE {predicate}");
    let value = connection
        .query_row(&value_sql, parameters, |row| row.get::<_, String>(0))
        .map_err(AnnotationError::sqlite)?;
    if value.len() != length || value.contains('\0') {
        return Err(AnnotationError::schema(
            "annotation text changed type or length while reading",
        ));
    }
    Ok(Some(value))
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
            2 => {
                validate_legacy_rows(&transaction)?;
                transaction
                    .execute_batch(
                        "ALTER TABLE event_annotations RENAME TO event_annotations_v2;
                         ALTER TABLE local_symbol_names RENAME TO local_symbol_names_v2;
                         ALTER TABLE highlights RENAME TO highlights_v2;",
                    )
                    .map_err(AnnotationError::sqlite)?;
                create_annotation_tables(&transaction)?;
                transaction
                    .execute_batch(
                        "INSERT INTO event_annotations SELECT * FROM event_annotations_v2;
                         INSERT INTO local_symbol_names SELECT * FROM local_symbol_names_v2;
                         INSERT INTO highlights SELECT * FROM highlights_v2;
                         DROP TABLE event_annotations_v2;
                         DROP TABLE local_symbol_names_v2;
                         DROP TABLE highlights_v2;",
                    )
                    .map_err(AnnotationError::sqlite)?;
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

fn validate_legacy_rows(transaction: &Transaction<'_>) -> Result<(), AnnotationError> {
    let oversized: bool = transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM event_annotations WHERE length(CAST(comment AS BLOB)) NOT BETWEEN 1 AND 65536
                 UNION ALL SELECT 1 FROM local_symbol_names WHERE length(CAST(name AS BLOB)) NOT BETWEEN 1 AND 4096
                 UNION ALL SELECT 1 FROM highlights WHERE length(CAST(value AS BLOB)) NOT BETWEEN 1 AND 256
             )",
            [],
            |row| row.get(0),
        )
        .map_err(AnnotationError::sqlite)?;
    if oversized {
        return Err(AnnotationError::resource(
            "legacy annotation text exceeds its byte limit",
        ));
    }
    let wrong_type: bool = transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM event_annotations WHERE typeof(comment)!='text'
                 UNION ALL SELECT 1 FROM local_symbol_names WHERE typeof(name)!='text'
                 UNION ALL SELECT 1 FROM highlights WHERE typeof(value)!='text'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(AnnotationError::sqlite)?;
    if wrong_type {
        return Err(AnnotationError::schema(
            "legacy annotation text has an invalid SQLite storage class",
        ));
    }
    Ok(())
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
                 event_key BLOB PRIMARY KEY NOT NULL CHECK(typeof(event_key)='blob' AND length(event_key)=70),\n\
                 comment TEXT NOT NULL CHECK(typeof(comment)='text' AND length(CAST(comment AS BLOB)) BETWEEN 1 AND 65536 AND instr(comment, char(0))=0)\n\
             );\n\
             CREATE TABLE IF NOT EXISTS local_symbol_names(\n\
                 module_digest BLOB NOT NULL CHECK(typeof(module_digest)='blob' AND length(module_digest)=32),\n\
                 relative_pc BLOB NOT NULL CHECK(typeof(relative_pc)='blob' AND length(relative_pc)=8),\n\
                 name TEXT NOT NULL CHECK(typeof(name)='text' AND length(CAST(name AS BLOB)) BETWEEN 1 AND 4096 AND instr(name, char(0))=0),\n\
                 PRIMARY KEY(module_digest, relative_pc)\n\
             );\n\
             CREATE TABLE IF NOT EXISTS highlights(\n\
                 event_key BLOB PRIMARY KEY NOT NULL CHECK(typeof(event_key)='blob' AND length(event_key)=70),\n\
                 value TEXT NOT NULL CHECK(typeof(value)='text' AND length(CAST(value AS BLOB)) BETWEEN 1 AND 256 AND instr(value, char(0))=0)\n\
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

    pub(crate) fn path(detail: impl Into<String>) -> Self {
        Self::new("annotation.path_escape", detail)
    }

    pub(crate) fn identity(detail: impl Into<String>) -> Self {
        Self::new("annotation.identity_changed", detail)
    }

    pub(crate) fn permission(detail: impl Into<String>) -> Self {
        Self::new("annotation.permission_denied", detail)
    }

    fn io(detail: impl Into<String>) -> Self {
        Self::new("annotation.io", detail)
    }

    fn sqlite(error: rusqlite::Error) -> Self {
        Self::new("annotation.sqlite", error.to_string())
    }

    pub(crate) fn vfs(detail: impl Into<String>) -> Self {
        Self::new("annotation.io", detail)
    }

    fn schema(detail: impl Into<String>) -> Self {
        Self::new("annotation.schema_corrupt", detail)
    }

    fn resource(detail: impl Into<String>) -> Self {
        Self::new("annotation.resource_exhausted", detail)
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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::{Arc, Mutex},
    };

    use qtrace_provider::{ArtifactDigest, EventKey, TimelineId};
    use tempfile::TempDir;

    use super::{
        AnnotationOpenRequest, AnnotationStore, AuthorizedPath, EventAnnotation, OPEN_HOOK,
        OpenHookPhase,
    };

    #[test]
    fn sqlite_io_never_follows_an_aba_replacement_after_main_fd_is_held() {
        let root = TempDir::new().unwrap();
        let session = ArtifactDigest::new([0xa5; 32]);
        let request =
            AnnotationOpenRequest::new(AuthorizedPath::new(root.path().to_owned()), session);
        drop(AnnotationStore::open(request.clone()).unwrap());

        let database = root
            .path()
            .join("qtrace-ui")
            .join(session.to_hex())
            .join("annotations.sqlite3");
        let held = database.with_extension("held");
        let attacker = database.with_extension("attacker");
        let phases = Arc::new(Mutex::new(0_u8));
        let hook_phases = Arc::clone(&phases);
        let hook_database = database.clone();
        let hook_held = held.clone();
        let hook_attacker = attacker.clone();
        *OPEN_HOOK.get_or_init(|| Mutex::new(None)).lock().unwrap() =
            Some(Box::new(move |phase| match phase {
                OpenHookPhase::BeforeSqliteOpen => {
                    fs::rename(&hook_database, &hook_held).unwrap();
                    fs::write(&hook_database, []).unwrap();
                    fs::set_permissions(&hook_database, fs::Permissions::from_mode(0o600)).unwrap();
                    *hook_phases.lock().unwrap() |= 1;
                }
                OpenHookPhase::AfterSqliteOpen => {
                    fs::rename(&hook_database, &hook_attacker).unwrap();
                    fs::rename(&hook_held, &hook_database).unwrap();
                    *hook_phases.lock().unwrap() |= 2;
                }
            }));

        let mut store = AnnotationStore::open(request).unwrap();
        *OPEN_HOOK.get().unwrap().lock().unwrap() = None;
        assert_eq!(*phases.lock().unwrap(), 3);
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction
                .put_event_annotation(
                    &EventAnnotation::new(
                        EventKey::new(session, TimelineId(1), 2, 3, Some(4), Some(5)),
                        "must stay on the held inode",
                    )
                    .unwrap(),
                )
                .unwrap();
            transaction.commit().unwrap();
        }
        drop(store);

        assert_eq!(
            fs::metadata(&attacker).unwrap().len(),
            0,
            "SQLite wrote through the attacker-controlled pathname replacement"
        );
    }
}
