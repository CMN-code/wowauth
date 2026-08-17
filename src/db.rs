use anyhow::{Context, Result};
use diesel::connection::SimpleConnection;
use diesel::r2d2::{ConnectionManager, CustomizeConnection, Pool};
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

pub type DbPool = Pool<ConnectionManager<SqliteConnection>>;

// Embedding the migrations in the binary means the schema is always brought
// up to date, regardless of whether anyone remembered to run
// `diesel migration run` first.
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

/// Applied to every connection as it's handed out by the pool. SQLite
/// pragmas are per-connection and don't persist in the database file, and
/// running pending migrations here — rather than once at startup — means a
/// database file that's missing, empty, or gets replaced out from under a
/// running process gets its schema rebuilt the moment the pool next opens a
/// connection to it, with no restart needed.
#[derive(Debug)]
struct ConnectionOptions;

impl CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for ConnectionOptions {
    fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), diesel::r2d2::Error> {
        conn.batch_execute(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA busy_timeout = 5000;",
        )?;
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(diesel::result::Error::QueryBuilderError)
            .map_err(diesel::r2d2::Error::QueryError)?;
        Ok(())
    }
}

pub fn init_pool(database_url: &str) -> Result<DbPool> {
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    let pool = Pool::builder()
        .connection_customizer(Box::new(ConnectionOptions))
        // SQLite only ever has one writer at a time regardless of pool size,
        // and creating connections lazily (rather than eagerly opening
        // `max_size` of them up front) avoids a burst of connections racing
        // to switch a brand-new database file into WAL mode on startup.
        .max_size(8)
        .min_idle(Some(0))
        .build(manager)
        .context("failed to build the database connection pool")?;

    // Forces a connection now (and so the pragmas/migrations above) rather
    // than lazily on the first request, so a broken database is a startup
    // failure, not a surprise mid-request.
    let _ = pool.get().context("failed to acquire a connection")?;

    Ok(pool)
}
