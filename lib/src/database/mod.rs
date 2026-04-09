mod admin_store;
pub mod agents;
mod auth_listener;
pub mod command_runs;
pub mod principals;
mod server_store;
pub mod sessions;

pub use admin_store::{
    AdminStoreError, AgentGroupCreateOutcome, AgentGroupDeleteOutcome, AgentGroupListEntry,
    AgentGroupMemberAddOutcome, AgentGroupMemberRemoveOutcome, AgentGroupMoveOutcome,
    AgentGroupSetNameOutcome, AgentGroupUpsertOutcome, KeyAddOutcome, KeyRevokeOutcome,
    KeyRotateOutcome, PrincipalAddOutcome, PrincipalAttestationSetOutcome, PrincipalDisableOutcome,
    PrincipalListEntry,
};
pub use auth_listener::{AuthConfigListener, AuthConfigListenerError, AuthConfigNotification};
pub use server_store::{ActivePrincipalKey, PruneLogsResult, ServerStoreError};

use std::{env, error::Error, fmt, io, time::Duration};

use sqlx::{
    PgPool,
    migrate::{MigrateError, Migrator},
    postgres::PgPoolOptions,
};

pub const MIN_LOG_RETENTION_DAYS: u16 = 30;
pub const DEFAULT_LOG_RETENTION_DAYS: u16 = 60;
pub const MAX_LOG_RETENTION_DAYS: u16 = 90;

pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRetentionDays(u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRetentionDaysError {
    pub min: u16,
    pub max: u16,
    pub got: u16,
}

impl fmt::Display for LogRetentionDaysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "log retention days must be between {} and {} (got {})",
            self.min, self.max, self.got
        )
    }
}

impl Error for LogRetentionDaysError {}

impl LogRetentionDays {
    pub fn new(days: u16) -> Result<Self, LogRetentionDaysError> {
        if !(MIN_LOG_RETENTION_DAYS..=MAX_LOG_RETENTION_DAYS).contains(&days) {
            return Err(LogRetentionDaysError {
                min: MIN_LOG_RETENTION_DAYS,
                max: MAX_LOG_RETENTION_DAYS,
                got: days,
            });
        }
        Ok(Self(days))
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

impl Default for LogRetentionDays {
    fn default() -> Self {
        Self(DEFAULT_LOG_RETENTION_DAYS)
    }
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub database_url: String,
    pub max_connections: u32,
    pub acquire_timeout: Duration,
    pub log_retention_days: LogRetentionDays,
}

impl DatabaseConfig {
    pub fn new(database_url: impl Into<String>) -> Self {
        Self {
            database_url: database_url.into(),
            max_connections: 10,
            acquire_timeout: Duration::from_secs(5),
            log_retention_days: LogRetentionDays::default(),
        }
    }
}

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
    log_retention_days: LogRetentionDays,
}

#[derive(Debug)]
pub enum DatabaseInitError {
    Connect(sqlx::Error),
    Migrate(MigrateError),
    PruneLogs(ServerStoreError),
    EnvVar(io::Error),
}

impl fmt::Display for DatabaseInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DatabaseInitError::Connect(source) => {
                write!(f, "failed to connect to postgres: {}", source)
            }
            DatabaseInitError::Migrate(source) => write!(f, "failed to run migrations: {}", source),
            DatabaseInitError::PruneLogs(source) => write!(f, "failed to prune logs: {}", source),
            DatabaseInitError::EnvVar(source) => {
                write!(f, "invalid database environment: {}", source)
            }
        }
    }
}

impl Error for DatabaseInitError {}

impl Database {
    pub async fn connect(config: &DatabaseConfig) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.acquire_timeout)
            .connect(&config.database_url)
            .await?;

        Ok(Self {
            pool,
            log_retention_days: config.log_retention_days,
        })
    }

    pub async fn connect_and_migrate(config: &DatabaseConfig) -> Result<Self, DatabaseInitError> {
        let database = Self::connect(config)
            .await
            .map_err(DatabaseInitError::Connect)?;
        database
            .migrate()
            .await
            .map_err(DatabaseInitError::Migrate)?;
        Ok(database)
    }

    pub async fn migrate(&self) -> Result<(), MigrateError> {
        MIGRATOR.run(&self.pool).await
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn log_retention_days(&self) -> LogRetentionDays {
        self.log_retention_days
    }

    pub async fn close(self) {
        self.pool.close().await;
    }

    pub async fn from_env() -> Result<Self, DatabaseInitError> {
        let database_url = env::var("DATABASE_URL").map_err(|_| {
            DatabaseInitError::EnvVar(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DATABASE_URL must be set for the server",
            ))
        })?;

        let mut config = DatabaseConfig::new(database_url);
        if let Ok(raw) = env::var("DATABASE_MAX_CONNECTIONS") {
            config.max_connections = raw.parse::<u32>().map_err(|err| {
                DatabaseInitError::EnvVar(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid DATABASE_MAX_CONNECTIONS '{}': {}", raw, err),
                ))
            })?;
        }
        if let Ok(raw) = env::var("DATABASE_ACQUIRE_TIMEOUT_SECS") {
            let seconds = raw.parse::<u64>().map_err(|err| {
                DatabaseInitError::EnvVar(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid DATABASE_ACQUIRE_TIMEOUT_SECS '{}': {}", raw, err),
                ))
            })?;
            config.acquire_timeout = Duration::from_secs(seconds);
        }
        if let Ok(raw) = env::var("LOG_RETENTION_DAYS") {
            let days = raw.parse::<u16>().map_err(|err| {
                DatabaseInitError::EnvVar(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid LOG_RETENTION_DAYS '{}': {}", raw, err),
                ))
            })?;
            config.log_retention_days = LogRetentionDays::new(days).map_err(|err| {
                DatabaseInitError::EnvVar(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid LOG_RETENTION_DAYS: {}", err),
                ))
            })?;
        }

        let database = Database::connect_and_migrate(&config).await?;
        database
            .prune_logs()
            .await
            .map_err(DatabaseInitError::PruneLogs)?;
        Ok(database)
    }
}
