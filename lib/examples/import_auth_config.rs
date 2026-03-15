use std::{env, error::Error, fs, path::PathBuf};

use alaric_lib::database::{
    Database, DatabaseConfig,
    principals::{KeyAlgorithm, PrincipalKind},
};
use serde::Deserialize;
use sqlx::types::Uuid;

#[derive(Debug, Deserialize)]
struct AuthConfigFile {
    version: u16,
    #[serde(default)]
    agents: std::collections::BTreeMap<String, AuthConfigIdentity>,
    #[serde(default)]
    clients: std::collections::BTreeMap<String, AuthConfigIdentity>,
}

#[derive(Debug, Deserialize)]
struct AuthConfigIdentity {
    key_id: String,
    public_key: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./server-auth.json"));
    let database_url = env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set before importing auth config")?;

    let raw = fs::read_to_string(&path)?;
    let config: AuthConfigFile = serde_json::from_str(&raw)?;
    if config.version != 2 {
        return Err(format!(
            "unsupported auth config version {}; expected 2",
            config.version
        )
        .into());
    }

    let mut db_config = DatabaseConfig::new(database_url);
    db_config.max_connections = 2;
    let database = Database::connect_and_migrate(&db_config).await?;

    for (external_id, identity) in config.agents {
        upsert_identity(
            &database,
            PrincipalKind::Agent,
            &external_id,
            &identity.key_id,
            &identity.public_key,
        )
        .await?;
    }
    for (external_id, identity) in config.clients {
        upsert_identity(
            &database,
            PrincipalKind::Client,
            &external_id,
            &identity.key_id,
            &identity.public_key,
        )
        .await?;
    }

    database.close().await;
    println!("imported auth config from {}", path.display());
    Ok(())
}

async fn upsert_identity(
    database: &Database,
    kind: PrincipalKind,
    external_id: &str,
    key_id: &str,
    public_key_hex: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let public_key = hex::decode(public_key_hex)?;

    let principal_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO principals (kind, external_id, metadata)
        VALUES ($1, $2, '{}'::jsonb)
        ON CONFLICT (kind, external_id) DO UPDATE
        SET disabled_at = NULL
        RETURNING id
        "#,
    )
    .bind(kind)
    .bind(external_id)
    .fetch_one(database.pool())
    .await?;

    sqlx::query(
        r#"
        INSERT INTO principal_keys (
            principal_id,
            key_id,
            algorithm,
            public_key,
            valid_from
        )
        VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (principal_id, key_id) DO UPDATE
        SET algorithm = EXCLUDED.algorithm,
            public_key = EXCLUDED.public_key,
            revoked_at = NULL,
            valid_to = NULL
        "#,
    )
    .bind(principal_id)
    .bind(key_id)
    .bind(KeyAlgorithm::Ed25519)
    .bind(public_key)
    .execute(database.pool())
    .await?;

    Ok(())
}
