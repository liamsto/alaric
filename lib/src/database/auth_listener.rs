use std::{error::Error, fmt};

use sqlx::postgres::PgListener;

use crate::{constants::AUTH_CONFIG_NOTIFY_CHANNEL, database::Database};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfigNotification {
    pub channel: String,
    pub payload: String,
}

#[derive(Debug)]
pub enum AuthConfigListenerError {
    Sqlx(sqlx::Error),
}

impl fmt::Display for AuthConfigListenerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthConfigListenerError::Sqlx(source) => write!(f, "database error: {}", source),
        }
    }
}

impl Error for AuthConfigListenerError {}

impl From<sqlx::Error> for AuthConfigListenerError {
    fn from(value: sqlx::Error) -> Self {
        Self::Sqlx(value)
    }
}

pub struct AuthConfigListener {
    listener: PgListener,
}

impl AuthConfigListener {
    pub async fn connect(database: &Database) -> Result<Self, AuthConfigListenerError> {
        let mut listener = PgListener::connect_with(database.pool()).await?;
        listener.listen(AUTH_CONFIG_NOTIFY_CHANNEL).await?;
        Ok(Self { listener })
    }

    pub async fn recv(&mut self) -> Result<AuthConfigNotification, AuthConfigListenerError> {
        let notification = self.listener.recv().await?;
        Ok(AuthConfigNotification {
            channel: notification.channel().to_string(),
            payload: notification.payload().to_string(),
        })
    }
}

impl Database {
    pub async fn listen_for_auth_config_changes(
        &self,
    ) -> Result<AuthConfigListener, AuthConfigListenerError> {
        AuthConfigListener::connect(self).await
    }
}
