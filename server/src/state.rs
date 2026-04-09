use std::{collections::HashMap, sync::Arc};

use alaric_lib::{
    database::Database,
    protocol::{AgentId, SessionId},
};
use tokio::{
    net::TcpStream,
    sync::{RwLock, oneshot},
};

use crate::auth::HandshakeAuthenticator;

pub(crate) type AgentWaiter = oneshot::Sender<TcpStream>;

pub(crate) struct WaitingAgent {
    pub(crate) session_id: SessionId,
    pub(crate) waiter: AgentWaiter,
}

pub(crate) type AgentRegistry = Arc<RwLock<HashMap<AgentId, WaitingAgent>>>;

#[derive(Clone)]
pub struct ServerState {
    pub(crate) agents: AgentRegistry,
    authenticator: Arc<RwLock<Arc<HandshakeAuthenticator>>>,
    pub database: Arc<Database>,
}

impl ServerState {
    pub fn new(authenticator: HandshakeAuthenticator, database: Arc<Database>) -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            authenticator: Arc::new(RwLock::new(Arc::new(authenticator))),
            database,
        }
    }

    #[must_use]
    pub fn next_session_id(&self) -> SessionId {
        SessionId::new_random()
    }

    pub async fn authenticator_snapshot(&self) -> Arc<HandshakeAuthenticator> {
        self.authenticator.read().await.clone()
    }

    pub async fn replace_authenticator(&self, authenticator: HandshakeAuthenticator) {
        *self.authenticator.write().await = Arc::new(authenticator);
    }
}
