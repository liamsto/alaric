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
pub(crate) struct ServerState {
    pub(crate) agents: AgentRegistry,
    authenticator: Arc<RwLock<Arc<HandshakeAuthenticator>>>,
    pub(crate) database: Option<Arc<Database>>,
}

impl ServerState {
    pub(crate) fn new(
        authenticator: HandshakeAuthenticator,
        database: Option<Arc<Database>>,
    ) -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            authenticator: Arc::new(RwLock::new(Arc::new(authenticator))),
            database,
        }
    }

    pub(crate) fn next_session_id(&self) -> SessionId {
        SessionId::new_random()
    }

    pub(crate) async fn authenticator_snapshot(&self) -> Arc<HandshakeAuthenticator> {
        self.authenticator.read().await.clone()
    }

    pub(crate) async fn replace_authenticator(&self, authenticator: HandshakeAuthenticator) {
        *self.authenticator.write().await = Arc::new(authenticator);
    }
}
