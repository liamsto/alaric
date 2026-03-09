use std::{collections::HashMap, sync::Arc};

use alaric_lib::protocol::{AgentId, SessionId};
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
    pub(crate) authenticator: Arc<HandshakeAuthenticator>,
}

impl ServerState {
    pub(crate) fn new(authenticator: HandshakeAuthenticator) -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            authenticator: Arc::new(authenticator),
        }
    }

    pub(crate) fn next_session_id(&self) -> SessionId {
        SessionId::new_random()
    }
}
