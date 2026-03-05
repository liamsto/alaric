use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use alaric_lib::protocol::{AgentId, SessionId};
use tokio::{
    net::TcpStream,
    sync::{RwLock, oneshot},
};

use crate::auth::HandshakeAuthenticator;

pub(crate) type AgentWaiter = oneshot::Sender<TcpStream>;
pub(crate) type AgentRegistry = Arc<RwLock<HashMap<AgentId, AgentWaiter>>>;

#[derive(Clone)]
pub(crate) struct ServerState {
    pub(crate) agents: AgentRegistry,
    sessions: Arc<AtomicU64>,
    pub(crate) authenticator: Arc<HandshakeAuthenticator>,
}

impl ServerState {
    pub(crate) fn new(authenticator: HandshakeAuthenticator) -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(AtomicU64::new(1)),
            authenticator: Arc::new(authenticator),
        }
    }

    pub(crate) fn next_session_id(&self) -> SessionId {
        SessionId(self.sessions.fetch_add(1, Ordering::Relaxed))
    }
}
