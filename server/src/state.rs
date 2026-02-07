use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use lib::protocol::{AgentId, SessionId};
use tokio::sync::{RwLock, mpsc::Sender};

pub(crate) type AgentTx = Sender<Vec<u8>>;
pub(crate) type AgentRegistry = Arc<RwLock<HashMap<AgentId, AgentTx>>>;

#[derive(Clone)]
pub(crate) struct ServerState {
    pub(crate) agents: AgentRegistry,
    sessions: Arc<AtomicU64>,
}

impl ServerState {
    pub(crate) fn new() -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(AtomicU64::new(1)),
        }
    }

    pub(crate) fn next_session_id(&self) -> SessionId {
        SessionId(self.sessions.fetch_add(1, Ordering::Relaxed))
    }
}
