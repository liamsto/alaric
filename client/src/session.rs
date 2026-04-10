use std::{env, io};

use alaric_lib::{
    constants::DEFAULT_SERVER_PORT,
    protocol::{
        ClientId, HandshakeProofRequest, HandshakeRequest, HandshakeResponse, ListAgentsResponse,
        SessionId, build_auth_proof_ed25519, read_json_frame, write_json_frame,
    },
};
use tokio::net::TcpStream;

use crate::DynError;

#[derive(Debug)]
pub(super) struct ClientAuth {
    pub(super) client_id: ClientId,
    pub(super) auth_key_id: String,
    pub(super) auth_private_key: String,
}

#[derive(Debug)]
pub(super) struct AuthenticatedConnection {
    pub(super) stream: TcpStream,
    pub(super) session_id: SessionId,
}

impl ClientAuth {
    pub(super) fn load_from_env() -> Result<Self, DynError> {
        let client_id = ClientId::new(
            env::var("CLIENT_ID").unwrap_or_else(|_| format!("client-{}", std::process::id())),
        )
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid CLIENT_ID value: {err}"),
            )
        })?;

        let auth_key_id = required_env(
            "CLIENT_AUTH_KEY_ID",
            "CLIENT_AUTH_KEY_ID must be set for handshake authentication",
        )?;
        let auth_private_key = required_env(
            "CLIENT_AUTH_PRIVATE_KEY",
            "CLIENT_AUTH_PRIVATE_KEY must be set for handshake authentication",
        )?;

        Ok(Self {
            client_id,
            auth_key_id,
            auth_private_key,
        })
    }
}

pub(super) async fn fetch_discovery(auth: &ClientAuth) -> Result<ListAgentsResponse, DynError> {
    let request = HandshakeRequest::client_discovery(auth.client_id.clone());
    let mut connection = connect_authenticated(&request, auth).await?;
    let response = read_json_frame::<_, ListAgentsResponse>(&mut connection.stream).await?;
    Ok(response)
}

pub(super) async fn connect_authenticated(
    request: &HandshakeRequest,
    auth: &ClientAuth,
) -> Result<AuthenticatedConnection, DynError> {
    let addr = format!("127.0.0.1:{DEFAULT_SERVER_PORT}");
    let mut stream = TcpStream::connect(addr).await?;

    write_json_frame(&mut stream, request).await?;

    let initial = read_json_frame::<_, HandshakeResponse>(&mut stream).await?;
    let final_response = match initial {
        HandshakeResponse::Challenge(challenge) => {
            let proof = build_auth_proof_ed25519(
                request,
                &challenge,
                &auth.auth_key_id,
                &auth.auth_private_key,
            )?;
            write_json_frame(&mut stream, &HandshakeProofRequest::new(proof)).await?;
            read_json_frame::<_, HandshakeResponse>(&mut stream).await?
        }
        other => other,
    };

    match final_response {
        HandshakeResponse::Accepted(accepted) => Ok(AuthenticatedConnection {
            stream,
            session_id: accepted.session_id,
        }),
        HandshakeResponse::Rejected(rejected) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "handshake rejected ({}): {:?}: {}",
                request_context(request),
                rejected.code,
                rejected.message
            ),
        )
        .into()),
        HandshakeResponse::Challenge(_) => {
            Err(io::Error::other("unexpected second handshake challenge from server").into())
        }
    }
}

fn required_env(name: &str, message: &str) -> Result<String, io::Error> {
    env::var(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, message))
}

fn request_context(request: &HandshakeRequest) -> String {
    match request {
        HandshakeRequest::Client {
            target_agent_id, ..
        } => format!("target={target_agent_id}"),
        HandshakeRequest::ClientDiscovery { .. } => "mode=discovery".to_string(),
        HandshakeRequest::Agent { .. } => "mode=agent".to_string(),
    }
}
