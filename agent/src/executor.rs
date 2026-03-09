use std::{
    collections::BTreeMap,
    io,
    process::{ExitStatus, Stdio},
    time::Duration,
};

use alaric_lib::protocol::{
    AgentMessage, CommandId, CommandProtocolError, OutputStream, RejectionCode, RequestId,
    SecureChannel, send_secure_json,
};
use regex::Regex;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    process::Command,
    time::{Instant, sleep},
};

use crate::policy::{ArgSpec, CommandSpec, Policy, ValidationRule};

pub async fn execute_request<S>(
    channel: &mut SecureChannel,
    stream: &mut S,
    policy: &Policy,
    request_id: RequestId,
    command_id: &CommandId,
    args: &BTreeMap<String, String>,
) -> Result<(), CommandProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(command) = policy.command_by_id(command_id.as_str()) else {
        return send_rejected(
            channel,
            stream,
            request_id,
            RejectionCode::UnknownCommand,
            format!("unknown command id '{}'", command_id),
        )
        .await;
    };

    let ordered_args = match validate_and_order_args(command, args) {
        Ok(ordered_args) => ordered_args,
        Err(message) => {
            return send_rejected(
                channel,
                stream,
                request_id,
                RejectionCode::InvalidArgs,
                message,
            )
            .await;
        }
    };

    let mut child = match spawn_child(command, ordered_args) {
        Ok(child) => child,
        Err(err) => {
            return send_rejected(
                channel,
                stream,
                request_id,
                RejectionCode::ExecutionError,
                format!("failed to spawn command '{}': {}", command.id, err),
            )
            .await;
        }
    };

    send_secure_json(channel, stream, &AgentMessage::Started { request_id }).await?;

    let timeout = Duration::from_secs(command.effective_timeout_secs(policy.default_timeout_secs));
    let max_output_bytes = command.effective_max_output_bytes(policy.max_output_bytes);
    let run_outcome = stream_process_output(
        channel,
        stream,
        request_id,
        &mut child,
        timeout,
        max_output_bytes,
    )
    .await;

    match run_outcome {
        Ok((status, timed_out, truncated)) => {
            let exit_code = status.code().unwrap_or(-1);
            send_secure_json(
                channel,
                stream,
                &AgentMessage::Completed {
                    request_id,
                    exit_code,
                    timed_out,
                    truncated,
                },
            )
            .await?;
        }
        Err(CommandProtocolError::Io(_)) => {
            send_secure_json(
                channel,
                stream,
                &AgentMessage::Completed {
                    request_id,
                    exit_code: -1,
                    timed_out: false,
                    truncated: false,
                },
            )
            .await?;
            return Ok(());
        }
        Err(err) => return Err(err),
    }

    Ok(())
}

fn spawn_child(
    command: &CommandSpec,
    ordered_args: Vec<String>,
) -> Result<tokio::process::Child, io::Error> {
    let mut cmd = Command::new(&command.program);
    cmd.args(&command.fixed_args);
    cmd.args(ordered_args);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.env_clear();
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    cmd.current_dir("/");
    cmd.spawn()
}

async fn stream_process_output<S>(
    channel: &mut SecureChannel,
    stream: &mut S,
    request_id: RequestId,
    child: &mut tokio::process::Child,
    timeout: Duration,
    max_output_bytes: usize,
) -> Result<(ExitStatus, bool, bool), CommandProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("child stdout was not piped"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("child stderr was not piped"))?;

    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut status: Option<ExitStatus> = None;
    let deadline = Instant::now() + timeout;
    let mut total_output_bytes = 0usize;
    let mut timed_out = false;
    let mut truncated = false;

    let mut stdout_buf = [0u8; 1024];
    let mut stderr_buf = [0u8; 1024];

    while !(stdout_done && stderr_done && status.is_some()) {
        let now = Instant::now();
        let sleep_for = deadline.saturating_duration_since(now);
        let timeout_ready = sleep_for.is_zero() && status.is_none();

        if timeout_ready && !timed_out {
            timed_out = true;
            let _ = child.kill().await;
            status = Some(child.wait().await?);
            continue;
        }

        tokio::select! {
            wait_result = child.wait(), if status.is_none() => {
                status = Some(wait_result?);
            }
            read_result = stdout.read(&mut stdout_buf), if !stdout_done => {
                let n = read_result?;
                if n == 0 {
                    stdout_done = true;
                } else if !timed_out
                    && stream_output(
                        channel,
                        stream,
                        request_id,
                        OutputStream::Stdout,
                        &stdout_buf[..n],
                        &mut total_output_bytes,
                        max_output_bytes,
                    ).await? {
                        truncated = true;
                    }
            }
            read_result = stderr.read(&mut stderr_buf), if !stderr_done => {
                let n = read_result?;
                if n == 0 {
                    stderr_done = true;
                } else if !timed_out
                    && stream_output(
                        channel,
                        stream,
                        request_id,
                        OutputStream::Stderr,
                        &stderr_buf[..n],
                        &mut total_output_bytes,
                        max_output_bytes,
                    ).await? {
                        truncated = true;
                    }
            }
            _ = sleep(sleep_for), if status.is_none() && !timed_out => {
                timed_out = true;
                let _ = child.kill().await;
                status = Some(child.wait().await?);
            }
        }

        if truncated && status.is_none() {
            let _ = child.kill().await;
            status = Some(child.wait().await?);
        }
    }

    Ok((
        status.expect("status must be set before loop exit"),
        timed_out,
        truncated,
    ))
}

async fn stream_output<S>(
    channel: &mut SecureChannel,
    stream: &mut S,
    request_id: RequestId,
    output_stream: OutputStream,
    bytes: &[u8],
    total_output_bytes: &mut usize,
    max_output_bytes: usize,
) -> Result<bool, CommandProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if *total_output_bytes >= max_output_bytes {
        return Ok(true);
    }

    let remaining = max_output_bytes - *total_output_bytes;
    let overflowed = bytes.len() > remaining;
    let emit_len = bytes.len().min(remaining);
    if emit_len == 0 {
        return Ok(true);
    }

    let chunk = String::from_utf8_lossy(&bytes[..emit_len]).into_owned();
    send_secure_json(
        channel,
        stream,
        &AgentMessage::Output {
            request_id,
            stream: output_stream,
            chunk,
        },
    )
    .await?;

    *total_output_bytes += emit_len;
    Ok(overflowed)
}

fn validate_and_order_args(
    command: &CommandSpec,
    args: &BTreeMap<String, String>,
) -> Result<Vec<String>, String> {
    for key in args.keys() {
        if command.arg_spec(key).is_none() {
            return Err(format!(
                "argument '{}' is not allowed for command '{}'",
                key, command.id
            ));
        }
    }

    let mut ordered_args = Vec::new();
    for arg_spec in &command.arg_specs {
        match args.get(&arg_spec.name) {
            Some(value) => {
                validate_arg(command, arg_spec, value)?;
                ordered_args.push(value.to_string());
            }
            None if arg_spec.required => {
                return Err(format!(
                    "missing required argument '{}' for command '{}'",
                    arg_spec.name, command.id
                ));
            }
            None => {}
        }
    }

    Ok(ordered_args)
}

fn validate_arg(command: &CommandSpec, spec: &ArgSpec, value: &str) -> Result<(), String> {
    let Some(rule) = &spec.validation else {
        return Ok(());
    };

    match rule {
        ValidationRule::Regex { pattern } => {
            let full_match_pattern = format!("^(?:{})$", pattern);
            let regex = Regex::new(&full_match_pattern).map_err(|err| {
                format!(
                    "internal policy regex compile error for command '{}' arg '{}': {}",
                    command.id, spec.name, err
                )
            })?;
            if !regex.is_match(value) {
                return Err(format!(
                    "argument '{}' value '{}' failed regex validation",
                    spec.name, value
                ));
            }
        }
        ValidationRule::Enum { values } => {
            if !values.iter().any(|allowed| allowed == value) {
                return Err(format!(
                    "argument '{}' value '{}' is not one of [{}]",
                    spec.name,
                    value,
                    values.join(", ")
                ));
            }
        }
    }

    Ok(())
}

async fn send_rejected<S>(
    channel: &mut SecureChannel,
    stream: &mut S,
    request_id: RequestId,
    code: RejectionCode,
    message: String,
) -> Result<(), CommandProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_secure_json(
        channel,
        stream,
        &AgentMessage::Rejected {
            request_id,
            code,
            message,
        },
    )
    .await
}
