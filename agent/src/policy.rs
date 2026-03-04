use std::{
    collections::HashSet,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use regex::Regex;
use serde::Deserialize;

const POLICY_VERSION_V1: u16 = 1;

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub version: u16,
    pub default_timeout_secs: u64,
    pub max_output_bytes: usize,
    pub commands: Vec<CommandSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommandSpec {
    pub id: String,
    pub program: String,
    #[serde(default)]
    pub fixed_args: Vec<String>,
    #[serde(default)]
    pub arg_specs: Vec<ArgSpec>,
    pub timeout_secs: Option<u64>,
    pub max_output_bytes: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ArgSpec {
    pub name: String,
    #[serde(default)]
    pub required: bool,
    pub validation: Option<ValidationRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ValidationRule {
    Regex { pattern: String },
    Enum { values: Vec<String> },
}

#[derive(Debug)]
pub enum PolicyError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    Invalid(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Io { path, source } => {
                write!(
                    f,
                    "failed to read policy file '{}': {}",
                    path.display(),
                    source
                )
            }
            PolicyError::Parse { path, source } => {
                write!(
                    f,
                    "failed to parse policy file '{}': {}",
                    path.display(),
                    source
                )
            }
            PolicyError::Invalid(message) => write!(f, "invalid policy: {}", message),
        }
    }
}

impl Error for PolicyError {}

impl Policy {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref().to_path_buf();
        let raw = fs::read_to_string(&path).map_err(|source| PolicyError::Io {
            path: path.clone(),
            source,
        })?;

        let policy: Policy = serde_json::from_str(&raw).map_err(|source| PolicyError::Parse {
            path: path.clone(),
            source,
        })?;

        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != POLICY_VERSION_V1 {
            return Err(PolicyError::Invalid(format!(
                "unsupported policy version {}; expected {}",
                self.version, POLICY_VERSION_V1
            )));
        }

        if self.default_timeout_secs == 0 {
            return Err(PolicyError::Invalid(
                "default_timeout_secs must be greater than 0".to_string(),
            ));
        }

        if self.max_output_bytes == 0 {
            return Err(PolicyError::Invalid(
                "max_output_bytes must be greater than 0".to_string(),
            ));
        }

        if self.commands.is_empty() {
            return Err(PolicyError::Invalid(
                "commands must include at least one entry".to_string(),
            ));
        }

        let mut command_ids = HashSet::new();
        for command in &self.commands {
            if command.id.trim().is_empty() {
                return Err(PolicyError::Invalid(
                    "command id must not be empty".to_string(),
                ));
            }
            if command.program.trim().is_empty() {
                return Err(PolicyError::Invalid(format!(
                    "command '{}' has an empty program field",
                    command.id
                )));
            }
            if !command_ids.insert(command.id.as_str()) {
                return Err(PolicyError::Invalid(format!(
                    "duplicate command id '{}'",
                    command.id
                )));
            }

            if matches!(command.timeout_secs, Some(0)) {
                return Err(PolicyError::Invalid(format!(
                    "command '{}' timeout_secs must be greater than 0",
                    command.id
                )));
            }
            if matches!(command.max_output_bytes, Some(0)) {
                return Err(PolicyError::Invalid(format!(
                    "command '{}' max_output_bytes must be greater than 0",
                    command.id
                )));
            }

            let mut arg_names = HashSet::new();
            for arg in &command.arg_specs {
                if arg.name.trim().is_empty() {
                    return Err(PolicyError::Invalid(format!(
                        "command '{}' contains an empty argument name",
                        command.id
                    )));
                }
                if !arg_names.insert(arg.name.as_str()) {
                    return Err(PolicyError::Invalid(format!(
                        "command '{}' contains duplicate arg spec '{}'",
                        command.id, arg.name
                    )));
                }

                if let Some(rule) = &arg.validation {
                    validate_rule(command, arg, rule)?;
                }
            }
        }

        Ok(())
    }

    pub fn command_by_id(&self, id: &str) -> Option<&CommandSpec> {
        self.commands.iter().find(|command| command.id == id)
    }
}

impl CommandSpec {
    pub fn effective_timeout_secs(&self, policy_default: u64) -> u64 {
        self.timeout_secs.unwrap_or(policy_default)
    }

    pub fn effective_max_output_bytes(&self, policy_default: usize) -> usize {
        self.max_output_bytes.unwrap_or(policy_default)
    }

    pub fn arg_spec(&self, name: &str) -> Option<&ArgSpec> {
        self.arg_specs.iter().find(|arg| arg.name == name)
    }
}

fn validate_rule(
    command: &CommandSpec,
    arg: &ArgSpec,
    rule: &ValidationRule,
) -> Result<(), PolicyError> {
    match rule {
        ValidationRule::Regex { pattern } => {
            let wrapped_pattern = format!("^(?:{})$", pattern);
            Regex::new(&wrapped_pattern).map_err(|err| {
                PolicyError::Invalid(format!(
                    "command '{}' arg '{}' has invalid regex '{}': {}",
                    command.id, arg.name, pattern, err
                ))
            })?;
        }
        ValidationRule::Enum { values } => {
            if values.is_empty() {
                return Err(PolicyError::Invalid(format!(
                    "command '{}' arg '{}' enum must include at least one value",
                    command.id, arg.name
                )));
            }

            if values.iter().any(|value| value.is_empty()) {
                return Err(PolicyError::Invalid(format!(
                    "command '{}' arg '{}' enum contains an empty value",
                    command.id, arg.name
                )));
            }

            let mut seen = HashSet::new();
            for value in values {
                if !seen.insert(value) {
                    return Err(PolicyError::Invalid(format!(
                        "command '{}' arg '{}' enum contains duplicate value '{}'",
                        command.id, arg.name, value
                    )));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{Policy, PolicyError};

    fn temp_file_path(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("alaric-policy-{}-{}.json", label, nanos))
    }

    fn write_policy(json: &str, label: &str) -> std::path::PathBuf {
        let path = temp_file_path(label);
        fs::write(&path, json).expect("write policy fixture");
        path
    }

    #[test]
    fn loads_valid_policy_from_file() {
        let path = write_policy(
            r#"{
                "version": 1,
                "default_timeout_secs": 5,
                "max_output_bytes": 2048,
                "commands": [
                    {
                        "id": "echo",
                        "program": "/bin/echo",
                        "fixed_args": ["hello"],
                        "arg_specs": [
                            {
                                "name": "suffix",
                                "required": false,
                                "validation": { "type": "regex", "pattern": "[a-z]+" }
                            }
                        ]
                    }
                ]
            }"#,
            "valid",
        );

        let policy = Policy::load_from_path(&path).expect("policy should load");
        assert_eq!(policy.version, 1);
        assert_eq!(policy.commands.len(), 1);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_invalid_regex() {
        let path = write_policy(
            r#"{
                "version": 1,
                "default_timeout_secs": 5,
                "max_output_bytes": 2048,
                "commands": [
                    {
                        "id": "bad_regex",
                        "program": "/bin/echo",
                        "arg_specs": [
                            {
                                "name": "value",
                                "required": true,
                                "validation": { "type": "regex", "pattern": "[" }
                            }
                        ]
                    }
                ]
            }"#,
            "bad-regex",
        );

        let err = Policy::load_from_path(&path).expect_err("policy should fail");
        assert!(matches!(err, PolicyError::Invalid(_)));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_duplicate_command_ids() {
        let path = write_policy(
            r#"{
                "version": 1,
                "default_timeout_secs": 5,
                "max_output_bytes": 2048,
                "commands": [
                    { "id": "same", "program": "/bin/echo" },
                    { "id": "same", "program": "/bin/echo" }
                ]
            }"#,
            "dup-command-id",
        );

        let err = Policy::load_from_path(&path).expect_err("policy should fail");
        assert!(matches!(err, PolicyError::Invalid(_)));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_missing_required_fields() {
        let path = write_policy(
            r#"{
                "version": 1,
                "default_timeout_secs": 5,
                "max_output_bytes": 2048,
                "commands": [
                    { "id": "missing_program" }
                ]
            }"#,
            "missing-required",
        );

        let err = Policy::load_from_path(&path).expect_err("policy should fail");
        assert!(matches!(err, PolicyError::Parse { .. }));

        let _ = fs::remove_file(path);
    }
}
