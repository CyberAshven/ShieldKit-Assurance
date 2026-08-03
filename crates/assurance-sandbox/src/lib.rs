use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use wait_timeout::ChildExt;
use walkdir::WalkDir;

pub const ROOTFS_MANIFEST_V1: &str = "shieldkit-assurance-rootfs/v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxAssuranceClass {
    DevelopmentHost,
    HermeticQualification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NetworkPolicy {
    Disabled,
    RecordedGateway {
        socket: PathBuf,
        endpoint_ids: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SandboxPolicy {
    pub assurance_class: SandboxAssuranceClass,
    pub source_root: PathBuf,
    pub run_root: PathBuf,
    pub object_root: PathBuf,
    pub rootfs: Option<PathBuf>,
    pub rootfs_manifest: Option<PathBuf>,
    pub rootfs_manifest_sha256: Option<String>,
    pub command: Vec<String>,
    pub working_directory: PathBuf,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    pub network: NetworkPolicy,
    pub timeout_milliseconds: u64,
    pub maximum_output_bytes_per_stream: u64,
    pub maximum_stdin_bytes: u64,
    pub maximum_secret_bytes: u64,
    pub maximum_secret_files: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SandboxObservation {
    pub assurance_class: SandboxAssuranceClass,
    pub command: Vec<String>,
    pub environment_keys: Vec<String>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub output_limit_exceeded: bool,
    pub wall_milliseconds: u128,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
}

#[derive(Debug)]
pub struct SandboxResult {
    pub observation: SandboxObservation,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Default)]
pub struct SandboxInput {
    pub stdin: Vec<u8>,
    pub secrets: Vec<SecretInput>,
}

pub struct SecretInput {
    pub id: String,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretInput")
            .field("id", &self.id)
            .field("bytes", &"<redacted>")
            .field("length", &self.bytes.len())
            .finish()
    }
}

impl Drop for SecretInput {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RootfsManifest {
    pub schema_version: String,
    pub entries: Vec<RootfsEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RootfsEntry {
    pub path: String,
    pub kind: RootfsEntryKind,
    pub mode: u32,
    pub size: u64,
    pub sha256: Option<String>,
    pub symlink_target: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RootfsEntryKind {
    Directory,
    File,
    Symlink,
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("invalid sandbox policy: {0}")]
    InvalidPolicy(String),
    #[error("sandbox path is unsafe: {0}")]
    UnsafePath(PathBuf),
    #[error("failed to start bubblewrap: {0}")]
    Spawn(#[source] io::Error),
    #[error("sandbox process I/O failed: {0}")]
    Io(#[source] io::Error),
    #[error("sandbox output reader panicked")]
    ReaderPanicked,
    #[error("sandbox input writer panicked")]
    WriterPanicked,
    #[error("invalid qualification rootfs manifest: {0}")]
    InvalidRootfsManifest(String),
    #[error("qualification rootfs differs from its pinned manifest")]
    RootfsManifestMismatch,
    #[error("sandbox command timed out")]
    TimedOut(Box<SandboxObservation>),
    #[error("sandbox output exceeded the declared limit")]
    OutputLimit(Box<SandboxObservation>),
    #[error("sandbox command failed")]
    CommandFailed(Box<SandboxObservation>),
}

#[derive(Debug)]
struct CapturedStream {
    retained: Vec<u8>,
    length: u64,
    sha256: String,
    exceeded: bool,
}

impl SandboxPolicy {
    pub fn validate(&self) -> Result<(), SandboxError> {
        validate_directory(&self.source_root)?;
        validate_directory(&self.run_root)?;
        validate_directory(&self.object_root)?;
        if self.source_root == self.run_root || self.source_root == self.object_root {
            return Err(SandboxError::InvalidPolicy(
                "source, run, and object roots must be distinct".into(),
            ));
        }
        if self.command.is_empty() || self.command[0].trim().is_empty() {
            return Err(SandboxError::InvalidPolicy("command is empty".into()));
        }
        if self.timeout_milliseconds == 0 {
            return Err(SandboxError::InvalidPolicy("timeout is zero".into()));
        }
        if self.maximum_output_bytes_per_stream == 0 {
            return Err(SandboxError::InvalidPolicy("output limit is zero".into()));
        }
        if self.maximum_stdin_bytes == 0 {
            return Err(SandboxError::InvalidPolicy("stdin limit is zero".into()));
        }
        if self.maximum_secret_bytes == 0 || self.maximum_secret_files == 0 {
            return Err(SandboxError::InvalidPolicy("secret limit is zero".into()));
        }
        validate_relative(&self.working_directory)?;
        for (key, value) in &self.environment {
            if !valid_environment_key(key) || value.as_bytes().contains(&0) {
                return Err(SandboxError::InvalidPolicy(format!(
                    "invalid environment entry: {key}"
                )));
            }
            if !key.starts_with("ASSURANCE_") {
                return Err(SandboxError::InvalidPolicy(format!(
                    "adapter environment key is outside the ASSURANCE_ namespace: {key}"
                )));
            }
        }
        match self.assurance_class {
            SandboxAssuranceClass::DevelopmentHost => {
                if self.rootfs.is_some()
                    || self.rootfs_manifest.is_some()
                    || self.rootfs_manifest_sha256.is_some()
                {
                    return Err(SandboxError::InvalidPolicy(
                        "development-host sandbox cannot claim a qualification rootfs".into(),
                    ));
                }
            }
            SandboxAssuranceClass::HermeticQualification => {
                let rootfs = self.rootfs.as_ref().ok_or_else(|| {
                    SandboxError::InvalidPolicy("qualification rootfs is missing".into())
                })?;
                validate_directory(rootfs)?;
                let manifest_path = self.rootfs_manifest.as_ref().ok_or_else(|| {
                    SandboxError::InvalidPolicy("qualification rootfs manifest is missing".into())
                })?;
                validate_regular_file(manifest_path)?;
                let digest = self.rootfs_manifest_sha256.as_deref().ok_or_else(|| {
                    SandboxError::InvalidPolicy(
                        "qualification rootfs manifest hash is missing".into(),
                    )
                })?;
                if digest.len() != 64
                    || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                    || digest.bytes().any(|byte| byte.is_ascii_uppercase())
                {
                    return Err(SandboxError::InvalidPolicy(
                        "qualification rootfs manifest hash is invalid".into(),
                    ));
                }
                verify_rootfs_manifest(rootfs, manifest_path, digest)?;
            }
        }
        if let NetworkPolicy::RecordedGateway {
            socket,
            endpoint_ids,
        } = &self.network
        {
            let metadata = fs::symlink_metadata(socket)
                .map_err(|_| SandboxError::UnsafePath(socket.clone()))?;
            if !metadata.file_type().is_socket() || endpoint_ids.is_empty() {
                return Err(SandboxError::InvalidPolicy(
                    "recorded gateway requires a Unix socket and endpoint IDs".into(),
                ));
            }
            let unique = endpoint_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>();
            if unique.len() != endpoint_ids.len()
                || endpoint_ids.iter().any(|value| value.trim().is_empty())
            {
                return Err(SandboxError::InvalidPolicy(
                    "recorded gateway endpoint IDs must be nonempty and unique".into(),
                ));
            }
        }
        Ok(())
    }
}

impl SandboxInput {
    fn validate(&self, policy: &SandboxPolicy) -> Result<(), SandboxError> {
        if self.stdin.len() as u64 > policy.maximum_stdin_bytes {
            return Err(SandboxError::InvalidPolicy(
                "stdin exceeds its declared limit".into(),
            ));
        }
        if self.secrets.len() > policy.maximum_secret_files as usize {
            return Err(SandboxError::InvalidPolicy(
                "secret file count exceeds its declared limit".into(),
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut total = 0u64;
        for secret in &self.secrets {
            if !valid_secret_id(&secret.id) || !ids.insert(secret.id.as_str()) {
                return Err(SandboxError::InvalidPolicy(format!(
                    "invalid or duplicate secret ID: {}",
                    secret.id
                )));
            }
            total = total
                .checked_add(secret.bytes.len() as u64)
                .ok_or_else(|| SandboxError::InvalidPolicy("secret byte count overflow".into()))?;
        }
        if total > policy.maximum_secret_bytes {
            return Err(SandboxError::InvalidPolicy(
                "secret bytes exceed their declared limit".into(),
            ));
        }
        Ok(())
    }
}

pub fn build_rootfs_manifest(rootfs: &Path) -> Result<RootfsManifest, SandboxError> {
    validate_directory(rootfs)?;
    let mut entries = Vec::new();
    for entry in WalkDir::new(rootfs).min_depth(1).follow_links(false) {
        let entry = entry.map_err(|error| {
            SandboxError::InvalidRootfsManifest(format!("walk {}: {error}", rootfs.display()))
        })?;
        let path = entry.path();
        let relative = path.strip_prefix(rootfs).map_err(|_| {
            SandboxError::InvalidRootfsManifest(format!("entry escaped rootfs: {}", path.display()))
        })?;
        validate_relative(relative)?;
        let relative = relative.to_str().ok_or_else(|| {
            SandboxError::InvalidRootfsManifest(format!(
                "non-UTF-8 rootfs path: {}",
                path.display()
            ))
        })?;
        let metadata = fs::symlink_metadata(path).map_err(SandboxError::Io)?;
        let mode = rootfs_mode(&metadata);
        let file_type = metadata.file_type();
        let value = if file_type.is_dir() {
            RootfsEntry {
                path: relative.into(),
                kind: RootfsEntryKind::Directory,
                mode,
                size: 0,
                sha256: None,
                symlink_target: None,
            }
        } else if file_type.is_file() {
            let (size, sha256) = hash_stable_file(path, &metadata)?;
            RootfsEntry {
                path: relative.into(),
                kind: RootfsEntryKind::File,
                mode,
                size,
                sha256: Some(sha256),
                symlink_target: None,
            }
        } else if file_type.is_symlink() {
            let target = fs::read_link(path).map_err(SandboxError::Io)?;
            let target = target.to_str().ok_or_else(|| {
                SandboxError::InvalidRootfsManifest(format!(
                    "non-UTF-8 symlink target: {}",
                    path.display()
                ))
            })?;
            RootfsEntry {
                path: relative.into(),
                kind: RootfsEntryKind::Symlink,
                mode,
                size: target.len() as u64,
                sha256: None,
                symlink_target: Some(target.into()),
            }
        } else {
            return Err(SandboxError::InvalidRootfsManifest(format!(
                "special file is forbidden in qualification rootfs: {}",
                path.display()
            )));
        };
        entries.push(value);
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(RootfsManifest {
        schema_version: ROOTFS_MANIFEST_V1.into(),
        entries,
    })
}

pub fn verify_rootfs_manifest(
    rootfs: &Path,
    manifest_path: &Path,
    expected_manifest_sha256: &str,
) -> Result<RootfsManifest, SandboxError> {
    let bytes = fs::read(manifest_path).map_err(SandboxError::Io)?;
    if hex::encode(Sha256::digest(&bytes)) != expected_manifest_sha256 {
        return Err(SandboxError::InvalidRootfsManifest(
            "manifest SHA-256 does not match the pin".into(),
        ));
    }
    let expected: RootfsManifest = serde_json::from_slice(&bytes).map_err(|error| {
        SandboxError::InvalidRootfsManifest(format!("parse {}: {error}", manifest_path.display()))
    })?;
    if expected.schema_version != ROOTFS_MANIFEST_V1 {
        return Err(SandboxError::InvalidRootfsManifest(format!(
            "unsupported schema: {}",
            expected.schema_version
        )));
    }
    if expected
        .entries
        .windows(2)
        .any(|pair| pair[0].path >= pair[1].path)
    {
        return Err(SandboxError::InvalidRootfsManifest(
            "entries are not strictly sorted and unique".into(),
        ));
    }
    let observed = build_rootfs_manifest(rootfs)?;
    if expected != observed {
        return Err(SandboxError::RootfsManifestMismatch);
    }
    Ok(expected)
}

fn hash_stable_file(path: &Path, before: &fs::Metadata) -> Result<(u64, String), SandboxError> {
    let mut file = File::open(path).map_err(SandboxError::Io)?;
    let opened = file.metadata().map_err(SandboxError::Io)?;
    if !opened.is_file() || !same_file_snapshot(before, &opened) {
        return Err(SandboxError::InvalidRootfsManifest(format!(
            "file changed while opening: {}",
            path.display()
        )));
    }
    let mut hasher = Sha256::new();
    let mut length = 0u64;
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut chunk).map_err(SandboxError::Io)?;
        if count == 0 {
            break;
        }
        hasher.update(&chunk[..count]);
        length = length.checked_add(count as u64).ok_or_else(|| {
            SandboxError::InvalidRootfsManifest(format!("file size overflow: {}", path.display()))
        })?;
    }
    let after = fs::symlink_metadata(path).map_err(SandboxError::Io)?;
    if length != before.len() || !same_file_snapshot(before, &after) {
        return Err(SandboxError::InvalidRootfsManifest(format!(
            "file changed while hashing: {}",
            path.display()
        )));
    }
    Ok((length, hex::encode(hasher.finalize())))
}

#[cfg(unix)]
fn same_file_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.mode() == right.mode()
}

#[cfg(not(unix))]
fn same_file_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

#[cfg(unix)]
fn rootfs_mode(metadata: &fs::Metadata) -> u32 {
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn rootfs_mode(metadata: &fs::Metadata) -> u32 {
    if metadata.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

pub fn execute(policy: &SandboxPolicy) -> Result<SandboxResult, SandboxError> {
    execute_with_input(policy, SandboxInput::default())
}

pub fn execute_with_input(
    policy: &SandboxPolicy,
    mut input: SandboxInput,
) -> Result<SandboxResult, SandboxError> {
    policy.validate()?;
    input.validate(policy)?;
    let mut command = Command::new("bwrap");
    command.args(["--die-with-parent", "--new-session", "--unshare-all"]);
    match policy.assurance_class {
        SandboxAssuranceClass::DevelopmentHost => add_development_root(&mut command),
        SandboxAssuranceClass::HermeticQualification => {
            command
                .arg("--ro-bind")
                .arg(policy.rootfs.as_ref().expect("validated rootfs"))
                .arg("/");
        }
    }
    command.args(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]);
    command
        .arg("--ro-bind")
        .arg(&policy.source_root)
        .arg("/subject");
    command
        .arg("--bind")
        .arg(&policy.run_root)
        .arg("/run/assurance/work");
    command
        .arg("--ro-bind")
        .arg(&policy.object_root)
        .arg("/run/assurance/objects");
    command.arg("--clearenv");
    if let NetworkPolicy::RecordedGateway {
        socket,
        endpoint_ids,
    } = &policy.network
    {
        command.args(["--dir", "/run/assurance/network"]);
        command
            .arg("--ro-bind")
            .arg(socket)
            .arg("/run/assurance/network/gateway.sock");
        command.args([
            "--setenv",
            "ASSURANCE_NETWORK_SOCKET",
            "/run/assurance/network/gateway.sock",
        ]);
        command.args(["--setenv", "ASSURANCE_NETWORK_ENDPOINT_IDS"]);
        command.arg(endpoint_ids.join(","));
    }
    command.args(["--setenv", "PATH", "/usr/bin:/bin"]);
    command.args(["--setenv", "LC_ALL", "C", "--setenv", "TZ", "UTC"]);
    let mut secret_pipes = Vec::new();
    if !input.secrets.is_empty() {
        command.args(["--dir", "/run/assurance/secrets"]);
        command.args(["--setenv", "ASSURANCE_SECRET_DIR", "/run/assurance/secrets"]);
        for secret in input.secrets.drain(..) {
            let (reader, writer) = qualification_pipe()?;
            command
                .args(["--perms", "0400", "--ro-bind-data"])
                .arg(reader.as_raw_fd().to_string())
                .arg(format!("/run/assurance/secrets/{}", secret.id));
            secret_pipes.push((reader, writer, secret));
        }
    }
    for (key, value) in &policy.environment {
        command.arg("--setenv").arg(key).arg(value);
    }
    let cwd = if policy.working_directory.as_os_str().is_empty() {
        PathBuf::from("/subject")
    } else {
        Path::new("/subject").join(&policy.working_directory)
    };
    command.arg("--chdir").arg(cwd).arg("--");
    command.args(&policy.command);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let started = Instant::now();
    let mut child = command.spawn().map_err(SandboxError::Spawn)?;
    let stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdin_bytes = std::mem::take(&mut input.stdin);
    let stdin_writer = thread::spawn(move || write_public_stdin(stdin, stdin_bytes));
    let mut secret_writers = Vec::with_capacity(secret_pipes.len());
    for (reader, writer, secret) in secret_pipes {
        drop(reader);
        secret_writers.push(thread::spawn(move || write_secret(writer, secret)));
    }
    let limit = policy.maximum_output_bytes_per_stream;
    let stdout_reader = thread::spawn(move || capture_stream(stdout, limit));
    let stderr_reader = thread::spawn(move || capture_stream(stderr, limit));
    let timeout = Duration::from_millis(policy.timeout_milliseconds);
    let (status, timed_out) = match child.wait_timeout(timeout).map_err(SandboxError::Io)? {
        Some(status) => (status, false),
        None => {
            child.kill().map_err(SandboxError::Io)?;
            (child.wait().map_err(SandboxError::Io)?, true)
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| SandboxError::ReaderPanicked)?
        .map_err(SandboxError::Io)?;
    stdin_writer
        .join()
        .map_err(|_| SandboxError::WriterPanicked)?
        .map_err(SandboxError::Io)?;
    for writer in secret_writers {
        writer
            .join()
            .map_err(|_| SandboxError::WriterPanicked)?
            .map_err(SandboxError::Io)?;
    }
    let stderr = stderr_reader
        .join()
        .map_err(|_| SandboxError::ReaderPanicked)?
        .map_err(SandboxError::Io)?;
    let observation = observation(
        policy,
        &status,
        timed_out,
        started.elapsed(),
        &stdout,
        &stderr,
    );
    if timed_out {
        return Err(SandboxError::TimedOut(Box::new(observation)));
    }
    if stdout.exceeded || stderr.exceeded {
        return Err(SandboxError::OutputLimit(Box::new(observation)));
    }
    if !status.success() {
        return Err(SandboxError::CommandFailed(Box::new(observation)));
    }
    Ok(SandboxResult {
        observation,
        stdout: stdout.retained,
        stderr: stderr.retained,
    })
}

#[cfg(unix)]
fn qualification_pipe() -> Result<(OwnedFd, OwnedFd), SandboxError> {
    use rustix::io::{FdFlags, fcntl_setfd};
    use rustix::pipe::{PipeFlags, pipe_with};

    let (reader, writer) =
        pipe_with(PipeFlags::CLOEXEC).map_err(|error| SandboxError::Io(error.into()))?;
    fcntl_setfd(&reader, FdFlags::empty()).map_err(|error| SandboxError::Io(error.into()))?;
    Ok((reader, writer))
}

#[cfg(not(unix))]
fn qualification_pipe() -> Result<(std::fs::File, std::fs::File), SandboxError> {
    Err(SandboxError::InvalidPolicy(
        "secret FD delivery requires Unix".into(),
    ))
}

fn write_public_stdin(mut output: impl Write, bytes: Vec<u8>) -> io::Result<()> {
    output.write_all(&bytes)?;
    output.flush()
}

#[cfg(unix)]
fn write_secret(writer: OwnedFd, mut secret: SecretInput) -> io::Result<()> {
    let mut output = File::from(writer);
    let result = output
        .write_all(&secret.bytes)
        .and_then(|()| output.flush());
    secret.bytes.fill(0);
    result
}

fn add_development_root(command: &mut Command) {
    for entry in ["/usr", "/bin", "/lib", "/lib64", "/etc/ssl/certs"] {
        if Path::new(entry).exists() {
            command.arg("--ro-bind").arg(entry).arg(entry);
        }
    }
}

fn capture_stream(mut input: impl Read, limit: u64) -> io::Result<CapturedStream> {
    let mut retained = Vec::with_capacity(limit.min(1024 * 1024) as usize);
    let mut hasher = Sha256::new();
    let mut length = 0u64;
    let mut exceeded = false;
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let count = input.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        hasher.update(&chunk[..count]);
        length = length.saturating_add(count as u64);
        let remaining = limit.saturating_sub(retained.len() as u64) as usize;
        retained.extend_from_slice(&chunk[..count.min(remaining)]);
        exceeded |= length > limit;
    }
    Ok(CapturedStream {
        retained,
        length,
        sha256: hex::encode(hasher.finalize()),
        exceeded,
    })
}

fn observation(
    policy: &SandboxPolicy,
    status: &ExitStatus,
    timed_out: bool,
    wall: Duration,
    stdout: &CapturedStream,
    stderr: &CapturedStream,
) -> SandboxObservation {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    SandboxObservation {
        assurance_class: policy.assurance_class,
        command: policy.command.clone(),
        environment_keys: policy.environment.keys().cloned().collect(),
        exit_code: status.code(),
        #[cfg(unix)]
        signal: status.signal(),
        #[cfg(not(unix))]
        signal: None,
        timed_out,
        output_limit_exceeded: stdout.exceeded || stderr.exceeded,
        wall_milliseconds: wall.as_millis(),
        stdout_bytes: stdout.length,
        stderr_bytes: stderr.length,
        stdout_sha256: stdout.sha256.clone(),
        stderr_sha256: stderr.sha256.clone(),
    }
}

fn validate_directory(path: &Path) -> Result<(), SandboxError> {
    if !path.is_absolute() {
        return Err(SandboxError::UnsafePath(path.into()));
    }
    let canonical = fs::canonicalize(path).map_err(|_| SandboxError::UnsafePath(path.into()))?;
    if canonical != path
        || !fs::metadata(path)
            .map(|value| value.is_dir())
            .unwrap_or(false)
    {
        return Err(SandboxError::UnsafePath(path.into()));
    }
    Ok(())
}

fn validate_regular_file(path: &Path) -> Result<(), SandboxError> {
    if !path.is_absolute() {
        return Err(SandboxError::UnsafePath(path.into()));
    }
    let canonical = fs::canonicalize(path).map_err(|_| SandboxError::UnsafePath(path.into()))?;
    let metadata = fs::symlink_metadata(path).map_err(|_| SandboxError::UnsafePath(path.into()))?;
    if canonical != path || !metadata.file_type().is_file() {
        return Err(SandboxError::UnsafePath(path.into()));
    }
    Ok(())
}

fn validate_relative(path: &Path) -> Result<(), SandboxError> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SandboxError::UnsafePath(path.into()));
    }
    Ok(())
}

fn valid_environment_key(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_uppercase() || byte == b'_' || (index > 0 && byte.is_ascii_digit())
        })
}

fn valid_secret_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    fn policy(
        command: Vec<String>,
    ) -> (
        tempfile::TempDir,
        tempfile::TempDir,
        tempfile::TempDir,
        SandboxPolicy,
    ) {
        let source = tempdir().unwrap();
        let run = tempdir().unwrap();
        let objects = tempdir().unwrap();
        let policy = SandboxPolicy {
            assurance_class: SandboxAssuranceClass::DevelopmentHost,
            source_root: source.path().to_path_buf(),
            run_root: run.path().to_path_buf(),
            object_root: objects.path().to_path_buf(),
            rootfs: None,
            rootfs_manifest: None,
            rootfs_manifest_sha256: None,
            command,
            working_directory: PathBuf::new(),
            environment: BTreeMap::from([("ASSURANCE_CASE_ID".into(), "case-1".into())]),
            network: NetworkPolicy::Disabled,
            timeout_milliseconds: 2_000,
            maximum_output_bytes_per_stream: 4_096,
            maximum_stdin_bytes: 4_096,
            maximum_secret_bytes: 4_096,
            maximum_secret_files: 8,
        };
        (source, run, objects, policy)
    }

    #[test]
    fn executes_with_a_scrubbed_environment_and_no_network_namespace() {
        let (_source, _run, _objects, policy) = policy(vec!["/usr/bin/env".into()]);
        let result = execute(&policy).unwrap();
        let output = String::from_utf8(result.stdout).unwrap();
        assert!(output.contains("ASSURANCE_CASE_ID=case-1"));
        assert!(output.contains("LC_ALL=C"));
        assert!(!output.contains("USER="));
        assert!(!output.contains("SSH_"));
        assert_eq!(
            result.observation.assurance_class,
            SandboxAssuranceClass::DevelopmentHost
        );
    }

    #[test]
    fn source_is_read_only_and_run_root_is_writable() {
        let (source, run, _objects, mut policy) = policy(vec![
            "/bin/sh".into(),
            "-c".into(),
            "touch /run/assurance/work/allowed && ! touch /subject/forbidden".into(),
        ]);
        execute(&policy).unwrap();
        assert!(run.path().join("allowed").exists());
        assert!(!source.path().join("forbidden").exists());
        fs::set_permissions(
            run.path().join("allowed"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        policy.working_directory = PathBuf::from("..");
        assert!(matches!(
            policy.validate(),
            Err(SandboxError::UnsafePath(_))
        ));
    }

    #[test]
    fn timeout_and_output_overrun_are_fail_closed() {
        let (_source, _run, _objects, mut timeout_policy) =
            policy(vec!["/bin/sleep".into(), "1".into()]);
        timeout_policy.timeout_milliseconds = 25;
        assert!(matches!(
            execute(&timeout_policy),
            Err(SandboxError::TimedOut(_))
        ));

        let (_source, _run, _objects, mut output_policy) =
            policy(vec!["/usr/bin/printf".into(), "123456789".into()]);
        output_policy.maximum_output_bytes_per_stream = 4;
        assert!(matches!(
            execute(&output_policy),
            Err(SandboxError::OutputLimit(_))
        ));
    }

    #[test]
    fn qualification_class_requires_an_explicit_pinned_rootfs() {
        let (_source, _run, _objects, mut policy) = policy(vec!["/bin/true".into()]);
        policy.assurance_class = SandboxAssuranceClass::HermeticQualification;
        assert!(matches!(
            policy.validate(),
            Err(SandboxError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn qualification_rootfs_manifest_is_content_pinned_and_closed_world() {
        let rootfs = tempdir().unwrap();
        fs::create_dir(rootfs.path().join("bin")).unwrap();
        fs::write(rootfs.path().join("bin/tool"), b"pinned tool bytes").unwrap();
        fs::set_permissions(
            rootfs.path().join("bin/tool"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::os::unix::fs::symlink("bin", rootfs.path().join("sbin")).unwrap();

        let manifest = build_rootfs_manifest(rootfs.path()).unwrap();
        assert_eq!(manifest.schema_version, ROOTFS_MANIFEST_V1);
        assert_eq!(manifest.entries.len(), 3);
        let manifest_directory = tempdir().unwrap();
        let manifest_path = manifest_directory.path().join("rootfs.json");
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(&manifest_path, &bytes).unwrap();
        let digest = hex::encode(Sha256::digest(&bytes));

        let (_source, _run, _objects, mut policy) = policy(vec!["/bin/true".into()]);
        policy.assurance_class = SandboxAssuranceClass::HermeticQualification;
        policy.rootfs = Some(rootfs.path().to_path_buf());
        policy.rootfs_manifest = Some(manifest_path);
        policy.rootfs_manifest_sha256 = Some(digest);
        policy.validate().unwrap();

        fs::write(rootfs.path().join("unexpected"), b"drift").unwrap();
        assert!(matches!(
            policy.validate(),
            Err(SandboxError::RootfsManifestMismatch)
        ));
    }

    #[test]
    fn delivers_public_stdin_and_anonymous_read_only_secret_files() {
        let secret = SecretInput {
            id: "wallet-key".into(),
            bytes: b"never-persist-this-secret".to_vec(),
        };
        assert!(!format!("{secret:?}").contains("never-persist"));
        let digest = hex::encode(Sha256::digest(&secret.bytes));
        let script = format!(
            "IFS= read -r line && test \"$line\" = public-request && test \"$(stat -c %a \"$ASSURANCE_SECRET_DIR/wallet-key\")\" = 400 && test \"$(sha256sum \"$ASSURANCE_SECRET_DIR/wallet-key\" | cut -d' ' -f1)\" = {digest}"
        );
        let (_source, _run, _objects, policy) = policy(vec!["/bin/sh".into(), "-c".into(), script]);
        let result = execute_with_input(
            &policy,
            SandboxInput {
                stdin: b"public-request\n".to_vec(),
                secrets: vec![secret],
            },
        )
        .unwrap();
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn rejects_secret_path_injection_and_input_limit_overrun() {
        let (_source, _run, _objects, mut policy) = policy(vec!["/bin/true".into()]);
        let injected = SandboxInput {
            stdin: vec![],
            secrets: vec![SecretInput {
                id: "../escape".into(),
                bytes: vec![1],
            }],
        };
        assert!(matches!(
            execute_with_input(&policy, injected),
            Err(SandboxError::InvalidPolicy(_))
        ));

        policy.maximum_stdin_bytes = 1;
        assert!(matches!(
            execute_with_input(
                &policy,
                SandboxInput {
                    stdin: vec![1, 2],
                    secrets: vec![],
                }
            ),
            Err(SandboxError::InvalidPolicy(_))
        ));
    }
}
