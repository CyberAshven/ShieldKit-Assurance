//! Immutable, closed-world snapshots of a pinned Git subject.
//!
//! The worktree itself is never mounted into a qualification sandbox. A new
//! private snapshot is exported from the pinned commit, every regular file is
//! re-hashed as both a Git blob and SHA-256, modes are checked against the Git
//! tree, and the resulting directory is verified closed-world before atomic
//! publication. Ignored build products and dirty worktree bytes cannot enter.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};

use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tempfile::Builder;
use thiserror::Error;
use walkdir::WalkDir;

pub const SOURCE_MANIFEST_V1: &str = "shieldkit-assurance-source-snapshot/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubjectPin {
    pub repository: String,
    pub revision: String,
    pub tree: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SnapshotLimits {
    pub maximum_files: u64,
    pub maximum_total_bytes: u64,
    pub maximum_file_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceManifest {
    pub schema_version: String,
    pub repository: String,
    pub revision: String,
    pub tree: String,
    pub object_format: GitObjectFormat,
    pub files: Vec<SourceFile>,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceFile {
    pub path: String,
    pub mode: u32,
    pub git_object: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GitObjectFormat {
    Sha1,
    Sha256,
}

#[derive(Debug, Error)]
pub enum SubjectError {
    #[error("unsafe path: {0}")]
    UnsafePath(PathBuf),
    #[error("destination already exists: {0}")]
    DestinationExists(PathBuf),
    #[error("invalid subject pin: {0}")]
    InvalidPin(String),
    #[error("Git command failed: {command}: {stderr}")]
    Git { command: String, stderr: String },
    #[error("Git output is malformed: {0}")]
    MalformedGitOutput(String),
    #[error("repository differs: expected {expected}, observed {observed}")]
    RepositoryMismatch { expected: String, observed: String },
    #[error("revision differs: expected {expected}, observed {observed}")]
    RevisionMismatch { expected: String, observed: String },
    #[error("tree differs: expected {expected}, observed {observed}")]
    TreeMismatch { expected: String, observed: String },
    #[error("unsupported tracked Git mode {mode:o} at {path}")]
    UnsupportedMode { path: String, mode: u32 },
    #[error("source limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("archive contains an unsupported entry at {0}")]
    UnsupportedArchiveEntry(String),
    #[error("archive and Git tree differ at {0}")]
    ArchiveMismatch(String),
    #[error("snapshot contains an unexpected entry: {0}")]
    UnexpectedEntry(String),
    #[error("snapshot is missing an entry: {0}")]
    MissingEntry(String),
    #[error("snapshot file changed while hashing: {0}")]
    UnstableFile(String),
    #[error("canonical JSON encoding failed: {0}")]
    Canonical(String),
    #[error("I/O error at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

#[derive(Debug, Clone)]
struct GitTreeFile {
    mode: u32,
    object: String,
}

pub fn snapshot_subject(
    checkout: &Path,
    destination: &Path,
    pin: &SubjectPin,
    limits: &SnapshotLimits,
) -> Result<SourceManifest, SubjectError> {
    validate_limits(limits)?;
    let checkout = canonical_directory(checkout)?;
    let (parent, leaf) = safe_new_destination(destination)?;
    validate_pin_shape(pin)?;
    let object_format = read_object_format(&checkout)?;
    validate_hash(&pin.revision, object_format)?;
    validate_hash(&pin.tree, object_format)?;

    let origin = git_text(&checkout, &["remote", "get-url", "origin"])?;
    let expected_repository = canonical_repository(&pin.repository)?;
    let observed_repository = canonical_repository(&origin)?;
    if expected_repository != observed_repository {
        return Err(SubjectError::RepositoryMismatch {
            expected: expected_repository,
            observed: observed_repository,
        });
    }
    let revision = git_text(&checkout, &["rev-parse", "--verify", &pin.revision])?;
    if revision != pin.revision {
        return Err(SubjectError::RevisionMismatch {
            expected: pin.revision.clone(),
            observed: revision,
        });
    }
    if git_text(&checkout, &["cat-file", "-t", &pin.revision])? != "commit" {
        return Err(SubjectError::InvalidPin("revision is not a commit".into()));
    }
    let tree = git_text(
        &checkout,
        &[
            "rev-parse",
            "--verify",
            &format!("{}^{{tree}}", pin.revision),
        ],
    )?;
    if tree != pin.tree {
        return Err(SubjectError::TreeMismatch {
            expected: pin.tree.clone(),
            observed: tree,
        });
    }
    if !git_text(&checkout, &["replace", "-l"])?.is_empty() {
        return Err(SubjectError::InvalidPin(
            "repository has replacement objects configured".into(),
        ));
    }

    let expected = read_git_tree(&checkout, pin, object_format, limits)?;
    let stage = Builder::new()
        .prefix(".assurance-source-")
        .tempdir_in(&parent)
        .map_err(|source| io_error(&parent, source))?;
    set_directory_mode(stage.path())?;
    let archive = Builder::new()
        .prefix(".assurance-archive-")
        .suffix(".tar")
        .tempfile_in(&parent)
        .map_err(|source| io_error(&parent, source))?;
    let archive_path = archive.path().to_path_buf();
    let output_argument = format!("--output={}", archive_path.display());
    git_success(
        &checkout,
        &["archive", "--format=tar", &output_argument, &pin.revision],
    )?;
    let files = extract_and_verify_archive(
        &archive_path,
        stage.path(),
        &expected,
        &pin.revision,
        object_format,
        limits,
    )?;
    let total_bytes = files.iter().try_fold(0u64, |total, file| {
        total
            .checked_add(file.size)
            .ok_or_else(|| SubjectError::LimitExceeded("total byte count overflow".into()))
    })?;
    let manifest = SourceManifest {
        schema_version: SOURCE_MANIFEST_V1.into(),
        repository: pin.repository.clone(),
        revision: pin.revision.clone(),
        tree: pin.tree.clone(),
        object_format,
        files,
        total_bytes,
    };
    verify_source_snapshot(stage.path(), &manifest, limits)?;
    sync_tree(stage.path())?;
    let stage_path = stage.keep();
    let final_path = parent.join(leaf);
    fs::rename(&stage_path, &final_path).map_err(|source| io_error(&final_path, source))?;
    sync_directory(&parent)?;
    Ok(manifest)
}

pub fn verify_source_snapshot(
    root: &Path,
    manifest: &SourceManifest,
    limits: &SnapshotLimits,
) -> Result<(), SubjectError> {
    validate_limits(limits)?;
    if manifest.schema_version != SOURCE_MANIFEST_V1 {
        return Err(SubjectError::InvalidPin(format!(
            "unsupported source manifest schema: {}",
            manifest.schema_version
        )));
    }
    validate_hash(&manifest.revision, manifest.object_format)?;
    validate_hash(&manifest.tree, manifest.object_format)?;
    if manifest.files.len() as u64 > limits.maximum_files {
        return Err(SubjectError::LimitExceeded("file count".into()));
    }
    let root = canonical_directory(root)?;
    let mut expected = BTreeMap::new();
    let mut expected_total = 0u64;
    for file in &manifest.files {
        validate_relative_path(&file.path)?;
        if file.mode != 0o100644 && file.mode != 0o100755 {
            return Err(SubjectError::UnsupportedMode {
                path: file.path.clone(),
                mode: file.mode,
            });
        }
        validate_hash(&file.git_object, manifest.object_format)?;
        validate_sha256(&file.sha256)?;
        if file.size > limits.maximum_file_bytes {
            return Err(SubjectError::LimitExceeded(file.path.clone()));
        }
        expected_total = expected_total
            .checked_add(file.size)
            .ok_or_else(|| SubjectError::LimitExceeded("total byte count overflow".into()))?;
        if expected.insert(file.path.as_str(), file).is_some() {
            return Err(SubjectError::ArchiveMismatch(format!(
                "duplicate manifest path {}",
                file.path
            )));
        }
    }
    if expected_total != manifest.total_bytes || expected_total > limits.maximum_total_bytes {
        return Err(SubjectError::LimitExceeded(
            "manifest total bytes differs or exceeds limit".into(),
        ));
    }
    let mut observed = BTreeSet::new();
    for entry in WalkDir::new(&root).min_depth(1).follow_links(false) {
        let entry = entry
            .map_err(|error| SubjectError::UnsafePath(error.path().unwrap_or(&root).into()))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
        let relative = relative_string(&root, path)?;
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            return Err(SubjectError::UnexpectedEntry(relative));
        }
        if metadata.is_dir() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(SubjectError::UnexpectedEntry(relative));
            }
        }
        let expected_file = expected
            .get(relative.as_str())
            .ok_or_else(|| SubjectError::UnexpectedEntry(relative.clone()))?;
        let hashed = hash_stable_file(path, manifest.object_format)?;
        if hashed.size != expected_file.size
            || hashed.git_object != expected_file.git_object
            || hashed.sha256 != expected_file.sha256
            || filesystem_git_mode(path, &metadata) != expected_file.mode
        {
            return Err(SubjectError::ArchiveMismatch(relative));
        }
        observed.insert(relative);
    }
    if let Some(path) = expected.keys().find(|path| !observed.contains(**path)) {
        return Err(SubjectError::MissingEntry((*path).into()));
    }
    Ok(())
}

pub fn source_manifest_digest(manifest: &SourceManifest) -> Result<String, SubjectError> {
    let bytes = serde_json_canonicalizer::to_vec(manifest)
        .map_err(|error| SubjectError::Canonical(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn read_object_format(checkout: &Path) -> Result<GitObjectFormat, SubjectError> {
    match git_text(checkout, &["rev-parse", "--show-object-format"])?.as_str() {
        "sha1" => Ok(GitObjectFormat::Sha1),
        "sha256" => Ok(GitObjectFormat::Sha256),
        value => Err(SubjectError::MalformedGitOutput(format!(
            "unsupported object format: {value}"
        ))),
    }
}

fn read_git_tree(
    checkout: &Path,
    pin: &SubjectPin,
    object_format: GitObjectFormat,
    limits: &SnapshotLimits,
) -> Result<BTreeMap<String, GitTreeFile>, SubjectError> {
    let output = git_output(checkout, &["ls-tree", "-rz", "--full-tree", &pin.revision])?;
    let mut files = BTreeMap::new();
    for record in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| SubjectError::MalformedGitOutput("ls-tree record lacks tab".into()))?;
        let header = std::str::from_utf8(&record[..tab])
            .map_err(|_| SubjectError::MalformedGitOutput("non-UTF-8 ls-tree header".into()))?;
        let path = std::str::from_utf8(&record[tab + 1..])
            .map_err(|_| SubjectError::MalformedGitOutput("non-UTF-8 source path".into()))?
            .to_owned();
        validate_relative_path(&path)?;
        let mut parts = header.split(' ');
        let mode = u32::from_str_radix(parts.next().unwrap_or_default(), 8)
            .map_err(|_| SubjectError::MalformedGitOutput(header.into()))?;
        let kind = parts.next().unwrap_or_default();
        let object = parts.next().unwrap_or_default().to_owned();
        if parts.next().is_some() || kind != "blob" {
            return Err(SubjectError::MalformedGitOutput(header.into()));
        }
        if mode != 0o100644 && mode != 0o100755 {
            return Err(SubjectError::UnsupportedMode { path, mode });
        }
        validate_hash(&object, object_format)?;
        if files
            .insert(path.clone(), GitTreeFile { mode, object })
            .is_some()
        {
            return Err(SubjectError::MalformedGitOutput(format!(
                "duplicate tree path: {path}"
            )));
        }
    }
    if files.is_empty() || files.len() as u64 > limits.maximum_files {
        return Err(SubjectError::LimitExceeded(format!(
            "tracked file count {}",
            files.len()
        )));
    }
    Ok(files)
}

fn extract_and_verify_archive(
    archive_path: &Path,
    destination: &Path,
    expected: &BTreeMap<String, GitTreeFile>,
    expected_revision: &str,
    object_format: GitObjectFormat,
    limits: &SnapshotLimits,
) -> Result<Vec<SourceFile>, SubjectError> {
    let file = File::open(archive_path).map_err(|source| io_error(archive_path, source))?;
    let mut archive = tar::Archive::new(file);
    let allowed_directories = directory_prefixes(expected.keys().map(String::as_str));
    let mut observed = BTreeSet::new();
    let mut files = Vec::with_capacity(expected.len());
    let mut total_bytes = 0u64;
    let mut observed_global_header = false;
    for entry in archive
        .entries()
        .map_err(|source| io_error(archive_path, source))?
    {
        let mut entry = entry.map_err(|source| io_error(archive_path, source))?;
        let entry_type = entry.header().entry_type();
        let relative = entry
            .path()
            .map_err(|source| io_error(archive_path, source))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| SubjectError::UnsupportedArchiveEntry("non-UTF-8 path".into()))?
            .to_owned();
        if entry_type.is_pax_global_extensions() {
            if observed_global_header || relative != "pax_global_header" || entry.size() > 256 {
                return Err(SubjectError::UnsupportedArchiveEntry(relative));
            }
            let extensions = entry
                .pax_extensions()
                .map_err(|source| io_error(archive_path, source))?
                .ok_or_else(|| {
                    SubjectError::UnsupportedArchiveEntry("empty pax_global_header".into())
                })?;
            let mut count = 0usize;
            for extension in extensions {
                let extension = extension.map_err(|source| io_error(archive_path, source))?;
                count += 1;
                if extension.key_bytes() != b"comment"
                    || extension.value_bytes() != expected_revision.as_bytes()
                {
                    return Err(SubjectError::UnsupportedArchiveEntry(
                        "unexpected pax_global_header metadata".into(),
                    ));
                }
            }
            if count != 1 {
                return Err(SubjectError::UnsupportedArchiveEntry(
                    "pax_global_header must contain exactly one revision comment".into(),
                ));
            }
            observed_global_header = true;
            continue;
        }
        if entry_type.is_pax_local_extensions()
            || entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
        {
            return Err(SubjectError::UnsupportedArchiveEntry(relative));
        }
        if entry_type.is_dir() {
            let directory = relative.strip_suffix('/').unwrap_or(&relative);
            validate_relative_path(directory)?;
            if !allowed_directories.contains(directory) {
                return Err(SubjectError::UnsupportedArchiveEntry(relative));
            }
            create_private_directories(destination, Path::new(directory))?;
            continue;
        }
        validate_relative_path(&relative)?;
        if !entry_type.is_file() {
            return Err(SubjectError::UnsupportedArchiveEntry(relative));
        }
        let expected_file = expected
            .get(relative.as_str())
            .ok_or_else(|| SubjectError::UnsupportedArchiveEntry(relative.clone()))?;
        if !observed.insert(relative.clone()) {
            return Err(SubjectError::UnsupportedArchiveEntry(format!(
                "duplicate {relative}"
            )));
        }
        let declared_size = entry.size();
        if declared_size > limits.maximum_file_bytes {
            return Err(SubjectError::LimitExceeded(relative));
        }
        total_bytes = total_bytes
            .checked_add(declared_size)
            .ok_or_else(|| SubjectError::LimitExceeded("total byte count overflow".into()))?;
        if total_bytes > limits.maximum_total_bytes {
            return Err(SubjectError::LimitExceeded("total bytes".into()));
        }
        let destination_file = destination.join(&relative);
        create_private_directories(
            destination,
            Path::new(&relative)
                .parent()
                .unwrap_or_else(|| Path::new("")),
        )?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open(&destination_file)
            .map_err(|source| io_error(&destination_file, source))?;
        let mut hashers = FileHashers::new(object_format, declared_size);
        let mut copied = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = entry
                .read(&mut buffer)
                .map_err(|source| io_error(archive_path, source))?;
            if count == 0 {
                break;
            }
            output
                .write_all(&buffer[..count])
                .map_err(|source| io_error(&destination_file, source))?;
            hashers.update(&buffer[..count]);
            copied = copied
                .checked_add(count as u64)
                .ok_or_else(|| SubjectError::LimitExceeded(relative.clone()))?;
        }
        output
            .sync_all()
            .map_err(|source| io_error(&destination_file, source))?;
        if copied != declared_size {
            return Err(SubjectError::ArchiveMismatch(relative));
        }
        set_file_mode(&destination_file, expected_file.mode)?;
        let (git_object, sha256) = hashers.finish();
        if git_object != expected_file.object {
            return Err(SubjectError::ArchiveMismatch(relative));
        }
        files.push(SourceFile {
            path: relative,
            mode: expected_file.mode,
            git_object,
            sha256,
            size: copied,
        });
    }
    if let Some(path) = expected.keys().find(|path| !observed.contains(*path)) {
        return Err(SubjectError::MissingEntry(path.clone()));
    }
    if !observed_global_header {
        return Err(SubjectError::UnsupportedArchiveEntry(
            "missing revision-bound pax_global_header".into(),
        ));
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

struct FileHashers {
    git: GitHasher,
    sha256: Sha256,
}

enum GitHasher {
    Sha1(Sha1),
    Sha256(Sha256),
}

impl FileHashers {
    fn new(format: GitObjectFormat, size: u64) -> Self {
        let header = format!("blob {size}\0");
        let mut git = match format {
            GitObjectFormat::Sha1 => GitHasher::Sha1(Sha1::new()),
            GitObjectFormat::Sha256 => GitHasher::Sha256(Sha256::new()),
        };
        git.update(header.as_bytes());
        Self {
            git,
            sha256: Sha256::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.git.update(bytes);
        self.sha256.update(bytes);
    }

    fn finish(self) -> (String, String) {
        let git = match self.git {
            GitHasher::Sha1(hasher) => hex::encode(hasher.finalize()),
            GitHasher::Sha256(hasher) => hex::encode(hasher.finalize()),
        };
        (git, hex::encode(self.sha256.finalize()))
    }
}

impl GitHasher {
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(hasher) => hasher.update(bytes),
            Self::Sha256(hasher) => hasher.update(bytes),
        }
    }
}

fn hash_stable_file(path: &Path, format: GitObjectFormat) -> Result<SourceFile, SubjectError> {
    let before = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if !before.is_file() {
        return Err(SubjectError::UnexpectedEntry(path.display().to_string()));
    }
    let mut input = File::open(path).map_err(|source| io_error(path, source))?;
    let opened = input.metadata().map_err(|source| io_error(path, source))?;
    if !same_file(&before, &opened) {
        return Err(SubjectError::UnstableFile(path.display().to_string()));
    }
    let mut hashers = FileHashers::new(format, before.len());
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|source| io_error(path, source))?;
        if count == 0 {
            break;
        }
        hashers.update(&buffer[..count]);
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| SubjectError::LimitExceeded(path.display().to_string()))?;
    }
    let after = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if size != before.len() || !same_file(&before, &after) {
        return Err(SubjectError::UnstableFile(path.display().to_string()));
    }
    let (git_object, sha256) = hashers.finish();
    Ok(SourceFile {
        path: String::new(),
        mode: filesystem_git_mode(path, &after),
        git_object,
        sha256,
        size,
    })
}

fn canonical_repository(value: &str) -> Result<String, SubjectError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.contains('\0') || trimmed.contains(['\n', '\r']) {
        return Err(SubjectError::InvalidPin("invalid repository URL".into()));
    }
    let normalized = if let Some((user_host, path)) = trimmed.split_once(':') {
        if !user_host.contains('/') && user_host.contains('@') {
            let host = user_host.rsplit('@').next().unwrap_or_default();
            format!("{host}/{path}")
        } else {
            normalize_url_repository(trimmed)?
        }
    } else if trimmed.contains("://") {
        normalize_url_repository(trimmed)?
    } else {
        format!("local:{trimmed}")
    };
    Ok(normalized
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .to_owned())
}

fn normalize_url_repository(value: &str) -> Result<String, SubjectError> {
    let (_, remainder) = value
        .split_once("://")
        .ok_or_else(|| SubjectError::InvalidPin("invalid repository URL".into()))?;
    let authority_end = remainder
        .find('/')
        .ok_or_else(|| SubjectError::InvalidPin("repository URL has no path".into()))?;
    let authority = &remainder[..authority_end];
    if authority.is_empty() || authority.contains('@') && !value.starts_with("ssh://") {
        return Err(SubjectError::InvalidPin(
            "credentialed repository URLs are forbidden".into(),
        ));
    }
    let host = authority
        .rsplit('@')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let path = &remainder[authority_end + 1..];
    if host.is_empty() || path.is_empty() {
        return Err(SubjectError::InvalidPin("invalid repository URL".into()));
    }
    Ok(format!("{host}/{path}"))
}

fn git_output(checkout: &Path, arguments: &[&str]) -> Result<Output, SubjectError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .output()
        .map_err(|source| io_error(checkout, source))?;
    if !output.status.success() {
        return Err(SubjectError::Git {
            command: format!("git -C <subject> {}", arguments.join(" ")),
            stderr: bounded_text(&output.stderr),
        });
    }
    Ok(output)
}

fn git_success(checkout: &Path, arguments: &[&str]) -> Result<(), SubjectError> {
    git_output(checkout, arguments).map(|_| ())
}

fn git_text(checkout: &Path, arguments: &[&str]) -> Result<String, SubjectError> {
    let output = git_output(checkout, arguments)?;
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| SubjectError::MalformedGitOutput(arguments.join(" ")))?;
    Ok(value.trim_end_matches(['\n', '\r']).to_owned())
}

fn bounded_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(8192)]).into_owned()
}

fn validate_pin_shape(pin: &SubjectPin) -> Result<(), SubjectError> {
    if pin.repository.trim().is_empty() {
        return Err(SubjectError::InvalidPin("repository is empty".into()));
    }
    Ok(())
}

fn validate_limits(limits: &SnapshotLimits) -> Result<(), SubjectError> {
    if limits.maximum_files == 0
        || limits.maximum_total_bytes == 0
        || limits.maximum_file_bytes == 0
        || limits.maximum_file_bytes > limits.maximum_total_bytes
    {
        return Err(SubjectError::LimitExceeded("invalid limits".into()));
    }
    Ok(())
}

fn validate_hash(value: &str, format: GitObjectFormat) -> Result<(), SubjectError> {
    let expected = match format {
        GitObjectFormat::Sha1 => 40,
        GitObjectFormat::Sha256 => 64,
    };
    if value.len() != expected
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SubjectError::InvalidPin(format!(
            "invalid Git hash: {value}"
        )));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), SubjectError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SubjectError::InvalidPin(format!(
            "invalid SHA-256: {value}"
        )));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), SubjectError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\0')
        || value.contains('\\')
        || value.split('/').any(str::is_empty)
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SubjectError::UnsafePath(path.into()));
    }
    Ok(())
}

fn canonical_directory(path: &Path) -> Result<PathBuf, SubjectError> {
    if !path.is_absolute() {
        return Err(SubjectError::UnsafePath(path.into()));
    }
    let canonical = fs::canonicalize(path).map_err(|source| io_error(path, source))?;
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if canonical != path || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SubjectError::UnsafePath(path.into()));
    }
    Ok(canonical)
}

fn safe_new_destination(path: &Path) -> Result<(PathBuf, std::ffi::OsString), SubjectError> {
    if !path.is_absolute() || fs::symlink_metadata(path).is_ok() {
        return if fs::symlink_metadata(path).is_ok() {
            Err(SubjectError::DestinationExists(path.into()))
        } else {
            Err(SubjectError::UnsafePath(path.into()))
        };
    }
    let parent = path
        .parent()
        .ok_or_else(|| SubjectError::UnsafePath(path.into()))?;
    let parent = canonical_directory(parent)?;
    let leaf = path
        .file_name()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| SubjectError::UnsafePath(path.into()))?
        .to_os_string();
    Ok((parent, leaf))
}

fn relative_string(root: &Path, path: &Path) -> Result<String, SubjectError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| SubjectError::UnsafePath(path.into()))?;
    let value = relative
        .to_str()
        .ok_or_else(|| SubjectError::UnsafePath(path.into()))?
        .to_owned();
    validate_relative_path(&value)?;
    Ok(value)
}

fn directory_prefixes<'a>(paths: impl Iterator<Item = &'a str>) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for path in paths {
        let mut current = Path::new(path).parent();
        while let Some(directory) = current {
            if directory.as_os_str().is_empty() {
                break;
            }
            if let Some(value) = directory.to_str() {
                result.insert(value.into());
            }
            current = directory.parent();
        }
    }
    result
}

fn create_private_directories(root: &Path, relative: &Path) -> Result<(), SubjectError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(SubjectError::UnsafePath(relative.into()));
        }
        current.push(component.as_os_str());
        match fs::create_dir(&current) {
            Ok(()) => set_directory_mode(&current)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let metadata =
                    fs::symlink_metadata(&current).map_err(|source| io_error(&current, source))?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(SubjectError::UnsafePath(current));
                }
            }
            Err(source) => return Err(io_error(&current, source)),
        }
    }
    Ok(())
}

fn sync_tree(root: &Path) -> Result<(), SubjectError> {
    let mut directories = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry =
            entry.map_err(|error| SubjectError::UnsafePath(error.path().unwrap_or(root).into()))?;
        if entry.file_type().is_dir() {
            directories.push(entry.path().to_path_buf());
        }
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        sync_directory(&directory)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), SubjectError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
}

#[cfg(unix)]
fn set_directory_mode(path: &Path) -> Result<(), SubjectError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error(path, source))
}

#[cfg(not(unix))]
fn set_directory_mode(_: &Path) -> Result<(), SubjectError> {
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(path: &Path, git_mode: u32) -> Result<(), SubjectError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if git_mode == 0o100755 { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|source| io_error(path, source))
}

#[cfg(not(unix))]
fn set_file_mode(_: &Path, _: u32) -> Result<(), SubjectError> {
    Ok(())
}

#[cfg(unix)]
fn filesystem_git_mode(_: &Path, metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 != 0 {
        0o100755
    } else {
        0o100644
    }
}

#[cfg(not(unix))]
fn filesystem_git_mode(_: &Path, _: &fs::Metadata) -> u32 {
    0o100644
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.mode() == right.mode()
        && left.nlink() == 1
        && right.nlink() == 1
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn io_error(path: &Path, source: io::Error) -> SubjectError {
    SubjectError::Io {
        path: path.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn git(root: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", bounded_text(&output.stderr));
        String::from_utf8(output.stdout).unwrap().trim_end().into()
    }

    fn repository() -> (tempfile::TempDir, SubjectPin) {
        let root = tempdir().unwrap();
        git(root.path(), &["init", "-q", "-b", "main"]);
        git(root.path(), &["config", "user.name", "Assurance Test"]);
        git(
            root.path(),
            &["config", "user.email", "test@example.invalid"],
        );
        git(
            root.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:example/subject.git",
            ],
        );
        fs::create_dir(root.path().join("nested")).unwrap();
        fs::write(root.path().join("nested/data"), b"committed").unwrap();
        fs::write(root.path().join("run.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                root.path().join("run.sh"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        git(root.path(), &["add", "."]);
        git(root.path(), &["commit", "-q", "-m", "subject"]);
        let revision = git(root.path(), &["rev-parse", "HEAD"]);
        let tree = git(root.path(), &["rev-parse", "HEAD^{tree}"]);
        (
            root,
            SubjectPin {
                repository: "https://github.com/example/subject".into(),
                revision,
                tree,
            },
        )
    }

    fn limits() -> SnapshotLimits {
        SnapshotLimits {
            maximum_files: 100,
            maximum_total_bytes: 1024 * 1024,
            maximum_file_bytes: 1024 * 1024,
        }
    }

    #[test]
    fn snapshots_only_the_exact_pinned_tree_and_verifies_closed_world() {
        let (repository, pin) = repository();
        fs::write(repository.path().join("ignored-output"), b"not tracked").unwrap();
        fs::write(repository.path().join("nested/data"), b"dirty worktree").unwrap();
        let output_parent = tempdir().unwrap();
        let output = output_parent.path().join("source");
        let manifest = snapshot_subject(repository.path(), &output, &pin, &limits()).unwrap();
        assert_eq!(manifest.files.len(), 2);
        assert_eq!(fs::read(output.join("nested/data")).unwrap(), b"committed");
        assert!(!output.join("ignored-output").exists());
        verify_source_snapshot(&output, &manifest, &limits()).unwrap();
        assert_eq!(source_manifest_digest(&manifest).unwrap().len(), 71);

        fs::write(output.join("unexpected"), b"drift").unwrap();
        assert!(matches!(
            verify_source_snapshot(&output, &manifest, &limits()),
            Err(SubjectError::UnexpectedEntry(_))
        ));
    }

    #[test]
    fn detects_archive_substitution_attributes_instead_of_accepting_changed_bytes() {
        let (repository, mut pin) = repository();
        fs::write(repository.path().join("format.txt"), b"$Format:%H$\n").unwrap();
        fs::write(
            repository.path().join(".gitattributes"),
            b"format.txt export-subst\n",
        )
        .unwrap();
        git(repository.path(), &["add", "."]);
        git(repository.path(), &["commit", "-q", "-m", "attributes"]);
        pin.revision = git(repository.path(), &["rev-parse", "HEAD"]);
        pin.tree = git(repository.path(), &["rev-parse", "HEAD^{tree}"]);
        let output_parent = tempdir().unwrap();
        assert!(matches!(
            snapshot_subject(
                repository.path(),
                &output_parent.path().join("source"),
                &pin,
                &limits()
            ),
            Err(SubjectError::ArchiveMismatch(path)) if path == "format.txt"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_tracked_symlinks_and_repository_or_tree_substitution() {
        use std::os::unix::fs::symlink;
        let (repo, mut pin) = repository();
        symlink("nested/data", repo.path().join("link")).unwrap();
        git(repo.path(), &["add", "link"]);
        git(repo.path(), &["commit", "-q", "-m", "symlink"]);
        pin.revision = git(repo.path(), &["rev-parse", "HEAD"]);
        pin.tree = git(repo.path(), &["rev-parse", "HEAD^{tree}"]);
        let output_parent = tempdir().unwrap();
        assert!(matches!(
            snapshot_subject(
                repo.path(),
                &output_parent.path().join("source"),
                &pin,
                &limits()
            ),
            Err(SubjectError::UnsupportedMode { mode: 0o120000, .. })
        ));

        let (_, mut wrong) = repository();
        wrong.repository = "https://github.com/other/repository".into();
        assert!(matches!(
            snapshot_subject(
                repo.path(),
                &output_parent.path().join("other"),
                &wrong,
                &limits()
            ),
            Err(SubjectError::RepositoryMismatch { .. })
                | Err(SubjectError::RevisionMismatch { .. })
        ));
    }
}
