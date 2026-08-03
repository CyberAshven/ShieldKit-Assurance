//! Strict, offline evidence-bundle storage and verification.
//!
//! A bundle has one control file (`run.json`) and a closed inventory of
//! content-addressed evidence files below `blobs/sha256/`. Verification first
//! snapshots stable regular files into a private temporary directory, then
//! verifies that snapshot rather than a mutable source directory.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use thiserror::Error;

pub const RUN_SCHEMA_V1: &str = "shieldkit-assurance-run/v1";
pub const RUN_SCHEMA_V2: &str = "shieldkit-assurance-run/v2";
pub const RUN_FILE_NAME: &str = "run.json";
pub const BLOBS_DIRECTORY: &str = "blobs/sha256";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseVerdict {
    Pass,
    Fail,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObligationVerdict {
    Satisfied,
    Violated,
    Blocked,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimVerdict {
    Supported,
    Refuted,
    Blocked,
    NotApplicable,
}

/// Provenance class of one concrete object. It is policy input, not proof that
/// the object is correct or independently produced.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    RawObservation,
    DerivedIndex,
    SignedAttestation,
    SemanticVerifierResult,
    LocalTest,
    SyntheticFixture,
    BlockedBoundary,
}

impl EvidenceClass {
    pub const fn is_promotion_eligible(self) -> bool {
        matches!(
            self,
            Self::RawObservation | Self::SignedAttestation | Self::SemanticVerifierResult
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObjectRef {
    pub algorithm: String,
    pub digest: String,
    pub size: u64,
    pub media_type: String,
}

/// A v2 inventory entry. The path is strictly relative and must equal
/// `blobs/sha256/<sha256 digest>` so an object cannot be substituted by path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceFile {
    pub path: String,
    #[serde(rename = "class")]
    pub class: EvidenceClass,
    pub object: ObjectRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RunManifest {
    pub schema_version: String,
    pub pack: ObjectRef,
    pub suite_id: String,
    pub subject_revision: String,
    pub subject_tree: String,
    pub environment: ObjectRef,
    #[serde(default)]
    pub seeds: Vec<String>,
    /// Retained for v1 compatibility. Every v2 object must have one typed
    /// matching entry in `evidence_files`.
    #[serde(default)]
    pub objects: Vec<ObjectRef>,
    #[serde(default)]
    pub evidence_files: Vec<EvidenceFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RunEnvelope {
    pub run_id: String,
    pub manifest: RunManifest,
}

/// Private, content-addressed object writer rooted at a bundle directory.
#[derive(Debug, Clone)]
pub struct ContentStore {
    root: PathBuf,
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid JSON at {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedHash(String),
    #[error("invalid SHA-256 digest: {0}")]
    InvalidDigest(String),
    #[error("object is missing: {0}")]
    MissingObject(String),
    #[error("object size differs: {0}")]
    SizeMismatch(String),
    #[error("object digest differs: {0}")]
    DigestMismatch(String),
    #[error("run ID differs: expected {expected}, observed {observed}")]
    RunIdMismatch { expected: String, observed: String },
    #[error("unsupported run schema: {0}")]
    UnsupportedRunSchema(String),
    #[error("canonical JSON failure: {0}")]
    Canonical(String),
    #[error("unsafe bundle path: {0}")]
    UnsafePath(String),
    #[error("bundle path is not a regular file: {0}")]
    NotRegularFile(String),
    #[error("bundle contains a symbolic link: {0}")]
    Symlink(String),
    #[error("bundle file has multiple hard links: {0}")]
    MultipleHardLinks(String),
    #[error("duplicate inventory path: {0}")]
    DuplicateInventoryPath(String),
    #[error("duplicate inventory digest: {0}")]
    DuplicateInventoryDigest(String),
    #[error("bundle file is not declared by inventory: {0}")]
    UnexpectedFile(String),
    #[error("bundle inventory file is missing: {0}")]
    MissingInventoryFile(String),
    #[error("v2 evidence inventory is required and must not be empty")]
    EmptyEvidenceInventory,
    #[error("v2 path is not its content-store path: {0}")]
    InvalidContentStorePath(String),
    #[error("manifest object has no typed inventory entry: {0}")]
    UntypedObjectReference(String),
    #[error("bundle changed while it was being snapshotted")]
    UnstableBundle,
    #[error("evidence class is not eligible for promotion: {class:?} at {path}")]
    NonPromotableEvidence { class: EvidenceClass, path: String },
    #[error("promotion verification requires a semantic verifier result")]
    MissingSemanticVerifierResult,
    #[error("existing content-store object is corrupt: {0}")]
    CorruptExistingObject(String),
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, EvidenceError> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|error| EvidenceError::Canonical(error.to_string()))
}

pub fn derive_run_id(manifest: &RunManifest) -> Result<String, EvidenceError> {
    Ok(format!(
        "sha256:{}",
        sha256_bytes(&canonical_json(manifest)?)
    ))
}

pub fn object_ref(bytes: &[u8], media_type: impl Into<String>) -> ObjectRef {
    ObjectRef {
        algorithm: "sha256".into(),
        digest: sha256_bytes(bytes),
        size: bytes.len() as u64,
        media_type: media_type.into(),
    }
}

impl EvidenceFile {
    pub fn for_object(object: ObjectRef, class: EvidenceClass) -> Self {
        Self {
            path: content_store_relative_path(&object.digest),
            class,
            object,
        }
    }
}

impl ContentStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, EvidenceError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|source| io(&root, source))?;
        assert_safe_directory(&root)?;
        private_dir(&root)?;
        let blobs = root.join(BLOBS_DIRECTORY);
        fs::create_dir_all(&blobs).map_err(|source| io(&blobs, source))?;
        assert_safe_directory(&root.join("blobs"))?;
        assert_safe_directory(&blobs)?;
        private_dir(&root.join("blobs"))?;
        private_dir(&blobs)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn put(
        &self,
        bytes: &[u8],
        media_type: impl Into<String>,
        class: EvidenceClass,
    ) -> Result<EvidenceFile, EvidenceError> {
        let object = object_ref(bytes, media_type);
        let destination = self.root.join(BLOBS_DIRECTORY).join(&object.digest);
        if destination.exists() {
            let existing = read_stable_regular_file(&self.root, &destination)?;
            if existing != bytes || sha256_bytes(&existing) != object.digest {
                return Err(EvidenceError::CorruptExistingObject(object.digest));
            }
        } else {
            atomic_write_private(&destination, bytes)?;
        }
        Ok(EvidenceFile::for_object(object, class))
    }

    pub fn write_run(&self, envelope: &RunEnvelope) -> Result<(), EvidenceError> {
        validate_envelope(envelope)?;
        atomic_write_private(&self.root.join(RUN_FILE_NAME), &canonical_json(envelope)?)
    }
}

/// Verify a v1/v2 bundle from a private snapshot. V1 is readable only for
/// migration and is categorically rejected by `verify_promotable_bundle`.
pub fn verify_bundle(root: &Path) -> Result<RunEnvelope, EvidenceError> {
    assert_safe_directory(root)?;
    let before = collect_files(root)?;
    let run_path = root.join(RUN_FILE_NAME);
    let run_bytes = read_stable_regular_file(root, &run_path)?;
    let envelope: RunEnvelope =
        serde_json::from_slice(&run_bytes).map_err(|source| EvidenceError::Json {
            path: run_path,
            source,
        })?;
    validate_envelope(&envelope)?;
    let expected = expected_paths(&envelope.manifest)?;
    compare_inventory(&before, &expected)?;

    let snapshot = TempDir::new().map_err(|source| io(&std::env::temp_dir(), source))?;
    private_dir(snapshot.path())?;
    snapshot_file(snapshot.path(), RUN_FILE_NAME, &run_bytes)?;
    for path in expected
        .iter()
        .filter(|path| path.as_str() != RUN_FILE_NAME)
    {
        let bytes = read_stable_regular_file(root, &root.join(path))?;
        snapshot_file(snapshot.path(), path, &bytes)?;
    }
    if before != collect_files(root)? {
        return Err(EvidenceError::UnstableBundle);
    }
    verify_snapshot(snapshot.path(), &envelope)?;
    Ok(envelope)
}

/// Verify that a v2 bundle contains no local/synthetic/derived/blocked input
/// and includes a semantic verifier result. This is deliberately not a claim
/// of release qualification.
pub fn verify_promotable_bundle(root: &Path) -> Result<RunEnvelope, EvidenceError> {
    let envelope = verify_bundle(root)?;
    if envelope.manifest.schema_version != RUN_SCHEMA_V2 {
        return Err(EvidenceError::UnsupportedRunSchema(
            envelope.manifest.schema_version.clone(),
        ));
    }
    let mut semantic = false;
    for file in &envelope.manifest.evidence_files {
        if !file.class.is_promotion_eligible() {
            return Err(EvidenceError::NonPromotableEvidence {
                class: file.class,
                path: file.path.clone(),
            });
        }
        semantic |= file.class == EvidenceClass::SemanticVerifierResult;
    }
    if !semantic {
        return Err(EvidenceError::MissingSemanticVerifierResult);
    }
    Ok(envelope)
}

/// Verify a single fixed-layout content-store object with stable reads.
pub fn verify_object(root: &Path, reference: &ObjectRef) -> Result<(), EvidenceError> {
    validate_object_ref(reference)?;
    let path = root.join(BLOBS_DIRECTORY).join(&reference.digest);
    let bytes = match read_stable_regular_file(root, &path) {
        Ok(bytes) => bytes,
        Err(EvidenceError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(EvidenceError::MissingObject(reference.digest.clone()));
        }
        Err(error) => return Err(error),
    };
    verify_object_bytes(reference, &bytes)
}

fn verify_snapshot(root: &Path, envelope: &RunEnvelope) -> Result<(), EvidenceError> {
    if read_stable_regular_file(root, &root.join(RUN_FILE_NAME))? != canonical_json(envelope)? {
        return Err(EvidenceError::UnstableBundle);
    }
    for reference in std::iter::once(&envelope.manifest.pack)
        .chain(std::iter::once(&envelope.manifest.environment))
        .chain(envelope.manifest.objects.iter())
    {
        verify_object(root, reference)?;
    }
    for file in &envelope.manifest.evidence_files {
        verify_object_bytes(
            &file.object,
            &read_stable_regular_file(root, &root.join(&file.path))?,
        )?;
    }
    Ok(())
}

fn validate_envelope(envelope: &RunEnvelope) -> Result<(), EvidenceError> {
    match envelope.manifest.schema_version.as_str() {
        RUN_SCHEMA_V1 | RUN_SCHEMA_V2 => {}
        _ => {
            return Err(EvidenceError::UnsupportedRunSchema(
                envelope.manifest.schema_version.clone(),
            ));
        }
    }
    let expected = derive_run_id(&envelope.manifest)?;
    if envelope.run_id != expected {
        return Err(EvidenceError::RunIdMismatch {
            expected,
            observed: envelope.run_id.clone(),
        });
    }
    for reference in std::iter::once(&envelope.manifest.pack)
        .chain(std::iter::once(&envelope.manifest.environment))
        .chain(envelope.manifest.objects.iter())
    {
        validate_object_ref(reference)?;
    }
    if envelope.manifest.schema_version == RUN_SCHEMA_V2 {
        validate_v2_inventory(&envelope.manifest)?;
    }
    Ok(())
}

fn validate_v2_inventory(manifest: &RunManifest) -> Result<(), EvidenceError> {
    if manifest.evidence_files.is_empty() {
        return Err(EvidenceError::EmptyEvidenceInventory);
    }
    let (mut paths, mut digests, mut objects) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for file in &manifest.evidence_files {
        validate_safe_relative_path(&file.path)?;
        validate_object_ref(&file.object)?;
        if !paths.insert(file.path.clone()) {
            return Err(EvidenceError::DuplicateInventoryPath(file.path.clone()));
        }
        if !digests.insert(file.object.digest.clone()) {
            return Err(EvidenceError::DuplicateInventoryDigest(
                file.object.digest.clone(),
            ));
        }
        if file.path != content_store_relative_path(&file.object.digest) {
            return Err(EvidenceError::InvalidContentStorePath(file.path.clone()));
        }
        objects.insert(file.object.clone());
    }
    for reference in std::iter::once(&manifest.pack)
        .chain(std::iter::once(&manifest.environment))
        .chain(manifest.objects.iter())
    {
        if !objects.contains(reference) {
            return Err(EvidenceError::UntypedObjectReference(
                reference.digest.clone(),
            ));
        }
    }
    Ok(())
}

fn expected_paths(manifest: &RunManifest) -> Result<BTreeSet<String>, EvidenceError> {
    let mut paths = BTreeSet::from([RUN_FILE_NAME.to_owned()]);
    match manifest.schema_version.as_str() {
        RUN_SCHEMA_V1 => {
            for reference in std::iter::once(&manifest.pack)
                .chain(std::iter::once(&manifest.environment))
                .chain(manifest.objects.iter())
            {
                paths.insert(content_store_relative_path(&reference.digest));
            }
        }
        RUN_SCHEMA_V2 => {
            for file in &manifest.evidence_files {
                paths.insert(file.path.clone());
            }
        }
        _ => {
            return Err(EvidenceError::UnsupportedRunSchema(
                manifest.schema_version.clone(),
            ));
        }
    }
    Ok(paths)
}

fn compare_inventory(
    actual: &BTreeSet<String>,
    expected: &BTreeSet<String>,
) -> Result<(), EvidenceError> {
    if let Some(path) = actual.difference(expected).next() {
        return Err(EvidenceError::UnexpectedFile(path.clone()));
    }
    if let Some(path) = expected.difference(actual).next() {
        return Err(EvidenceError::MissingInventoryFile(path.clone()));
    }
    Ok(())
}

fn verify_object_bytes(reference: &ObjectRef, bytes: &[u8]) -> Result<(), EvidenceError> {
    if bytes.len() as u64 != reference.size {
        return Err(EvidenceError::SizeMismatch(reference.digest.clone()));
    }
    if sha256_bytes(bytes) != reference.digest {
        return Err(EvidenceError::DigestMismatch(reference.digest.clone()));
    }
    Ok(())
}

fn validate_object_ref(reference: &ObjectRef) -> Result<(), EvidenceError> {
    if reference.algorithm != "sha256" {
        return Err(EvidenceError::UnsupportedHash(reference.algorithm.clone()));
    }
    validate_digest(&reference.digest)?;
    if reference.media_type.is_empty()
        || reference
            .media_type
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(EvidenceError::Canonical(
            "media type must be a non-empty token".into(),
        ));
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<(), EvidenceError> {
    if digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || digest.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(EvidenceError::InvalidDigest(digest.to_owned()));
    }
    Ok(())
}

fn content_store_relative_path(digest: &str) -> String {
    format!("{BLOBS_DIRECTORY}/{digest}")
}

fn validate_safe_relative_path(path: &str) -> Result<(), EvidenceError> {
    if path.is_empty()
        || path.contains('\\')
        || path.contains('\0')
        || path.split('/').any(str::is_empty)
        || Path::new(path).is_absolute()
    {
        return Err(EvidenceError::UnsafePath(path.to_owned()));
    }
    let candidate = Path::new(path);
    let mut count = 0usize;
    for component in candidate.components() {
        match component {
            Component::Normal(part) if !part.is_empty() => count += 1,
            _ => return Err(EvidenceError::UnsafePath(path.to_owned())),
        }
    }
    if count == 0 || candidate.to_string_lossy() != path {
        return Err(EvidenceError::UnsafePath(path.to_owned()));
    }
    Ok(())
}

fn collect_files(root: &Path) -> Result<BTreeSet<String>, EvidenceError> {
    let mut files = BTreeSet::new();
    collect_files_inner(root, root, &mut files)?;
    Ok(files)
}

fn collect_files_inner(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<String>,
) -> Result<(), EvidenceError> {
    assert_safe_directory(directory)?;
    for entry in fs::read_dir(directory).map_err(|source| io(directory, source))? {
        let entry = entry.map_err(|source| io(directory, source))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| io(&path, source))?;
        if metadata.file_type().is_symlink() {
            return Err(EvidenceError::Symlink(display_relative(root, &path)));
        }
        if metadata.is_dir() {
            collect_files_inner(root, &path, files)?;
        } else if metadata.is_file() {
            assert_single_link_file(&path, &metadata)?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| EvidenceError::UnsafePath(path.display().to_string()))?
                .to_str()
                .ok_or_else(|| EvidenceError::UnsafePath(path.display().to_string()))?
                .to_owned();
            validate_safe_relative_path(&relative)?;
            files.insert(relative);
        } else {
            return Err(EvidenceError::NotRegularFile(display_relative(root, &path)));
        }
    }
    Ok(())
}

fn read_stable_regular_file(root: &Path, path: &Path) -> Result<Vec<u8>, EvidenceError> {
    assert_safe_ancestors(root, path)?;
    let before = fs::symlink_metadata(path).map_err(|source| io(path, source))?;
    if before.file_type().is_symlink() {
        return Err(EvidenceError::Symlink(display_relative(root, path)));
    }
    if !before.is_file() {
        return Err(EvidenceError::NotRegularFile(display_relative(root, path)));
    }
    assert_single_link_file(path, &before)?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    File::open(path)
        .map_err(|source| io(path, source))?
        .read_to_end(&mut bytes)
        .map_err(|source| io(path, source))?;
    let after = fs::symlink_metadata(path).map_err(|source| io(path, source))?;
    if !same_file_identity(&before, &after) || bytes.len() as u64 != after.len() {
        return Err(EvidenceError::UnstableBundle);
    }
    assert_single_link_file(path, &after)?;
    Ok(bytes)
}

fn assert_safe_ancestors(root: &Path, path: &Path) -> Result<(), EvidenceError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| EvidenceError::UnsafePath(path.display().to_string()))?;
    validate_safe_relative_path(
        relative
            .to_str()
            .ok_or_else(|| EvidenceError::UnsafePath(path.display().to_string()))?,
    )?;
    assert_safe_directory(root)?;
    let mut current = root.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        current.push(component.as_os_str());
        if components.peek().is_some() {
            assert_safe_directory(&current)?;
        }
    }
    Ok(())
}

fn assert_safe_directory(path: &Path) -> Result<(), EvidenceError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io(path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(EvidenceError::Symlink(path.display().to_string()));
    }
    if !metadata.is_dir() {
        return Err(EvidenceError::NotRegularFile(path.display().to_string()));
    }
    Ok(())
}

#[cfg(unix)]
fn assert_single_link_file(path: &Path, metadata: &fs::Metadata) -> Result<(), EvidenceError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.nlink() != 1 {
        return Err(EvidenceError::MultipleHardLinks(path.display().to_string()));
    }
    Ok(())
}
#[cfg(not(unix))]
fn assert_single_link_file(_: &Path, _: &fs::Metadata) -> Result<(), EvidenceError> {
    Ok(())
}

#[cfg(unix)]
fn same_file_identity(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
}
#[cfg(not(unix))]
fn same_file_identity(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.len() == after.len() && before.modified().ok() == after.modified().ok()
}

fn display_relative(root: &Path, path: &Path) -> String {
    match path.strip_prefix(root).ok().and_then(|part| part.to_str()) {
        Some(relative) => relative.to_owned(),
        None => path.to_string_lossy().into_owned(),
    }
}
fn io(path: &Path, source: std::io::Error) -> EvidenceError {
    EvidenceError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn snapshot_file(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), EvidenceError> {
    validate_safe_relative_path(relative)?;
    atomic_write_private(&root.join(relative), bytes)
}

fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<(), EvidenceError> {
    let parent = path
        .parent()
        .ok_or_else(|| EvidenceError::UnsafePath(path.display().to_string()))?;
    fs::create_dir_all(parent).map_err(|source| io(parent, source))?;
    assert_safe_directory(parent)?;
    private_dir(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| EvidenceError::UnsafePath(path.display().to_string()))?;
    let temporary = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    private_file_options(&mut options);
    let mut file = options
        .open(&temporary)
        .map_err(|source| io(&temporary, source))?;
    let result = (|| -> Result<(), EvidenceError> {
        file.write_all(bytes)
            .map_err(|source| io(&temporary, source))?;
        file.sync_all().map_err(|source| io(&temporary, source))?;
        fs::rename(&temporary, path).map_err(|source| io(path, source))?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn private_file_options(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}
#[cfg(not(unix))]
fn private_file_options(_: &mut OpenOptions) {}
#[cfg(unix)]
fn private_dir(path: &Path) -> Result<(), EvidenceError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| io(path, source))
}
#[cfg(not(unix))]
fn private_dir(_: &Path) -> Result<(), EvidenceError> {
    Ok(())
}
#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), EvidenceError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|source| io(path, source))
}
#[cfg(not(unix))]
fn sync_directory(_: &Path) -> Result<(), EvidenceError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn v2_bundle(root: &Path, classes: &[EvidenceClass]) -> RunEnvelope {
        let store = ContentStore::open(root).unwrap();
        let files: Vec<_> = classes
            .iter()
            .copied()
            .enumerate()
            .map(|(index, class)| {
                store
                    .put(
                        format!("evidence-{index}").as_bytes(),
                        "application/octet-stream",
                        class,
                    )
                    .unwrap()
            })
            .collect();
        let manifest = RunManifest {
            schema_version: RUN_SCHEMA_V2.into(),
            pack: files[0].object.clone(),
            suite_id: "framework.release".into(),
            subject_revision: "a".repeat(40),
            subject_tree: "b".repeat(40),
            environment: files[1.min(files.len() - 1)].object.clone(),
            seeds: vec!["seed-1".into()],
            objects: files
                .iter()
                .skip(2)
                .map(|file| file.object.clone())
                .collect(),
            evidence_files: files,
        };
        let envelope = RunEnvelope {
            run_id: derive_run_id(&manifest).unwrap(),
            manifest,
        };
        store.write_run(&envelope).unwrap();
        envelope
    }

    #[test]
    fn verifies_closed_world_bundle_and_rejects_tampering() {
        let directory = tempdir().unwrap();
        let envelope = v2_bundle(
            directory.path(),
            &[
                EvidenceClass::RawObservation,
                EvidenceClass::SemanticVerifierResult,
            ],
        );
        assert_eq!(verify_bundle(directory.path()).unwrap(), envelope);
        assert_eq!(
            verify_promotable_bundle(directory.path()).unwrap(),
            envelope
        );
        fs::write(
            directory
                .path()
                .join(BLOBS_DIRECTORY)
                .join(&envelope.manifest.evidence_files[1].object.digest),
            b"tampered",
        )
        .unwrap();
        assert!(matches!(
            verify_bundle(directory.path()),
            Err(EvidenceError::SizeMismatch(_)) | Err(EvidenceError::DigestMismatch(_))
        ));
    }

    #[test]
    fn rejects_extra_and_missing_inventory_files() {
        let directory = tempdir().unwrap();
        let envelope = v2_bundle(
            directory.path(),
            &[
                EvidenceClass::RawObservation,
                EvidenceClass::SemanticVerifierResult,
            ],
        );
        fs::write(directory.path().join("surprise.txt"), b"no").unwrap();
        assert!(matches!(
            verify_bundle(directory.path()),
            Err(EvidenceError::UnexpectedFile(_))
        ));
        fs::remove_file(directory.path().join("surprise.txt")).unwrap();
        fs::remove_file(
            directory
                .path()
                .join(BLOBS_DIRECTORY)
                .join(&envelope.manifest.evidence_files[0].object.digest),
        )
        .unwrap();
        assert!(matches!(
            verify_bundle(directory.path()),
            Err(EvidenceError::MissingInventoryFile(_))
        ));
    }

    #[test]
    fn synthetic_local_derived_and_blocked_classes_cannot_promote() {
        for class in [
            EvidenceClass::LocalTest,
            EvidenceClass::SyntheticFixture,
            EvidenceClass::DerivedIndex,
            EvidenceClass::BlockedBoundary,
        ] {
            let directory = tempdir().unwrap();
            v2_bundle(
                directory.path(),
                &[EvidenceClass::SemanticVerifierResult, class],
            );
            assert!(
                matches!(verify_promotable_bundle(directory.path()), Err(EvidenceError::NonPromotableEvidence { class: observed, .. }) if observed == class)
            );
        }
    }

    #[test]
    fn promotion_requires_semantic_result() {
        let directory = tempdir().unwrap();
        v2_bundle(
            directory.path(),
            &[
                EvidenceClass::RawObservation,
                EvidenceClass::SignedAttestation,
            ],
        );
        assert!(matches!(
            verify_promotable_bundle(directory.path()),
            Err(EvidenceError::MissingSemanticVerifierResult)
        ));
    }

    #[test]
    fn rejects_escaping_and_noncanonical_paths() {
        for path in [
            "",
            "/absolute",
            "../escape",
            "./current",
            "blobs//sha256/x",
            "blobs\\sha256\\x",
        ] {
            assert!(
                matches!(
                    validate_safe_relative_path(path),
                    Err(EvidenceError::UnsafePath(_))
                ),
                "{path}"
            );
        }
        assert!(validate_safe_relative_path("blobs/sha256/abc").is_ok());
    }

    #[test]
    fn rejects_duplicate_untyped_and_uppercase_inventory_data() {
        let directory = tempdir().unwrap();
        let mut envelope = v2_bundle(
            directory.path(),
            &[
                EvidenceClass::RawObservation,
                EvidenceClass::SemanticVerifierResult,
            ],
        );
        envelope
            .manifest
            .evidence_files
            .push(envelope.manifest.evidence_files[0].clone());
        envelope.run_id = derive_run_id(&envelope.manifest).unwrap();
        assert!(matches!(
            validate_envelope(&envelope),
            Err(EvidenceError::DuplicateInventoryPath(_))
        ));
        let mut envelope = v2_bundle(
            directory.path(),
            &[
                EvidenceClass::RawObservation,
                EvidenceClass::SemanticVerifierResult,
            ],
        );
        envelope
            .manifest
            .objects
            .push(object_ref(b"untyped", "application/octet-stream"));
        envelope.run_id = derive_run_id(&envelope.manifest).unwrap();
        assert!(matches!(
            validate_envelope(&envelope),
            Err(EvidenceError::UntypedObjectReference(_))
        ));
        let mut envelope = v2_bundle(
            directory.path(),
            &[
                EvidenceClass::RawObservation,
                EvidenceClass::SemanticVerifierResult,
            ],
        );
        envelope.manifest.pack.digest.make_ascii_uppercase();
        envelope.run_id = derive_run_id(&envelope.manifest).unwrap();
        assert!(matches!(
            validate_envelope(&envelope),
            Err(EvidenceError::InvalidDigest(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_and_hardlink_and_writes_private_content() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        let directory = tempdir().unwrap();
        let envelope = v2_bundle(
            directory.path(),
            &[
                EvidenceClass::RawObservation,
                EvidenceClass::SemanticVerifierResult,
            ],
        );
        let target = directory
            .path()
            .join(BLOBS_DIRECTORY)
            .join(&envelope.manifest.evidence_files[0].object.digest);
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::metadata(&target).unwrap().nlink(), 1);
        assert_eq!(
            fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let link = directory.path().join("unexpected-link");
        symlink(&target, &link).unwrap();
        assert!(matches!(
            verify_bundle(directory.path()),
            Err(EvidenceError::Symlink(_))
        ));
        fs::remove_file(&link).unwrap();
        let hard = directory.path().join("unexpected-hard-link");
        fs::hard_link(&target, &hard).unwrap();
        assert!(matches!(
            verify_bundle(directory.path()),
            Err(EvidenceError::MultipleHardLinks(_))
        ));
    }

    #[test]
    fn legacy_v1_is_readable_but_explicitly_non_promotable() {
        let directory = tempdir().unwrap();
        let store = ContentStore::open(directory.path()).unwrap();
        let pack = store
            .put(
                b"pack",
                "application/octet-stream",
                EvidenceClass::RawObservation,
            )
            .unwrap()
            .object;
        let environment = store
            .put(
                b"environment",
                "application/octet-stream",
                EvidenceClass::RawObservation,
            )
            .unwrap()
            .object;
        let manifest = RunManifest {
            schema_version: RUN_SCHEMA_V1.into(),
            pack,
            suite_id: "legacy".into(),
            subject_revision: "a".repeat(40),
            subject_tree: "b".repeat(40),
            environment,
            seeds: vec![],
            objects: vec![],
            evidence_files: vec![],
        };
        let envelope = RunEnvelope {
            run_id: derive_run_id(&manifest).unwrap(),
            manifest,
        };
        store.write_run(&envelope).unwrap();
        assert_eq!(verify_bundle(directory.path()).unwrap(), envelope);
        assert!(matches!(
            verify_promotable_bundle(directory.path()),
            Err(EvidenceError::UnsupportedRunSchema(_))
        ));
    }
}
