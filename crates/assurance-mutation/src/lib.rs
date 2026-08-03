//! Protocol-neutral, source-bound mutation-test coordination.
//!
//! The crate materializes only declared mutations over caller-provided bytes.
//! It contains no compiler, VM, test runner, network code, entropy source, or
//! protocol adapter. External execution observations are bound and checked but
//! never synthesized by this crate.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SOURCE_TREE_SCHEMA_V1: &str = "shieldkit-assurance-mutation-source-tree/v1";
pub const PLAN_SCHEMA_V1: &str = "shieldkit-assurance-mutation-plan/v1";
pub const REPLAY_SCHEMA_V1: &str = "shieldkit-assurance-mutation-replay/v1";
pub const REPORT_SCHEMA_V1: &str = "shieldkit-assurance-mutation-report/v1";

const FILE_DOMAIN: &[u8] = b"shieldkit-assurance/mutation-file/v1\0";
const TREE_DOMAIN: &[u8] = b"shieldkit-assurance/mutation-tree/v1\0";
const PLAN_DOMAIN: &[u8] = b"shieldkit-assurance/mutation-plan/v1\0";
const MUTANT_DOMAIN: &[u8] = b"shieldkit-assurance/mutation-mutant/v1\0";
const MATERIAL_DOMAIN: &[u8] = b"shieldkit-assurance/mutation-material/v1\0";
const REPLAY_DOMAIN: &[u8] = b"shieldkit-assurance/mutation-replay/v1\0";
const REPORT_DOMAIN: &[u8] = b"shieldkit-assurance/mutation-report/v1\0";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MutationError {
    #[error("invalid source tree: {0}")]
    InvalidTree(String),
    #[error("invalid mutation plan: {0}")]
    InvalidPlan(String),
    #[error("invalid report: {0}")]
    InvalidReport(String),
    #[error("canonical JSON encoding failed: {0}")]
    Canonical(String),
    #[error("duplicate {kind}: {value}")]
    Duplicate { kind: &'static str, value: String },
    #[error("source or plan drift: {0}")]
    Drift(String),
    #[error("conflicting mutation patches: {0}")]
    Conflict(String),
    #[error("resource budget exhausted: {0}")]
    BudgetExhausted(String),
    #[error("baseline did not pass")]
    BaselineFailed,
    #[error("release blocked by mutants: {0:?}")]
    ReleaseBlocked(Vec<String>),
}

pub type Result<T> = std::result::Result<T, MutationError>;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceFile {
    pub path: String,
    /// Hex encodes arbitrary bytes, including non-UTF8 inputs for byte operators.
    pub content_hex: String,
    pub byte_length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceTree {
    pub schema_version: String,
    pub files: Vec<SourceFile>,
    pub tree_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MutationBudgets {
    pub max_mutants: u64,
    pub max_materialized_bytes: u64,
    pub max_execution_attempts: u64,
    pub max_case_timeout_ms: u64,
    pub max_total_timeout_ms: u64,
}

/// Explicit release policy for a complete mutation campaign. All limits are
/// inclusive; a production plan normally sets every relevant failure limit to
/// zero. The engine never supplies permissive defaults.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MutationThresholds {
    pub minimum_selected: u64,
    pub minimum_executed: u64,
    pub maximum_survived_relevant: u64,
    pub maximum_unresolved_invalid_relevant: u64,
    pub maximum_timeout_relevant: u64,
    pub maximum_error_relevant: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MutationOperator {
    ByteFlip {
        path: String,
        offset: u64,
        xor_mask: u8,
    },
    TextReplace {
        path: String,
        needle: String,
        replacement: String,
        occurrence: u64,
    },
    JsonReplace {
        path: String,
        pointer: String,
        replacement: Value,
    },
    ExternalAst {
        envelope: ExternalAstEnvelope,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalAstEnvelope {
    pub mutator_id: String,
    pub source_tree_sha256: String,
    pub path: String,
    pub range: ByteRange,
    pub replacement_hex: String,
    /// Hash of independently retained AST-mutator evidence; no boolean waiver.
    pub evidence_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MutantDefinition {
    pub label: String,
    pub claim_ids: Vec<String>,
    pub relevant: bool,
    pub operators: Vec<MutationOperator>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MutationPlan {
    pub schema_version: String,
    pub plan_name: String,
    pub source_tree_sha256: String,
    pub claim_ids: Vec<String>,
    pub budgets: MutationBudgets,
    pub thresholds: MutationThresholds,
    pub mutants: Vec<MutantDefinition>,
    pub plan_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MaterializedFile {
    pub path: String,
    pub content_hex: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MaterializedMutant {
    pub mutant_id: String,
    pub operator_ids: Vec<String>,
    pub claim_ids: Vec<String>,
    pub relevant: bool,
    pub files: Vec<MaterializedFile>,
    pub materialization_sha256: String,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MutationShard {
    pub shard_index: u64,
    pub shard_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MutationReplayManifest {
    pub schema_version: String,
    pub plan_sha256: String,
    pub source_tree_sha256: String,
    pub shard: MutationShard,
    pub mutant_ids: Vec<String>,
    pub replay_sha256: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BaselineVerdict {
    Pass,
    Fail,
    Timeout,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BaselineValidation {
    pub plan_sha256: String,
    pub source_tree_sha256: String,
    pub verdict: BaselineVerdict,
    pub elapsed_ms: u64,
    pub evidence_sha256: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MutationOutcome {
    Kill,
    Survive,
    Invalid,
    Timeout,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EquivalentDisposition {
    pub reviewer_id: String,
    pub justification_sha256: String,
    pub independent_evidence_sha256: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObservedMutationResult {
    pub mutant_id: String,
    pub outcome: MutationOutcome,
    pub elapsed_ms: u64,
    pub evidence_sha256: String,
    #[serde(default)]
    pub equivalent_disposition: Option<EquivalentDisposition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Coverage {
    pub claim_ids: Vec<String>,
    pub operator_ids: Vec<String>,
}

/// Canonical, independently checkable accounting for the selected campaign.
/// `selected_mutant_ids` are the generated identities selected by this report;
/// every selected identity must occur exactly once in `executed_mutant_ids`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MutationAccounting {
    pub selected_mutant_ids: Vec<String>,
    pub executed_mutant_ids: Vec<String>,
    pub selected: u64,
    pub executed: u64,
    pub killed: u64,
    pub survived: u64,
    pub invalid: u64,
    pub timed_out: u64,
    pub errored: u64,
    pub relevant_selected: u64,
    pub relevant_executed: u64,
    pub relevant_killed: u64,
    pub relevant_survived: u64,
    pub relevant_invalid: u64,
    pub relevant_unresolved_invalid: u64,
    pub relevant_timed_out: u64,
    pub relevant_errored: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MutationReport {
    pub schema_version: String,
    pub plan_sha256: String,
    pub source_tree_sha256: String,
    pub baseline: BaselineValidation,
    /// Binds the report to the exact deterministic materializations executed.
    pub materialized_campaign_sha256: String,
    pub results: Vec<ObservedMutationResult>,
    pub coverage: Coverage,
    pub accounting: MutationAccounting,
    pub total_elapsed_ms: u64,
    pub report_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReleaseVerdict {
    pub accepted: bool,
    pub blocking_mutant_ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TreeIdentity<'a> {
    schema_version: &'a str,
    files: &'a [SourceFile],
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanIdentity<'a> {
    schema_version: &'a str,
    plan_name: &'a str,
    source_tree_sha256: &'a str,
    claim_ids: &'a [String],
    budgets: &'a MutationBudgets,
    thresholds: &'a MutationThresholds,
    mutants: &'a [MutantDefinition],
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MutantIdentity<'a> {
    plan_sha256: &'a str,
    definition: &'a MutantDefinition,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MaterialIdentity<'a> {
    mutant_id: &'a str,
    files: &'a [MaterializedFile],
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayIdentity<'a> {
    schema_version: &'a str,
    plan_sha256: &'a str,
    source_tree_sha256: &'a str,
    shard: &'a MutationShard,
    mutant_ids: &'a [String],
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportIdentity<'a> {
    schema_version: &'a str,
    plan_sha256: &'a str,
    source_tree_sha256: &'a str,
    baseline: &'a BaselineValidation,
    materialized_campaign_sha256: &'a str,
    results: &'a [ObservedMutationResult],
    coverage: &'a Coverage,
    accounting: &'a MutationAccounting,
    total_elapsed_ms: u64,
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|error| MutationError::Canonical(error.to_string()))
}
fn hash(domain: &[u8], bytes: &[u8]) -> String {
    let mut value = Sha256::new();
    value.update(domain);
    value.update(bytes);
    format!("sha256:{}", hex::encode(value.finalize()))
}
fn digest_ok(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn id_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}
fn path_ok(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'_' | b'-'))
}
fn bytes(file: &SourceFile) -> Result<Vec<u8>> {
    if !digest_ok(&file.sha256) || !path_ok(&file.path) {
        return Err(MutationError::InvalidTree(format!(
            "invalid source file {}",
            file.path
        )));
    }
    let decoded = hex::decode(&file.content_hex)
        .map_err(|_| MutationError::InvalidTree(format!("invalid contentHex for {}", file.path)))?;
    if decoded.len() as u64 != file.byte_length || hash(FILE_DOMAIN, &decoded) != file.sha256 {
        return Err(MutationError::Drift(format!(
            "source file binding differs: {}",
            file.path
        )));
    }
    Ok(decoded)
}
fn source_map(tree: &SourceTree) -> Result<BTreeMap<String, Vec<u8>>> {
    validate_tree(tree)?;
    tree.files
        .iter()
        .map(|file| Ok((file.path.clone(), bytes(file)?)))
        .collect()
}

pub fn validate_tree(tree: &SourceTree) -> Result<()> {
    if tree.schema_version != SOURCE_TREE_SCHEMA_V1 {
        return Err(MutationError::InvalidTree(
            "unsupported schemaVersion".into(),
        ));
    }
    if tree.files.is_empty() {
        return Err(MutationError::InvalidTree("files cannot be empty".into()));
    }
    let mut paths = BTreeSet::new();
    let mut previous = None::<String>;
    for file in &tree.files {
        bytes(file)?;
        if !paths.insert(file.path.clone()) {
            return Err(MutationError::Duplicate {
                kind: "source path",
                value: file.path.clone(),
            });
        }
        if let Some(last) = previous.as_ref()
            && last >= &file.path
        {
            return Err(MutationError::InvalidTree(
                "files must be lexically sorted".into(),
            ));
        }
        previous = Some(file.path.clone());
    }
    let identity = TreeIdentity {
        schema_version: &tree.schema_version,
        files: &tree.files,
    };
    if hash(TREE_DOMAIN, &canonical(&identity)?) != tree.tree_sha256 {
        return Err(MutationError::Drift("tree hash differs".into()));
    }
    Ok(())
}

pub fn make_source_tree(files: Vec<(String, Vec<u8>)>) -> Result<SourceTree> {
    if files.is_empty() {
        return Err(MutationError::InvalidTree("files cannot be empty".into()));
    }
    let mut records: Vec<_> = files
        .into_iter()
        .map(|(path, content)| SourceFile {
            path,
            content_hex: hex::encode(&content),
            byte_length: content.len() as u64,
            sha256: hash(FILE_DOMAIN, &content),
        })
        .collect();
    records.sort_by(|left, right| left.path.cmp(&right.path));
    let identity = TreeIdentity {
        schema_version: SOURCE_TREE_SCHEMA_V1,
        files: &records,
    };
    let tree_sha256 = hash(TREE_DOMAIN, &canonical(&identity)?);
    let tree = SourceTree {
        schema_version: SOURCE_TREE_SCHEMA_V1.into(),
        files: records,
        tree_sha256,
    };
    validate_tree(&tree)?;
    Ok(tree)
}

fn operator_id(plan_sha256: &str, operator: &MutationOperator) -> Result<String> {
    Ok(hash(
        MUTANT_DOMAIN,
        &canonical(&serde_json::json!({"planSha256": plan_sha256, "operator": operator}))?,
    ))
}
pub fn mutant_id(plan_sha256: &str, definition: &MutantDefinition) -> Result<String> {
    Ok(hash(
        MUTANT_DOMAIN,
        &canonical(&MutantIdentity {
            plan_sha256,
            definition,
        })?,
    ))
}

pub fn validate_plan(plan: &MutationPlan, tree: &SourceTree) -> Result<()> {
    validate_tree(tree)?;
    if plan.schema_version != PLAN_SCHEMA_V1
        || !id_ok(&plan.plan_name)
        || plan.source_tree_sha256 != tree.tree_sha256
    {
        return Err(MutationError::InvalidPlan(
            "schemaVersion, planName, or sourceTree binding differs".into(),
        ));
    }
    let b = &plan.budgets;
    if b.max_mutants == 0
        || b.max_materialized_bytes == 0
        || b.max_execution_attempts == 0
        || b.max_case_timeout_ms == 0
        || b.max_total_timeout_ms == 0
    {
        return Err(MutationError::InvalidPlan(
            "all budgets must be nonzero".into(),
        ));
    }
    let thresholds = &plan.thresholds;
    if thresholds.minimum_selected == 0
        || thresholds.minimum_executed == 0
        || thresholds.minimum_selected > b.max_mutants
        || thresholds.minimum_executed > b.max_mutants
        || thresholds.maximum_survived_relevant > b.max_mutants
        || thresholds.maximum_unresolved_invalid_relevant > b.max_mutants
        || thresholds.maximum_timeout_relevant > b.max_mutants
        || thresholds.maximum_error_relevant > b.max_mutants
    {
        return Err(MutationError::InvalidPlan(
            "mutation thresholds are outside campaign bounds".into(),
        ));
    }
    if plan.mutants.is_empty() || plan.mutants.len() as u64 > b.max_mutants {
        return Err(MutationError::BudgetExhausted(
            "mutant count exceeds maxMutants".into(),
        ));
    }
    let claims: BTreeSet<_> = plan.claim_ids.iter().cloned().collect();
    if claims.is_empty()
        || claims.len() != plan.claim_ids.len()
        || !claims.iter().all(|value| id_ok(value))
    {
        return Err(MutationError::InvalidPlan(
            "claimIds must be unique stable identifiers".into(),
        ));
    }
    let sources = source_map(tree)?;
    let mut labels = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut covered = BTreeSet::new();
    for mutant in &plan.mutants {
        if !id_ok(&mutant.label)
            || !labels.insert(mutant.label.clone())
            || mutant.claim_ids.is_empty()
            || mutant.operators.is_empty()
        {
            return Err(MutationError::InvalidPlan(
                "mutant labels, claims, and operators must be nonempty and unique".into(),
            ));
        }
        if !mutant.claim_ids.iter().all(|value| claims.contains(value)) {
            return Err(MutationError::InvalidPlan(
                "mutant references undeclared claim".into(),
            ));
        }
        covered.extend(mutant.claim_ids.iter().cloned());
        for operator in &mutant.operators {
            validate_operator(operator, &sources, &tree.tree_sha256)?;
        }
        let id = mutant_id(&plan.plan_sha256, mutant)?;
        if !ids.insert(id.clone()) {
            return Err(MutationError::Duplicate {
                kind: "mutant ID",
                value: id,
            });
        }
    }
    if covered != claims {
        return Err(MutationError::InvalidPlan(
            "every declared claim requires at least one mutant".into(),
        ));
    }
    let identity = PlanIdentity {
        schema_version: &plan.schema_version,
        plan_name: &plan.plan_name,
        source_tree_sha256: &plan.source_tree_sha256,
        claim_ids: &plan.claim_ids,
        budgets: &plan.budgets,
        thresholds: &plan.thresholds,
        mutants: &plan.mutants,
    };
    if hash(PLAN_DOMAIN, &canonical(&identity)?) != plan.plan_sha256 {
        return Err(MutationError::Drift("plan hash differs".into()));
    }
    Ok(())
}

pub fn make_plan(
    plan_name: String,
    tree: &SourceTree,
    claim_ids: Vec<String>,
    budgets: MutationBudgets,
    thresholds: MutationThresholds,
    mutants: Vec<MutantDefinition>,
) -> Result<MutationPlan> {
    validate_tree(tree)?;
    let identity = PlanIdentity {
        schema_version: PLAN_SCHEMA_V1,
        plan_name: &plan_name,
        source_tree_sha256: &tree.tree_sha256,
        claim_ids: &claim_ids,
        budgets: &budgets,
        thresholds: &thresholds,
        mutants: &mutants,
    };
    let plan_sha256 = hash(PLAN_DOMAIN, &canonical(&identity)?);
    let plan = MutationPlan {
        schema_version: PLAN_SCHEMA_V1.into(),
        plan_name,
        source_tree_sha256: tree.tree_sha256.clone(),
        claim_ids,
        budgets,
        thresholds,
        mutants,
        plan_sha256,
    };
    validate_plan(&plan, tree)?;
    Ok(plan)
}

fn validate_range(range: &ByteRange, length: usize) -> Result<()> {
    if range.start > range.end || range.end > length as u64 {
        Err(MutationError::InvalidPlan(
            "byte range is outside source".into(),
        ))
    } else {
        Ok(())
    }
}
fn validate_operator(
    operator: &MutationOperator,
    sources: &BTreeMap<String, Vec<u8>>,
    tree_sha256: &str,
) -> Result<()> {
    let get = |path: &String| {
        sources.get(path).ok_or_else(|| {
            MutationError::InvalidPlan(format!("operator source path is absent: {path}"))
        })
    };
    match operator {
        MutationOperator::ByteFlip {
            path,
            offset,
            xor_mask,
        } => {
            if *xor_mask == 0 || *offset >= get(path)?.len() as u64 {
                return Err(MutationError::InvalidPlan(
                    "byte flip offset/mask is invalid".into(),
                ));
            }
        }
        MutationOperator::TextReplace {
            path,
            needle,
            replacement,
            occurrence,
        } => {
            if needle.is_empty() || needle == replacement {
                return Err(MutationError::InvalidPlan(
                    "text replacement must change a nonempty needle".into(),
                ));
            }
            let text = std::str::from_utf8(get(path)?).map_err(|_| {
                MutationError::InvalidPlan("text replacement requires UTF-8 source".into())
            })?;
            if nth_match(text.as_bytes(), needle.as_bytes(), *occurrence).is_none() {
                return Err(MutationError::InvalidPlan(
                    "text replacement occurrence is absent".into(),
                ));
            }
        }
        MutationOperator::JsonReplace {
            path,
            pointer,
            replacement: _,
        } => {
            let value: Value = serde_json::from_slice(get(path)?).map_err(|_| {
                MutationError::InvalidPlan("JSON replacement requires JSON source".into())
            })?;
            if value.pointer(pointer).is_none() {
                return Err(MutationError::InvalidPlan("JSON pointer is absent".into()));
            }
        }
        MutationOperator::ExternalAst { envelope } => {
            if !id_ok(&envelope.mutator_id)
                || envelope.source_tree_sha256 != tree_sha256
                || !digest_ok(&envelope.evidence_sha256)
            {
                return Err(MutationError::InvalidPlan(
                    "external AST envelope binding is invalid".into(),
                ));
            }
            validate_range(&envelope.range, get(&envelope.path)?.len())?;
            hex::decode(&envelope.replacement_hex).map_err(|_| {
                MutationError::InvalidPlan("external AST replacement hex is invalid".into())
            })?;
        }
    };
    Ok(())
}
fn nth_match(bytes: &[u8], needle: &[u8], occurrence: u64) -> Option<usize> {
    let mut start = 0;
    let mut count = 0;
    while start <= bytes.len().saturating_sub(needle.len()) {
        let index = bytes[start..]
            .windows(needle.len())
            .position(|window| window == needle)?
            + start;
        if count == occurrence {
            return Some(index);
        }
        count += 1;
        start = index + needle.len();
    }
    None
}
#[derive(Clone)]
struct Patch {
    path: String,
    range: ByteRange,
    replacement: Vec<u8>,
}
fn patch_for(operator: &MutationOperator, sources: &BTreeMap<String, Vec<u8>>) -> Result<Patch> {
    match operator {
        MutationOperator::ByteFlip {
            path,
            offset,
            xor_mask,
        } => {
            let original = sources
                .get(path)
                .ok_or_else(|| MutationError::InvalidPlan("source absent".into()))?
                [*offset as usize];
            Ok(Patch {
                path: path.clone(),
                range: ByteRange {
                    start: *offset,
                    end: offset + 1,
                },
                replacement: vec![original ^ xor_mask],
            })
        }
        MutationOperator::TextReplace {
            path,
            needle,
            replacement,
            occurrence,
        } => {
            let data = sources
                .get(path)
                .ok_or_else(|| MutationError::InvalidPlan("source absent".into()))?;
            let start = nth_match(data, needle.as_bytes(), *occurrence)
                .ok_or_else(|| MutationError::Drift("text occurrence vanished".into()))?
                as u64;
            Ok(Patch {
                path: path.clone(),
                range: ByteRange {
                    start,
                    end: start + needle.len() as u64,
                },
                replacement: replacement.as_bytes().to_vec(),
            })
        }
        MutationOperator::JsonReplace {
            path,
            pointer,
            replacement,
        } => {
            let data = sources
                .get(path)
                .ok_or_else(|| MutationError::InvalidPlan("source absent".into()))?;
            let mut value: Value = serde_json::from_slice(data)
                .map_err(|_| MutationError::Drift("JSON source became invalid".into()))?;
            *value
                .pointer_mut(pointer)
                .ok_or_else(|| MutationError::Drift("JSON pointer vanished".into()))? =
                replacement.clone();
            Ok(Patch {
                path: path.clone(),
                range: ByteRange {
                    start: 0,
                    end: data.len() as u64,
                },
                replacement: canonical(&value)?,
            })
        }
        MutationOperator::ExternalAst { envelope } => Ok(Patch {
            path: envelope.path.clone(),
            range: envelope.range.clone(),
            replacement: hex::decode(&envelope.replacement_hex).map_err(|_| {
                MutationError::InvalidPlan("external AST replacement hex is invalid".into())
            })?,
        }),
    }
}
fn apply_patches(
    mut sources: BTreeMap<String, Vec<u8>>,
    mut patches: Vec<Patch>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    patches.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.range.start.cmp(&right.range.start))
            .then(left.range.end.cmp(&right.range.end))
    });
    for pair in patches.windows(2) {
        if pair[0].path == pair[1].path && pair[0].range.end > pair[1].range.start {
            return Err(MutationError::Conflict(pair[0].path.clone()));
        }
    }
    for patch in patches.into_iter().rev() {
        let content = sources
            .get_mut(&patch.path)
            .ok_or_else(|| MutationError::InvalidPlan("source absent".into()))?;
        validate_range(&patch.range, content.len())?;
        content.splice(
            patch.range.start as usize..patch.range.end as usize,
            patch.replacement,
        );
    }
    Ok(sources)
}

pub fn materialize_mutants(
    plan: &MutationPlan,
    tree: &SourceTree,
) -> Result<Vec<MaterializedMutant>> {
    validate_plan(plan, tree)?;
    let sources = source_map(tree)?;
    let mut materialized = Vec::new();
    let mut output_hashes = BTreeSet::new();
    let mut total = 0_u64;
    for definition in &plan.mutants {
        let mutant_id = mutant_id(&plan.plan_sha256, definition)?;
        let operator_ids: Vec<_> = definition
            .operators
            .iter()
            .map(|operator| operator_id(&plan.plan_sha256, operator))
            .collect::<Result<_>>()?;
        let changed = apply_patches(
            sources.clone(),
            definition
                .operators
                .iter()
                .map(|operator| patch_for(operator, &sources))
                .collect::<Result<_>>()?,
        )?;
        let files: Vec<_> = changed
            .into_iter()
            .map(|(path, content)| MaterializedFile {
                path,
                sha256: hash(FILE_DOMAIN, &content),
                content_hex: hex::encode(content),
            })
            .collect();
        let bytes = files
            .iter()
            .map(|file| (file.content_hex.len() / 2) as u64)
            .sum::<u64>();
        total = total
            .checked_add(bytes)
            .ok_or_else(|| MutationError::BudgetExhausted("materialized bytes overflow".into()))?;
        if total > plan.budgets.max_materialized_bytes {
            return Err(MutationError::BudgetExhausted(
                "maxMaterializedBytes exceeded".into(),
            ));
        }
        let output_sha256 = hash(MATERIAL_DOMAIN, &canonical(&files)?);
        let materialization_sha256 = hash(
            MATERIAL_DOMAIN,
            &canonical(&MaterialIdentity {
                mutant_id: &mutant_id,
                files: &files,
            })?,
        );
        if !output_hashes.insert(output_sha256.clone()) {
            return Err(MutationError::Duplicate {
                kind: "materialized output",
                value: output_sha256,
            });
        }
        materialized.push(MaterializedMutant {
            mutant_id,
            operator_ids,
            claim_ids: definition.claim_ids.clone(),
            relevant: definition.relevant,
            files,
            materialization_sha256,
            total_bytes: bytes,
        });
    }
    materialized.sort_by(|left, right| left.mutant_id.cmp(&right.mutant_id));
    Ok(materialized)
}

pub fn shard_mutants(
    mutants: &[MaterializedMutant],
    shard: MutationShard,
) -> Result<Vec<MaterializedMutant>> {
    if shard.shard_count == 0 || shard.shard_index >= shard.shard_count {
        return Err(MutationError::InvalidPlan("invalid shard".into()));
    }
    let mut ids = BTreeSet::new();
    let mut selected = Vec::new();
    for mutant in mutants {
        if !ids.insert(mutant.mutant_id.clone()) {
            return Err(MutationError::Duplicate {
                kind: "mutant ID",
                value: mutant.mutant_id.clone(),
            });
        }
        let prefix = u64::from_be_bytes(
            hex::decode(&mutant.mutant_id[7..23])
                .map_err(|_| MutationError::InvalidPlan("mutant ID is malformed".into()))?
                .try_into()
                .map_err(|_| MutationError::InvalidPlan("mutant ID prefix malformed".into()))?,
        );
        if prefix % shard.shard_count == shard.shard_index {
            selected.push(mutant.clone());
        }
    }
    selected.sort_by(|left, right| left.mutant_id.cmp(&right.mutant_id));
    Ok(selected)
}
pub fn make_replay_manifest(
    plan: &MutationPlan,
    tree: &SourceTree,
    shard: MutationShard,
) -> Result<MutationReplayManifest> {
    let mutants = shard_mutants(&materialize_mutants(plan, tree)?, shard.clone())?;
    let mutant_ids: Vec<_> = mutants.into_iter().map(|mutant| mutant.mutant_id).collect();
    let identity = ReplayIdentity {
        schema_version: REPLAY_SCHEMA_V1,
        plan_sha256: &plan.plan_sha256,
        source_tree_sha256: &tree.tree_sha256,
        shard: &shard,
        mutant_ids: &mutant_ids,
    };
    let replay_sha256 = hash(REPLAY_DOMAIN, &canonical(&identity)?);
    Ok(MutationReplayManifest {
        schema_version: REPLAY_SCHEMA_V1.into(),
        plan_sha256: plan.plan_sha256.clone(),
        source_tree_sha256: tree.tree_sha256.clone(),
        shard,
        mutant_ids,
        replay_sha256,
    })
}
pub fn verify_replay_manifest(
    plan: &MutationPlan,
    tree: &SourceTree,
    manifest: &MutationReplayManifest,
) -> Result<()> {
    if manifest.schema_version != REPLAY_SCHEMA_V1
        || manifest.plan_sha256 != plan.plan_sha256
        || manifest.source_tree_sha256 != tree.tree_sha256
    {
        return Err(MutationError::Drift("replay identity differs".into()));
    }
    let expected = make_replay_manifest(plan, tree, manifest.shard.clone())?;
    if &expected != manifest {
        return Err(MutationError::Drift("replay manifest differs".into()));
    }
    Ok(())
}

fn validate_baseline(
    plan: &MutationPlan,
    tree: &SourceTree,
    baseline: &BaselineValidation,
) -> Result<()> {
    if baseline.plan_sha256 != plan.plan_sha256
        || baseline.source_tree_sha256 != tree.tree_sha256
        || !digest_ok(&baseline.evidence_sha256)
    {
        return Err(MutationError::InvalidReport(
            "baseline binding/evidence is invalid".into(),
        ));
    }
    if baseline.verdict != BaselineVerdict::Pass {
        return Err(MutationError::BaselineFailed);
    }
    if baseline.elapsed_ms > plan.budgets.max_case_timeout_ms {
        return Err(MutationError::BudgetExhausted(
            "baseline timeout exceeds maxCaseTimeoutMs".into(),
        ));
    }
    Ok(())
}
fn validate_equivalent(result: &ObservedMutationResult) -> Result<()> {
    if let Some(equivalent) = &result.equivalent_disposition
        && (result.outcome != MutationOutcome::Invalid
            || !id_ok(&equivalent.reviewer_id)
            || !digest_ok(&equivalent.justification_sha256)
            || !digest_ok(&equivalent.independent_evidence_sha256)
            || equivalent.justification_sha256 == equivalent.independent_evidence_sha256
            || equivalent.summary.trim().is_empty())
    {
        return Err(MutationError::InvalidReport("equivalent disposition requires invalid outcome and two distinct hashed evidence objects".into()));
    }
    Ok(())
}

fn materialized_campaign_sha256(mutants: &[MaterializedMutant]) -> Result<String> {
    Ok(hash(MATERIAL_DOMAIN, &canonical(&mutants.to_vec())?))
}

fn accounting_for(
    mutants: &[MaterializedMutant],
    results: &[ObservedMutationResult],
) -> MutationAccounting {
    let selected_mutant_ids: Vec<_> = mutants
        .iter()
        .map(|mutant| mutant.mutant_id.clone())
        .collect();
    let executed_mutant_ids: Vec<_> = results
        .iter()
        .map(|result| result.mutant_id.clone())
        .collect();
    let relevant: BTreeMap<_, _> = mutants
        .iter()
        .map(|mutant| (mutant.mutant_id.as_str(), mutant.relevant))
        .collect();
    let mut accounting = MutationAccounting {
        selected: selected_mutant_ids.len() as u64,
        executed: executed_mutant_ids.len() as u64,
        selected_mutant_ids,
        executed_mutant_ids,
        killed: 0,
        survived: 0,
        invalid: 0,
        timed_out: 0,
        errored: 0,
        relevant_selected: mutants.iter().filter(|mutant| mutant.relevant).count() as u64,
        relevant_executed: 0,
        relevant_killed: 0,
        relevant_survived: 0,
        relevant_invalid: 0,
        relevant_unresolved_invalid: 0,
        relevant_timed_out: 0,
        relevant_errored: 0,
    };
    for result in results {
        let is_relevant = relevant
            .get(result.mutant_id.as_str())
            .copied()
            .unwrap_or(false);
        if is_relevant {
            accounting.relevant_executed += 1;
        }
        match result.outcome {
            MutationOutcome::Kill => {
                accounting.killed += 1;
                if is_relevant {
                    accounting.relevant_killed += 1;
                }
            }
            MutationOutcome::Survive => {
                accounting.survived += 1;
                if is_relevant {
                    accounting.relevant_survived += 1;
                }
            }
            MutationOutcome::Invalid => {
                accounting.invalid += 1;
                if is_relevant {
                    accounting.relevant_invalid += 1;
                    if result.equivalent_disposition.is_none() {
                        accounting.relevant_unresolved_invalid += 1;
                    }
                }
            }
            MutationOutcome::Timeout => {
                accounting.timed_out += 1;
                if is_relevant {
                    accounting.relevant_timed_out += 1;
                }
            }
            MutationOutcome::Error => {
                accounting.errored += 1;
                if is_relevant {
                    accounting.relevant_errored += 1;
                }
            }
        }
    }
    accounting
}

fn validate_minimum_accounting(
    thresholds: &MutationThresholds,
    accounting: &MutationAccounting,
) -> Result<()> {
    if accounting.selected < thresholds.minimum_selected
        || accounting.executed < thresholds.minimum_executed
        || accounting.selected != accounting.executed
        || accounting.selected_mutant_ids != accounting.executed_mutant_ids
    {
        return Err(MutationError::InvalidReport(
            "selected/executed accounting does not meet the declared policy".into(),
        ));
    }
    Ok(())
}

pub fn build_report(
    plan: &MutationPlan,
    tree: &SourceTree,
    baseline: BaselineValidation,
    mut results: Vec<ObservedMutationResult>,
) -> Result<MutationReport> {
    validate_plan(plan, tree)?;
    validate_baseline(plan, tree, &baseline)?;
    let mutants = materialize_mutants(plan, tree)?;
    if results.len() != mutants.len() || results.len() as u64 > plan.budgets.max_execution_attempts
    {
        return Err(MutationError::BudgetExhausted(
            "results do not fit execution budget".into(),
        ));
    }
    results.sort_by(|left, right| left.mutant_id.cmp(&right.mutant_id));
    let expected: BTreeMap<_, _> = mutants
        .iter()
        .map(|mutant| (mutant.mutant_id.clone(), mutant))
        .collect();
    let mut seen = BTreeSet::new();
    let mut total = baseline.elapsed_ms;
    let mut claims = BTreeSet::new();
    let mut operators = BTreeSet::new();
    for result in &results {
        if !seen.insert(result.mutant_id.clone()) {
            return Err(MutationError::Duplicate {
                kind: "result mutant ID",
                value: result.mutant_id.clone(),
            });
        }
        let mutant = expected.get(&result.mutant_id).ok_or_else(|| {
            MutationError::InvalidReport("result references unknown mutant".into())
        })?;
        if !digest_ok(&result.evidence_sha256)
            || result.elapsed_ms > plan.budgets.max_case_timeout_ms
        {
            return Err(MutationError::InvalidReport(
                "result evidence/timeout is invalid".into(),
            ));
        }
        validate_equivalent(result)?;
        total = total
            .checked_add(result.elapsed_ms)
            .ok_or_else(|| MutationError::BudgetExhausted("total elapsed overflow".into()))?;
        claims.extend(mutant.claim_ids.iter().cloned());
        operators.extend(mutant.operator_ids.iter().cloned());
    }
    if seen.len() != expected.len() || total > plan.budgets.max_total_timeout_ms {
        return Err(MutationError::BudgetExhausted(
            "missing results or maxTotalTimeoutMs exceeded".into(),
        ));
    }
    let coverage = Coverage {
        claim_ids: claims.into_iter().collect(),
        operator_ids: operators.into_iter().collect(),
    };
    let expected_claims: BTreeSet<_> = plan.claim_ids.iter().cloned().collect();
    if coverage.claim_ids.iter().cloned().collect::<BTreeSet<_>>() != expected_claims {
        return Err(MutationError::InvalidReport(
            "claim coverage is incomplete".into(),
        ));
    }
    let accounting = accounting_for(&mutants, &results);
    validate_minimum_accounting(&plan.thresholds, &accounting)?;
    let materialized_campaign_sha256 = materialized_campaign_sha256(&mutants)?;
    let identity = ReportIdentity {
        schema_version: REPORT_SCHEMA_V1,
        plan_sha256: &plan.plan_sha256,
        source_tree_sha256: &tree.tree_sha256,
        baseline: &baseline,
        materialized_campaign_sha256: &materialized_campaign_sha256,
        results: &results,
        coverage: &coverage,
        accounting: &accounting,
        total_elapsed_ms: total,
    };
    let report_sha256 = hash(REPORT_DOMAIN, &canonical(&identity)?);
    Ok(MutationReport {
        schema_version: REPORT_SCHEMA_V1.into(),
        plan_sha256: plan.plan_sha256.clone(),
        source_tree_sha256: tree.tree_sha256.clone(),
        baseline,
        materialized_campaign_sha256,
        results,
        coverage,
        accounting,
        total_elapsed_ms: total,
        report_sha256,
    })
}
pub fn verify_report(
    plan: &MutationPlan,
    tree: &SourceTree,
    report: &MutationReport,
) -> Result<()> {
    let expected = build_report(plan, tree, report.baseline.clone(), report.results.clone())?;
    if &expected != report {
        return Err(MutationError::Drift("report differs".into()));
    }
    Ok(())
}
pub fn release_verdict(
    plan: &MutationPlan,
    tree: &SourceTree,
    report: &MutationReport,
) -> Result<ReleaseVerdict> {
    verify_report(plan, tree, report)?;
    let mutants: BTreeMap<_, _> = materialize_mutants(plan, tree)?
        .into_iter()
        .map(|mutant| (mutant.mutant_id.clone(), mutant))
        .collect();
    let mut blockers = Vec::new();
    let accounting = &report.accounting;
    let thresholds = &plan.thresholds;
    let exceeded_survivors = accounting.relevant_survived > thresholds.maximum_survived_relevant;
    let exceeded_invalid =
        accounting.relevant_unresolved_invalid > thresholds.maximum_unresolved_invalid_relevant;
    let exceeded_timeouts = accounting.relevant_timed_out > thresholds.maximum_timeout_relevant;
    let exceeded_errors = accounting.relevant_errored > thresholds.maximum_error_relevant;
    for result in &report.results {
        let mutant = &mutants[&result.mutant_id];
        if !mutant.relevant {
            continue;
        }
        let blocks = match result.outcome {
            MutationOutcome::Survive => exceeded_survivors,
            MutationOutcome::Invalid => result.equivalent_disposition.is_none() && exceeded_invalid,
            MutationOutcome::Timeout => exceeded_timeouts,
            MutationOutcome::Error => exceeded_errors,
            MutationOutcome::Kill => false,
        };
        if blocks {
            blockers.push(result.mutant_id.clone());
        }
    }
    blockers.sort();
    if blockers.is_empty() {
        Ok(ReleaseVerdict {
            accepted: true,
            blocking_mutant_ids: blockers,
        })
    } else {
        Err(MutationError::ReleaseBlocked(blockers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> String {
        hash(b"test\0", label.as_bytes())
    }
    fn tree() -> SourceTree {
        make_source_tree(vec![
            ("a.txt".into(), b"alpha beta".to_vec()),
            ("b.json".into(), br#"{"flag":true,"n":1}"#.to_vec()),
        ])
        .unwrap()
    }
    fn budgets() -> MutationBudgets {
        MutationBudgets {
            max_mutants: 8,
            max_materialized_bytes: 10_000,
            max_execution_attempts: 8,
            max_case_timeout_ms: 10,
            max_total_timeout_ms: 100,
        }
    }
    fn thresholds() -> MutationThresholds {
        MutationThresholds {
            minimum_selected: 1,
            minimum_executed: 1,
            maximum_survived_relevant: 0,
            maximum_unresolved_invalid_relevant: 0,
            maximum_timeout_relevant: 0,
            maximum_error_relevant: 0,
        }
    }
    fn plan(tree: &SourceTree) -> MutationPlan {
        make_plan(
            "plan.alpha".into(),
            tree,
            vec!["claim.alpha".into(), "claim.beta".into()],
            budgets(),
            thresholds(),
            vec![
                MutantDefinition {
                    label: "byte".into(),
                    claim_ids: vec!["claim.alpha".into()],
                    relevant: true,
                    operators: vec![MutationOperator::ByteFlip {
                        path: "a.txt".into(),
                        offset: 0,
                        xor_mask: 1,
                    }],
                },
                MutantDefinition {
                    label: "text-json".into(),
                    claim_ids: vec!["claim.beta".into()],
                    relevant: true,
                    operators: vec![
                        MutationOperator::TextReplace {
                            path: "a.txt".into(),
                            needle: "beta".into(),
                            replacement: "BETA".into(),
                            occurrence: 0,
                        },
                        MutationOperator::JsonReplace {
                            path: "b.json".into(),
                            pointer: "/flag".into(),
                            replacement: Value::Bool(false),
                        },
                    ],
                },
            ],
        )
        .unwrap()
    }
    fn baseline(plan: &MutationPlan, tree: &SourceTree) -> BaselineValidation {
        BaselineValidation {
            plan_sha256: plan.plan_sha256.clone(),
            source_tree_sha256: tree.tree_sha256.clone(),
            verdict: BaselineVerdict::Pass,
            elapsed_ms: 1,
            evidence_sha256: digest("baseline"),
        }
    }
    fn results(
        plan: &MutationPlan,
        tree: &SourceTree,
        outcome: MutationOutcome,
    ) -> Vec<ObservedMutationResult> {
        materialize_mutants(plan, tree)
            .unwrap()
            .into_iter()
            .map(|mutant| ObservedMutationResult {
                mutant_id: mutant.mutant_id,
                outcome,
                elapsed_ms: 1,
                evidence_sha256: digest("result"),
                equivalent_disposition: None,
            })
            .collect()
    }

    #[test]
    fn deterministic_materialization_and_replay_sharding_are_complete() {
        let tree = tree();
        let plan = plan(&tree);
        let first = materialize_mutants(&plan, &tree).unwrap();
        let second = materialize_mutants(&plan, &tree).unwrap();
        assert_eq!(first, second);
        let all: BTreeSet<_> = first
            .iter()
            .map(|mutant| mutant.mutant_id.clone())
            .collect();
        let mut joined = BTreeSet::new();
        for index in 0..3 {
            let manifest = make_replay_manifest(
                &plan,
                &tree,
                MutationShard {
                    shard_index: index,
                    shard_count: 3,
                },
            )
            .unwrap();
            verify_replay_manifest(&plan, &tree, &manifest).unwrap();
            joined.extend(manifest.mutant_ids);
        }
        assert_eq!(joined, all);
    }
    #[test]
    fn source_drift_overlaps_and_duplicates_fail_closed() {
        let tree = tree();
        let plan = plan(&tree);
        let mut drift = tree.clone();
        drift.files[0].content_hex = hex::encode(b"changed");
        assert!(matches!(
            validate_plan(&plan, &drift),
            Err(MutationError::Drift(_))
        ));
        let overlap = make_plan(
            "plan.overlap".into(),
            &tree,
            vec!["claim.alpha".into()],
            budgets(),
            thresholds(),
            vec![MutantDefinition {
                label: "overlap".into(),
                claim_ids: vec!["claim.alpha".into()],
                relevant: true,
                operators: vec![
                    MutationOperator::ByteFlip {
                        path: "a.txt".into(),
                        offset: 0,
                        xor_mask: 1,
                    },
                    MutationOperator::ByteFlip {
                        path: "a.txt".into(),
                        offset: 0,
                        xor_mask: 2,
                    },
                ],
            }],
        )
        .unwrap();
        assert!(matches!(
            materialize_mutants(&overlap, &tree),
            Err(MutationError::Conflict(_))
        ));
        let duplicate = make_plan(
            "plan.duplicate".into(),
            &tree,
            vec!["claim.alpha".into()],
            budgets(),
            thresholds(),
            vec![
                MutantDefinition {
                    label: "one".into(),
                    claim_ids: vec!["claim.alpha".into()],
                    relevant: true,
                    operators: vec![MutationOperator::ByteFlip {
                        path: "a.txt".into(),
                        offset: 0,
                        xor_mask: 1,
                    }],
                },
                MutantDefinition {
                    label: "two".into(),
                    claim_ids: vec!["claim.alpha".into()],
                    relevant: true,
                    operators: vec![MutationOperator::ByteFlip {
                        path: "a.txt".into(),
                        offset: 0,
                        xor_mask: 1,
                    }],
                },
            ],
        )
        .unwrap();
        assert!(matches!(
            materialize_mutants(&duplicate, &tree),
            Err(MutationError::Duplicate { .. })
        ));
    }
    #[test]
    fn baseline_equivalent_and_release_rules_are_fail_closed() {
        let tree = tree();
        let plan = plan(&tree);
        let bad = BaselineValidation {
            verdict: BaselineVerdict::Fail,
            ..baseline(&plan, &tree)
        };
        assert!(matches!(
            build_report(
                &plan,
                &tree,
                bad,
                results(&plan, &tree, MutationOutcome::Kill)
            ),
            Err(MutationError::BaselineFailed)
        ));
        let report = build_report(
            &plan,
            &tree,
            baseline(&plan, &tree),
            results(&plan, &tree, MutationOutcome::Survive),
        )
        .unwrap();
        assert!(matches!(
            release_verdict(&plan, &tree, &report),
            Err(MutationError::ReleaseBlocked(_))
        ));
        let mut invalid = results(&plan, &tree, MutationOutcome::Invalid);
        invalid[0].equivalent_disposition = Some(EquivalentDisposition {
            reviewer_id: "reviewer.alpha".into(),
            justification_sha256: digest("justification"),
            independent_evidence_sha256: digest("independent"),
            summary: "Semantics are unchanged under independently retained analysis.".into(),
        });
        invalid[1].equivalent_disposition = Some(EquivalentDisposition {
            reviewer_id: "reviewer.beta".into(),
            justification_sha256: digest("justification2"),
            independent_evidence_sha256: digest("independent2"),
            summary: "Semantics are unchanged under independently retained analysis.".into(),
        });
        let equivalent = build_report(&plan, &tree, baseline(&plan, &tree), invalid).unwrap();
        assert!(release_verdict(&plan, &tree, &equivalent).unwrap().accepted);
        let mut misuse = results(&plan, &tree, MutationOutcome::Kill);
        misuse[0].equivalent_disposition = Some(EquivalentDisposition {
            reviewer_id: "reviewer.alpha".into(),
            justification_sha256: digest("same"),
            independent_evidence_sha256: digest("same"),
            summary: "bad".into(),
        });
        assert!(matches!(
            build_report(&plan, &tree, baseline(&plan, &tree), misuse),
            Err(MutationError::InvalidReport(_))
        ));
    }
    #[test]
    fn accounting_and_materialization_provenance_are_complete_and_tamper_evident() {
        let tree = tree();
        let plan = plan(&tree);
        let report = build_report(
            &plan,
            &tree,
            baseline(&plan, &tree),
            results(&plan, &tree, MutationOutcome::Kill),
        )
        .unwrap();
        assert_eq!(report.accounting.selected, 2);
        assert_eq!(report.accounting.executed, 2);
        assert_eq!(report.accounting.killed, 2);
        assert_eq!(report.accounting.survived, 0);
        assert_eq!(report.accounting.invalid, 0);
        assert_eq!(report.accounting.timed_out, 0);
        assert_eq!(report.accounting.errored, 0);
        assert_eq!(
            report.accounting.selected_mutant_ids,
            report.accounting.executed_mutant_ids
        );
        assert!(digest_ok(&report.materialized_campaign_sha256));
        assert!(release_verdict(&plan, &tree, &report).unwrap().accepted);

        let mut altered_accounting = report.clone();
        altered_accounting.accounting.executed = 1;
        assert!(matches!(
            verify_report(&plan, &tree, &altered_accounting),
            Err(MutationError::Drift(_))
        ));
        let mut altered_materialization = report;
        altered_materialization.materialized_campaign_sha256 = digest("other-materialization");
        assert!(matches!(
            verify_report(&plan, &tree, &altered_materialization),
            Err(MutationError::Drift(_))
        ));
    }
    #[test]
    fn resource_budget_and_strict_schema_fail_closed() {
        let tree = tree();
        let mut constrained = budgets();
        constrained.max_materialized_bytes = 1;
        let plan = make_plan(
            "plan.budget".into(),
            &tree,
            vec!["claim.alpha".into()],
            constrained,
            thresholds(),
            vec![MutantDefinition {
                label: "one".into(),
                claim_ids: vec!["claim.alpha".into()],
                relevant: true,
                operators: vec![MutationOperator::ByteFlip {
                    path: "a.txt".into(),
                    offset: 0,
                    xor_mask: 1,
                }],
            }],
        )
        .unwrap();
        assert!(matches!(
            materialize_mutants(&plan, &tree),
            Err(MutationError::BudgetExhausted(_))
        ));
        let value = serde_json::json!({"path":"x","contentHex":"00","byteLength":1,"sha256":digest("x"),"extra":true});
        assert!(serde_json::from_value::<SourceFile>(value).is_err());
    }
    #[test]
    fn external_ast_envelope_is_source_bound_and_materialized_without_a_backend() {
        let tree = tree();
        let external = make_plan(
            "plan.ast".into(),
            &tree,
            vec!["claim.alpha".into()],
            budgets(),
            thresholds(),
            vec![MutantDefinition {
                label: "ast".into(),
                claim_ids: vec!["claim.alpha".into()],
                relevant: true,
                operators: vec![MutationOperator::ExternalAst {
                    envelope: ExternalAstEnvelope {
                        mutator_id: "ast.mutator".into(),
                        source_tree_sha256: tree.tree_sha256.clone(),
                        path: "a.txt".into(),
                        range: ByteRange { start: 6, end: 10 },
                        replacement_hex: hex::encode(b"BETA"),
                        evidence_sha256: digest("ast-evidence"),
                    },
                }],
            }],
        )
        .unwrap();
        let materialized = materialize_mutants(&external, &tree).unwrap();
        assert_eq!(
            hex::decode(
                &materialized[0]
                    .files
                    .iter()
                    .find(|file| file.path == "a.txt")
                    .unwrap()
                    .content_hex
            )
            .unwrap(),
            b"alpha BETA"
        );
        let mut drift = external.clone();
        if let MutationOperator::ExternalAst { envelope } = &mut drift.mutants[0].operators[0] {
            envelope.source_tree_sha256 = digest("wrong");
        }
        assert!(matches!(
            validate_plan(&drift, &tree),
            Err(MutationError::InvalidPlan(_))
        ));
    }
}
