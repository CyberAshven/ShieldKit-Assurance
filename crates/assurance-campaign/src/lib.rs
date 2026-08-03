//! Protocol-neutral deterministic campaign coordination.
//!
//! This crate has no protocol adapters, random source, clock source, network
//! client, or backend implementation. External generators/evaluators supply
//! JSON values and measured durations; this coordinator domain-separates seeds,
//! fixes ordering, binds replay manifests, enforces reported budgets, and
//! rejects drift rather than repairing or silently deduplicating it.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CAMPAIGN_SCHEMA_V1: &str = "shieldkit-assurance-campaign-definition/v1";
pub const CASE_SCHEMA_V1: &str = "shieldkit-assurance-campaign-case/v1";
pub const REPLAY_SCHEMA_V1: &str = "shieldkit-assurance-campaign-replay/v1";
pub const RESULT_SCHEMA_V1: &str = "shieldkit-assurance-campaign-result/v1";
pub const SHRINK_SCHEMA_V1: &str = "shieldkit-assurance-campaign-shrink/v1";

const SEED_DOMAIN: &[u8] = b"shieldkit-assurance/campaign-seed/v1\0";
const CASE_DOMAIN: &[u8] = b"shieldkit-assurance/campaign-case/v1\0";
const DEFINITION_DOMAIN: &[u8] = b"shieldkit-assurance/campaign-definition/v1\0";
const REPLAY_DOMAIN: &[u8] = b"shieldkit-assurance/campaign-replay/v1\0";
const PAYLOAD_DOMAIN: &[u8] = b"shieldkit-assurance/campaign-payload/v1\0";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CampaignError {
    #[error("invalid campaign definition: {0}")]
    InvalidDefinition(String),
    #[error("invalid case envelope: {0}")]
    InvalidCase(String),
    #[error("invalid replay manifest: {0}")]
    InvalidReplay(String),
    #[error("invalid campaign result: {0}")]
    InvalidResult(String),
    #[error("canonical JSON encoding failed: {0}")]
    Canonical(String),
    #[error("duplicate {kind}: {value}")]
    Duplicate { kind: &'static str, value: String },
    #[error("drift detected: {0}")]
    Drift(String),
    #[error("budget exhausted: {0}")]
    BudgetExhausted(String),
    #[error("reported timeout: {0}")]
    Timeout(String),
    #[error("external generator failed: {0}")]
    Generator(String),
    #[error("external evaluator failed: {0}")]
    Evaluator(String),
    #[error("flaky predicate for payload {0}")]
    FlakyPredicate(String),
    #[error("the supplied failing case does not fail")]
    InitialCaseNotFailing,
}

pub type Result<T> = std::result::Result<T, CampaignError>;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CampaignDefinition {
    pub schema_version: String,
    pub campaign_id: String,
    pub namespace: String,
    /// A caller-supplied, recorded 32-byte seed. It is never generated here.
    pub master_seed_sha256: String,
    pub schedule: ScheduleDefinition,
    pub budgets: CampaignBudgets,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScheduleDefinition {
    #[serde(default)]
    pub boundary_cases: Vec<BoundaryCase>,
    pub seeded_case_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BoundaryCase {
    pub label: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CampaignBudgets {
    pub max_cases: u64,
    pub max_evaluation_attempts: u64,
    pub max_shrink_evaluations: u64,
    pub max_case_bytes: u64,
    pub case_timeout_ms: u64,
    pub campaign_timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseOrigin {
    Boundary,
    Seeded,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CaseEnvelope {
    pub schema_version: String,
    pub campaign_id: String,
    pub origin: CaseOrigin,
    /// Ordinal within its origin class, not a mutable execution index.
    pub ordinal: u64,
    pub seed_sha256: String,
    pub payload: Value,
    pub payload_sha256: String,
    pub encoded_size: u64,
    pub case_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SeededCaseRequest {
    pub campaign_id: String,
    pub ordinal: u64,
    pub seed_sha256: String,
}

/// External generators implement protocol semantics; this crate only fixes the
/// request sequence and verifies the resulting envelope binding.
pub trait SeededCaseGenerator {
    fn generate(&self, request: &SeededCaseRequest) -> Result<Value>;
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReplayManifest {
    pub schema_version: String,
    pub campaign_id: String,
    pub definition_sha256: String,
    pub cases: Vec<CaseEnvelope>,
    pub replay_sha256: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseVerdict {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CaseEvaluation {
    pub verdict: CaseVerdict,
    /// Measured by the external evaluator. The coordinator checks it but never
    /// fabricates a duration or claims a wall-clock timeout it did not enforce.
    pub elapsed_ms: u64,
    pub observation_sha256: String,
}

pub trait CaseEvaluator {
    fn evaluate(&self, case: &CaseEnvelope) -> Result<CaseEvaluation>;
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CaseResult {
    pub schema_version: String,
    pub case_id: String,
    pub verdict: CaseVerdict,
    pub elapsed_ms: u64,
    pub observation_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CampaignResult {
    pub schema_version: String,
    pub campaign_id: String,
    pub definition_sha256: String,
    pub replay_sha256: String,
    pub attempted_cases: u64,
    pub total_elapsed_ms: u64,
    pub cases: Vec<CaseResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ValidShrinkCandidate {
    pub payload: Value,
    /// SHA-256 of caller-defined validation evidence. This binds the external
    /// validity-preservation assertion; it does not falsely turn it into a
    /// protocol-neutral proof.
    pub validity_witness_sha256: String,
}

pub trait ValidityPreservingShrinkGenerator {
    fn candidates(&self, current: &Value) -> Result<Vec<ValidShrinkCandidate>>;
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PredicateEvaluation {
    pub fails: bool,
    pub elapsed_ms: u64,
}

pub trait FailingPredicate {
    fn evaluate(&self, payload: &Value) -> Result<PredicateEvaluation>;
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShrinkResult {
    pub schema_version: String,
    pub original_case_id: String,
    pub minimal_payload: Value,
    pub minimal_payload_sha256: String,
    pub minimal_encoded_size: u64,
    pub validity_witness_sha256: Option<String>,
    pub predicate_evaluations: u64,
    pub total_elapsed_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DefinitionIdentity<'a> {
    schema_version: &'a str,
    campaign_id: &'a str,
    namespace: &'a str,
    master_seed_sha256: &'a str,
    schedule: &'a ScheduleDefinition,
    budgets: &'a CampaignBudgets,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CaseIdentity<'a> {
    schema_version: &'a str,
    campaign_id: &'a str,
    origin: CaseOrigin,
    ordinal: u64,
    seed_sha256: &'a str,
    payload: &'a Value,
    payload_sha256: &'a str,
    encoded_size: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayIdentity<'a> {
    schema_version: &'a str,
    campaign_id: &'a str,
    definition_sha256: &'a str,
    cases: &'a [CaseEnvelope],
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|error| CampaignError::Canonical(error.to_string()))
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    format!("sha256:{}", hex::encode(digest.finalize()))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}

fn payload_details(payload: &Value) -> Result<(String, u64)> {
    let encoded = canonical_bytes(payload)?;
    Ok((hash_domain(PAYLOAD_DOMAIN, &encoded), encoded.len() as u64))
}

pub fn definition_sha256(definition: &CampaignDefinition) -> Result<String> {
    validate_definition(definition)?;
    let identity = DefinitionIdentity {
        schema_version: &definition.schema_version,
        campaign_id: &definition.campaign_id,
        namespace: &definition.namespace,
        master_seed_sha256: &definition.master_seed_sha256,
        schedule: &definition.schedule,
        budgets: &definition.budgets,
    };
    Ok(hash_domain(DEFINITION_DOMAIN, &canonical_bytes(&identity)?))
}

pub fn derive_seed(
    definition: &CampaignDefinition,
    origin: CaseOrigin,
    ordinal: u64,
) -> Result<String> {
    let definition_hash = definition_sha256(definition)?;
    let origin_label = match origin {
        CaseOrigin::Boundary => "boundary",
        CaseOrigin::Seeded => "seeded",
    };
    let identity = serde_json::json!({
        "campaignId": definition.campaign_id,
        "definitionSha256": definition_hash,
        "masterSeedSha256": definition.master_seed_sha256,
        "origin": origin_label,
        "ordinal": ordinal,
    });
    Ok(hash_domain(SEED_DOMAIN, &canonical_bytes(&identity)?))
}

pub fn validate_definition(definition: &CampaignDefinition) -> Result<()> {
    if definition.schema_version != CAMPAIGN_SCHEMA_V1 {
        return Err(CampaignError::InvalidDefinition(
            "unsupported schemaVersion".into(),
        ));
    }
    if !is_identifier(&definition.campaign_id) || !is_identifier(&definition.namespace) {
        return Err(CampaignError::InvalidDefinition(
            "campaignId and namespace must be stable identifiers".into(),
        ));
    }
    if !is_sha256(&definition.master_seed_sha256) {
        return Err(CampaignError::InvalidDefinition(
            "masterSeedSha256 must be lowercase sha256".into(),
        ));
    }
    let budgets = &definition.budgets;
    if budgets.max_cases == 0
        || budgets.max_evaluation_attempts == 0
        || budgets.max_shrink_evaluations == 0
        || budgets.max_case_bytes == 0
        || budgets.case_timeout_ms == 0
        || budgets.campaign_timeout_ms == 0
    {
        return Err(CampaignError::InvalidDefinition(
            "all budgets must be nonzero".into(),
        ));
    }
    let scheduled = (definition.schedule.boundary_cases.len() as u64)
        .checked_add(definition.schedule.seeded_case_count)
        .ok_or_else(|| CampaignError::InvalidDefinition("scheduled case count overflow".into()))?;
    if scheduled == 0 {
        return Err(CampaignError::InvalidDefinition(
            "schedule must contain at least one case".into(),
        ));
    }
    if scheduled > budgets.max_cases {
        return Err(CampaignError::InvalidDefinition(
            "schedule exceeds maxCases".into(),
        ));
    }
    if scheduled > budgets.max_evaluation_attempts {
        return Err(CampaignError::InvalidDefinition(
            "schedule exceeds maxEvaluationAttempts".into(),
        ));
    }
    let mut labels = BTreeSet::new();
    let mut payloads = BTreeSet::new();
    for boundary in &definition.schedule.boundary_cases {
        if !is_identifier(&boundary.label) {
            return Err(CampaignError::InvalidDefinition(
                "boundary label must be a stable identifier".into(),
            ));
        }
        if !labels.insert(boundary.label.clone()) {
            return Err(CampaignError::Duplicate {
                kind: "boundary label",
                value: boundary.label.clone(),
            });
        }
        let (payload_hash, encoded_size) = payload_details(&boundary.payload)?;
        if encoded_size > budgets.max_case_bytes {
            return Err(CampaignError::InvalidDefinition(
                "boundary payload exceeds maxCaseBytes".into(),
            ));
        }
        if !payloads.insert(payload_hash.clone()) {
            return Err(CampaignError::Duplicate {
                kind: "boundary payload",
                value: payload_hash,
            });
        }
    }
    Ok(())
}

fn make_case(
    definition: &CampaignDefinition,
    origin: CaseOrigin,
    ordinal: u64,
    payload: Value,
) -> Result<CaseEnvelope> {
    let seed_sha256 = derive_seed(definition, origin, ordinal)?;
    let (payload_sha256, encoded_size) = payload_details(&payload)?;
    if encoded_size > definition.budgets.max_case_bytes {
        return Err(CampaignError::BudgetExhausted(format!(
            "case payload {} exceeds maxCaseBytes",
            payload_sha256
        )));
    }
    let identity = CaseIdentity {
        schema_version: CASE_SCHEMA_V1,
        campaign_id: &definition.campaign_id,
        origin,
        ordinal,
        seed_sha256: &seed_sha256,
        payload: &payload,
        payload_sha256: &payload_sha256,
        encoded_size,
    };
    let case_id = hash_domain(CASE_DOMAIN, &canonical_bytes(&identity)?);
    Ok(CaseEnvelope {
        schema_version: CASE_SCHEMA_V1.into(),
        campaign_id: definition.campaign_id.clone(),
        origin,
        ordinal,
        seed_sha256,
        payload,
        payload_sha256,
        encoded_size,
        case_id,
    })
}

pub fn build_schedule<G: SeededCaseGenerator>(
    definition: &CampaignDefinition,
    generator: &G,
) -> Result<Vec<CaseEnvelope>> {
    validate_definition(definition)?;
    // Do not preallocate caller-controlled capacity: a valid but intentionally
    // large declared budget must not turn schedule validation into an immediate
    // allocation attempt. The explicit maxCases contract remains the bound.
    let mut cases = Vec::new();
    for (ordinal, boundary) in definition.schedule.boundary_cases.iter().enumerate() {
        cases.push(make_case(
            definition,
            CaseOrigin::Boundary,
            ordinal as u64,
            boundary.payload.clone(),
        )?);
    }
    for ordinal in 0..definition.schedule.seeded_case_count {
        let request = SeededCaseRequest {
            campaign_id: definition.campaign_id.clone(),
            ordinal,
            seed_sha256: derive_seed(definition, CaseOrigin::Seeded, ordinal)?,
        };
        cases.push(make_case(
            definition,
            CaseOrigin::Seeded,
            ordinal,
            generator.generate(&request)?,
        )?);
    }
    validate_schedule(definition, &cases)?;
    Ok(cases)
}

pub fn validate_case(definition: &CampaignDefinition, case: &CaseEnvelope) -> Result<()> {
    validate_definition(definition)?;
    if case.schema_version != CASE_SCHEMA_V1 || case.campaign_id != definition.campaign_id {
        return Err(CampaignError::InvalidCase(
            "schemaVersion or campaignId differs".into(),
        ));
    }
    let expected = make_case(definition, case.origin, case.ordinal, case.payload.clone())?;
    if expected.seed_sha256 != case.seed_sha256
        || expected.payload_sha256 != case.payload_sha256
        || expected.encoded_size != case.encoded_size
        || expected.case_id != case.case_id
    {
        return Err(CampaignError::Drift(format!(
            "case envelope differs from canonical binding: {}",
            case.case_id
        )));
    }
    Ok(())
}

pub fn validate_schedule(definition: &CampaignDefinition, cases: &[CaseEnvelope]) -> Result<()> {
    validate_definition(definition)?;
    let expected_len = (definition.schedule.boundary_cases.len() as u64)
        .checked_add(definition.schedule.seeded_case_count)
        .ok_or_else(|| CampaignError::InvalidDefinition("scheduled case count overflow".into()))?;
    if cases.len() as u64 != expected_len {
        return Err(CampaignError::Drift(format!(
            "schedule length differs: expected {expected_len}, got {}",
            cases.len()
        )));
    }
    let mut case_ids = BTreeSet::new();
    let mut payloads = BTreeSet::new();
    for (index, case) in cases.iter().enumerate() {
        validate_case(definition, case)?;
        let expected_origin = if index < definition.schedule.boundary_cases.len() {
            CaseOrigin::Boundary
        } else {
            CaseOrigin::Seeded
        };
        let expected_ordinal = if expected_origin == CaseOrigin::Boundary {
            index as u64
        } else {
            (index - definition.schedule.boundary_cases.len()) as u64
        };
        if case.origin != expected_origin || case.ordinal != expected_ordinal {
            return Err(CampaignError::Drift(format!(
                "schedule order differs at index {index}"
            )));
        }
        if case.origin == CaseOrigin::Boundary
            && case.payload != definition.schedule.boundary_cases[case.ordinal as usize].payload
        {
            return Err(CampaignError::Drift(format!(
                "boundary payload differs at ordinal {}",
                case.ordinal
            )));
        }
        if !case_ids.insert(case.case_id.clone()) {
            return Err(CampaignError::Duplicate {
                kind: "case ID",
                value: case.case_id.clone(),
            });
        }
        if !payloads.insert(case.payload_sha256.clone()) {
            return Err(CampaignError::Duplicate {
                kind: "case payload",
                value: case.payload_sha256.clone(),
            });
        }
    }
    Ok(())
}

pub fn build_replay_manifest(
    definition: &CampaignDefinition,
    cases: &[CaseEnvelope],
) -> Result<ReplayManifest> {
    validate_schedule(definition, cases)?;
    let definition_sha256 = definition_sha256(definition)?;
    let identity = ReplayIdentity {
        schema_version: REPLAY_SCHEMA_V1,
        campaign_id: &definition.campaign_id,
        definition_sha256: &definition_sha256,
        cases,
    };
    let replay_sha256 = hash_domain(REPLAY_DOMAIN, &canonical_bytes(&identity)?);
    Ok(ReplayManifest {
        schema_version: REPLAY_SCHEMA_V1.into(),
        campaign_id: definition.campaign_id.clone(),
        definition_sha256,
        cases: cases.to_vec(),
        replay_sha256,
    })
}

pub fn verify_replay_manifest(
    definition: &CampaignDefinition,
    manifest: &ReplayManifest,
) -> Result<()> {
    if manifest.schema_version != REPLAY_SCHEMA_V1 || manifest.campaign_id != definition.campaign_id
    {
        return Err(CampaignError::InvalidReplay(
            "schemaVersion or campaignId differs".into(),
        ));
    }
    if manifest.definition_sha256 != definition_sha256(definition)? {
        return Err(CampaignError::Drift("definition hash differs".into()));
    }
    validate_schedule(definition, &manifest.cases)?;
    let identity = ReplayIdentity {
        schema_version: REPLAY_SCHEMA_V1,
        campaign_id: &manifest.campaign_id,
        definition_sha256: &manifest.definition_sha256,
        cases: &manifest.cases,
    };
    if hash_domain(REPLAY_DOMAIN, &canonical_bytes(&identity)?) != manifest.replay_sha256 {
        return Err(CampaignError::Drift("replay hash differs".into()));
    }
    Ok(())
}

pub fn run_campaign<E: CaseEvaluator>(
    definition: &CampaignDefinition,
    manifest: &ReplayManifest,
    evaluator: &E,
) -> Result<CampaignResult> {
    verify_replay_manifest(definition, manifest)?;
    let mut total_elapsed_ms = 0_u64;
    let mut results = Vec::with_capacity(manifest.cases.len());
    for (index, case) in manifest.cases.iter().enumerate() {
        if index as u64 >= definition.budgets.max_evaluation_attempts {
            return Err(CampaignError::BudgetExhausted(
                "maxEvaluationAttempts reached".into(),
            ));
        }
        let evaluation = evaluator.evaluate(case)?;
        if !is_sha256(&evaluation.observation_sha256) {
            return Err(CampaignError::InvalidResult(
                "observationSha256 must be lowercase sha256".into(),
            ));
        }
        if evaluation.elapsed_ms > definition.budgets.case_timeout_ms {
            return Err(CampaignError::Timeout(format!(
                "case {} exceeded caseTimeoutMs",
                case.case_id
            )));
        }
        total_elapsed_ms = total_elapsed_ms
            .checked_add(evaluation.elapsed_ms)
            .ok_or_else(|| CampaignError::BudgetExhausted("elapsed time overflow".into()))?;
        if total_elapsed_ms > definition.budgets.campaign_timeout_ms {
            return Err(CampaignError::Timeout(
                "campaign exceeded campaignTimeoutMs".into(),
            ));
        }
        results.push(CaseResult {
            schema_version: RESULT_SCHEMA_V1.into(),
            case_id: case.case_id.clone(),
            verdict: evaluation.verdict,
            elapsed_ms: evaluation.elapsed_ms,
            observation_sha256: evaluation.observation_sha256,
        });
    }
    let result = CampaignResult {
        schema_version: RESULT_SCHEMA_V1.into(),
        campaign_id: definition.campaign_id.clone(),
        definition_sha256: definition_sha256(definition)?,
        replay_sha256: manifest.replay_sha256.clone(),
        attempted_cases: results.len() as u64,
        total_elapsed_ms,
        cases: results,
    };
    validate_campaign_result(definition, manifest, &result)?;
    Ok(result)
}

pub fn validate_campaign_result(
    definition: &CampaignDefinition,
    manifest: &ReplayManifest,
    result: &CampaignResult,
) -> Result<()> {
    verify_replay_manifest(definition, manifest)?;
    if result.schema_version != RESULT_SCHEMA_V1
        || result.campaign_id != definition.campaign_id
        || result.definition_sha256 != definition_sha256(definition)?
        || result.replay_sha256 != manifest.replay_sha256
    {
        return Err(CampaignError::InvalidResult(
            "identity binding differs".into(),
        ));
    }
    if result.attempted_cases != result.cases.len() as u64
        || result.cases.len() != manifest.cases.len()
    {
        return Err(CampaignError::InvalidResult("case count differs".into()));
    }
    let mut total = 0_u64;
    let mut ids = BTreeSet::new();
    for (case, observed) in manifest.cases.iter().zip(&result.cases) {
        if observed.schema_version != RESULT_SCHEMA_V1
            || observed.case_id != case.case_id
            || !is_sha256(&observed.observation_sha256)
        {
            return Err(CampaignError::InvalidResult(
                "case result binding differs".into(),
            ));
        }
        if observed.elapsed_ms > definition.budgets.case_timeout_ms {
            return Err(CampaignError::Timeout(
                "stored case result exceeds caseTimeoutMs".into(),
            ));
        }
        if !ids.insert(observed.case_id.clone()) {
            return Err(CampaignError::Duplicate {
                kind: "result case ID",
                value: observed.case_id.clone(),
            });
        }
        total = total
            .checked_add(observed.elapsed_ms)
            .ok_or_else(|| CampaignError::InvalidResult("elapsed time overflow".into()))?;
    }
    if total != result.total_elapsed_ms || total > definition.budgets.campaign_timeout_ms {
        return Err(CampaignError::InvalidResult(
            "total elapsed time differs or exceeds campaignTimeoutMs".into(),
        ));
    }
    Ok(())
}

fn compare_payload_key(left: &(Value, String, u64), right: &(Value, String, u64)) -> Ordering {
    left.2.cmp(&right.2).then_with(|| left.1.cmp(&right.1))
}

fn stable_predicate<P: FailingPredicate>(
    definition: &CampaignDefinition,
    payload: &Value,
    predicate: &P,
    evaluations: &mut u64,
    total_elapsed_ms: &mut u64,
) -> Result<bool> {
    if definition
        .budgets
        .max_shrink_evaluations
        .saturating_sub(*evaluations)
        < 2
    {
        return Err(CampaignError::BudgetExhausted(
            "maxShrinkEvaluations reached".into(),
        ));
    }
    let first = predicate.evaluate(payload)?;
    let second = predicate.evaluate(payload)?;
    *evaluations += 2;
    for elapsed in [first.elapsed_ms, second.elapsed_ms] {
        if elapsed > definition.budgets.case_timeout_ms {
            return Err(CampaignError::Timeout(
                "shrink predicate exceeded caseTimeoutMs".into(),
            ));
        }
        *total_elapsed_ms = total_elapsed_ms
            .checked_add(elapsed)
            .ok_or_else(|| CampaignError::BudgetExhausted("shrink elapsed overflow".into()))?;
        if *total_elapsed_ms > definition.budgets.campaign_timeout_ms {
            return Err(CampaignError::Timeout(
                "shrink predicate exceeded campaignTimeoutMs".into(),
            ));
        }
    }
    if first.fails != second.fails {
        return Err(CampaignError::FlakyPredicate(payload_details(payload)?.0));
    }
    Ok(first.fails)
}

pub fn shrink_failure<G: ValidityPreservingShrinkGenerator, P: FailingPredicate>(
    definition: &CampaignDefinition,
    failing_case: &CaseEnvelope,
    generator: &G,
    predicate: &P,
) -> Result<ShrinkResult> {
    validate_case(definition, failing_case)?;
    let mut evaluations = 0_u64;
    let mut total_elapsed_ms = 0_u64;
    if !stable_predicate(
        definition,
        &failing_case.payload,
        predicate,
        &mut evaluations,
        &mut total_elapsed_ms,
    )? {
        return Err(CampaignError::InitialCaseNotFailing);
    }
    let (root_hash, root_size) = payload_details(&failing_case.payload)?;
    let mut seen = BTreeSet::from([root_hash.clone()]);
    let mut pending = vec![(
        failing_case.payload.clone(),
        None::<String>,
        root_hash.clone(),
        root_size,
    )];
    let mut failures = pending.clone();
    let mut next = 0_usize;
    while next < pending.len() {
        let (current, _, _, _) = pending[next].clone();
        next += 1;
        let mut candidates = generator.candidates(&current)?;
        let mut normalized = Vec::with_capacity(candidates.len());
        for candidate in candidates.drain(..) {
            if !is_sha256(&candidate.validity_witness_sha256) {
                return Err(CampaignError::InvalidCase(
                    "shrink validityWitnessSha256 must be lowercase sha256".into(),
                ));
            }
            let (payload_hash, encoded_size) = payload_details(&candidate.payload)?;
            if encoded_size > definition.budgets.max_case_bytes {
                return Err(CampaignError::BudgetExhausted(format!(
                    "shrink payload {payload_hash} exceeds maxCaseBytes"
                )));
            }
            normalized.push((
                candidate.payload,
                candidate.validity_witness_sha256,
                payload_hash,
                encoded_size,
            ));
        }
        normalized.sort_by(|left, right| {
            compare_payload_key(
                &(left.0.clone(), left.2.clone(), left.3),
                &(right.0.clone(), right.2.clone(), right.3),
            )
        });
        for (payload, witness, payload_hash, encoded_size) in normalized {
            if !seen.insert(payload_hash.clone()) {
                return Err(CampaignError::Duplicate {
                    kind: "shrink payload",
                    value: payload_hash,
                });
            }
            if stable_predicate(
                definition,
                &payload,
                predicate,
                &mut evaluations,
                &mut total_elapsed_ms,
            )? {
                let entry = (payload, Some(witness), payload_hash, encoded_size);
                failures.push(entry.clone());
                pending.push(entry);
            }
        }
    }
    failures.sort_by(|left, right| {
        compare_payload_key(
            &(left.0.clone(), left.2.clone(), left.3),
            &(right.0.clone(), right.2.clone(), right.3),
        )
    });
    let (minimal_payload, validity_witness_sha256, minimal_payload_sha256, minimal_encoded_size) =
        failures.into_iter().next().expect("root failure exists");
    Ok(ShrinkResult {
        schema_version: SHRINK_SCHEMA_V1.into(),
        original_case_id: failing_case.case_id.clone(),
        minimal_payload,
        minimal_payload_sha256,
        minimal_encoded_size,
        validity_witness_sha256,
        predicate_evaluations: evaluations,
        total_elapsed_ms,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeMap;

    use super::*;

    fn digest(label: &str) -> String {
        hash_domain(b"test-digest\0", label.as_bytes())
    }
    fn definition() -> CampaignDefinition {
        CampaignDefinition {
            schema_version: CAMPAIGN_SCHEMA_V1.into(),
            campaign_id: "campaign.alpha".into(),
            namespace: "protocol-neutral".into(),
            master_seed_sha256: digest("master"),
            schedule: ScheduleDefinition {
                boundary_cases: vec![
                    BoundaryCase {
                        label: "zero".into(),
                        payload: serde_json::json!({"n": 0}),
                    },
                    BoundaryCase {
                        label: "one".into(),
                        payload: serde_json::json!({"n": 1}),
                    },
                ],
                seeded_case_count: 3,
            },
            budgets: CampaignBudgets {
                max_cases: 8,
                max_evaluation_attempts: 8,
                max_shrink_evaluations: 64,
                max_case_bytes: 1024,
                case_timeout_ms: 10,
                campaign_timeout_ms: 100,
            },
        }
    }

    struct Generator;
    impl SeededCaseGenerator for Generator {
        fn generate(&self, request: &SeededCaseRequest) -> Result<Value> {
            Ok(serde_json::json!({"ordinal": request.ordinal, "seed": request.seed_sha256}))
        }
    }
    struct Evaluator;
    impl CaseEvaluator for Evaluator {
        fn evaluate(&self, case: &CaseEnvelope) -> Result<CaseEvaluation> {
            Ok(CaseEvaluation {
                verdict: if case.ordinal == 1 {
                    CaseVerdict::Fail
                } else {
                    CaseVerdict::Pass
                },
                elapsed_ms: 2,
                observation_sha256: digest(&case.case_id),
            })
        }
    }

    #[test]
    fn deterministic_schedule_replay_and_result_are_bound_and_reproducible() {
        let def = definition();
        let first = build_schedule(&def, &Generator).unwrap();
        let second = build_schedule(&def, &Generator).unwrap();
        assert_eq!(first, second);
        let manifest = build_replay_manifest(&def, &first).unwrap();
        verify_replay_manifest(&def, &manifest).unwrap();
        let result = run_campaign(&def, &manifest, &Evaluator).unwrap();
        assert_eq!(result.attempted_cases, 5);
        assert_eq!(result.total_elapsed_ms, 10);
        assert!(
            result
                .cases
                .iter()
                .any(|case| case.verdict == CaseVerdict::Fail)
        );
        validate_campaign_result(&def, &manifest, &result).unwrap();
    }

    #[test]
    fn replay_and_duplicate_drift_are_rejected() {
        let def = definition();
        let cases = build_schedule(&def, &Generator).unwrap();
        let mut manifest = build_replay_manifest(&def, &cases).unwrap();
        manifest.cases[0].payload = serde_json::json!({"n": 9});
        assert!(matches!(
            verify_replay_manifest(&def, &manifest),
            Err(CampaignError::Drift(_))
        ));
        let mut duplicate = definition();
        duplicate.schedule.boundary_cases.push(BoundaryCase {
            label: "other".into(),
            payload: serde_json::json!({"n": 0}),
        });
        assert!(matches!(
            validate_definition(&duplicate),
            Err(CampaignError::Duplicate { .. })
        ));
    }

    #[test]
    fn evaluation_budget_and_reported_timeout_fail_closed() {
        let mut def = definition();
        def.budgets.max_evaluation_attempts = 2;
        assert!(matches!(
            validate_definition(&def),
            Err(CampaignError::InvalidDefinition(_))
        ));
        let mut empty = definition();
        empty.schedule.boundary_cases.clear();
        empty.schedule.seeded_case_count = 0;
        assert!(matches!(
            validate_definition(&empty),
            Err(CampaignError::InvalidDefinition(_))
        ));
        struct Slow;
        impl CaseEvaluator for Slow {
            fn evaluate(&self, _: &CaseEnvelope) -> Result<CaseEvaluation> {
                Ok(CaseEvaluation {
                    verdict: CaseVerdict::Pass,
                    elapsed_ms: 11,
                    observation_sha256: digest("slow"),
                })
            }
        }
        let def = definition();
        let manifest =
            build_replay_manifest(&def, &build_schedule(&def, &Generator).unwrap()).unwrap();
        assert!(matches!(
            run_campaign(&def, &manifest, &Slow),
            Err(CampaignError::Timeout(_))
        ));
    }

    struct Shrinker {
        graph: BTreeMap<String, Vec<Value>>,
    }
    impl ValidityPreservingShrinkGenerator for Shrinker {
        fn candidates(&self, current: &Value) -> Result<Vec<ValidShrinkCandidate>> {
            let key = canonical_bytes(current)?;
            Ok(self
                .graph
                .get(&String::from_utf8(key).unwrap())
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|payload| ValidShrinkCandidate {
                    validity_witness_sha256: digest("valid"),
                    payload,
                })
                .collect())
        }
    }
    struct StablePredicate;
    impl FailingPredicate for StablePredicate {
        fn evaluate(&self, payload: &Value) -> Result<PredicateEvaluation> {
            Ok(PredicateEvaluation {
                fails: payload
                    .get("fail")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                elapsed_ms: 1,
            })
        }
    }

    #[test]
    fn shrinker_explores_valid_candidates_and_selects_global_size_then_hash_minimum() {
        let def = definition();
        let case = make_case(
            &def,
            CaseOrigin::Boundary,
            0,
            serde_json::json!({"fail": true, "long": "xxxxxxxx"}),
        )
        .unwrap();
        let root = String::from_utf8(canonical_bytes(&case.payload).unwrap()).unwrap();
        let left = serde_json::json!({"fail": true, "x": 1});
        let right = serde_json::json!({"fail": true, "x": 2});
        let graph = BTreeMap::from([(root, vec![right.clone(), left.clone()])]);
        let result = shrink_failure(&def, &case, &Shrinker { graph }, &StablePredicate).unwrap();
        let (_, left_size) = payload_details(&left).unwrap();
        let (_, right_size) = payload_details(&right).unwrap();
        let expected = if left_size < right_size
            || (left_size == right_size
                && payload_details(&left).unwrap().0 < payload_details(&right).unwrap().0)
        {
            left
        } else {
            right
        };
        assert_eq!(result.minimal_payload, expected);
        assert_eq!(result.predicate_evaluations, 6);
        assert_eq!(result.validity_witness_sha256, Some(digest("valid")));
    }

    #[test]
    fn shrinker_rejects_flaky_predicates_duplicate_candidates_and_budget_exhaustion() {
        let def = definition();
        let case = make_case(
            &def,
            CaseOrigin::Boundary,
            0,
            serde_json::json!({"fail": true}),
        )
        .unwrap();
        struct Flaky(Cell<bool>);
        impl FailingPredicate for Flaky {
            fn evaluate(&self, _: &Value) -> Result<PredicateEvaluation> {
                let value = self.0.get();
                self.0.set(!value);
                Ok(PredicateEvaluation {
                    fails: value,
                    elapsed_ms: 1,
                })
            }
        }
        assert!(matches!(
            shrink_failure(
                &def,
                &case,
                &Shrinker {
                    graph: BTreeMap::new()
                },
                &Flaky(Cell::new(true))
            ),
            Err(CampaignError::FlakyPredicate(_))
        ));
        let root = String::from_utf8(canonical_bytes(&case.payload).unwrap()).unwrap();
        let duplicate_graph = BTreeMap::from([(
            root,
            vec![
                serde_json::json!({"fail": true, "x": 1}),
                serde_json::json!({"fail": true, "x": 1}),
            ],
        )]);
        assert!(matches!(
            shrink_failure(
                &def,
                &case,
                &Shrinker {
                    graph: duplicate_graph
                },
                &StablePredicate
            ),
            Err(CampaignError::Duplicate { .. })
        ));
        let mut limited = definition();
        limited.budgets.max_shrink_evaluations = 1;
        let limited_case = make_case(
            &limited,
            CaseOrigin::Boundary,
            0,
            serde_json::json!({"fail": true}),
        )
        .unwrap();
        assert!(matches!(
            shrink_failure(
                &limited,
                &limited_case,
                &Shrinker {
                    graph: BTreeMap::new()
                },
                &StablePredicate
            ),
            Err(CampaignError::BudgetExhausted(_))
        ));
    }

    #[test]
    fn property_seed_derivation_is_deterministic_and_domain_separated_without_os_entropy() {
        for ordinal in 0..128_u64 {
            let def = definition();
            let first = derive_seed(&def, CaseOrigin::Seeded, ordinal).unwrap();
            let second = derive_seed(&def, CaseOrigin::Seeded, ordinal).unwrap();
            let boundary = derive_seed(&def, CaseOrigin::Boundary, ordinal).unwrap();
            assert_eq!(first, second);
            assert_ne!(first, boundary);
            if ordinal > 0 {
                assert_ne!(
                    first,
                    derive_seed(&def, CaseOrigin::Seeded, ordinal - 1).unwrap()
                );
            }
        }
    }

    #[test]
    fn strict_serde_rejects_unknown_schema_fields() {
        let value = serde_json::json!({
            "schemaVersion": CAMPAIGN_SCHEMA_V1, "campaignId": "campaign.alpha", "namespace": "protocol-neutral", "masterSeedSha256": digest("master"),
            "schedule": {"boundaryCases": [], "seededCaseCount": 0},
            "budgets": {"maxCases": 1, "maxEvaluationAttempts": 1, "maxShrinkEvaluations": 1, "maxCaseBytes": 1, "caseTimeoutMs": 1, "campaignTimeoutMs": 1},
            "unexpected": true
        });
        assert!(serde_json::from_value::<CampaignDefinition>(value).is_err());
    }
}
