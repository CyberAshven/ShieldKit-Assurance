//! Deterministic, offline claim-to-evidence reporting.
//!
//! Rendering never executes an adapter or interprets a command as evidence.
//! The only input is a strict, caller-supplied status document. Qualification
//! is fail-closed: missing, unknown, forbidden, skipped, waived, local, beta,
//! historical, and synthetic material cannot support a qualified claim.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const REPORT_INPUT_SCHEMA_V1: &str = "shieldkit-assurance-report-input/v1";
pub const REPORT_SCHEMA_V1: &str = "shieldkit-assurance-report/v1";
pub const SARIF_SCHEMA_V2_1_0: &str = "https://json.schemastore.org/sarif-2.1.0.json";

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReportInput {
    pub schema_version: String,
    pub report_id: String,
    pub subject: SubjectStatus,
    pub setup_trust: SetupTrustStatus,
    #[serde(default)]
    pub source_links: Vec<SourceReference>,
    pub claims: Vec<ClaimStatus>,
    pub obligations: Vec<ObligationStatus>,
    pub cases: Vec<CaseStatusRecord>,
    pub evidence: Vec<EvidenceStatusRecord>,
    pub provenance: Vec<ProvenanceStatusRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubjectStatus {
    pub repository: String,
    pub revision: String,
    pub tree: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SetupTrustStatus {
    pub status: SetupTrustDisposition,
    pub profile: SetupTrustProfile,
    pub participant_independence_established: bool,
    pub statement: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SetupTrustDisposition {
    Disclosed,
    Missing,
    Unknown,
    Forbidden,
    Skipped,
    Waived,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SetupTrustProfile {
    SingleContributor,
    MultiParty,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceReference {
    pub source_id: String,
    pub label: String,
    /// Deliberately rendered as escaped text, never as an HTML link.
    pub reference: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClaimStatus {
    pub claim_id: String,
    pub statement: String,
    pub obligation_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObligationStatus {
    pub obligation_id: String,
    pub claim_id: String,
    pub mandatory: bool,
    pub case_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub provenance_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CaseStatusRecord {
    pub case_id: String,
    pub status: CaseDisposition,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseDisposition {
    Pass,
    Fail,
    Missing,
    Unknown,
    Forbidden,
    Skipped,
    Waived,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceStatusRecord {
    pub evidence_id: String,
    pub status: EvidenceDisposition,
    pub class: EvidenceClass,
    pub source_link_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDisposition {
    Verified,
    Missing,
    Unknown,
    Forbidden,
    Skipped,
    Waived,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    Final,
    Historical,
    Beta,
    Synthetic,
    Local,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProvenanceStatusRecord {
    pub provenance_id: String,
    pub status: ProvenanceDisposition,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceDisposition {
    Verified,
    Missing,
    Unknown,
    Forbidden,
    Skipped,
    Waived,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum QualificationVerdict {
    Qualified,
    Nonqualified,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RenderedReport {
    pub json: Vec<u8>,
    pub html: Vec<u8>,
    pub junit_xml: Vec<u8>,
    pub sarif: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReportDocument {
    pub schema_version: String,
    pub report_id: String,
    pub subject: SubjectStatus,
    pub overall_verdict: QualificationVerdict,
    pub setup_trust: RenderedSetupTrust,
    pub source_links: Vec<SourceReference>,
    pub claims: Vec<RenderedClaim>,
    pub obligations: Vec<RenderedObligation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RenderedSetupTrust {
    pub disposition: SetupTrustDisposition,
    pub profile: SetupTrustProfile,
    pub participant_independence_established: bool,
    pub statement: String,
    pub qualification_effect: QualificationVerdict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RenderedClaim {
    pub claim_id: String,
    pub statement: String,
    pub verdict: QualificationVerdict,
    pub obligation_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RenderedObligation {
    pub obligation_id: String,
    pub claim_id: String,
    pub mandatory: bool,
    pub verdict: QualificationVerdict,
    pub reasons: Vec<String>,
    pub case_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub provenance_ids: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("unsupported report schema: {0}")]
    UnsupportedSchema(String),
    #[error("invalid {kind} identifier: {id}")]
    InvalidId { kind: &'static str, id: String },
    #[error("duplicate {kind} identifier: {id}")]
    DuplicateId { kind: &'static str, id: String },
    #[error("duplicate {kind} reference from {owner}: {id}")]
    DuplicateReference {
        kind: &'static str,
        owner: String,
        id: String,
    },
    #[error("missing {kind} reference from {owner}: {id}")]
    MissingReference {
        kind: &'static str,
        owner: String,
        id: String,
    },
    #[error("claim/obligation mapping is not reciprocal: {claim_id} <-> {obligation_id}")]
    NonReciprocalMapping {
        claim_id: String,
        obligation_id: String,
    },
    #[error("invalid SHA-256 identifier: {0}")]
    InvalidSha256(String),
    #[error("unsafe output path: {0}")]
    UnsafeOutputPath(PathBuf),
    #[error("output path already exists: {0}")]
    OutputExists(PathBuf),
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("canonical JSON failure: {0}")]
    Canonical(String),
}

/// Validate, sort, and derive the canonical report model. No adapter is run.
pub fn derive_report(input: &ReportInput) -> Result<ReportDocument, ReportError> {
    validate_input(input)?;

    let mut sources = input.source_links.clone();
    sources.sort_by(|left, right| left.source_id.cmp(&right.source_id));
    let cases: BTreeMap<_, _> = input
        .cases
        .iter()
        .map(|value| (value.case_id.as_str(), value))
        .collect();
    let evidence: BTreeMap<_, _> = input
        .evidence
        .iter()
        .map(|value| (value.evidence_id.as_str(), value))
        .collect();
    let provenance: BTreeMap<_, _> = input
        .provenance
        .iter()
        .map(|value| (value.provenance_id.as_str(), value))
        .collect();

    let mut obligations = input.obligations.clone();
    obligations.sort_by(|left, right| left.obligation_id.cmp(&right.obligation_id));
    let rendered_obligations: Vec<_> = obligations
        .iter()
        .map(|obligation| render_obligation(obligation, &cases, &evidence, &provenance))
        .collect();
    let by_obligation: BTreeMap<_, _> = rendered_obligations
        .iter()
        .map(|value| (value.obligation_id.as_str(), value.verdict))
        .collect();

    let mut claims = input.claims.clone();
    claims.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
    let rendered_claims: Vec<_> = claims
        .into_iter()
        .map(|claim| {
            let mut obligation_ids = claim.obligation_ids.clone();
            obligation_ids.sort();
            let verdict = combine(obligation_ids.iter().map(|id| by_obligation[id.as_str()]));
            RenderedClaim {
                claim_id: claim.claim_id,
                statement: claim.statement,
                verdict,
                obligation_ids,
            }
        })
        .collect();

    let setup_effect = setup_effect(input.setup_trust.status);
    let overall_verdict = combine(
        rendered_claims
            .iter()
            .map(|claim| claim.verdict)
            .chain(std::iter::once(setup_effect)),
    );
    Ok(ReportDocument {
        schema_version: REPORT_SCHEMA_V1.into(),
        report_id: input.report_id.clone(),
        subject: input.subject.clone(),
        overall_verdict,
        setup_trust: RenderedSetupTrust {
            disposition: input.setup_trust.status,
            profile: input.setup_trust.profile,
            participant_independence_established: input
                .setup_trust
                .participant_independence_established,
            statement: input.setup_trust.statement.clone(),
            qualification_effect: setup_effect,
        },
        source_links: sources,
        claims: rendered_claims,
        obligations: rendered_obligations,
    })
}

/// Render all offline formats from the exact same derived report.
pub fn render_report(input: &ReportInput) -> Result<RenderedReport, ReportError> {
    let report = derive_report(input)?;
    Ok(RenderedReport {
        json: canonical_json(&report)?,
        html: render_html(&report).into_bytes(),
        junit_xml: render_junit(&report).into_bytes(),
        sarif: render_sarif(&report)?,
    })
}

/// Atomically publish a fresh report directory. The target must be a new,
/// absolute path below an already-existing, non-symlink parent hierarchy.
pub fn write_report_directory(
    output_dir: &Path,
    rendered: &RenderedReport,
) -> Result<(), ReportError> {
    let (parent, leaf) = safe_output_parent(output_dir)?;
    let final_path = parent.join(&leaf);
    if fs::symlink_metadata(&final_path).is_ok() {
        return Err(ReportError::OutputExists(final_path));
    }

    let stage = unique_stage(&parent, &leaf)?;
    let write_result = (|| {
        create_restrictive_dir(&stage)?;
        write_restrictive_file(&stage.join("report.json"), &rendered.json)?;
        write_restrictive_file(&stage.join("report.html"), &rendered.html)?;
        write_restrictive_file(&stage.join("report.junit.xml"), &rendered.junit_xml)?;
        write_restrictive_file(&stage.join("report.sarif.json"), &rendered.sarif)?;
        sync_directory(&stage)?;
        fs::rename(&stage, &final_path).map_err(|source| ReportError::Io {
            path: final_path.clone(),
            source,
        })?;
        sync_directory(&parent)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    write_result
}

fn render_obligation(
    obligation: &ObligationStatus,
    cases: &BTreeMap<&str, &CaseStatusRecord>,
    evidence: &BTreeMap<&str, &EvidenceStatusRecord>,
    provenance: &BTreeMap<&str, &ProvenanceStatusRecord>,
) -> RenderedObligation {
    let mut reasons = Vec::new();
    let mut case_ids = obligation.case_ids.clone();
    let mut evidence_ids = obligation.evidence_ids.clone();
    let mut provenance_ids = obligation.provenance_ids.clone();
    case_ids.sort();
    evidence_ids.sort();
    provenance_ids.sort();
    let mut verdicts = Vec::new();

    if case_ids.is_empty() {
        reasons.push("missing-case-evidence".into());
        verdicts.push(QualificationVerdict::Blocked);
    }
    if evidence_ids.is_empty() {
        reasons.push("missing-evidence".into());
        verdicts.push(QualificationVerdict::Blocked);
    }
    if provenance_ids.is_empty() {
        reasons.push("missing-provenance".into());
        verdicts.push(QualificationVerdict::Blocked);
    }
    for id in &case_ids {
        match cases[id.as_str()].status {
            CaseDisposition::Pass => verdicts.push(QualificationVerdict::Qualified),
            CaseDisposition::Fail => {
                reasons.push(format!("case:{id}:fail"));
                verdicts.push(QualificationVerdict::Nonqualified);
            }
            status => {
                reasons.push(format!("case:{id}:{}", case_reason(status)));
                verdicts.push(QualificationVerdict::Blocked);
            }
        }
    }
    for id in &evidence_ids {
        let item = evidence[id.as_str()];
        match item.status {
            EvidenceDisposition::Verified => match item.class {
                EvidenceClass::Final => verdicts.push(QualificationVerdict::Qualified),
                class => {
                    reasons.push(format!("evidence:{id}:{}", evidence_class_reason(class)));
                    verdicts.push(QualificationVerdict::Nonqualified);
                }
            },
            status => {
                reasons.push(format!("evidence:{id}:{}", evidence_reason(status)));
                verdicts.push(QualificationVerdict::Blocked);
            }
        }
    }
    for id in &provenance_ids {
        match provenance[id.as_str()].status {
            ProvenanceDisposition::Verified => verdicts.push(QualificationVerdict::Qualified),
            status => {
                reasons.push(format!("provenance:{id}:{}", provenance_reason(status)));
                verdicts.push(QualificationVerdict::Blocked);
            }
        }
    }
    reasons.sort();
    let verdict = if verdicts.is_empty() {
        QualificationVerdict::Blocked
    } else {
        combine(verdicts)
    };
    RenderedObligation {
        obligation_id: obligation.obligation_id.clone(),
        claim_id: obligation.claim_id.clone(),
        mandatory: obligation.mandatory,
        verdict,
        reasons,
        case_ids,
        evidence_ids,
        provenance_ids,
    }
}

fn combine(values: impl IntoIterator<Item = QualificationVerdict>) -> QualificationVerdict {
    values
        .into_iter()
        .max()
        .unwrap_or(QualificationVerdict::Blocked)
}

fn setup_effect(status: SetupTrustDisposition) -> QualificationVerdict {
    match status {
        SetupTrustDisposition::Disclosed => QualificationVerdict::Qualified,
        SetupTrustDisposition::Missing
        | SetupTrustDisposition::Unknown
        | SetupTrustDisposition::Forbidden
        | SetupTrustDisposition::Skipped
        | SetupTrustDisposition::Waived => QualificationVerdict::Blocked,
    }
}

fn case_reason(status: CaseDisposition) -> &'static str {
    match status {
        CaseDisposition::Pass => "pass",
        CaseDisposition::Fail => "fail",
        CaseDisposition::Missing => "missing",
        CaseDisposition::Unknown => "unknown",
        CaseDisposition::Forbidden => "forbidden",
        CaseDisposition::Skipped => "skipped",
        CaseDisposition::Waived => "waived",
    }
}
fn evidence_reason(status: EvidenceDisposition) -> &'static str {
    match status {
        EvidenceDisposition::Verified => "verified",
        EvidenceDisposition::Missing => "missing",
        EvidenceDisposition::Unknown => "unknown",
        EvidenceDisposition::Forbidden => "forbidden",
        EvidenceDisposition::Skipped => "skipped",
        EvidenceDisposition::Waived => "waived",
    }
}
fn provenance_reason(status: ProvenanceDisposition) -> &'static str {
    match status {
        ProvenanceDisposition::Verified => "verified",
        ProvenanceDisposition::Missing => "missing",
        ProvenanceDisposition::Unknown => "unknown",
        ProvenanceDisposition::Forbidden => "forbidden",
        ProvenanceDisposition::Skipped => "skipped",
        ProvenanceDisposition::Waived => "waived",
    }
}
fn evidence_class_reason(class: EvidenceClass) -> &'static str {
    match class {
        EvidenceClass::Final => "final",
        EvidenceClass::Historical => "historical",
        EvidenceClass::Beta => "beta",
        EvidenceClass::Synthetic => "synthetic",
        EvidenceClass::Local => "local",
    }
}

fn validate_input(input: &ReportInput) -> Result<(), ReportError> {
    if input.schema_version != REPORT_INPUT_SCHEMA_V1 {
        return Err(ReportError::UnsupportedSchema(input.schema_version.clone()));
    }
    validate_id("report", &input.report_id)?;
    if input.claims.is_empty() {
        return Err(ReportError::InvalidId {
            kind: "report",
            id: "no-claims".into(),
        });
    }
    if input.subject.repository.trim().is_empty()
        || !is_hex_40(&input.subject.revision)
        || !is_hex_40(&input.subject.tree)
    {
        return Err(ReportError::InvalidId {
            kind: "subject",
            id: format!(
                "{}/{}/{}",
                input.subject.repository, input.subject.revision, input.subject.tree
            ),
        });
    }
    if input.setup_trust.statement.trim().is_empty() {
        return Err(ReportError::InvalidId {
            kind: "setup-trust",
            id: "empty-statement".into(),
        });
    }
    unique_and_validate(
        "source",
        input
            .source_links
            .iter()
            .map(|item| item.source_id.as_str()),
    )?;
    unique_and_validate(
        "claim",
        input.claims.iter().map(|item| item.claim_id.as_str()),
    )?;
    unique_and_validate(
        "obligation",
        input
            .obligations
            .iter()
            .map(|item| item.obligation_id.as_str()),
    )?;
    unique_and_validate("case", input.cases.iter().map(|item| item.case_id.as_str()))?;
    unique_and_validate(
        "evidence",
        input.evidence.iter().map(|item| item.evidence_id.as_str()),
    )?;
    unique_and_validate(
        "provenance",
        input
            .provenance
            .iter()
            .map(|item| item.provenance_id.as_str()),
    )?;
    for link in &input.source_links {
        if link.label.trim().is_empty()
            || link.reference.contains('\0')
            || link.reference.contains('\n')
            || link.reference.contains('\r')
        {
            return Err(ReportError::InvalidId {
                kind: "source",
                id: link.source_id.clone(),
            });
        }
        validate_sha256(&link.sha256)?;
    }
    for item in &input.cases {
        if item.summary.trim().is_empty() {
            return Err(ReportError::InvalidId {
                kind: "case",
                id: item.case_id.clone(),
            });
        }
    }
    for item in &input.provenance {
        if item.summary.trim().is_empty() {
            return Err(ReportError::InvalidId {
                kind: "provenance",
                id: item.provenance_id.clone(),
            });
        }
    }
    let claims: BTreeMap<_, _> = input
        .claims
        .iter()
        .map(|value| (value.claim_id.as_str(), value))
        .collect();
    let obligations: BTreeMap<_, _> = input
        .obligations
        .iter()
        .map(|value| (value.obligation_id.as_str(), value))
        .collect();
    let cases: BTreeSet<_> = input
        .cases
        .iter()
        .map(|value| value.case_id.as_str())
        .collect();
    let evidence: BTreeMap<_, _> = input
        .evidence
        .iter()
        .map(|value| (value.evidence_id.as_str(), value))
        .collect();
    let provenance: BTreeSet<_> = input
        .provenance
        .iter()
        .map(|value| value.provenance_id.as_str())
        .collect();
    let sources: BTreeSet<_> = input
        .source_links
        .iter()
        .map(|value| value.source_id.as_str())
        .collect();
    for claim in &input.claims {
        if claim.statement.trim().is_empty() || claim.obligation_ids.is_empty() {
            return Err(ReportError::InvalidId {
                kind: "claim",
                id: claim.claim_id.clone(),
            });
        }
        unique_references("obligation", &claim.claim_id, &claim.obligation_ids)?;
        for id in &claim.obligation_ids {
            let obligation = obligations
                .get(id.as_str())
                .ok_or_else(|| missing("obligation", &claim.claim_id, id))?;
            if obligation.claim_id != claim.claim_id {
                return Err(ReportError::NonReciprocalMapping {
                    claim_id: claim.claim_id.clone(),
                    obligation_id: id.clone(),
                });
            }
        }
    }
    for obligation in &input.obligations {
        let claim = claims
            .get(obligation.claim_id.as_str())
            .ok_or_else(|| missing("claim", &obligation.obligation_id, &obligation.claim_id))?;
        if !claim.obligation_ids.contains(&obligation.obligation_id) {
            return Err(ReportError::NonReciprocalMapping {
                claim_id: obligation.claim_id.clone(),
                obligation_id: obligation.obligation_id.clone(),
            });
        }
        unique_references("case", &obligation.obligation_id, &obligation.case_ids)?;
        unique_references(
            "evidence",
            &obligation.obligation_id,
            &obligation.evidence_ids,
        )?;
        unique_references(
            "provenance",
            &obligation.obligation_id,
            &obligation.provenance_ids,
        )?;
        for id in &obligation.case_ids {
            if !cases.contains(id.as_str()) {
                return Err(missing("case", &obligation.obligation_id, id));
            }
        }
        for id in &obligation.evidence_ids {
            if !evidence.contains_key(id.as_str()) {
                return Err(missing("evidence", &obligation.obligation_id, id));
            }
        }
        for id in &obligation.provenance_ids {
            if !provenance.contains(id.as_str()) {
                return Err(missing("provenance", &obligation.obligation_id, id));
            }
        }
    }
    for item in &input.evidence {
        if item.source_link_ids.is_empty() {
            return Err(ReportError::InvalidId {
                kind: "evidence",
                id: item.evidence_id.clone(),
            });
        }
        unique_references("source", &item.evidence_id, &item.source_link_ids)?;
        for source in &item.source_link_ids {
            if !sources.contains(source.as_str()) {
                return Err(missing("source", &item.evidence_id, source));
            }
        }
    }
    Ok(())
}

fn unique_references(
    kind: &'static str,
    owner: &str,
    values: &[String],
) -> Result<(), ReportError> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_id(kind, value)?;
        if !seen.insert(value.as_str()) {
            return Err(ReportError::DuplicateReference {
                kind,
                owner: owner.into(),
                id: value.clone(),
            });
        }
    }
    Ok(())
}

fn unique_and_validate<'a>(
    kind: &'static str,
    values: impl Iterator<Item = &'a str>,
) -> Result<(), ReportError> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_id(kind, value)?;
        if !seen.insert(value) {
            return Err(ReportError::DuplicateId {
                kind,
                id: value.into(),
            });
        }
    }
    Ok(())
}

fn validate_id(kind: &'static str, id: &str) -> Result<(), ReportError> {
    let valid = !id.is_empty()
        && id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'-' | b'_'))
        });
    if valid {
        Ok(())
    } else {
        Err(ReportError::InvalidId {
            kind,
            id: id.into(),
        })
    }
}

fn validate_sha256(value: &str) -> Result<(), ReportError> {
    let raw = value.strip_prefix("sha256:").unwrap_or(value);
    if raw.len() == 64
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ReportError::InvalidSha256(value.into()))
    }
}

fn is_hex_40(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn missing(kind: &'static str, owner: &str, id: &str) -> ReportError {
    ReportError::MissingReference {
        kind,
        owner: owner.into(),
        id: id.into(),
    }
}
fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ReportError> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|error| ReportError::Canonical(error.to_string()))
}

fn render_html(report: &ReportDocument) -> String {
    let mut output = String::from(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>ShieldKit assurance report</title><style>body{font:14px system-ui,sans-serif;margin:2rem;color:#171717}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #bbb;padding:.45rem;text-align:left;vertical-align:top}code{word-break:break-all}.qualified{color:#126b32}.nonqualified,.blocked{color:#9d2020}</style></head><body>",
    );
    output.push_str(&format!(
        "<h1>Assurance report: {}</h1><p>Overall verdict: <strong class=\"{}\">{}</strong></p>",
        escape_html(&report.report_id),
        verdict_class(report.overall_verdict),
        verdict_text(report.overall_verdict)
    ));
    output.push_str(&format!("<h2>Subject</h2><p>Repository: <code>{}</code><br>Revision: <code>{}</code><br>Tree: <code>{}</code></p>", escape_html(&report.subject.repository), escape_html(&report.subject.revision), escape_html(&report.subject.tree)));
    output.push_str(&format!("<h2>Setup trust</h2><p>Disposition: <code>{}</code><br>Profile: <code>{}</code><br>Participant independence established: <code>{}</code><br>Qualification effect: <strong class=\"{}\">{}</strong><br>{}</p>", setup_text(report.setup_trust.disposition), setup_profile_text(report.setup_trust.profile), report.setup_trust.participant_independence_established, verdict_class(report.setup_trust.qualification_effect), verdict_text(report.setup_trust.qualification_effect), escape_html(&report.setup_trust.statement)));
    output.push_str("<h2>Claims</h2><table><thead><tr><th>ID</th><th>Verdict</th><th>Statement</th></tr></thead><tbody>");
    for claim in &report.claims {
        output.push_str(&format!(
            "<tr><td><code>{}</code></td><td class=\"{}\">{}</td><td>{}</td></tr>",
            escape_html(&claim.claim_id),
            verdict_class(claim.verdict),
            verdict_text(claim.verdict),
            escape_html(&claim.statement)
        ));
    }
    output.push_str("</tbody></table><h2>Obligations</h2><table><thead><tr><th>ID</th><th>Verdict</th><th>Reasons</th></tr></thead><tbody>");
    for obligation in &report.obligations {
        output.push_str(&format!(
            "<tr><td><code>{}</code></td><td class=\"{}\">{}</td><td>{}</td></tr>",
            escape_html(&obligation.obligation_id),
            verdict_class(obligation.verdict),
            verdict_text(obligation.verdict),
            escape_html(&obligation.reasons.join(", "))
        ));
    }
    output.push_str("</tbody></table><h2>Source references</h2><table><thead><tr><th>Label</th><th>Reference (inert text)</th><th>SHA-256</th></tr></thead><tbody>");
    for source in &report.source_links {
        output.push_str(&format!(
            "<tr><td>{}</td><td><code>{}</code></td><td><code>{}</code></td></tr>",
            escape_html(&source.label),
            escape_html(&source.reference),
            escape_html(&source.sha256)
        ));
    }
    output.push_str("</tbody></table></body></html>");
    output
}

fn render_junit(report: &ReportDocument) -> String {
    let failures = report
        .obligations
        .iter()
        .filter(|item| item.verdict != QualificationVerdict::Qualified)
        .count();
    let mut output = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"0\">",
        escape_xml(&report.report_id),
        report.obligations.len(),
        failures
    );
    for obligation in &report.obligations {
        output.push_str(&format!(
            "<testcase classname=\"assurance.obligation\" name=\"{}\">",
            escape_xml(&obligation.obligation_id)
        ));
        if obligation.verdict != QualificationVerdict::Qualified {
            output.push_str(&format!(
                "<failure type=\"{}\" message=\"{}\">{}</failure>",
                verdict_text(obligation.verdict),
                escape_xml(&obligation.reasons.join(", ")),
                escape_xml(&obligation.reasons.join(", "))
            ));
        }
        output.push_str("</testcase>");
    }
    output.push_str("</testsuite>");
    output
}

fn render_sarif(report: &ReportDocument) -> Result<Vec<u8>, ReportError> {
    let results: Vec<_> = report.obligations.iter().filter(|item| item.verdict != QualificationVerdict::Qualified).map(|item| serde_json::json!({"ruleId": item.obligation_id, "level": if item.verdict == QualificationVerdict::Blocked { "error" } else { "warning" }, "message": {"text": format!("{}: {}", verdict_text(item.verdict), item.reasons.join(", "))}})).collect();
    let rules: Vec<_> = report.obligations.iter().map(|item| serde_json::json!({"id": item.obligation_id, "name": item.obligation_id, "shortDescription": {"text": format!("Claim {}", item.claim_id)}})).collect();
    canonical_json(
        &serde_json::json!({"$schema": SARIF_SCHEMA_V2_1_0, "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ShieldKit Assurance", "rules": rules}}, "properties": {"reportId": report.report_id, "overallVerdict": verdict_text(report.overall_verdict), "setupTrust": report.setup_trust, "sourceReferences": report.source_links}, "results": results}]}),
    )
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn escape_xml(value: &str) -> String {
    escape_html(value)
}
fn verdict_text(value: QualificationVerdict) -> &'static str {
    match value {
        QualificationVerdict::Qualified => "qualified",
        QualificationVerdict::Nonqualified => "nonqualified",
        QualificationVerdict::Blocked => "blocked",
    }
}
fn verdict_class(value: QualificationVerdict) -> &'static str {
    verdict_text(value)
}
fn setup_text(value: SetupTrustDisposition) -> &'static str {
    match value {
        SetupTrustDisposition::Disclosed => "disclosed",
        SetupTrustDisposition::Missing => "missing",
        SetupTrustDisposition::Unknown => "unknown",
        SetupTrustDisposition::Forbidden => "forbidden",
        SetupTrustDisposition::Skipped => "skipped",
        SetupTrustDisposition::Waived => "waived",
    }
}
fn setup_profile_text(value: SetupTrustProfile) -> &'static str {
    match value {
        SetupTrustProfile::SingleContributor => "single_contributor",
        SetupTrustProfile::MultiParty => "multi_party",
        SetupTrustProfile::Other => "other",
    }
}

fn safe_output_parent(output_dir: &Path) -> Result<(PathBuf, std::ffi::OsString), ReportError> {
    if !output_dir.is_absolute()
        || output_dir
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ReportError::UnsafeOutputPath(output_dir.into()));
    }
    let leaf = output_dir
        .file_name()
        .filter(|name| {
            !name.is_empty()
                && *name != std::ffi::OsStr::new(".")
                && *name != std::ffi::OsStr::new("..")
        })
        .ok_or_else(|| ReportError::UnsafeOutputPath(output_dir.into()))?
        .to_os_string();
    let parent = output_dir
        .parent()
        .ok_or_else(|| ReportError::UnsafeOutputPath(output_dir.into()))?;
    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|source| ReportError::Io {
            path: current.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ReportError::UnsafeOutputPath(current));
        }
    }
    Ok((parent.to_path_buf(), leaf))
}

fn unique_stage(parent: &Path, leaf: &std::ffi::OsStr) -> Result<PathBuf, ReportError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ReportError::UnsafeOutputPath(parent.into()))?
        .as_nanos();
    for _ in 0..128 {
        let counter = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{}.staging-{}-{}-{}",
            leaf.to_string_lossy(),
            std::process::id(),
            nanos,
            counter
        ));
        if fs::symlink_metadata(&candidate).is_err() {
            return Ok(candidate);
        }
    }
    Err(ReportError::UnsafeOutputPath(parent.into()))
}

fn create_restrictive_dir(path: &Path) -> Result<(), ReportError> {
    fs::create_dir(path).map_err(|source| ReportError::Io {
        path: path.into(),
        source,
    })?;
    set_mode(path, 0o700)?;
    Ok(())
}
fn write_restrictive_file(path: &Path, bytes: &[u8]) -> Result<(), ReportError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|source| ReportError::Io {
        path: path.into(),
        source,
    })?;
    file.write_all(bytes).map_err(|source| ReportError::Io {
        path: path.into(),
        source,
    })?;
    file.sync_all().map_err(|source| ReportError::Io {
        path: path.into(),
        source,
    })?;
    set_mode(path, 0o600)?;
    Ok(())
}
fn sync_directory(path: &Path) -> Result<(), ReportError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|source| ReportError::Io {
            path: path.into(),
            source,
        })
}
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), ReportError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| ReportError::Io {
        path: path.into(),
        source,
    })
}
#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) -> Result<(), ReportError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn valid() -> ReportInput {
        ReportInput {
            schema_version: REPORT_INPUT_SCHEMA_V1.into(),
            report_id: "shieldkit.report".into(),
            subject: SubjectStatus {
                repository: "shieldkit-sdk".into(),
                revision: "a".repeat(40),
                tree: "b".repeat(40),
            },
            setup_trust: SetupTrustStatus {
                status: SetupTrustDisposition::Disclosed,
                profile: SetupTrustProfile::SingleContributor,
                participant_independence_established: false,
                statement: "disclosed separately".into(),
            },
            source_links: vec![SourceReference {
                source_id: "source.one".into(),
                label: "manifest".into(),
                reference: "final/manifest.json".into(),
                sha256: format!("sha256:{}", "c".repeat(64)),
            }],
            claims: vec![ClaimStatus {
                claim_id: "claim.one".into(),
                statement: "claim".into(),
                obligation_ids: vec!["obligation.one".into()],
            }],
            obligations: vec![ObligationStatus {
                obligation_id: "obligation.one".into(),
                claim_id: "claim.one".into(),
                mandatory: true,
                case_ids: vec!["case.one".into()],
                evidence_ids: vec!["evidence.one".into()],
                provenance_ids: vec!["provenance.one".into()],
            }],
            cases: vec![CaseStatusRecord {
                case_id: "case.one".into(),
                status: CaseDisposition::Pass,
                summary: "pass".into(),
            }],
            evidence: vec![EvidenceStatusRecord {
                evidence_id: "evidence.one".into(),
                status: EvidenceDisposition::Verified,
                class: EvidenceClass::Final,
                source_link_ids: vec!["source.one".into()],
            }],
            provenance: vec![ProvenanceStatusRecord {
                provenance_id: "provenance.one".into(),
                status: ProvenanceDisposition::Verified,
                summary: "verified".into(),
            }],
        }
    }

    #[test]
    fn qualification_and_setup_trust_are_separate() {
        let report = derive_report(&valid()).unwrap();
        assert_eq!(report.overall_verdict, QualificationVerdict::Qualified);
        assert!(!report.setup_trust.participant_independence_established);
        assert_eq!(report.claims[0].verdict, QualificationVerdict::Qualified);
    }

    #[test]
    fn rejects_missing_evidence_and_forbidden_case_fail_closed() {
        let mut missing = valid();
        missing.evidence[0].status = EvidenceDisposition::Missing;
        assert_eq!(
            derive_report(&missing).unwrap().overall_verdict,
            QualificationVerdict::Blocked
        );
        let mut forbidden = valid();
        forbidden.cases[0].status = CaseDisposition::Forbidden;
        assert_eq!(
            derive_report(&forbidden).unwrap().overall_verdict,
            QualificationVerdict::Blocked
        );
    }

    #[test]
    fn never_promotes_historical_beta_or_synthetic_evidence() {
        for class in [
            EvidenceClass::Historical,
            EvidenceClass::Beta,
            EvidenceClass::Synthetic,
            EvidenceClass::Local,
        ] {
            let mut input = valid();
            input.evidence[0].class = class;
            let report = derive_report(&input).unwrap();
            assert_eq!(report.claims[0].verdict, QualificationVerdict::Nonqualified);
            assert_eq!(report.overall_verdict, QualificationVerdict::Nonqualified);
        }
    }

    #[test]
    fn rejects_duplicate_ids() {
        let mut input = valid();
        input.cases.push(input.cases[0].clone());
        assert!(matches!(
            derive_report(&input),
            Err(ReportError::DuplicateId { kind: "case", .. })
        ));
    }

    #[test]
    fn output_is_exactly_deterministic_under_input_order_changes() {
        let mut left = valid();
        left.source_links.push(SourceReference {
            source_id: "source.two".into(),
            label: "two".into(),
            reference: "two".into(),
            sha256: "d".repeat(64),
        });
        left.evidence[0].source_link_ids.push("source.two".into());
        let mut right = left.clone();
        right.source_links.reverse();
        right.evidence[0].source_link_ids.reverse();
        assert_eq!(
            render_report(&left).unwrap(),
            render_report(&right).unwrap()
        );
        assert_eq!(
            render_report(&left).unwrap().json,
            render_report(&left).unwrap().json
        );
    }

    #[test]
    fn html_escapes_xss_and_source_references_are_inert() {
        let mut input = valid();
        input.claims[0].statement =
            "<img src=x onerror=alert(1)> & <script>alert(1)</script>".into();
        input.source_links[0].reference = "https://example.invalid/?x=<script>".into();
        let html = String::from_utf8(render_report(&input).unwrap().html).unwrap();
        assert!(html.contains("default-src 'none'"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(!html.contains("href="));
    }

    #[test]
    fn atomic_writer_rejects_path_injection_and_symlink_parent() {
        let rendered = render_report(&valid()).unwrap();
        assert!(matches!(
            write_report_directory(Path::new("../escape"), &rendered),
            Err(ReportError::UnsafeOutputPath(_))
        ));
        let root = tempdir().unwrap();
        let destination = root.path().join("result");
        write_report_directory(&destination, &rendered).unwrap();
        assert_eq!(
            fs::read(destination.join("report.json")).unwrap(),
            rendered.json
        );
        assert!(matches!(
            write_report_directory(&destination, &rendered),
            Err(ReportError::OutputExists(_))
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let real = root.path().join("real");
            fs::create_dir(&real).unwrap();
            let link = root.path().join("link");
            symlink(&real, &link).unwrap();
            assert!(matches!(
                write_report_directory(&link.join("escape"), &rendered),
                Err(ReportError::UnsafeOutputPath(_))
            ));
        }
    }
}
