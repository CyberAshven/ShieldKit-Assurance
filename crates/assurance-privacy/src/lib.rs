//! Deterministic, protocol-neutral privacy-measurement analysis.
//!
//! A passing result means only that the supplied measurements did not cross the
//! configured leakage thresholds. It never establishes cryptographic privacy.
//! Inputs are rejected rather than silently repaired if provenance, public
//! context, sample splitting, or finite numeric measurements are incomplete.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PRIVACY_INPUT_SCHEMA_V1: &str = "shieldkit-assurance-privacy-input/v1";
pub const PRIVACY_REPORT_SCHEMA_V1: &str = "shieldkit-assurance-privacy-report/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PrivacyAnalysisInput {
    pub schema_version: String,
    pub analysis_id: String,
    pub hypothesis: Hypothesis,
    pub secret_classes: Vec<SecretClass>,
    pub public_classes: Vec<PublicClass>,
    pub observables: Vec<ObservableDefinition>,
    pub provenance: Vec<ProvenanceRecord>,
    pub samples: Vec<MeasurementSample>,
    pub analyses: Vec<ObservableAnalysis>,
    #[serde(default)]
    pub classifiers: Vec<ClassifierAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Hypothesis {
    pub hypothesis_id: String,
    pub statement: String,
    /// Must acknowledge that statistics do not prove cryptographic privacy.
    pub cryptographic_privacy_not_established: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecretClass {
    pub class_id: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PublicClass {
    pub class_id: String,
    pub allowed_values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObservableDefinition {
    pub observable_id: String,
    pub family: ObservableFamily,
    pub unit: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ObservableFamily {
    Timing,
    Size,
    NetworkAccessPattern,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProvenanceRecord {
    pub provenance_id: String,
    pub status: ProvenanceStatus,
    pub source: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceStatus {
    Verified,
    Missing,
    Unknown,
    Forbidden,
    Synthetic,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SampleSplit {
    Train,
    Test,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MeasurementSample {
    pub sample_id: String,
    /// Capture identity; cannot occur in both a classifier's train and test set.
    pub capture_id: String,
    pub secret_class_id: String,
    pub split: SampleSplit,
    pub public_context: BTreeMap<String, String>,
    pub provenance_id: String,
    pub measurements: BTreeMap<String, f64>,
    #[serde(default)]
    pub linkability_tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObservableAnalysis {
    pub analysis_id: String,
    pub observable_id: String,
    pub class_a: String,
    pub class_b: String,
    pub thresholds: StatisticalThresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatisticalThresholds {
    pub minimum_samples_per_class: u32,
    pub minimum_power: f64,
    pub alpha: f64,
    pub maximum_absolute_cohens_d: f64,
    pub maximum_absolute_mean_difference: f64,
    pub permutation_iterations: u32,
    /// Caller-recorded deterministic seed. OS entropy is never used.
    pub permutation_seed: u64,
    pub correction: MultipleTestingCorrection,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MultipleTestingCorrection {
    Bonferroni,
    BenjaminiHochberg,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClassifierAnalysis {
    pub analysis_id: String,
    pub class_a: String,
    pub class_b: String,
    pub feature_ids: Vec<String>,
    pub minimum_train_samples_per_class: u32,
    pub minimum_test_samples_per_class: u32,
    pub minimum_power: f64,
    pub maximum_balanced_accuracy: f64,
    pub alpha: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisVerdict {
    NoStatisticalLeakageDetected,
    LeakDetected,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QualificationStatus {
    /// A measured leak or inadequate evidence blocks qualification.
    Blocked,
    /// Statistics passed, but that is only measurement evidence—not a proof.
    MeasurementEvidenceOnly,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CryptographicPrivacyClaim {
    NotEstablishedByStatisticalAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PrivacyReport {
    pub schema_version: String,
    pub analysis_id: String,
    pub input_sha256: String,
    pub replay_sha256: String,
    pub report_sha256: String,
    pub cryptographic_privacy_claim: CryptographicPrivacyClaim,
    pub overall_verdict: AnalysisVerdict,
    pub qualification_status: QualificationStatus,
    pub public_context: BTreeMap<String, String>,
    pub observable_results: Vec<ObservableResult>,
    pub classifier_results: Vec<ClassifierResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObservableResult {
    pub analysis_id: String,
    pub observable_id: String,
    pub family: ObservableFamily,
    pub verdict: AnalysisVerdict,
    pub qualification_status: QualificationStatus,
    pub sample_count_a: usize,
    pub sample_count_b: usize,
    pub mean_a: f64,
    pub mean_b: f64,
    pub mean_difference: f64,
    pub welch_t: f64,
    pub welch_degrees_of_freedom: f64,
    pub welch_p_value: f64,
    pub corrected_p_value: f64,
    pub permutation_p_value: f64,
    pub cohens_d: f64,
    pub confidence_low: f64,
    pub confidence_high: f64,
    pub estimated_power: f64,
    pub exact_distinguisher: ExactDistinguisher,
    pub reasons: Vec<String>,
    pub replay_seed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExactDistinguisher {
    pub size_value_count: usize,
    pub size_values_unique_to_one_secret: usize,
    pub linkability_tag_count: usize,
    pub linkability_tags_reused: usize,
    pub linkability_tags_unique_to_one_secret: usize,
    pub exists: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClassifierResult {
    pub analysis_id: String,
    pub verdict: AnalysisVerdict,
    pub qualification_status: QualificationStatus,
    pub train_count_a: usize,
    pub train_count_b: usize,
    pub test_count_a: usize,
    pub test_count_b: usize,
    pub balanced_accuracy: f64,
    pub confidence_low: f64,
    pub confidence_high: f64,
    pub estimated_power: f64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Error)]
pub enum PrivacyError {
    #[error("unsupported privacy schema: {0}")]
    UnsupportedSchema(String),
    #[error("invalid {kind} identifier or value: {id}")]
    Invalid { kind: &'static str, id: String },
    #[error("duplicate {kind}: {id}")]
    Duplicate { kind: &'static str, id: String },
    #[error("missing {kind} referenced by {owner}: {id}")]
    MissingReference {
        kind: &'static str,
        owner: String,
        id: String,
    },
    #[error("sample {sample_id} has mixed public context")]
    MixedPublicContext { sample_id: String },
    #[error("sample {sample_id} lacks verified provenance: {provenance_id}")]
    UnverifiedProvenance {
        sample_id: String,
        provenance_id: String,
    },
    #[error("classifier {analysis_id} leaks capture {capture_id} across train and test")]
    TrainTestLeakage {
        analysis_id: String,
        capture_id: String,
    },
    #[error("canonical JSON error: {0}")]
    Canonical(String),
}

/// Validate, normalize, and analyze caller-supplied observations. This does
/// not collect data, execute commands, access a network, or create samples.
pub fn analyze(input: &PrivacyAnalysisInput) -> Result<PrivacyReport, PrivacyError> {
    let normalized = normalize(input)?;
    let input_sha256 = hash_canonical(&normalized)?;
    let public_context = normalized.samples[0].public_context.clone();
    let mut observable_results: Vec<_> = normalized
        .analyses
        .iter()
        .map(|analysis| analyze_observable(analysis, &normalized))
        .collect();
    apply_multiple_testing_correction(&mut observable_results, &normalized.analyses);
    for result in &mut observable_results {
        finalize_observable_verdict(result, &normalized.analyses);
    }
    let classifier_results: Vec<_> = normalized
        .classifiers
        .iter()
        .map(|analysis| analyze_classifier(analysis, &normalized))
        .collect();
    let all_verdicts = observable_results
        .iter()
        .map(|result| result.verdict)
        .chain(classifier_results.iter().map(|result| result.verdict));
    let overall_verdict = combine_verdicts(all_verdicts);
    let qualification_status = qualification_for(overall_verdict);
    let replay_sha256 = hash_canonical(&ReplayManifest {
        schema_version: PRIVACY_INPUT_SCHEMA_V1,
        input_sha256: &input_sha256,
        analysis_ids: normalized
            .analyses
            .iter()
            .map(|item| item.analysis_id.as_str())
            .collect(),
        classifier_ids: normalized
            .classifiers
            .iter()
            .map(|item| item.analysis_id.as_str())
            .collect(),
        permutation_seeds: normalized
            .analyses
            .iter()
            .map(|item| item.thresholds.permutation_seed)
            .collect(),
    })?;
    let body = PrivacyReportBody {
        schema_version: PRIVACY_REPORT_SCHEMA_V1,
        analysis_id: &normalized.analysis_id,
        input_sha256: &input_sha256,
        replay_sha256: &replay_sha256,
        cryptographic_privacy_claim: CryptographicPrivacyClaim::NotEstablishedByStatisticalAnalysis,
        overall_verdict,
        qualification_status,
        public_context: &public_context,
        observable_results: &observable_results,
        classifier_results: &classifier_results,
    };
    let report_sha256 = hash_canonical(&body)?;
    Ok(PrivacyReport {
        schema_version: PRIVACY_REPORT_SCHEMA_V1.into(),
        analysis_id: normalized.analysis_id,
        input_sha256,
        replay_sha256,
        report_sha256,
        cryptographic_privacy_claim: CryptographicPrivacyClaim::NotEstablishedByStatisticalAnalysis,
        overall_verdict,
        qualification_status,
        public_context,
        observable_results,
        classifier_results,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayManifest<'a> {
    schema_version: &'a str,
    input_sha256: &'a str,
    analysis_ids: Vec<&'a str>,
    classifier_ids: Vec<&'a str>,
    permutation_seeds: Vec<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivacyReportBody<'a> {
    schema_version: &'a str,
    analysis_id: &'a str,
    input_sha256: &'a str,
    replay_sha256: &'a str,
    cryptographic_privacy_claim: CryptographicPrivacyClaim,
    overall_verdict: AnalysisVerdict,
    qualification_status: QualificationStatus,
    public_context: &'a BTreeMap<String, String>,
    observable_results: &'a [ObservableResult],
    classifier_results: &'a [ClassifierResult],
}

fn normalize(input: &PrivacyAnalysisInput) -> Result<PrivacyAnalysisInput, PrivacyError> {
    validate_input(input)?;
    let mut normalized = input.clone();
    normalized
        .secret_classes
        .sort_by(|a, b| a.class_id.cmp(&b.class_id));
    normalized
        .public_classes
        .sort_by(|a, b| a.class_id.cmp(&b.class_id));
    normalized
        .observables
        .sort_by(|a, b| a.observable_id.cmp(&b.observable_id));
    normalized
        .provenance
        .sort_by(|a, b| a.provenance_id.cmp(&b.provenance_id));
    normalized
        .samples
        .sort_by(|a, b| a.sample_id.cmp(&b.sample_id));
    normalized
        .analyses
        .sort_by(|a, b| a.analysis_id.cmp(&b.analysis_id));
    normalized
        .classifiers
        .sort_by(|a, b| a.analysis_id.cmp(&b.analysis_id));
    for item in &mut normalized.public_classes {
        item.allowed_values.sort();
    }
    for item in &mut normalized.classifiers {
        item.feature_ids.sort();
    }
    Ok(normalized)
}

fn validate_input(input: &PrivacyAnalysisInput) -> Result<(), PrivacyError> {
    if input.schema_version != PRIVACY_INPUT_SCHEMA_V1 {
        return Err(PrivacyError::UnsupportedSchema(
            input.schema_version.clone(),
        ));
    }
    valid_id("analysis", &input.analysis_id)?;
    valid_id("hypothesis", &input.hypothesis.hypothesis_id)?;
    if input.hypothesis.statement.trim().is_empty()
        || !input.hypothesis.cryptographic_privacy_not_established
    {
        return Err(PrivacyError::Invalid {
            kind: "hypothesis",
            id: input.hypothesis.hypothesis_id.clone(),
        });
    }
    nonempty_unique(
        "secret class",
        input.secret_classes.iter().map(|x| x.class_id.as_str()),
    )?;
    nonempty_unique(
        "public class",
        input.public_classes.iter().map(|x| x.class_id.as_str()),
    )?;
    nonempty_unique(
        "observable",
        input.observables.iter().map(|x| x.observable_id.as_str()),
    )?;
    nonempty_unique(
        "provenance",
        input.provenance.iter().map(|x| x.provenance_id.as_str()),
    )?;
    nonempty_unique("sample", input.samples.iter().map(|x| x.sample_id.as_str()))?;
    nonempty_unique(
        "observable analysis",
        input.analyses.iter().map(|x| x.analysis_id.as_str()),
    )?;
    nonempty_unique(
        "classifier",
        input.classifiers.iter().map(|x| x.analysis_id.as_str()),
    )?;
    if input.samples.is_empty() || input.analyses.is_empty() {
        return Err(PrivacyError::Invalid {
            kind: "input",
            id: "samples-and-analyses-must-not-be-empty".into(),
        });
    }
    let secret_ids: BTreeSet<_> = input
        .secret_classes
        .iter()
        .map(|x| x.class_id.as_str())
        .collect();
    let observable_ids: BTreeSet<_> = input
        .observables
        .iter()
        .map(|x| x.observable_id.as_str())
        .collect();
    let provenance: BTreeMap<_, _> = input
        .provenance
        .iter()
        .map(|x| (x.provenance_id.as_str(), x))
        .collect();
    let public: BTreeMap<_, _> = input
        .public_classes
        .iter()
        .map(|x| (x.class_id.as_str(), x))
        .collect();
    let expected_context: BTreeSet<_> = public.keys().copied().collect();
    let expected_measurements: BTreeSet<_> = observable_ids.iter().copied().collect();
    for class in &input.secret_classes {
        if class.description.trim().is_empty() {
            return Err(PrivacyError::Invalid {
                kind: "secret class",
                id: class.class_id.clone(),
            });
        }
    }
    for class in &input.public_classes {
        if class.allowed_values.is_empty()
            || class.allowed_values.iter().any(|value| value.is_empty())
        {
            return Err(PrivacyError::Invalid {
                kind: "public class",
                id: class.class_id.clone(),
            });
        }
        let mut values = BTreeSet::new();
        for value in &class.allowed_values {
            if !values.insert(value) {
                return Err(PrivacyError::Duplicate {
                    kind: "public class value",
                    id: format!("{}:{value}", class.class_id),
                });
            }
        }
    }
    for record in &input.provenance {
        if record.source.trim().is_empty() || !sha256_text(&record.sha256) {
            return Err(PrivacyError::Invalid {
                kind: "provenance",
                id: record.provenance_id.clone(),
            });
        }
    }
    let first_context = &input.samples[0].public_context;
    for sample in &input.samples {
        valid_id("capture", &sample.capture_id)?;
        if !secret_ids.contains(sample.secret_class_id.as_str()) {
            return Err(missing(
                "secret class",
                &sample.sample_id,
                &sample.secret_class_id,
            ));
        }
        let record = provenance
            .get(sample.provenance_id.as_str())
            .ok_or_else(|| missing("provenance", &sample.sample_id, &sample.provenance_id))?;
        if record.status != ProvenanceStatus::Verified {
            return Err(PrivacyError::UnverifiedProvenance {
                sample_id: sample.sample_id.clone(),
                provenance_id: sample.provenance_id.clone(),
            });
        }
        if sample.public_context != *first_context
            || sample
                .public_context
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != expected_context
        {
            return Err(PrivacyError::MixedPublicContext {
                sample_id: sample.sample_id.clone(),
            });
        }
        for (key, value) in &sample.public_context {
            let definition = public[key.as_str()];
            if !definition.allowed_values.contains(value) {
                return Err(PrivacyError::Invalid {
                    kind: "public context",
                    id: format!("{key}:{value}"),
                });
            }
        }
        if sample
            .measurements
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != expected_measurements
        {
            return Err(PrivacyError::Invalid {
                kind: "measurements",
                id: sample.sample_id.clone(),
            });
        }
        if sample
            .measurements
            .values()
            .any(|value| !value.is_finite() || *value < 0.0)
        {
            return Err(PrivacyError::Invalid {
                kind: "measurement",
                id: sample.sample_id.clone(),
            });
        }
        if sample
            .linkability_tags
            .iter()
            .any(|(key, value)| key.is_empty() || value.is_empty())
        {
            return Err(PrivacyError::Invalid {
                kind: "linkability tag",
                id: sample.sample_id.clone(),
            });
        }
    }
    for analysis in &input.analyses {
        if !observable_ids.contains(analysis.observable_id.as_str()) {
            return Err(missing(
                "observable",
                &analysis.analysis_id,
                &analysis.observable_id,
            ));
        }
        validate_classes(
            &analysis.analysis_id,
            &analysis.class_a,
            &analysis.class_b,
            &secret_ids,
        )?;
        validate_thresholds(&analysis.thresholds, &analysis.analysis_id)?;
    }
    for classifier in &input.classifiers {
        validate_classes(
            &classifier.analysis_id,
            &classifier.class_a,
            &classifier.class_b,
            &secret_ids,
        )?;
        if classifier.feature_ids.is_empty()
            || classifier
                .feature_ids
                .iter()
                .any(|item| !observable_ids.contains(item.as_str()))
            || duplicate_strings(&classifier.feature_ids)
        {
            return Err(PrivacyError::Invalid {
                kind: "classifier features",
                id: classifier.analysis_id.clone(),
            });
        }
        if classifier.minimum_train_samples_per_class == 0
            || classifier.minimum_test_samples_per_class == 0
            || !unit_interval(classifier.minimum_power)
            || !unit_interval(classifier.maximum_balanced_accuracy)
            || !open_unit_interval(classifier.alpha)
        {
            return Err(PrivacyError::Invalid {
                kind: "classifier threshold",
                id: classifier.analysis_id.clone(),
            });
        }
        reject_train_test_capture_overlap(classifier, &input.samples)?;
    }
    Ok(())
}

fn validate_classes(
    analysis_id: &str,
    a: &str,
    b: &str,
    valid: &BTreeSet<&str>,
) -> Result<(), PrivacyError> {
    if a == b {
        return Err(PrivacyError::Invalid {
            kind: "secret class pair",
            id: analysis_id.into(),
        });
    }
    if !valid.contains(a) {
        return Err(missing("secret class", analysis_id, a));
    }
    if !valid.contains(b) {
        return Err(missing("secret class", analysis_id, b));
    }
    Ok(())
}

fn validate_thresholds(t: &StatisticalThresholds, id: &str) -> Result<(), PrivacyError> {
    if t.minimum_samples_per_class == 0
        || !unit_interval(t.minimum_power)
        || !open_unit_interval(t.alpha)
        || !t.maximum_absolute_cohens_d.is_finite()
        || t.maximum_absolute_cohens_d < 0.0
        || !t.maximum_absolute_mean_difference.is_finite()
        || t.maximum_absolute_mean_difference < 0.0
        || t.permutation_iterations == 0
    {
        return Err(PrivacyError::Invalid {
            kind: "statistical threshold",
            id: id.into(),
        });
    }
    Ok(())
}

fn reject_train_test_capture_overlap(
    analysis: &ClassifierAnalysis,
    samples: &[MeasurementSample],
) -> Result<(), PrivacyError> {
    let mut splits: BTreeMap<&str, SampleSplit> = BTreeMap::new();
    for sample in samples.iter().filter(|sample| {
        sample.secret_class_id == analysis.class_a || sample.secret_class_id == analysis.class_b
    }) {
        if let Some(previous) = splits.insert(&sample.capture_id, sample.split)
            && previous != sample.split
        {
            return Err(PrivacyError::TrainTestLeakage {
                analysis_id: analysis.analysis_id.clone(),
                capture_id: sample.capture_id.clone(),
            });
        }
    }
    Ok(())
}

fn analyze_observable(
    analysis: &ObservableAnalysis,
    input: &PrivacyAnalysisInput,
) -> ObservableResult {
    let a = collect_measurements(input, &analysis.class_a, &analysis.observable_id);
    let b = collect_measurements(input, &analysis.class_b, &analysis.observable_id);
    let family = input
        .observables
        .iter()
        .find(|item| item.observable_id == analysis.observable_id)
        .unwrap()
        .family;
    let (mean_a, variance_a) = mean_variance(&a);
    let (mean_b, variance_b) = mean_variance(&b);
    let difference = mean_a - mean_b;
    let (welch_t, degrees, p_value, low, high) = welch(&a, &b, analysis.thresholds.alpha);
    let cohens_d = cohens_d(&a, &b, mean_a, mean_b, variance_a, variance_b);
    let power = estimated_power(a.len(), b.len(), cohens_d.abs(), analysis.thresholds.alpha);
    let permutation = permutation_p_value(
        &a,
        &b,
        analysis.thresholds.permutation_iterations,
        analysis.thresholds.permutation_seed,
    );
    let exact = exact_distinguisher(input, analysis, family);
    let mut reasons = Vec::new();
    if a.len() < analysis.thresholds.minimum_samples_per_class as usize
        || b.len() < analysis.thresholds.minimum_samples_per_class as usize
    {
        reasons.push("minimum-sample-gate-not-met".into());
    }
    if power < analysis.thresholds.minimum_power {
        reasons.push("minimum-power-gate-not-met".into());
    }
    if exact.exists {
        reasons.push("exact-distinguisher".into());
    }
    ObservableResult {
        analysis_id: analysis.analysis_id.clone(),
        observable_id: analysis.observable_id.clone(),
        family,
        verdict: AnalysisVerdict::Inconclusive,
        qualification_status: QualificationStatus::Blocked,
        sample_count_a: a.len(),
        sample_count_b: b.len(),
        mean_a,
        mean_b,
        mean_difference: difference,
        welch_t,
        welch_degrees_of_freedom: degrees,
        welch_p_value: p_value,
        corrected_p_value: p_value,
        permutation_p_value: permutation,
        cohens_d,
        confidence_low: low,
        confidence_high: high,
        estimated_power: power,
        exact_distinguisher: exact,
        reasons,
        replay_seed: analysis.thresholds.permutation_seed,
    }
}

fn apply_multiple_testing_correction(
    results: &mut [ObservableResult],
    analyses: &[ObservableAnalysis],
) {
    let mut groups: BTreeMap<MultipleTestingCorrection, Vec<usize>> = BTreeMap::new();
    for (index, analysis) in analyses.iter().enumerate() {
        groups
            .entry(analysis.thresholds.correction)
            .or_default()
            .push(index);
    }
    for (method, indexes) in groups {
        let count = indexes.len();
        match method {
            MultipleTestingCorrection::Bonferroni => {
                for index in indexes {
                    results[index].corrected_p_value =
                        (results[index].welch_p_value * count as f64).min(1.0);
                }
            }
            MultipleTestingCorrection::BenjaminiHochberg => {
                let mut ranked = indexes;
                ranked.sort_by(|left, right| {
                    results[*left]
                        .welch_p_value
                        .total_cmp(&results[*right].welch_p_value)
                        .then_with(|| results[*left].analysis_id.cmp(&results[*right].analysis_id))
                });
                let mut prior = 1.0;
                for (reverse_rank, index) in ranked.into_iter().rev().enumerate() {
                    let rank = count - reverse_rank;
                    let adjusted = (results[index].welch_p_value * count as f64 / rank as f64)
                        .min(prior)
                        .min(1.0);
                    results[index].corrected_p_value = adjusted;
                    prior = adjusted;
                }
            }
        }
    }
}

fn finalize_observable_verdict(result: &mut ObservableResult, analyses: &[ObservableAnalysis]) {
    let thresholds = &analyses
        .iter()
        .find(|item| item.analysis_id == result.analysis_id)
        .unwrap()
        .thresholds;
    if result.sample_count_a < thresholds.minimum_samples_per_class as usize
        || result.sample_count_b < thresholds.minimum_samples_per_class as usize
        || result.estimated_power < thresholds.minimum_power
    {
        result.verdict = AnalysisVerdict::Inconclusive;
        result.qualification_status = QualificationStatus::Blocked;
        return;
    }
    let statistical_leak = result.corrected_p_value <= thresholds.alpha
        && (result.cohens_d.abs() > thresholds.maximum_absolute_cohens_d
            || result.mean_difference.abs() > thresholds.maximum_absolute_mean_difference);
    let permutation_leak = result.permutation_p_value <= thresholds.alpha;
    if result.exact_distinguisher.exists || statistical_leak || permutation_leak {
        if statistical_leak {
            result
                .reasons
                .push("corrected-welch-threshold-crossed".into());
        }
        if permutation_leak {
            result.reasons.push("permutation-threshold-crossed".into());
        }
        result.verdict = AnalysisVerdict::LeakDetected;
        result.qualification_status = QualificationStatus::Blocked;
    } else {
        result.verdict = AnalysisVerdict::NoStatisticalLeakageDetected;
        result.qualification_status = QualificationStatus::MeasurementEvidenceOnly;
    }
    result.reasons.sort();
}

fn analyze_classifier(
    analysis: &ClassifierAnalysis,
    input: &PrivacyAnalysisInput,
) -> ClassifierResult {
    let select = |class_id: &str, split: SampleSplit| -> Vec<&MeasurementSample> {
        input
            .samples
            .iter()
            .filter(|sample| sample.secret_class_id == class_id && sample.split == split)
            .collect()
    };
    let train_a = select(&analysis.class_a, SampleSplit::Train);
    let train_b = select(&analysis.class_b, SampleSplit::Train);
    let test_a = select(&analysis.class_a, SampleSplit::Test);
    let test_b = select(&analysis.class_b, SampleSplit::Test);
    let mut reasons = Vec::new();
    if train_a.len() < analysis.minimum_train_samples_per_class as usize
        || train_b.len() < analysis.minimum_train_samples_per_class as usize
        || test_a.len() < analysis.minimum_test_samples_per_class as usize
        || test_b.len() < analysis.minimum_test_samples_per_class as usize
    {
        reasons.push("minimum-sample-gate-not-met".into());
    }
    let centroid_a = centroid(&train_a, &analysis.feature_ids);
    let centroid_b = centroid(&train_b, &analysis.feature_ids);
    let correct_a = test_a
        .iter()
        .filter(|sample| classify(sample, &analysis.feature_ids, &centroid_a, &centroid_b) == 0)
        .count();
    let correct_b = test_b
        .iter()
        .filter(|sample| classify(sample, &analysis.feature_ids, &centroid_a, &centroid_b) == 1)
        .count();
    let accuracy_a = ratio(correct_a, test_a.len());
    let accuracy_b = ratio(correct_b, test_b.len());
    let balanced = (accuracy_a + accuracy_b) / 2.0;
    let test_total = test_a.len() + test_b.len();
    let power = classifier_power(test_total, balanced, analysis.alpha);
    if power < analysis.minimum_power {
        reasons.push("minimum-power-gate-not-met".into());
    }
    let (low, high) = wilson_interval(correct_a + correct_b, test_total, analysis.alpha);
    let inadequate = !reasons.is_empty();
    let verdict = if inadequate {
        AnalysisVerdict::Inconclusive
    } else if balanced > analysis.maximum_balanced_accuracy {
        reasons.push("classifier-accuracy-threshold-crossed".into());
        AnalysisVerdict::LeakDetected
    } else {
        AnalysisVerdict::NoStatisticalLeakageDetected
    };
    reasons.sort();
    ClassifierResult {
        analysis_id: analysis.analysis_id.clone(),
        verdict,
        qualification_status: qualification_for(verdict),
        train_count_a: train_a.len(),
        train_count_b: train_b.len(),
        test_count_a: test_a.len(),
        test_count_b: test_b.len(),
        balanced_accuracy: balanced,
        confidence_low: low,
        confidence_high: high,
        estimated_power: power,
        reasons,
    }
}

fn collect_measurements(input: &PrivacyAnalysisInput, class: &str, observable: &str) -> Vec<f64> {
    input
        .samples
        .iter()
        .filter(|sample| sample.secret_class_id == class)
        .map(|sample| sample.measurements[observable])
        .collect()
}

fn exact_distinguisher(
    input: &PrivacyAnalysisInput,
    analysis: &ObservableAnalysis,
    family: ObservableFamily,
) -> ExactDistinguisher {
    let samples: Vec<_> = input
        .samples
        .iter()
        .filter(|sample| {
            sample.secret_class_id == analysis.class_a || sample.secret_class_id == analysis.class_b
        })
        .collect();
    let mut values: BTreeMap<u64, BTreeSet<&str>> = BTreeMap::new();
    if family == ObservableFamily::Size {
        for sample in &samples {
            values
                .entry(sample.measurements[analysis.observable_id.as_str()].to_bits())
                .or_default()
                .insert(&sample.secret_class_id);
        }
    }
    let size_unique = values.values().filter(|classes| classes.len() == 1).count();
    let mut tags: BTreeMap<String, Vec<&MeasurementSample>> = BTreeMap::new();
    for sample in &samples {
        for (name, value) in &sample.linkability_tags {
            tags.entry(format!("{name}={value}"))
                .or_default()
                .push(sample);
        }
    }
    let reused = tags.values().filter(|items| items.len() > 1).count();
    let tag_unique = tags
        .values()
        .filter(|items| {
            items.len() > 1
                && items
                    .iter()
                    .map(|sample| sample.secret_class_id.as_str())
                    .collect::<BTreeSet<_>>()
                    .len()
                    == 1
        })
        .count();
    ExactDistinguisher {
        size_value_count: values.len(),
        size_values_unique_to_one_secret: size_unique,
        linkability_tag_count: tags.len(),
        linkability_tags_reused: reused,
        linkability_tags_unique_to_one_secret: tag_unique,
        exists: size_unique > 0 || tag_unique > 0,
    }
}

fn mean_variance(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = if values.len() < 2 {
        0.0
    } else {
        values
            .iter()
            .map(|value| (value - mean).powi(2))
            .sum::<f64>()
            / (values.len() - 1) as f64
    };
    (mean, variance)
}
fn welch(a: &[f64], b: &[f64], alpha: f64) -> (f64, f64, f64, f64, f64) {
    let (ma, va) = mean_variance(a);
    let (mb, vb) = mean_variance(b);
    if a.len() < 2 || b.len() < 2 {
        return (0.0, 0.0, 1.0, f64::NEG_INFINITY, f64::INFINITY);
    }
    let aa = va / a.len() as f64;
    let bb = vb / b.len() as f64;
    let se = (aa + bb).sqrt();
    if se == 0.0 {
        let p = if ma == mb { 1.0 } else { 0.0 };
        return (
            if ma == mb { 0.0 } else { f64::INFINITY },
            f64::INFINITY,
            p,
            ma - mb,
            ma - mb,
        );
    }
    let t = (ma - mb) / se;
    let df =
        (aa + bb).powi(2) / (aa.powi(2) / (a.len() - 1) as f64 + bb.powi(2) / (b.len() - 1) as f64);
    let p = student_two_sided_p(t.abs(), df);
    let critical = inverse_student_two_sided(alpha, df);
    (t, df, p, ma - mb - critical * se, ma - mb + critical * se)
}
fn cohens_d(a: &[f64], b: &[f64], ma: f64, mb: f64, va: f64, vb: f64) -> f64 {
    if a.len() < 2 || b.len() < 2 {
        return 0.0;
    }
    let pooled = (((a.len() - 1) as f64 * va + (b.len() - 1) as f64 * vb)
        / (a.len() + b.len() - 2) as f64)
        .sqrt();
    if pooled == 0.0 {
        if ma == mb { 0.0 } else { f64::INFINITY }
    } else {
        (ma - mb) / pooled
    }
}
fn estimated_power(na: usize, nb: usize, d: f64, alpha: f64) -> f64 {
    if na == 0 || nb == 0 || !d.is_finite() {
        return if d.is_infinite() { 1.0 } else { 0.0 };
    }
    let noncentrality = (na as f64 * nb as f64 / (na + nb) as f64).sqrt() * d;
    normal_cdf(noncentrality - inverse_normal_cdf(1.0 - alpha / 2.0))
}
fn permutation_p_value(a: &[f64], b: &[f64], iterations: u32, seed: u64) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 1.0;
    }
    let observed =
        (a.iter().sum::<f64>() / a.len() as f64 - b.iter().sum::<f64>() / b.len() as f64).abs();
    let mut values = a.iter().chain(b).copied().collect::<Vec<_>>();
    let split = a.len();
    let mut rng = SplitMix64(seed);
    let mut extreme = 0u32;
    for _ in 0..iterations {
        shuffle(&mut values, &mut rng);
        let statistic = (values[..split].iter().sum::<f64>() / split as f64
            - values[split..].iter().sum::<f64>() / (values.len() - split) as f64)
            .abs();
        if statistic >= observed {
            extreme += 1;
        }
    }
    (extreme + 1) as f64 / (iterations + 1) as f64
}
struct SplitMix64(u64);
impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
}
fn shuffle<T>(values: &mut [T], rng: &mut SplitMix64) {
    for index in (1..values.len()).rev() {
        let target = (rng.next() as usize) % (index + 1);
        values.swap(index, target);
    }
}
fn centroid(samples: &[&MeasurementSample], features: &[String]) -> Vec<f64> {
    features
        .iter()
        .map(|feature| {
            if samples.is_empty() {
                0.0
            } else {
                samples
                    .iter()
                    .map(|sample| sample.measurements[feature.as_str()])
                    .sum::<f64>()
                    / samples.len() as f64
            }
        })
        .collect()
}
fn classify(sample: &MeasurementSample, features: &[String], a: &[f64], b: &[f64]) -> usize {
    let (da, db) = features
        .iter()
        .enumerate()
        .fold((0.0, 0.0), |(da, db), (index, feature)| {
            let value = sample.measurements[feature.as_str()];
            (
                da + (value - a[index]).powi(2),
                db + (value - b[index]).powi(2),
            )
        });
    if da <= db { 0 } else { 1 }
}
fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}
fn classifier_power(n: usize, accuracy: f64, alpha: f64) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let signal = (accuracy - 0.5).abs() * 2.0 * (n as f64).sqrt();
    normal_cdf(signal - inverse_normal_cdf(1.0 - alpha / 2.0))
}
fn wilson_interval(successes: usize, n: usize, alpha: f64) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    let z = inverse_normal_cdf(1.0 - alpha / 2.0);
    let p = successes as f64 / n as f64;
    let denominator = 1.0 + z * z / n as f64;
    let center = (p + z * z / (2.0 * n as f64)) / denominator;
    let radius = z
        * ((p * (1.0 - p) / n as f64 + z * z / (4.0 * (n as f64).powi(2))) / denominator.powi(2))
            .sqrt();
    ((center - radius).max(0.0), (center + radius).min(1.0))
}

fn student_two_sided_p(t: f64, df: f64) -> f64 {
    if !t.is_finite() {
        return 0.0;
    }
    if !df.is_finite() {
        return 2.0 * (1.0 - normal_cdf(t));
    }
    regularized_beta(df / (df + t * t), df / 2.0, 0.5).clamp(0.0, 1.0)
}
fn inverse_student_two_sided(alpha: f64, df: f64) -> f64 {
    if !df.is_finite() {
        return inverse_normal_cdf(1.0 - alpha / 2.0);
    }
    let mut low = 0.0;
    let mut high = 1.0;
    while student_two_sided_p(high, df) > alpha {
        high *= 2.0;
    }
    for _ in 0..80 {
        let mid = (low + high) / 2.0;
        if student_two_sided_p(mid, df) > alpha {
            low = mid;
        } else {
            high = mid;
        }
    }
    (low + high) / 2.0
}
fn regularized_beta(x: f64, a: f64, b: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let front =
        (a * x.ln() + b * (1.0 - x).ln() - ln_gamma(a) - ln_gamma(b) + ln_gamma(a + b)).exp();
    if x < (a + 1.0) / (a + b + 2.0) {
        front * beta_fraction(x, a, b) / a
    } else {
        1.0 - front * beta_fraction(1.0 - x, b, a) / b
    }
}
fn beta_fraction(x: f64, a: f64, b: f64) -> f64 {
    const EPS: f64 = 3e-14;
    const MIN: f64 = 1e-300;
    let qab = a + b;
    let qap = a + 1.0;
    let qam = a - 1.0;
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < MIN {
        d = MIN;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=200 {
        let m2 = 2.0 * m as f64;
        let mut aa = m as f64 * (b - m as f64) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if d.abs() < MIN {
            d = MIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < MIN {
            c = MIN;
        }
        d = 1.0 / d;
        h *= d * c;
        aa = -(a + m as f64) * (qab + m as f64) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < MIN {
            d = MIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < MIN {
            c = MIN;
        }
        d = 1.0 / d;
        let delta = d * c;
        h *= delta;
        if (delta - 1.0).abs() < EPS {
            break;
        }
    }
    h
}
fn ln_gamma(value: f64) -> f64 {
    let coefficients = [
        676.5203681218851,
        -1259.1392167224028,
        771.3234287776531,
        -176.6150291621406,
        12.507343278686905,
        -0.13857109526572012,
        9.984369578019572e-6,
        1.5056327351493116e-7,
    ];
    if value < 0.5 {
        return std::f64::consts::PI.ln()
            - (std::f64::consts::PI * value).sin().ln()
            - ln_gamma(1.0 - value);
    }
    let z = value - 1.0;
    let mut x = 0.9999999999998099;
    for (index, coefficient) in coefficients.iter().enumerate() {
        x += coefficient / (z + index as f64 + 1.0);
    }
    let t = z + coefficients.len() as f64 - 0.5;
    0.5 * (2.0 * std::f64::consts::PI).ln() + (z + 0.5) * t.ln() - t + x.ln()
}
fn normal_cdf(value: f64) -> f64 {
    0.5 * (1.0 + erf(value / 2.0_f64.sqrt()))
}
fn erf(value: f64) -> f64 {
    let sign = if value < 0.0 { -1.0 } else { 1.0 };
    let x = value.abs();
    let t = 1.0 / (1.0 + 0.3275911 * x);
    let polynomial = ((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t
        + 0.254829592)
        * t;
    sign * (1.0 - polynomial * (-x * x).exp())
}
fn inverse_normal_cdf(probability: f64) -> f64 {
    let p = probability.clamp(1e-15, 1.0 - 1e-15);
    let a = [
        -39.69683028665376,
        220.9460984245205,
        -275.9285104469687,
        138.357751867269,
        -30.66479806614716,
        2.506628277459239,
    ];
    let b = [
        -54.47609879822406,
        161.5858368580409,
        -155.6989798598866,
        66.80131188771972,
        -13.28068155288572,
    ];
    let c = [
        -0.007784894002430293,
        -0.3223964580411365,
        -2.400758277161838,
        -2.549732539343734,
        4.374664141464968,
        2.938163982698783,
    ];
    let d = [
        0.007784695709041462,
        0.3224671290700398,
        2.445134137142996,
        3.754408661907416,
    ];
    if p < 0.02425 {
        let q = (-2.0 * p.ln()).sqrt();
        return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5])
            / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0);
    }
    if p > 0.97575 {
        return -inverse_normal_cdf(1.0 - p);
    }
    let q = p - 0.5;
    let r = q * q;
    (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q
        / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1.0)
}

fn combine_verdicts(values: impl IntoIterator<Item = AnalysisVerdict>) -> AnalysisVerdict {
    let mut outcome = AnalysisVerdict::NoStatisticalLeakageDetected;
    for value in values {
        if value == AnalysisVerdict::LeakDetected {
            return AnalysisVerdict::LeakDetected;
        }
        if value == AnalysisVerdict::Inconclusive {
            outcome = AnalysisVerdict::Inconclusive;
        }
    }
    outcome
}
fn qualification_for(verdict: AnalysisVerdict) -> QualificationStatus {
    if verdict == AnalysisVerdict::NoStatisticalLeakageDetected {
        QualificationStatus::MeasurementEvidenceOnly
    } else {
        QualificationStatus::Blocked
    }
}
fn hash_canonical<T: Serialize>(value: &T) -> Result<String, PrivacyError> {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .map_err(|error| PrivacyError::Canonical(error.to_string()))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}
fn valid_id(kind: &'static str, id: &str) -> Result<(), PrivacyError> {
    if !id.is_empty()
        && id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'-' | b'_'))
        })
    {
        Ok(())
    } else {
        Err(PrivacyError::Invalid {
            kind,
            id: id.into(),
        })
    }
}
fn nonempty_unique<'a>(
    kind: &'static str,
    values: impl Iterator<Item = &'a str>,
) -> Result<(), PrivacyError> {
    let mut seen = BTreeSet::new();
    let mut count = 0;
    for value in values {
        valid_id(kind, value)?;
        if !seen.insert(value) {
            return Err(PrivacyError::Duplicate {
                kind,
                id: value.into(),
            });
        }
        count += 1;
    }
    if count == 0 {
        return Err(PrivacyError::Invalid {
            kind,
            id: "empty".into(),
        });
    }
    Ok(())
}
fn duplicate_strings(values: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value))
}
fn missing(kind: &'static str, owner: &str, id: &str) -> PrivacyError {
    PrivacyError::MissingReference {
        kind,
        owner: owner.into(),
        id: id.into(),
    }
}
fn sha256_text(value: &str) -> bool {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn unit_interval(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}
fn open_unit_interval(value: f64) -> bool {
    value.is_finite() && value > 0.0 && value < 1.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> PrivacyAnalysisInput {
        let classes = vec![
            SecretClass {
                class_id: "secret.a".into(),
                description: "A".into(),
            },
            SecretClass {
                class_id: "secret.b".into(),
                description: "B".into(),
            },
        ];
        let mut samples = Vec::new();
        for (class, base) in [("secret.a", 100.0), ("secret.b", 100.0)] {
            for index in 0..12 {
                let split = if index < 6 {
                    SampleSplit::Train
                } else {
                    SampleSplit::Test
                };
                samples.push(sample(
                    format!("{class}.{index}"),
                    format!("capture.{class}.{index}"),
                    class,
                    split,
                    base + (index % 3) as f64,
                    200.0 + (index % 2) as f64,
                ));
            }
        }
        PrivacyAnalysisInput {
            schema_version: PRIVACY_INPUT_SCHEMA_V1.into(),
            analysis_id: "privacy.run".into(),
            hypothesis: Hypothesis {
                hypothesis_id: "hypothesis.one".into(),
                statement: "Measurements are assessed without claiming cryptographic privacy."
                    .into(),
                cryptographic_privacy_not_established: true,
            },
            secret_classes: classes,
            public_classes: vec![PublicClass {
                class_id: "network".into(),
                allowed_values: vec!["chipnet".into()],
            }],
            observables: vec![
                ObservableDefinition {
                    observable_id: "timing".into(),
                    family: ObservableFamily::Timing,
                    unit: "ns".into(),
                },
                ObservableDefinition {
                    observable_id: "size".into(),
                    family: ObservableFamily::Size,
                    unit: "bytes".into(),
                },
            ],
            provenance: vec![ProvenanceRecord {
                provenance_id: "source.one".into(),
                status: ProvenanceStatus::Verified,
                source: "captured locally".into(),
                sha256: "a".repeat(64),
            }],
            samples,
            analyses: vec![analysis("timing"), analysis("size")],
            classifiers: vec![ClassifierAnalysis {
                analysis_id: "classifier.one".into(),
                class_a: "secret.a".into(),
                class_b: "secret.b".into(),
                feature_ids: vec!["timing".into(), "size".into()],
                minimum_train_samples_per_class: 4,
                minimum_test_samples_per_class: 4,
                minimum_power: 0.01,
                maximum_balanced_accuracy: 0.9,
                alpha: 0.05,
            }],
        }
    }
    fn sample(
        id: String,
        capture: String,
        class: &str,
        split: SampleSplit,
        timing: f64,
        size: f64,
    ) -> MeasurementSample {
        MeasurementSample {
            sample_id: id,
            capture_id: capture,
            secret_class_id: class.into(),
            split,
            public_context: BTreeMap::from([("network".into(), "chipnet".into())]),
            provenance_id: "source.one".into(),
            measurements: BTreeMap::from([("timing".into(), timing), ("size".into(), size)]),
            linkability_tags: BTreeMap::new(),
        }
    }
    fn analysis(observable: &str) -> ObservableAnalysis {
        ObservableAnalysis {
            analysis_id: format!("analysis.{observable}"),
            observable_id: observable.into(),
            class_a: "secret.a".into(),
            class_b: "secret.b".into(),
            thresholds: StatisticalThresholds {
                minimum_samples_per_class: 8,
                minimum_power: 0.01,
                alpha: 0.05,
                maximum_absolute_cohens_d: 0.8,
                maximum_absolute_mean_difference: 10.0,
                permutation_iterations: 99,
                permutation_seed: 77,
                correction: MultipleTestingCorrection::Bonferroni,
            },
        }
    }

    #[test]
    fn known_leak_is_detected_and_never_qualifies() {
        let mut value = input();
        for sample in &mut value.samples {
            if sample.secret_class_id == "secret.b" {
                sample.measurements.insert("timing".into(), 1000.0);
            }
        }
        let report = analyze(&value).unwrap();
        assert_eq!(
            report
                .observable_results
                .iter()
                .find(|x| x.observable_id == "timing")
                .unwrap()
                .verdict,
            AnalysisVerdict::LeakDetected
        );
        assert_eq!(report.qualification_status, QualificationStatus::Blocked);
        assert_eq!(
            report.cryptographic_privacy_claim,
            CryptographicPrivacyClaim::NotEstablishedByStatisticalAnalysis
        );
    }
    #[test]
    fn no_leak_is_measurement_evidence_only() {
        let report = analyze(&input()).unwrap();
        assert!(
            report
                .observable_results
                .iter()
                .all(|result| result.verdict == AnalysisVerdict::NoStatisticalLeakageDetected)
        );
        assert_eq!(
            report.qualification_status,
            QualificationStatus::MeasurementEvidenceOnly
        );
    }
    #[test]
    fn confounding_and_missing_provenance_are_rejected() {
        let mut value = input();
        value.samples[1]
            .public_context
            .insert("network".into(), "mainnet".into());
        assert!(matches!(
            analyze(&value),
            Err(PrivacyError::MixedPublicContext { .. } | PrivacyError::Invalid { .. })
        ));
        let mut value = input();
        value.samples[0].provenance_id = "absent".into();
        assert!(matches!(
            analyze(&value),
            Err(PrivacyError::MissingReference { .. })
        ));
    }
    #[test]
    fn train_test_leakage_is_rejected() {
        let mut value = input();
        value.samples[7].capture_id = value.samples[0].capture_id.clone();
        assert!(matches!(
            analyze(&value),
            Err(PrivacyError::TrainTestLeakage { .. })
        ));
    }
    #[test]
    fn permutation_seed_and_replay_hash_are_deterministic() {
        let left = analyze(&input()).unwrap();
        let right = analyze(&input()).unwrap();
        assert_eq!(left, right);
        assert!(left.replay_sha256.starts_with("sha256:"));
    }
    #[test]
    fn low_power_is_inconclusive_and_blocks() {
        let mut value = input();
        value.analyses[0].thresholds.minimum_power = 0.99;
        let report = analyze(&value).unwrap();
        assert_eq!(
            report
                .observable_results
                .iter()
                .find(|result| result.analysis_id == "analysis.timing")
                .unwrap()
                .verdict,
            AnalysisVerdict::Inconclusive
        );
        assert_eq!(
            report
                .observable_results
                .iter()
                .find(|result| result.analysis_id == "analysis.timing")
                .unwrap()
                .qualification_status,
            QualificationStatus::Blocked
        );
    }
    #[test]
    fn bonferroni_correction_and_threshold_boundary_are_applied() {
        let mut value = input();
        value.analyses[0]
            .thresholds
            .maximum_absolute_mean_difference = 0.0;
        value.analyses[0].thresholds.maximum_absolute_cohens_d = 0.0;
        let report = analyze(&value).unwrap();
        assert!(
            report
                .observable_results
                .iter()
                .all(|item| item.corrected_p_value >= item.welch_p_value)
        );
        let mut boundary = input();
        boundary.analyses[0].thresholds.minimum_samples_per_class = 12;
        assert_eq!(
            analyze(&boundary)
                .unwrap()
                .observable_results
                .iter()
                .find(|result| result.analysis_id == "analysis.timing")
                .unwrap()
                .verdict,
            AnalysisVerdict::NoStatisticalLeakageDetected
        );
    }
    #[test]
    fn malformed_samples_and_synthetic_provenance_are_rejected() {
        let mut value = input();
        value.samples[0].measurements.insert("extra".into(), 1.0);
        assert!(matches!(
            analyze(&value),
            Err(PrivacyError::Invalid {
                kind: "measurements",
                ..
            })
        ));
        let mut value = input();
        value.provenance[0].status = ProvenanceStatus::Synthetic;
        assert!(matches!(
            analyze(&value),
            Err(PrivacyError::UnverifiedProvenance { .. })
        ));
    }
}
