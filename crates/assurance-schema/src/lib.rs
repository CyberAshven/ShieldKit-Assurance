use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PACK_SCHEMA_V1: &str = "shieldkit-assurance-pack/v1";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssurancePack {
    pub schema_version: String,
    pub pack_id: String,
    pub pack_version: String,
    pub protocol_identity: String,
    pub subject: Subject,
    pub claims: Vec<Claim>,
    pub obligations: Vec<Obligation>,
    pub tests: Vec<TestDefinition>,
    pub suites: Vec<SuiteDefinition>,
    #[serde(default)]
    pub adapters: Vec<ComponentDefinition>,
    #[serde(default)]
    pub oracles: Vec<OracleDefinition>,
    #[serde(default)]
    pub generators: Vec<ComponentDefinition>,
    #[serde(default)]
    pub mutators: Vec<ComponentDefinition>,
    #[serde(default)]
    pub formal_models: Vec<ComponentDefinition>,
    #[serde(default)]
    pub backends: Vec<ComponentDefinition>,
    #[serde(default)]
    pub trust_profiles: Vec<TrustProfile>,
    pub release_policy: ReleasePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Subject {
    pub repository: String,
    pub revision: String,
    pub tree: String,
    #[serde(default)]
    pub implementation_roots: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Claim {
    pub claim_id: String,
    pub statement: String,
    pub category: String,
    pub severity: Severity,
    pub applicability: String,
    #[serde(default)]
    pub assumptions: Vec<String>,
    pub obligation_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Obligation {
    pub obligation_id: String,
    pub claim_ids: Vec<String>,
    pub modality: Modality,
    pub mandatory: bool,
    #[serde(default)]
    pub dependency_ids: Vec<String>,
    #[serde(default)]
    pub component_ids: Vec<String>,
    pub oracle_policy: OraclePolicy,
    pub evidence: EvidenceRequirement,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    Vector,
    Property,
    Exhaustive,
    Differential,
    Metamorphic,
    Fuzz,
    Mutation,
    Formal,
    Fault,
    Privacy,
    Performance,
    Live,
    Provenance,
    Audit,
    Ux,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OraclePolicy {
    #[serde(default)]
    pub oracle_ids: Vec<String>,
    pub minimum_independent: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceRequirement {
    pub qualification: bool,
    pub allow_synthetic: bool,
    #[serde(default)]
    pub required_artifacts: Vec<String>,
    #[serde(default)]
    pub required_signatures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TestDefinition {
    pub test_id: String,
    pub source: String,
    pub executor_id: String,
    pub obligation_ids: Vec<String>,
    pub classification: TestClassification,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestClassification {
    Regression,
    Independent,
    FrameworkSelfTest,
    Historical,
    Qualification,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SuiteDefinition {
    pub suite_id: String,
    #[serde(default)]
    pub obligation_ids: Vec<String>,
    #[serde(default)]
    pub test_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ComponentDefinition {
    pub component_id: String,
    pub implementation_root: String,
    pub command: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OracleDefinition {
    pub oracle_id: String,
    pub implementation_root: String,
    pub independence_class: String,
    pub command: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TrustProfile {
    pub trust_profile_id: String,
    pub statement: String,
    pub participant_independence_established: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReleasePolicy {
    pub required_suite_ids: Vec<String>,
    pub required_axes: Vec<String>,
    #[serde(default)]
    pub forbidden_case_statuses: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PackValidationError {
    #[error("unsupported pack schema: {0}")]
    UnsupportedSchema(String),
    #[error("invalid identifier at {field}: {value}")]
    InvalidIdentifier { field: String, value: String },
    #[error("duplicate {kind} identifier: {id}")]
    DuplicateId { kind: String, id: String },
    #[error("missing {kind} reference at {field}: {id}")]
    MissingReference {
        kind: String,
        field: String,
        id: String,
    },
    #[error("claim/obligation mapping is not reciprocal: {claim_id} <-> {obligation_id}")]
    NonReciprocalMapping {
        claim_id: String,
        obligation_id: String,
    },
    #[error("test has no obligation mapping: {0}")]
    UnmappedTest(String),
    #[error("qualification obligation permits synthetic evidence: {0}")]
    SyntheticQualification(String),
    #[error("qualification obligation has no required raw artifact: {0}")]
    QualificationWithoutArtifact(String),
    #[error("oracle independence policy cannot be met: {0}")]
    InsufficientIndependentOracles(String),
    #[error("mandatory obligation is absent from all required release suites: {0}")]
    MandatoryObligationOutsideRelease(String),
    #[error("obligation dependency cycle includes: {0}")]
    DependencyCycle(String),
    #[error("empty required field: {0}")]
    EmptyField(String),
}

impl AssurancePack {
    pub fn validate(&self) -> Result<(), PackValidationError> {
        if self.schema_version != PACK_SCHEMA_V1 {
            return Err(PackValidationError::UnsupportedSchema(
                self.schema_version.clone(),
            ));
        }
        nonempty("packId", &self.pack_id)?;
        nonempty("packVersion", &self.pack_version)?;
        nonempty("protocolIdentity", &self.protocol_identity)?;
        validate_id("packId", &self.pack_id)?;
        nonempty("subject.repository", &self.subject.repository)?;
        nonempty("subject.revision", &self.subject.revision)?;
        nonempty("subject.tree", &self.subject.tree)?;

        let claims = unique_ids(
            "claim",
            self.claims.iter().map(|value| value.claim_id.as_str()),
        )?;
        let obligations = unique_ids(
            "obligation",
            self.obligations
                .iter()
                .map(|value| value.obligation_id.as_str()),
        )?;
        let tests = unique_ids(
            "test",
            self.tests.iter().map(|value| value.test_id.as_str()),
        )?;
        let suites = unique_ids(
            "suite",
            self.suites.iter().map(|value| value.suite_id.as_str()),
        )?;
        let adapters = unique_ids(
            "adapter",
            self.adapters
                .iter()
                .map(|value| value.component_id.as_str()),
        )?;
        let generators = unique_ids(
            "generator",
            self.generators
                .iter()
                .map(|value| value.component_id.as_str()),
        )?;
        let mutators = unique_ids(
            "mutator",
            self.mutators
                .iter()
                .map(|value| value.component_id.as_str()),
        )?;
        let formal_models = unique_ids(
            "formal model",
            self.formal_models
                .iter()
                .map(|value| value.component_id.as_str()),
        )?;
        let backends = unique_ids(
            "backend",
            self.backends
                .iter()
                .map(|value| value.component_id.as_str()),
        )?;
        let oracle_ids = unique_ids(
            "oracle",
            self.oracles.iter().map(|value| value.oracle_id.as_str()),
        )?;
        let _trust_profiles = unique_ids(
            "trust profile",
            self.trust_profiles
                .iter()
                .map(|value| value.trust_profile_id.as_str()),
        )?;

        let mut component_ids = BTreeSet::new();
        for id in adapters
            .iter()
            .chain(generators.iter())
            .chain(mutators.iter())
            .chain(formal_models.iter())
            .chain(backends.iter())
        {
            if !component_ids.insert(id.clone()) {
                return Err(PackValidationError::DuplicateId {
                    kind: "component".into(),
                    id: id.clone(),
                });
            }
        }

        for claim in &self.claims {
            nonempty(
                &format!("claim.{}.statement", claim.claim_id),
                &claim.statement,
            )?;
            nonempty(
                &format!("claim.{}.category", claim.claim_id),
                &claim.category,
            )?;
            nonempty(
                &format!("claim.{}.applicability", claim.claim_id),
                &claim.applicability,
            )?;
            if claim.obligation_ids.is_empty() {
                return Err(PackValidationError::MissingReference {
                    kind: "obligation".into(),
                    field: format!("claim.{}.obligationIds", claim.claim_id),
                    id: "<empty>".into(),
                });
            }
            for obligation_id in &claim.obligation_ids {
                require_ref("obligation", &obligations, &claim.claim_id, obligation_id)?;
                let obligation = self
                    .obligations
                    .iter()
                    .find(|value| value.obligation_id == *obligation_id)
                    .expect("validated obligation reference");
                if !obligation.claim_ids.contains(&claim.claim_id) {
                    return Err(PackValidationError::NonReciprocalMapping {
                        claim_id: claim.claim_id.clone(),
                        obligation_id: obligation_id.clone(),
                    });
                }
            }
        }

        let oracle_by_id: BTreeMap<_, _> = self
            .oracles
            .iter()
            .map(|value| (value.oracle_id.as_str(), value))
            .collect();
        for obligation in &self.obligations {
            if obligation.claim_ids.is_empty() {
                return Err(PackValidationError::MissingReference {
                    kind: "claim".into(),
                    field: format!("obligation.{}.claimIds", obligation.obligation_id),
                    id: "<empty>".into(),
                });
            }
            for claim_id in &obligation.claim_ids {
                require_ref("claim", &claims, &obligation.obligation_id, claim_id)?;
                let claim = self
                    .claims
                    .iter()
                    .find(|value| value.claim_id == *claim_id)
                    .expect("validated claim reference");
                if !claim.obligation_ids.contains(&obligation.obligation_id) {
                    return Err(PackValidationError::NonReciprocalMapping {
                        claim_id: claim_id.clone(),
                        obligation_id: obligation.obligation_id.clone(),
                    });
                }
            }
            for dependency_id in &obligation.dependency_ids {
                require_ref(
                    "obligation dependency",
                    &obligations,
                    &obligation.obligation_id,
                    dependency_id,
                )?;
            }
            for component_id in &obligation.component_ids {
                require_ref(
                    "component",
                    &component_ids,
                    &obligation.obligation_id,
                    component_id,
                )?;
            }
            for oracle_id in &obligation.oracle_policy.oracle_ids {
                require_ref("oracle", &oracle_ids, &obligation.obligation_id, oracle_id)?;
            }
            let independent: BTreeSet<_> = obligation
                .oracle_policy
                .oracle_ids
                .iter()
                .filter_map(|id| oracle_by_id.get(id.as_str()))
                .map(|oracle| oracle.independence_class.as_str())
                .filter(|class| *class != "subject")
                .collect();
            if independent.len() < obligation.oracle_policy.minimum_independent as usize {
                return Err(PackValidationError::InsufficientIndependentOracles(
                    obligation.obligation_id.clone(),
                ));
            }
            if obligation.evidence.qualification && obligation.evidence.allow_synthetic {
                return Err(PackValidationError::SyntheticQualification(
                    obligation.obligation_id.clone(),
                ));
            }
            if obligation.evidence.qualification
                && obligation.evidence.required_artifacts.is_empty()
            {
                return Err(PackValidationError::QualificationWithoutArtifact(
                    obligation.obligation_id.clone(),
                ));
            }
        }

        for test in &self.tests {
            nonempty(&format!("test.{}.source", test.test_id), &test.source)?;
            if test.obligation_ids.is_empty() {
                return Err(PackValidationError::UnmappedTest(test.test_id.clone()));
            }
            require_ref(
                "component",
                &component_ids,
                &test.test_id,
                &test.executor_id,
            )?;
            for obligation_id in &test.obligation_ids {
                require_ref("obligation", &obligations, &test.test_id, obligation_id)?;
            }
        }

        for suite in &self.suites {
            for obligation_id in &suite.obligation_ids {
                require_ref("obligation", &obligations, &suite.suite_id, obligation_id)?;
            }
            for test_id in &suite.test_ids {
                require_ref("test", &tests, &suite.suite_id, test_id)?;
            }
        }
        for suite_id in &self.release_policy.required_suite_ids {
            require_ref("suite", &suites, "releasePolicy.requiredSuiteIds", suite_id)?;
        }

        let release_obligations: BTreeSet<_> = self
            .suites
            .iter()
            .filter(|suite| {
                self.release_policy
                    .required_suite_ids
                    .contains(&suite.suite_id)
            })
            .flat_map(|suite| suite.obligation_ids.iter().cloned())
            .collect();
        for obligation in self.obligations.iter().filter(|value| value.mandatory) {
            if !release_obligations.contains(&obligation.obligation_id) {
                return Err(PackValidationError::MandatoryObligationOutsideRelease(
                    obligation.obligation_id.clone(),
                ));
            }
        }

        validate_dependency_dag(&self.obligations)?;
        Ok(())
    }
}

fn nonempty(field: &str, value: &str) -> Result<(), PackValidationError> {
    if value.trim().is_empty() {
        return Err(PackValidationError::EmptyField(field.into()));
    }
    Ok(())
}

fn validate_id(field: &str, value: &str) -> Result<(), PackValidationError> {
    let valid = !value.is_empty()
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'/' | b'-'))
        });
    if !valid {
        return Err(PackValidationError::InvalidIdentifier {
            field: field.into(),
            value: value.into(),
        });
    }
    Ok(())
}

fn unique_ids<'a>(
    kind: &str,
    values: impl Iterator<Item = &'a str>,
) -> Result<BTreeSet<String>, PackValidationError> {
    let mut result = BTreeSet::new();
    for value in values {
        validate_id(kind, value)?;
        if !result.insert(value.to_owned()) {
            return Err(PackValidationError::DuplicateId {
                kind: kind.into(),
                id: value.into(),
            });
        }
    }
    Ok(result)
}

fn require_ref(
    kind: &str,
    values: &BTreeSet<String>,
    field: &str,
    id: &str,
) -> Result<(), PackValidationError> {
    if !values.contains(id) {
        return Err(PackValidationError::MissingReference {
            kind: kind.into(),
            field: field.into(),
            id: id.into(),
        });
    }
    Ok(())
}

fn validate_dependency_dag(obligations: &[Obligation]) -> Result<(), PackValidationError> {
    let dependencies: BTreeMap<_, _> = obligations
        .iter()
        .map(|value| {
            (
                value.obligation_id.as_str(),
                value.dependency_ids.as_slice(),
            )
        })
        .collect();
    let mut visiting = BTreeSet::new();
    let mut complete = BTreeSet::new();
    fn visit<'a>(
        id: &'a str,
        dependencies: &BTreeMap<&'a str, &'a [String]>,
        visiting: &mut BTreeSet<&'a str>,
        complete: &mut BTreeSet<&'a str>,
    ) -> Result<(), PackValidationError> {
        if complete.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id) {
            return Err(PackValidationError::DependencyCycle(id.into()));
        }
        if let Some(next) = dependencies.get(id) {
            for dependency in *next {
                visit(dependency, dependencies, visiting, complete)?;
            }
        }
        visiting.remove(id);
        complete.insert(id);
        Ok(())
    }
    for obligation in obligations {
        visit(
            &obligation.obligation_id,
            &dependencies,
            &mut visiting,
            &mut complete,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_pack() -> AssurancePack {
        AssurancePack {
            schema_version: PACK_SCHEMA_V1.into(),
            pack_id: "assurance/framework-self-test".into(),
            pack_version: "0.1.0".into(),
            protocol_identity: "framework-contract-only".into(),
            subject: Subject {
                repository: "local:self-test".into(),
                revision: "a".repeat(40),
                tree: "b".repeat(40),
                implementation_roots: vec!["subject".into()],
            },
            claims: vec![Claim {
                claim_id: "framework.pack-validation".into(),
                statement: "Malformed pack graphs are rejected.".into(),
                category: "framework".into(),
                severity: Severity::High,
                applicability: "always".into(),
                assumptions: vec![],
                obligation_ids: vec!["framework.pack-validation.valid".into()],
            }],
            obligations: vec![Obligation {
                obligation_id: "framework.pack-validation.valid".into(),
                claim_ids: vec!["framework.pack-validation".into()],
                modality: Modality::Property,
                mandatory: true,
                dependency_ids: vec![],
                component_ids: vec!["framework.self-test".into()],
                oracle_policy: OraclePolicy {
                    oracle_ids: vec!["framework.schema-oracle".into()],
                    minimum_independent: 1,
                },
                evidence: EvidenceRequirement {
                    qualification: false,
                    allow_synthetic: false,
                    required_artifacts: vec!["test-output".into()],
                    required_signatures: vec![],
                },
            }],
            tests: vec![TestDefinition {
                test_id: "framework.pack-validation.unit".into(),
                source: "crates/assurance-schema/src/lib.rs".into(),
                executor_id: "framework.self-test".into(),
                obligation_ids: vec!["framework.pack-validation.valid".into()],
                classification: TestClassification::FrameworkSelfTest,
            }],
            suites: vec![SuiteDefinition {
                suite_id: "framework.release".into(),
                obligation_ids: vec!["framework.pack-validation.valid".into()],
                test_ids: vec!["framework.pack-validation.unit".into()],
            }],
            adapters: vec![ComponentDefinition {
                component_id: "framework.self-test".into(),
                implementation_root: "subject".into(),
                command: vec!["cargo".into(), "test".into()],
                capabilities: vec![],
            }],
            oracles: vec![OracleDefinition {
                oracle_id: "framework.schema-oracle".into(),
                implementation_root: "independent-schema".into(),
                independence_class: "json-schema".into(),
                command: vec!["schema-check".into()],
                capabilities: vec![],
            }],
            generators: vec![],
            mutators: vec![],
            formal_models: vec![],
            backends: vec![],
            trust_profiles: vec![],
            release_policy: ReleasePolicy {
                required_suite_ids: vec!["framework.release".into()],
                required_axes: vec!["frameworkQualified".into()],
                forbidden_case_statuses: vec!["skip".into()],
            },
        }
    }

    #[test]
    fn accepts_a_complete_reciprocal_graph() {
        valid_pack().validate().unwrap();
    }

    #[test]
    fn rejects_unmapped_tests() {
        let mut pack = valid_pack();
        pack.tests[0].obligation_ids.clear();
        assert_eq!(
            pack.validate(),
            Err(PackValidationError::UnmappedTest(
                "framework.pack-validation.unit".into()
            ))
        );
    }

    #[test]
    fn rejects_synthetic_qualification_evidence() {
        let mut pack = valid_pack();
        pack.obligations[0].evidence.qualification = true;
        pack.obligations[0].evidence.allow_synthetic = true;
        assert_eq!(
            pack.validate(),
            Err(PackValidationError::SyntheticQualification(
                "framework.pack-validation.valid".into()
            ))
        );
    }

    #[test]
    fn rejects_dependency_cycles() {
        let mut pack = valid_pack();
        pack.obligations[0].dependency_ids = vec!["framework.pack-validation.valid".into()];
        assert_eq!(
            pack.validate(),
            Err(PackValidationError::DependencyCycle(
                "framework.pack-validation.valid".into()
            ))
        );
    }
}
