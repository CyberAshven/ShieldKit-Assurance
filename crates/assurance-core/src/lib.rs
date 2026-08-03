use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use shieldkit_assurance_schema::{AssurancePack, Modality, PackValidationError};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExecutionPlan {
    pub pack_id: String,
    pub pack_version: String,
    pub suite_id: String,
    pub subject_revision: String,
    pub subject_tree: String,
    pub obligations: Vec<PlannedObligation>,
    pub test_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlannedObligation {
    pub obligation_id: String,
    pub modality: Modality,
    pub mandatory: bool,
}

#[derive(Debug, Error)]
pub enum PlanError {
    #[error(transparent)]
    InvalidPack(#[from] PackValidationError),
    #[error("unknown suite: {0}")]
    UnknownSuite(String),
}

pub fn build_execution_plan(
    pack: &AssurancePack,
    suite_id: &str,
) -> Result<ExecutionPlan, PlanError> {
    pack.validate()?;
    let suite = pack
        .suites
        .iter()
        .find(|value| value.suite_id == suite_id)
        .ok_or_else(|| PlanError::UnknownSuite(suite_id.into()))?;
    let obligations: BTreeMap<_, _> = pack
        .obligations
        .iter()
        .map(|value| (value.obligation_id.as_str(), value))
        .collect();
    let mut selected = BTreeSet::new();
    fn include(
        id: &str,
        obligations: &BTreeMap<&str, &shieldkit_assurance_schema::Obligation>,
        selected: &mut BTreeSet<String>,
    ) {
        if !selected.insert(id.into()) {
            return;
        }
        for dependency in &obligations[id].dependency_ids {
            include(dependency, obligations, selected);
        }
    }
    for id in &suite.obligation_ids {
        include(id, &obligations, &mut selected);
    }

    let mut ordered = Vec::new();
    let mut complete = BTreeSet::new();
    fn order(
        id: &str,
        obligations: &BTreeMap<&str, &shieldkit_assurance_schema::Obligation>,
        selected: &BTreeSet<String>,
        complete: &mut BTreeSet<String>,
        ordered: &mut Vec<PlannedObligation>,
    ) {
        if complete.contains(id) {
            return;
        }
        for dependency in &obligations[id].dependency_ids {
            if selected.contains(dependency) {
                order(dependency, obligations, selected, complete, ordered);
            }
        }
        let obligation = obligations[id];
        ordered.push(PlannedObligation {
            obligation_id: obligation.obligation_id.clone(),
            modality: obligation.modality,
            mandatory: obligation.mandatory,
        });
        complete.insert(id.into());
    }
    for id in &suite.obligation_ids {
        order(id, &obligations, &selected, &mut complete, &mut ordered);
    }

    let selected_tests: BTreeSet<_> = suite.test_ids.iter().cloned().collect();
    Ok(ExecutionPlan {
        pack_id: pack.pack_id.clone(),
        pack_version: pack.pack_version.clone(),
        suite_id: suite_id.into(),
        subject_revision: pack.subject.revision.clone(),
        subject_tree: pack.subject.tree.clone(),
        obligations: ordered,
        test_ids: selected_tests.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use shieldkit_assurance_schema::{
        Claim, ComponentDefinition, EvidenceRequirement, Modality, Obligation, OracleDefinition,
        OraclePolicy, PACK_SCHEMA_V1, ReleasePolicy, Severity, Subject, SuiteDefinition,
        TestClassification, TestDefinition,
    };

    use super::*;

    fn pack() -> AssurancePack {
        let obligation = |id: &str, dependencies: Vec<String>| Obligation {
            obligation_id: id.into(),
            claim_ids: vec!["claim".into()],
            modality: Modality::Property,
            mandatory: true,
            dependency_ids: dependencies,
            component_ids: vec!["executor".into()],
            oracle_policy: OraclePolicy {
                oracle_ids: vec!["oracle".into()],
                minimum_independent: 1,
            },
            evidence: EvidenceRequirement {
                qualification: false,
                allow_synthetic: false,
                required_artifacts: vec!["raw".into()],
                required_signatures: vec![],
            },
        };
        AssurancePack {
            schema_version: PACK_SCHEMA_V1.into(),
            pack_id: "pack".into(),
            pack_version: "1".into(),
            protocol_identity: "protocol".into(),
            subject: Subject {
                repository: "local".into(),
                revision: "a".repeat(40),
                tree: "b".repeat(40),
                implementation_roots: vec!["subject".into()],
            },
            claims: vec![Claim {
                claim_id: "claim".into(),
                statement: "Dependency order is preserved.".into(),
                category: "framework".into(),
                severity: Severity::High,
                applicability: "always".into(),
                assumptions: vec![],
                obligation_ids: vec!["first".into(), "second".into()],
            }],
            obligations: vec![
                obligation("first", vec![]),
                obligation("second", vec!["first".into()]),
            ],
            tests: vec![TestDefinition {
                test_id: "test".into(),
                source: "source".into(),
                executor_id: "executor".into(),
                obligation_ids: vec!["first".into(), "second".into()],
                classification: TestClassification::FrameworkSelfTest,
            }],
            suites: vec![SuiteDefinition {
                suite_id: "release".into(),
                obligation_ids: vec!["second".into(), "first".into()],
                test_ids: vec!["test".into()],
            }],
            adapters: vec![ComponentDefinition {
                component_id: "executor".into(),
                implementation_root: "subject".into(),
                command: vec!["run".into()],
                capabilities: vec![],
            }],
            oracles: vec![OracleDefinition {
                oracle_id: "oracle".into(),
                implementation_root: "oracle".into(),
                independence_class: "independent".into(),
                command: vec!["verify".into()],
                capabilities: vec![],
            }],
            generators: vec![],
            mutators: vec![],
            formal_models: vec![],
            backends: vec![],
            trust_profiles: vec![],
            release_policy: ReleasePolicy {
                required_suite_ids: vec!["release".into()],
                required_axes: vec!["frameworkQualified".into()],
                forbidden_case_statuses: vec!["skip".into()],
            },
        }
    }

    #[test]
    fn plans_dependencies_once_before_consumers() {
        let plan = build_execution_plan(&pack(), "release").unwrap();
        assert_eq!(
            plan.obligations
                .iter()
                .map(|value| value.obligation_id.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        assert_eq!(plan.test_ids, vec!["test"]);
    }
}
