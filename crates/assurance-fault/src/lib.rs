//! Protocol-neutral, deterministic fault-simulation coordination.
//!
//! This crate does not implement a network, filesystem, process manager, clock,
//! or protocol. It instead makes the externally supplied adapter's observations
//! replayable, causally constrained, coverage-accounted, and fail-closed.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const DEFINITION_SCHEMA_V1: &str = "shieldkit-assurance-fault-definition/v1";
pub const SCHEDULE_SCHEMA_V1: &str = "shieldkit-assurance-fault-schedule/v1";
pub const REPLAY_SCHEMA_V1: &str = "shieldkit-assurance-fault-replay/v1";
pub const OBSERVATION_SCHEMA_V1: &str = "shieldkit-assurance-fault-observation/v1";
pub const EVALUATION_SCHEMA_V1: &str = "shieldkit-assurance-fault-evaluation/v1";
pub const REPORT_SCHEMA_V1: &str = "shieldkit-assurance-fault-report/v1";
pub const SHRINK_SCHEMA_V1: &str = "shieldkit-assurance-fault-shrink/v1";

const DEFINITION_DOMAIN: &[u8] = b"shieldkit-assurance/fault-definition/v1\0";
const SEED_DOMAIN: &[u8] = b"shieldkit-assurance/fault-seed/v1\0";
const FAULT_DOMAIN: &[u8] = b"shieldkit-assurance/fault-instance/v1\0";
const SCHEDULE_DOMAIN: &[u8] = b"shieldkit-assurance/fault-schedule/v1\0";
const EVENT_DOMAIN: &[u8] = b"shieldkit-assurance/fault-event/v1\0";
const OBSERVATION_DOMAIN: &[u8] = b"shieldkit-assurance/fault-observation/v1\0";
const EVALUATION_DOMAIN: &[u8] = b"shieldkit-assurance/fault-evaluation/v1\0";
const REPLAY_DOMAIN: &[u8] = b"shieldkit-assurance/fault-replay/v1\0";
const REPORT_DOMAIN: &[u8] = b"shieldkit-assurance/fault-report/v1\0";
const SHRINK_DOMAIN: &[u8] = b"shieldkit-assurance/fault-shrink/v1\0";
const SELECT_DOMAIN: &[u8] = b"shieldkit-assurance/fault-select/v1\0";

pub type Result<T> = std::result::Result<T, FaultError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FaultError {
    #[error("invalid definition: {0}")]
    InvalidDefinition(String),
    #[error("invalid schedule: {0}")]
    InvalidSchedule(String),
    #[error("invalid replay manifest: {0}")]
    InvalidReplay(String),
    #[error("invalid evaluation: {0}")]
    InvalidEvaluation(String),
    #[error("canonical JSON encoding failed: {0}")]
    Canonical(String),
    #[error("duplicate {kind}: {value}")]
    Duplicate { kind: &'static str, value: String },
    #[error("replay drift: {0}")]
    Drift(String),
    #[error("budget exhausted: {0}")]
    BudgetExhausted(String),
    #[error("mandatory coverage was not explored: {0:?}")]
    CoverageIncomplete(Vec<FaultKind>),
    #[error("evaluation timed out at logical tick {0}")]
    Timeout(u64),
    #[error("evaluation is flaky for schedule {0}")]
    Flaky(String),
    #[error("adapter failed: {0}")]
    Adapter(String),
    #[error("initial schedule does not demonstrate a safety or liveness violation")]
    InitialScheduleNotFailing,
    #[error("safety verdict is not satisfied: {0:?}")]
    SafetyNotSatisfied(InvariantVerdict),
    #[error("liveness verdict is not satisfied: {0:?}")]
    LivenessNotSatisfied(InvariantVerdict),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Actor {
    pub actor_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DurableState {
    pub state_id: String,
    pub initial_state_sha256: String,
}

/// The coordinator deliberately receives only a hash for operation content.
/// Protocol-specific inputs remain owned by the adapter/evidence store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Operation {
    pub operation_id: String,
    pub actor_id: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub durable_state_ids: Vec<String>,
    pub payload_sha256: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FaultKind {
    NetworkReorder,
    NetworkDrop,
    NetworkDuplicate,
    NetworkDelay,
    ProcessCrash,
    ProcessRestart,
    StorageTornWrite,
    StorageFsyncLoss,
    StorageCasConflict,
    StorageStaleRead,
    ClockJump,
}

/// Every fault is anchored after a completed operation. This lets the
/// coordinator validate the fault against an explicit causal frontier without
/// inventing network or storage semantics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FaultPoint {
    NetworkReorder {
        after_operation_id: String,
        first_operation_id: String,
        second_operation_id: String,
    },
    NetworkDrop {
        after_operation_id: String,
        operation_id: String,
    },
    NetworkDuplicate {
        after_operation_id: String,
        operation_id: String,
    },
    NetworkDelay {
        after_operation_id: String,
        operation_id: String,
        delay_ticks: u64,
    },
    ProcessCrash {
        after_operation_id: String,
        actor_id: String,
    },
    ProcessRestart {
        after_operation_id: String,
        actor_id: String,
    },
    StorageTornWrite {
        after_operation_id: String,
        state_id: String,
        retained_bytes: u64,
    },
    StorageFsyncLoss {
        after_operation_id: String,
        state_id: String,
    },
    StorageCasConflict {
        after_operation_id: String,
        state_id: String,
        expected_generation: u64,
    },
    StorageStaleRead {
        after_operation_id: String,
        state_id: String,
        observed_generation: u64,
    },
    ClockJump {
        after_operation_id: String,
        actor_id: String,
        offset_ticks: i64,
    },
}

impl FaultPoint {
    pub const fn kind(&self) -> FaultKind {
        match self {
            Self::NetworkReorder { .. } => FaultKind::NetworkReorder,
            Self::NetworkDrop { .. } => FaultKind::NetworkDrop,
            Self::NetworkDuplicate { .. } => FaultKind::NetworkDuplicate,
            Self::NetworkDelay { .. } => FaultKind::NetworkDelay,
            Self::ProcessCrash { .. } => FaultKind::ProcessCrash,
            Self::ProcessRestart { .. } => FaultKind::ProcessRestart,
            Self::StorageTornWrite { .. } => FaultKind::StorageTornWrite,
            Self::StorageFsyncLoss { .. } => FaultKind::StorageFsyncLoss,
            Self::StorageCasConflict { .. } => FaultKind::StorageCasConflict,
            Self::StorageStaleRead { .. } => FaultKind::StorageStaleRead,
            Self::ClockJump { .. } => FaultKind::ClockJump,
        }
    }

    pub fn after_operation_id(&self) -> &str {
        match self {
            Self::NetworkReorder {
                after_operation_id, ..
            }
            | Self::NetworkDrop {
                after_operation_id, ..
            }
            | Self::NetworkDuplicate {
                after_operation_id, ..
            }
            | Self::NetworkDelay {
                after_operation_id, ..
            }
            | Self::ProcessCrash {
                after_operation_id, ..
            }
            | Self::ProcessRestart {
                after_operation_id, ..
            }
            | Self::StorageTornWrite {
                after_operation_id, ..
            }
            | Self::StorageFsyncLoss {
                after_operation_id, ..
            }
            | Self::StorageCasConflict {
                after_operation_id, ..
            }
            | Self::StorageStaleRead {
                after_operation_id, ..
            }
            | Self::ClockJump {
                after_operation_id, ..
            } => after_operation_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExplorationPolicy {
    pub exhaustive_max_faults: u32,
    pub seeded_schedule_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SimulationBudgets {
    pub max_schedules: u64,
    pub max_events_per_schedule: u64,
    pub max_faults_per_schedule: u32,
    pub max_evaluation_attempts: u64,
    pub max_logical_ticks: u64,
    pub max_shrink_evaluations: u64,
    /// Must be at least two; a single run cannot detect nondeterminism.
    pub determinism_replays: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FaultDefinition {
    pub schema_version: String,
    pub simulation_id: String,
    pub namespace: String,
    /// Caller-recorded entropy, never generated or augmented by this crate.
    pub master_seed_sha256: String,
    pub actors: Vec<Actor>,
    pub durable_states: Vec<DurableState>,
    pub operations: Vec<Operation>,
    pub fault_catalog: Vec<FaultPoint>,
    #[serde(default)]
    pub mandatory_fault_kinds: Vec<FaultKind>,
    pub exploration: ExplorationPolicy,
    pub budgets: SimulationBudgets,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleOrigin {
    Exhaustive,
    Seeded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FaultInstance {
    pub fault_id: String,
    pub point: FaultPoint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TimelineEventKind {
    Operation { operation_id: String },
    Fault { fault_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TimelineEvent {
    pub event_id: String,
    pub sequence: u64,
    pub logical_tick: u64,
    pub kind: TimelineEventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FaultSchedule {
    pub schema_version: String,
    pub simulation_id: String,
    pub definition_sha256: String,
    pub origin: ScheduleOrigin,
    pub ordinal: u64,
    pub seed_sha256: String,
    pub faults: Vec<FaultInstance>,
    pub events: Vec<TimelineEvent>,
    pub schedule_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CoverageAccounting {
    pub schedule_count: u64,
    pub event_count: u64,
    pub fault_occurrences: BTreeMap<FaultKind, u64>,
    pub mandatory_fault_kinds: Vec<FaultKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReplayManifest {
    pub schema_version: String,
    pub simulation_id: String,
    pub definition_sha256: String,
    pub schedules: Vec<FaultSchedule>,
    pub coverage: CoverageAccounting,
    pub replay_sha256: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvariantVerdict {
    Satisfied,
    Violated,
    Blocked,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdapterObservation {
    pub observation_sha256: String,
    /// A monotonically non-decreasing logical clock supplied by the adapter.
    pub logical_ticks: u64,
    pub safety: InvariantVerdict,
    pub liveness: InvariantVerdict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EventObservation {
    pub schema_version: String,
    pub event_id: String,
    pub sequence: u64,
    pub state_sha256: String,
    pub observation_sha256: String,
    pub logical_ticks: u64,
    pub safety: InvariantVerdict,
    pub liveness: InvariantVerdict,
    pub binding_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScheduleEvaluation {
    pub schema_version: String,
    pub schedule_id: String,
    pub observations: Vec<EventObservation>,
    pub evaluation_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SimulationReport {
    pub schema_version: String,
    pub replay_sha256: String,
    pub definition_sha256: String,
    pub coverage: CoverageAccounting,
    pub evaluation_attempts: u64,
    pub schedules: Vec<ScheduleEvaluation>,
    pub safety: InvariantVerdict,
    pub liveness: InvariantVerdict,
    pub report_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShrinkResult {
    pub schema_version: String,
    pub original_schedule_id: String,
    pub minimized_schedule: FaultSchedule,
    pub evaluation_attempts: u64,
    pub one_minimal: bool,
    pub shrink_sha256: String,
}

/// A protocol adapter owns the real state and fault application semantics.
/// The coordinator only binds its reported hashes and logical observations.
pub trait FaultAdapter {
    type State;
    fn initialize(&self, definition: &FaultDefinition) -> Result<Self::State>;
    fn apply_operation(
        &self,
        state: &mut Self::State,
        operation: &Operation,
        event: &TimelineEvent,
    ) -> Result<AdapterObservation>;
    fn apply_fault(
        &self,
        state: &mut Self::State,
        fault: &FaultInstance,
        event: &TimelineEvent,
    ) -> Result<AdapterObservation>;
    fn state_sha256(&self, state: &Self::State) -> Result<String>;
}

pub trait ScheduleEvaluator {
    fn evaluate(
        &self,
        definition: &FaultDefinition,
        schedule: &FaultSchedule,
    ) -> Result<ScheduleEvaluation>;
}

pub struct AdapterEvaluator<'a, A: FaultAdapter> {
    adapter: &'a A,
}
impl<'a, A: FaultAdapter> AdapterEvaluator<'a, A> {
    pub const fn new(adapter: &'a A) -> Self {
        Self { adapter }
    }
}

impl<A: FaultAdapter> ScheduleEvaluator for AdapterEvaluator<'_, A> {
    fn evaluate(
        &self,
        definition: &FaultDefinition,
        schedule: &FaultSchedule,
    ) -> Result<ScheduleEvaluation> {
        validate_schedule(definition, schedule)?;
        let operations = operation_map(definition)?;
        let faults: BTreeMap<_, _> = schedule
            .faults
            .iter()
            .map(|fault| (fault.fault_id.as_str(), fault))
            .collect();
        let mut state = self.adapter.initialize(definition)?;
        let mut observations = Vec::with_capacity(schedule.events.len());
        for event in &schedule.events {
            let raw = match &event.kind {
                TimelineEventKind::Operation { operation_id } => self.adapter.apply_operation(
                    &mut state,
                    operations.get(operation_id.as_str()).ok_or_else(|| {
                        FaultError::InvalidSchedule(
                            "operation event references unknown operation".into(),
                        )
                    })?,
                    event,
                )?,
                TimelineEventKind::Fault { fault_id } => self.adapter.apply_fault(
                    &mut state,
                    faults.get(fault_id.as_str()).ok_or_else(|| {
                        FaultError::InvalidSchedule("fault event references unknown fault".into())
                    })?,
                    event,
                )?,
            };
            observations.push(bind_observation(
                schedule,
                event,
                self.adapter.state_sha256(&state)?,
                raw,
            )?);
        }
        build_evaluation(schedule, observations)
    }
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|error| FaultError::Canonical(error.to_string()))
}
fn hash_domain<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(canonical_bytes(value)?);
    Ok(format!("sha256:{}", hex::encode(hash.finalize())))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
}

pub fn definition_sha256(definition: &FaultDefinition) -> Result<String> {
    validate_definition(definition)?;
    hash_domain(DEFINITION_DOMAIN, definition)
}

pub fn derive_schedule_seed(
    definition: &FaultDefinition,
    origin: ScheduleOrigin,
    ordinal: u64,
) -> Result<String> {
    let identity = serde_json::json!({"definitionSha256": definition_sha256(definition)?, "masterSeedSha256": definition.master_seed_sha256, "origin": origin, "ordinal": ordinal});
    hash_domain(SEED_DOMAIN, &identity)
}

pub fn validate_definition(definition: &FaultDefinition) -> Result<()> {
    if definition.schema_version != DEFINITION_SCHEMA_V1 {
        return Err(FaultError::InvalidDefinition(
            "unsupported schemaVersion".into(),
        ));
    }
    if !valid_id(&definition.simulation_id)
        || !valid_id(&definition.namespace)
        || !valid_hash(&definition.master_seed_sha256)
    {
        return Err(FaultError::InvalidDefinition(
            "simulationId, namespace, or masterSeedSha256 is invalid".into(),
        ));
    }
    if definition.actors.is_empty() || definition.operations.is_empty() {
        return Err(FaultError::InvalidDefinition(
            "actors and operations must not be empty".into(),
        ));
    }
    let budgets = &definition.budgets;
    if budgets.max_schedules == 0
        || budgets.max_events_per_schedule == 0
        || budgets.max_faults_per_schedule == 0
        || budgets.max_evaluation_attempts == 0
        || budgets.max_logical_ticks == 0
        || budgets.max_shrink_evaluations == 0
        || budgets.determinism_replays < 2
    {
        return Err(FaultError::InvalidDefinition(
            "budgets must be nonzero and determinismReplays >= 2".into(),
        ));
    }
    if definition.exploration.exhaustive_max_faults > budgets.max_faults_per_schedule {
        return Err(FaultError::InvalidDefinition(
            "exhaustiveMaxFaults exceeds maxFaultsPerSchedule".into(),
        ));
    }
    let mut actor_ids = BTreeSet::new();
    for actor in &definition.actors {
        if !valid_id(&actor.actor_id) {
            return Err(FaultError::InvalidDefinition("invalid actorId".into()));
        }
        if !actor_ids.insert(actor.actor_id.clone()) {
            return Err(FaultError::Duplicate {
                kind: "actor ID",
                value: actor.actor_id.clone(),
            });
        }
    }
    let mut state_ids = BTreeSet::new();
    for state in &definition.durable_states {
        if !valid_id(&state.state_id) || !valid_hash(&state.initial_state_sha256) {
            return Err(FaultError::InvalidDefinition(
                "invalid durable state".into(),
            ));
        }
        if !state_ids.insert(state.state_id.clone()) {
            return Err(FaultError::Duplicate {
                kind: "durable state ID",
                value: state.state_id.clone(),
            });
        }
    }
    let operations = operation_map(definition)?;
    for operation in &definition.operations {
        if !valid_id(&operation.operation_id)
            || !actor_ids.contains(&operation.actor_id)
            || !valid_hash(&operation.payload_sha256)
        {
            return Err(FaultError::InvalidDefinition(format!(
                "invalid operation {}",
                operation.operation_id
            )));
        }
        let mut dependencies = BTreeSet::new();
        for dependency in &operation.depends_on {
            if dependency == &operation.operation_id
                || !operations.contains_key(dependency.as_str())
            {
                return Err(FaultError::InvalidDefinition(format!(
                    "invalid dependency in {}",
                    operation.operation_id
                )));
            }
            if !dependencies.insert(dependency) {
                return Err(FaultError::Duplicate {
                    kind: "operation dependency",
                    value: dependency.clone(),
                });
            }
        }
        let mut used_states = BTreeSet::new();
        for state in &operation.durable_state_ids {
            if !state_ids.contains(state) {
                return Err(FaultError::InvalidDefinition(format!(
                    "unknown durable state in {}",
                    operation.operation_id
                )));
            }
            if !used_states.insert(state) {
                return Err(FaultError::Duplicate {
                    kind: "operation durable state",
                    value: state.clone(),
                });
            }
        }
    }
    let _ = topological_operations(definition)?;
    let mut required = BTreeSet::new();
    for kind in &definition.mandatory_fault_kinds {
        if !required.insert(*kind) {
            return Err(FaultError::Duplicate {
                kind: "mandatory fault kind",
                value: format!("{kind:?}"),
            });
        }
    }
    let mut prior = None;
    for point in &definition.fault_catalog {
        validate_fault_point(definition, point)?;
        let bytes = canonical_bytes(point)?;
        if prior
            .as_ref()
            .is_some_and(|previous: &Vec<u8>| previous >= &bytes)
        {
            return Err(FaultError::InvalidDefinition(
                "faultCatalog must be strictly canonical-byte ordered".into(),
            ));
        }
        prior = Some(bytes);
    }
    Ok(())
}

fn operation_map(definition: &FaultDefinition) -> Result<BTreeMap<&str, &Operation>> {
    let mut map = BTreeMap::new();
    for operation in &definition.operations {
        if map
            .insert(operation.operation_id.as_str(), operation)
            .is_some()
        {
            return Err(FaultError::Duplicate {
                kind: "operation ID",
                value: operation.operation_id.clone(),
            });
        }
    }
    Ok(map)
}

fn topological_operations(definition: &FaultDefinition) -> Result<Vec<&Operation>> {
    let map = operation_map(definition)?;
    let mut completed = BTreeSet::new();
    let mut output = Vec::with_capacity(map.len());
    while output.len() != map.len() {
        let next = map.iter().find_map(|(id, operation)| {
            (!completed.contains(*id)
                && operation
                    .depends_on
                    .iter()
                    .all(|dependency| completed.contains(dependency.as_str())))
            .then_some((*id, *operation))
        });
        let Some((id, operation)) = next else {
            return Err(FaultError::InvalidDefinition(
                "operation dependency graph has a cycle".into(),
            ));
        };
        completed.insert(id);
        output.push(operation);
    }
    Ok(output)
}

fn depends_transitively(
    map: &BTreeMap<&str, &Operation>,
    from: &str,
    target: &str,
    seen: &mut BTreeSet<String>,
) -> bool {
    if !seen.insert(from.to_owned()) {
        return false;
    }
    map.get(from).is_some_and(|operation| {
        operation.depends_on.iter().any(|dependency| {
            dependency == target || depends_transitively(map, dependency, target, seen)
        })
    })
}

fn validate_fault_point(definition: &FaultDefinition, point: &FaultPoint) -> Result<()> {
    let operations = operation_map(definition)?;
    let after = operations
        .get(point.after_operation_id())
        .ok_or_else(|| FaultError::InvalidDefinition("fault anchor operation is unknown".into()))?;
    let state_used = |state_id: &str| {
        after
            .durable_state_ids
            .iter()
            .any(|state| state == state_id)
    };
    match point {
        FaultPoint::NetworkReorder {
            first_operation_id,
            second_operation_id,
            ..
        } => {
            if first_operation_id == second_operation_id
                || !operations.contains_key(first_operation_id.as_str())
                || !operations.contains_key(second_operation_id.as_str())
            {
                return Err(FaultError::InvalidDefinition(
                    "network reorder references invalid operations".into(),
                ));
            }
            if depends_transitively(
                &operations,
                first_operation_id,
                second_operation_id,
                &mut BTreeSet::new(),
            ) || depends_transitively(
                &operations,
                second_operation_id,
                first_operation_id,
                &mut BTreeSet::new(),
            ) {
                return Err(FaultError::InvalidDefinition(
                    "cannot reorder causally dependent operations".into(),
                ));
            }
        }
        FaultPoint::NetworkDelay {
            operation_id,
            delay_ticks,
            ..
        } => {
            if !operations.contains_key(operation_id.as_str()) {
                return Err(FaultError::InvalidDefinition(
                    "network fault references unknown operation".into(),
                ));
            }
            if *delay_ticks == 0 {
                return Err(FaultError::InvalidDefinition(
                    "network delay must be nonzero".into(),
                ));
            }
        }
        FaultPoint::NetworkDrop { operation_id, .. }
        | FaultPoint::NetworkDuplicate { operation_id, .. } => {
            if !operations.contains_key(operation_id.as_str()) {
                return Err(FaultError::InvalidDefinition(
                    "network fault references unknown operation".into(),
                ));
            }
        }
        FaultPoint::ClockJump {
            actor_id,
            offset_ticks,
            ..
        } => {
            if !definition
                .actors
                .iter()
                .any(|actor| &actor.actor_id == actor_id)
            {
                return Err(FaultError::InvalidDefinition(
                    "process/clock fault references unknown actor".into(),
                ));
            }
            if *offset_ticks == 0 {
                return Err(FaultError::InvalidDefinition(
                    "clock jump must be nonzero".into(),
                ));
            }
        }
        FaultPoint::ProcessCrash { actor_id, .. } | FaultPoint::ProcessRestart { actor_id, .. } => {
            if !definition
                .actors
                .iter()
                .any(|actor| &actor.actor_id == actor_id)
            {
                return Err(FaultError::InvalidDefinition(
                    "process/clock fault references unknown actor".into(),
                ));
            }
        }
        FaultPoint::StorageTornWrite { state_id, .. }
        | FaultPoint::StorageFsyncLoss { state_id, .. }
        | FaultPoint::StorageCasConflict { state_id, .. }
        | FaultPoint::StorageStaleRead { state_id, .. }
            if !state_used(state_id) =>
        {
            return Err(FaultError::InvalidDefinition(
                "storage fault anchor does not use state".into(),
            ));
        }
        _ => {}
    }
    Ok(())
}

fn combinations(items: usize, maximum: usize, limit: u64) -> Result<Vec<Vec<usize>>> {
    let mut output = vec![Vec::new()];
    for size in 1..=maximum.min(items) {
        combinations_of_size(items, size, 0, &mut Vec::new(), &mut output, limit)?;
    }
    Ok(output)
}
fn combinations_of_size(
    items: usize,
    remaining: usize,
    start: usize,
    current: &mut Vec<usize>,
    output: &mut Vec<Vec<usize>>,
    limit: u64,
) -> Result<()> {
    if output.len() as u64 > limit {
        return Err(FaultError::BudgetExhausted(
            "exhaustive schedule space exceeds maxSchedules".into(),
        ));
    }
    if remaining == 0 {
        output.push(current.clone());
        return Ok(());
    }
    for index in start..=items.saturating_sub(remaining) {
        current.push(index);
        combinations_of_size(items, remaining - 1, index + 1, current, output, limit)?;
        current.pop();
    }
    Ok(())
}

pub fn generate_schedules(definition: &FaultDefinition) -> Result<Vec<FaultSchedule>> {
    validate_definition(definition)?;
    let exhaustive = combinations(
        definition.fault_catalog.len(),
        definition.exploration.exhaustive_max_faults as usize,
        definition.budgets.max_schedules,
    )?;
    let requested = (exhaustive.len() as u64)
        .checked_add(definition.exploration.seeded_schedule_count)
        .ok_or_else(|| FaultError::BudgetExhausted("schedule count overflow".into()))?;
    if requested > definition.budgets.max_schedules {
        return Err(FaultError::BudgetExhausted(
            "requested schedules exceed maxSchedules".into(),
        ));
    }
    let mut schedules = Vec::new();
    for (ordinal, indices) in exhaustive.iter().enumerate() {
        if let Ok(schedule) = make_schedule(
            definition,
            ScheduleOrigin::Exhaustive,
            ordinal as u64,
            indices
                .iter()
                .map(|index| definition.fault_catalog[*index].clone())
                .collect(),
        ) {
            schedules.push(schedule);
        }
    }
    for ordinal in 0..definition.exploration.seeded_schedule_count {
        let seed = derive_schedule_seed(definition, ScheduleOrigin::Seeded, ordinal)?;
        let points = seeded_points(definition, &seed)?;
        if let Ok(schedule) = make_schedule(definition, ScheduleOrigin::Seeded, ordinal, points) {
            schedules.push(schedule);
        }
    }
    if schedules.len() as u64 > definition.budgets.max_schedules {
        return Err(FaultError::BudgetExhausted(
            "valid schedule count exceeds maxSchedules".into(),
        ));
    }
    let mut ids = BTreeSet::new();
    for schedule in &schedules {
        if !ids.insert(schedule.schedule_id.clone()) {
            return Err(FaultError::Duplicate {
                kind: "schedule ID",
                value: schedule.schedule_id.clone(),
            });
        }
    }
    let coverage = coverage_for(definition, &schedules)?;
    ensure_mandatory_coverage(&coverage)?;
    Ok(schedules)
}

fn seeded_points(definition: &FaultDefinition, seed: &str) -> Result<Vec<FaultPoint>> {
    if definition.fault_catalog.is_empty() {
        return Ok(Vec::new());
    }
    let maximum =
        (definition.budgets.max_faults_per_schedule as usize).min(definition.fault_catalog.len());
    let count = 1 + (selector(seed, 0)? as usize % maximum);
    let mut ranked: Vec<_> = definition
        .fault_catalog
        .iter()
        .enumerate()
        .map(|(index, point)| Ok((selector(seed, (index + 1) as u64)?, point.clone())))
        .collect::<Result<_>>()?;
    ranked.sort_by_key(|entry| entry.0);
    let mut points: Vec<_> = ranked
        .into_iter()
        .take(count)
        .map(|(_, point)| point)
        .collect();
    points.sort_by(|left, right| {
        canonical_bytes(left)
            .unwrap_or_default()
            .cmp(&canonical_bytes(right).unwrap_or_default())
    });
    Ok(points)
}
fn selector(seed: &str, ordinal: u64) -> Result<u64> {
    let digest = hash_domain(
        SELECT_DOMAIN,
        &serde_json::json!({"seedSha256": seed, "ordinal": ordinal}),
    )?;
    u64::from_str_radix(&digest[7..23], 16)
        .map_err(|_| FaultError::InvalidDefinition("selector digest is invalid".into()))
}

fn make_schedule(
    definition: &FaultDefinition,
    origin: ScheduleOrigin,
    ordinal: u64,
    mut points: Vec<FaultPoint>,
) -> Result<FaultSchedule> {
    validate_definition(definition)?;
    if points.len() as u32 > definition.budgets.max_faults_per_schedule {
        return Err(FaultError::BudgetExhausted(
            "fault count exceeds maxFaultsPerSchedule".into(),
        ));
    }
    points.sort_by(|left, right| {
        canonical_bytes(left)
            .unwrap_or_default()
            .cmp(&canonical_bytes(right).unwrap_or_default())
    });
    let definition_sha256 = definition_sha256(definition)?;
    let seed_sha256 = derive_schedule_seed(definition, origin, ordinal)?;
    let mut seen = BTreeSet::new();
    let mut faults = Vec::new();
    for (index, point) in points.into_iter().enumerate() {
        validate_fault_point(definition, &point)?;
        let encoded = canonical_bytes(&point)?;
        if !seen.insert(encoded) {
            return Err(FaultError::Duplicate {
                kind: "fault point",
                value: format!("{:?}", point.kind()),
            });
        }
        let fault_id = hash_domain(
            FAULT_DOMAIN,
            &serde_json::json!({"definitionSha256": definition_sha256, "origin": origin, "ordinal": ordinal, "index": index, "point": point}),
        )?;
        faults.push(FaultInstance { fault_id, point });
    }
    let schedule_id = hash_domain(
        SCHEDULE_DOMAIN,
        &serde_json::json!({"schemaVersion": SCHEDULE_SCHEMA_V1, "simulationId": definition.simulation_id, "definitionSha256": definition_sha256, "origin": origin, "ordinal": ordinal, "seedSha256": seed_sha256, "faults": faults}),
    )?;
    let events = canonical_timeline(definition, &schedule_id, &faults)?;
    let schedule = FaultSchedule {
        schema_version: SCHEDULE_SCHEMA_V1.into(),
        simulation_id: definition.simulation_id.clone(),
        definition_sha256,
        origin,
        ordinal,
        seed_sha256,
        faults,
        events,
        schedule_id,
    };
    validate_schedule(definition, &schedule)?;
    Ok(schedule)
}

fn canonical_timeline(
    definition: &FaultDefinition,
    schedule_id: &str,
    faults: &[FaultInstance],
) -> Result<Vec<TimelineEvent>> {
    let mut events = Vec::new();
    for operation in topological_operations(definition)? {
        events.push(TimelineEvent {
            event_id: String::new(),
            sequence: events.len() as u64,
            logical_tick: events.len() as u64 + 1,
            kind: TimelineEventKind::Operation {
                operation_id: operation.operation_id.clone(),
            },
        });
        for fault in faults
            .iter()
            .filter(|fault| fault.point.after_operation_id() == operation.operation_id)
        {
            events.push(TimelineEvent {
                event_id: String::new(),
                sequence: events.len() as u64,
                logical_tick: events.len() as u64 + 1,
                kind: TimelineEventKind::Fault {
                    fault_id: fault.fault_id.clone(),
                },
            });
        }
    }
    for event in &mut events {
        event.event_id = hash_domain(
            EVENT_DOMAIN,
            &serde_json::json!({"scheduleId": schedule_id, "sequence": event.sequence, "logicalTick": event.logical_tick, "kind": event.kind}),
        )?;
    }
    Ok(events)
}

pub fn validate_schedule(definition: &FaultDefinition, schedule: &FaultSchedule) -> Result<()> {
    validate_definition(definition)?;
    if schedule.schema_version != SCHEDULE_SCHEMA_V1
        || schedule.simulation_id != definition.simulation_id
        || schedule.definition_sha256 != definition_sha256(definition)?
    {
        return Err(FaultError::InvalidSchedule(
            "schema, simulation, or definition binding differs".into(),
        ));
    }
    if schedule.seed_sha256 != derive_schedule_seed(definition, schedule.origin, schedule.ordinal)?
    {
        return Err(FaultError::Drift("schedule seed differs".into()));
    }
    if schedule.faults.len() as u32 > definition.budgets.max_faults_per_schedule {
        return Err(FaultError::BudgetExhausted(
            "schedule faults exceed maxFaultsPerSchedule".into(),
        ));
    }
    let mut prior = None;
    let mut seen = BTreeSet::new();
    for (index, fault) in schedule.faults.iter().enumerate() {
        validate_fault_point(definition, &fault.point)?;
        let encoded = canonical_bytes(&fault.point)?;
        if prior
            .as_ref()
            .is_some_and(|previous: &Vec<u8>| previous >= &encoded)
        {
            return Err(FaultError::InvalidSchedule(
                "faults are not strictly canonical-byte ordered".into(),
            ));
        }
        if !seen.insert(encoded) {
            return Err(FaultError::Duplicate {
                kind: "fault point",
                value: fault.fault_id.clone(),
            });
        }
        prior = Some(canonical_bytes(&fault.point)?);
        let expected = hash_domain(
            FAULT_DOMAIN,
            &serde_json::json!({"definitionSha256": schedule.definition_sha256, "origin": schedule.origin, "ordinal": schedule.ordinal, "index": index, "point": fault.point}),
        )?;
        if expected != fault.fault_id {
            return Err(FaultError::Drift("fault ID differs".into()));
        }
    }
    let expected_schedule_id = hash_domain(
        SCHEDULE_DOMAIN,
        &serde_json::json!({
            "schemaVersion": SCHEDULE_SCHEMA_V1,
            "simulationId": definition.simulation_id,
            "definitionSha256": schedule.definition_sha256,
            "origin": schedule.origin,
            "ordinal": schedule.ordinal,
            "seedSha256": schedule.seed_sha256,
            "faults": schedule.faults,
        }),
    )?;
    if schedule.schedule_id != expected_schedule_id {
        return Err(FaultError::Drift("schedule ID differs".into()));
    }
    let expected_events = canonical_timeline(definition, &schedule.schedule_id, &schedule.faults)?;
    if schedule.events != expected_events {
        return Err(FaultError::Drift(
            "schedule differs from canonical generation".into(),
        ));
    }
    if schedule.events.len() as u64 > definition.budgets.max_events_per_schedule {
        return Err(FaultError::BudgetExhausted(
            "schedule events exceed maxEventsPerSchedule".into(),
        ));
    }
    validate_crash_causality(definition, schedule)
}

fn validate_crash_causality(definition: &FaultDefinition, schedule: &FaultSchedule) -> Result<()> {
    let operations = operation_map(definition)?;
    let faults: BTreeMap<_, _> = schedule
        .faults
        .iter()
        .map(|fault| (fault.fault_id.as_str(), fault))
        .collect();
    let mut crashed = BTreeSet::new();
    for event in &schedule.events {
        match &event.kind {
            TimelineEventKind::Operation { operation_id } => {
                let operation = operations
                    .get(operation_id.as_str())
                    .ok_or_else(|| FaultError::InvalidSchedule("unknown operation event".into()))?;
                if crashed.contains(&operation.actor_id) {
                    return Err(FaultError::InvalidSchedule(
                        "operation occurs while actor is crashed".into(),
                    ));
                }
            }
            TimelineEventKind::Fault { fault_id } => match &faults
                .get(fault_id.as_str())
                .ok_or_else(|| FaultError::InvalidSchedule("unknown fault event".into()))?
                .point
            {
                FaultPoint::ProcessCrash { actor_id, .. } => {
                    if !crashed.insert(actor_id) {
                        return Err(FaultError::InvalidSchedule(
                            "actor crashes twice without restart".into(),
                        ));
                    }
                }
                FaultPoint::ProcessRestart { actor_id, .. } if !crashed.remove(actor_id) => {
                    return Err(FaultError::InvalidSchedule(
                        "actor restarts without crash".into(),
                    ));
                }
                _ => {}
            },
        }
    }
    Ok(())
}

fn coverage_for(
    definition: &FaultDefinition,
    schedules: &[FaultSchedule],
) -> Result<CoverageAccounting> {
    let mut faults = BTreeMap::new();
    let mut events = 0u64;
    for schedule in schedules {
        validate_schedule(definition, schedule)?;
        events = events
            .checked_add(schedule.events.len() as u64)
            .ok_or_else(|| FaultError::BudgetExhausted("event count overflow".into()))?;
        for fault in &schedule.faults {
            *faults.entry(fault.point.kind()).or_insert(0) += 1;
        }
    }
    Ok(CoverageAccounting {
        schedule_count: schedules.len() as u64,
        event_count: events,
        fault_occurrences: faults,
        mandatory_fault_kinds: definition.mandatory_fault_kinds.clone(),
    })
}
fn ensure_mandatory_coverage(coverage: &CoverageAccounting) -> Result<()> {
    let missing: Vec<_> = coverage
        .mandatory_fault_kinds
        .iter()
        .copied()
        .filter(|kind| coverage.fault_occurrences.get(kind).copied().unwrap_or(0) == 0)
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(FaultError::CoverageIncomplete(missing))
    }
}

pub fn build_replay_manifest(definition: &FaultDefinition) -> Result<ReplayManifest> {
    let schedules = generate_schedules(definition)?;
    let definition_sha256 = definition_sha256(definition)?;
    let coverage = coverage_for(definition, &schedules)?;
    let replay_sha256 = hash_domain(
        REPLAY_DOMAIN,
        &serde_json::json!({"schemaVersion": REPLAY_SCHEMA_V1, "simulationId": definition.simulation_id, "definitionSha256": definition_sha256, "schedules": schedules, "coverage": coverage}),
    )?;
    Ok(ReplayManifest {
        schema_version: REPLAY_SCHEMA_V1.into(),
        simulation_id: definition.simulation_id.clone(),
        definition_sha256,
        schedules,
        coverage,
        replay_sha256,
    })
}

pub fn verify_replay_manifest(
    definition: &FaultDefinition,
    manifest: &ReplayManifest,
) -> Result<()> {
    if manifest.schema_version != REPLAY_SCHEMA_V1
        || manifest.simulation_id != definition.simulation_id
        || manifest.definition_sha256 != definition_sha256(definition)?
    {
        return Err(FaultError::InvalidReplay(
            "schema, simulation, or definition differs".into(),
        ));
    }
    let expected = build_replay_manifest(definition)?;
    if manifest.schedules != expected.schedules
        || manifest.coverage != expected.coverage
        || manifest.replay_sha256 != expected.replay_sha256
    {
        return Err(FaultError::Drift(
            "replay manifest differs from deterministic generation".into(),
        ));
    }
    ensure_mandatory_coverage(&manifest.coverage)
}

pub fn bind_observation(
    schedule: &FaultSchedule,
    event: &TimelineEvent,
    state_sha256: String,
    raw: AdapterObservation,
) -> Result<EventObservation> {
    if !valid_hash(&state_sha256) || !valid_hash(&raw.observation_sha256) {
        return Err(FaultError::InvalidEvaluation(
            "stateSha256 and observationSha256 must be lowercase sha256".into(),
        ));
    }
    let binding_sha256 = hash_domain(
        OBSERVATION_DOMAIN,
        &serde_json::json!({"schemaVersion": OBSERVATION_SCHEMA_V1, "scheduleId": schedule.schedule_id, "eventId": event.event_id, "sequence": event.sequence, "stateSha256": state_sha256, "observationSha256": raw.observation_sha256, "logicalTicks": raw.logical_ticks, "safety": raw.safety, "liveness": raw.liveness}),
    )?;
    Ok(EventObservation {
        schema_version: OBSERVATION_SCHEMA_V1.into(),
        event_id: event.event_id.clone(),
        sequence: event.sequence,
        state_sha256,
        observation_sha256: raw.observation_sha256,
        logical_ticks: raw.logical_ticks,
        safety: raw.safety,
        liveness: raw.liveness,
        binding_sha256,
    })
}

pub fn build_evaluation(
    schedule: &FaultSchedule,
    observations: Vec<EventObservation>,
) -> Result<ScheduleEvaluation> {
    let evaluation_sha256 = hash_domain(
        EVALUATION_DOMAIN,
        &serde_json::json!({"schemaVersion": EVALUATION_SCHEMA_V1, "scheduleId": schedule.schedule_id, "observations": observations}),
    )?;
    Ok(ScheduleEvaluation {
        schema_version: EVALUATION_SCHEMA_V1.into(),
        schedule_id: schedule.schedule_id.clone(),
        observations,
        evaluation_sha256,
    })
}

pub fn verify_evaluation(
    definition: &FaultDefinition,
    schedule: &FaultSchedule,
    evaluation: &ScheduleEvaluation,
) -> Result<()> {
    validate_schedule(definition, schedule)?;
    if evaluation.schema_version != EVALUATION_SCHEMA_V1
        || evaluation.schedule_id != schedule.schedule_id
        || evaluation.observations.len() != schedule.events.len()
    {
        return Err(FaultError::InvalidEvaluation(
            "schema, schedule ID, or observation count differs".into(),
        ));
    }
    let mut prior_ticks = 0u64;
    for (event, observation) in schedule.events.iter().zip(&evaluation.observations) {
        if observation.schema_version != OBSERVATION_SCHEMA_V1
            || observation.event_id != event.event_id
            || observation.sequence != event.sequence
            || observation.logical_ticks < prior_ticks
            || observation.logical_ticks > definition.budgets.max_logical_ticks
        {
            return Err(
                if observation.logical_ticks > definition.budgets.max_logical_ticks {
                    FaultError::Timeout(observation.logical_ticks)
                } else {
                    FaultError::InvalidEvaluation(
                        "event observation does not bind the schedule timeline".into(),
                    )
                },
            );
        }
        prior_ticks = observation.logical_ticks;
        let expected = bind_observation(
            schedule,
            event,
            observation.state_sha256.clone(),
            AdapterObservation {
                observation_sha256: observation.observation_sha256.clone(),
                logical_ticks: observation.logical_ticks,
                safety: observation.safety,
                liveness: observation.liveness,
            },
        )?;
        if &expected != observation {
            return Err(FaultError::Drift(
                "event observation binding differs".into(),
            ));
        }
    }
    let expected = build_evaluation(schedule, evaluation.observations.clone())?;
    if expected.evaluation_sha256 != evaluation.evaluation_sha256 {
        return Err(FaultError::Drift("evaluation hash differs".into()));
    }
    Ok(())
}

pub fn run_replay<E: ScheduleEvaluator>(
    definition: &FaultDefinition,
    manifest: &ReplayManifest,
    evaluator: &E,
) -> Result<SimulationReport> {
    verify_replay_manifest(definition, manifest)?;
    let attempts = (manifest.schedules.len() as u64)
        .checked_mul(definition.budgets.determinism_replays as u64)
        .ok_or_else(|| FaultError::BudgetExhausted("evaluation attempt overflow".into()))?;
    if attempts > definition.budgets.max_evaluation_attempts {
        return Err(FaultError::BudgetExhausted(
            "required deterministic replays exceed maxEvaluationAttempts".into(),
        ));
    }
    let mut schedules = Vec::new();
    for schedule in &manifest.schedules {
        schedules.push(stable_evaluate(definition, schedule, evaluator)?.0);
    }
    let safety = aggregate(schedules.iter().flat_map(|evaluation| {
        evaluation
            .observations
            .iter()
            .map(|observation| observation.safety)
    }));
    let liveness = aggregate(schedules.iter().flat_map(|evaluation| {
        evaluation
            .observations
            .iter()
            .map(|observation| observation.liveness)
    }));
    let report_sha256 = hash_domain(
        REPORT_DOMAIN,
        &serde_json::json!({"schemaVersion": REPORT_SCHEMA_V1, "replaySha256": manifest.replay_sha256, "definitionSha256": manifest.definition_sha256, "coverage": manifest.coverage, "evaluationAttempts": attempts, "schedules": schedules, "safety": safety, "liveness": liveness}),
    )?;
    Ok(SimulationReport {
        schema_version: REPORT_SCHEMA_V1.into(),
        replay_sha256: manifest.replay_sha256.clone(),
        definition_sha256: manifest.definition_sha256.clone(),
        coverage: manifest.coverage.clone(),
        evaluation_attempts: attempts,
        schedules,
        safety,
        liveness,
        report_sha256,
    })
}

fn stable_evaluate<E: ScheduleEvaluator>(
    definition: &FaultDefinition,
    schedule: &FaultSchedule,
    evaluator: &E,
) -> Result<(ScheduleEvaluation, u64)> {
    let first = evaluator.evaluate(definition, schedule)?;
    verify_evaluation(definition, schedule, &first)?;
    for _ in 1..definition.budgets.determinism_replays {
        let next = evaluator.evaluate(definition, schedule)?;
        verify_evaluation(definition, schedule, &next)?;
        if next != first {
            return Err(FaultError::Flaky(schedule.schedule_id.clone()));
        }
    }
    Ok((first, definition.budgets.determinism_replays as u64))
}

fn aggregate(verdicts: impl Iterator<Item = InvariantVerdict>) -> InvariantVerdict {
    let mut blocked = false;
    let mut violated = false;
    let mut any = false;
    for verdict in verdicts {
        any = true;
        match verdict {
            InvariantVerdict::Violated => violated = true,
            InvariantVerdict::Blocked | InvariantVerdict::NotApplicable => blocked = true,
            InvariantVerdict::Satisfied => {}
        }
    }
    if violated {
        InvariantVerdict::Violated
    } else if blocked || !any {
        InvariantVerdict::Blocked
    } else {
        InvariantVerdict::Satisfied
    }
}

pub fn require_safe_and_live(report: &SimulationReport) -> Result<()> {
    if report.safety != InvariantVerdict::Satisfied {
        return Err(FaultError::SafetyNotSatisfied(report.safety));
    }
    if report.liveness != InvariantVerdict::Satisfied {
        return Err(FaultError::LivenessNotSatisfied(report.liveness));
    }
    Ok(())
}

pub fn shrink_failing_schedule<E: ScheduleEvaluator>(
    definition: &FaultDefinition,
    schedule: &FaultSchedule,
    evaluator: &E,
) -> Result<ShrinkResult> {
    validate_schedule(definition, schedule)?;
    let mut attempts = 0u64;
    let (initial, used) = shrink_evaluate(definition, schedule, evaluator, attempts)?;
    attempts += used;
    if !is_failure(&initial) {
        return Err(FaultError::InitialScheduleNotFailing);
    }
    let mut current = schedule.clone();
    let mut changed = true;
    while changed {
        changed = false;
        for index in 0..current.faults.len() {
            let points = current
                .faults
                .iter()
                .enumerate()
                .filter(|(candidate, _)| *candidate != index)
                .map(|(_, fault)| fault.point.clone())
                .collect();
            let candidate = make_schedule(definition, current.origin, current.ordinal, points)?;
            let (evaluation, used) = shrink_evaluate(definition, &candidate, evaluator, attempts)?;
            attempts += used;
            if is_failure(&evaluation) {
                current = candidate;
                changed = true;
                break;
            }
        }
    }
    let mut one_minimal = true;
    for index in 0..current.faults.len() {
        let points = current
            .faults
            .iter()
            .enumerate()
            .filter(|(candidate, _)| *candidate != index)
            .map(|(_, fault)| fault.point.clone())
            .collect();
        let candidate = make_schedule(definition, current.origin, current.ordinal, points)?;
        let (evaluation, used) = shrink_evaluate(definition, &candidate, evaluator, attempts)?;
        attempts += used;
        if is_failure(&evaluation) {
            one_minimal = false;
        }
    }
    let shrink_sha256 = hash_domain(
        SHRINK_DOMAIN,
        &serde_json::json!({"schemaVersion": SHRINK_SCHEMA_V1, "originalScheduleId": schedule.schedule_id, "minimizedSchedule": current, "evaluationAttempts": attempts, "oneMinimal": one_minimal}),
    )?;
    Ok(ShrinkResult {
        schema_version: SHRINK_SCHEMA_V1.into(),
        original_schedule_id: schedule.schedule_id.clone(),
        minimized_schedule: current,
        evaluation_attempts: attempts,
        one_minimal,
        shrink_sha256,
    })
}
fn shrink_evaluate<E: ScheduleEvaluator>(
    definition: &FaultDefinition,
    schedule: &FaultSchedule,
    evaluator: &E,
    attempts: u64,
) -> Result<(ScheduleEvaluation, u64)> {
    let required = definition.budgets.determinism_replays as u64;
    if attempts
        .checked_add(required)
        .is_none_or(|total| total > definition.budgets.max_shrink_evaluations)
    {
        return Err(FaultError::BudgetExhausted(
            "maxShrinkEvaluations reached".into(),
        ));
    }
    stable_evaluate(definition, schedule, evaluator)
}
fn is_failure(evaluation: &ScheduleEvaluation) -> bool {
    evaluation.observations.iter().any(|observation| {
        observation.safety == InvariantVerdict::Violated
            || observation.liveness == InvariantVerdict::Violated
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(label: &str) -> String {
        hash_domain(b"test\0", &label).unwrap()
    }
    fn operation(id: &str, actor: &str, dependencies: &[&str], states: &[&str]) -> Operation {
        Operation {
            operation_id: id.into(),
            actor_id: actor.into(),
            depends_on: dependencies.iter().map(|value| (*value).into()).collect(),
            durable_state_ids: states.iter().map(|value| (*value).into()).collect(),
            payload_sha256: hash(id),
        }
    }
    fn definition(catalog: Vec<FaultPoint>) -> FaultDefinition {
        FaultDefinition {
            schema_version: DEFINITION_SCHEMA_V1.into(),
            simulation_id: "fault.test".into(),
            namespace: "test".into(),
            master_seed_sha256: hash("seed"),
            actors: vec![
                Actor {
                    actor_id: "alice".into(),
                },
                Actor {
                    actor_id: "bob".into(),
                },
            ],
            durable_states: vec![DurableState {
                state_id: "ledger".into(),
                initial_state_sha256: hash("initial"),
            }],
            operations: vec![
                operation("op.a", "alice", &[], &["ledger"]),
                operation("op.b", "bob", &[], &["ledger"]),
                operation("op.c", "alice", &["op.a"], &["ledger"]),
            ],
            fault_catalog: catalog,
            mandatory_fault_kinds: vec![],
            exploration: ExplorationPolicy {
                exhaustive_max_faults: 1,
                seeded_schedule_count: 0,
            },
            budgets: SimulationBudgets {
                max_schedules: 32,
                max_events_per_schedule: 32,
                max_faults_per_schedule: 3,
                max_evaluation_attempts: 128,
                max_logical_ticks: 128,
                max_shrink_evaluations: 128,
                determinism_replays: 2,
            },
        }
    }
    fn ordered(mut definition: FaultDefinition) -> FaultDefinition {
        definition.fault_catalog.sort_by(|a, b| {
            canonical_bytes(a)
                .unwrap()
                .cmp(&canonical_bytes(b).unwrap())
        });
        definition
    }

    struct DeterministicAdapter;
    impl FaultAdapter for DeterministicAdapter {
        type State = u64;
        fn initialize(&self, _: &FaultDefinition) -> Result<Self::State> {
            Ok(0)
        }
        fn apply_operation(
            &self,
            state: &mut Self::State,
            operation: &Operation,
            event: &TimelineEvent,
        ) -> Result<AdapterObservation> {
            *state += 1;
            Ok(AdapterObservation {
                observation_sha256: hash(&format!("{}:{state}", operation.operation_id)),
                logical_ticks: event.logical_tick,
                safety: InvariantVerdict::Satisfied,
                liveness: InvariantVerdict::Satisfied,
            })
        }
        fn apply_fault(
            &self,
            state: &mut Self::State,
            fault: &FaultInstance,
            event: &TimelineEvent,
        ) -> Result<AdapterObservation> {
            *state += 1;
            Ok(AdapterObservation {
                observation_sha256: hash(&format!("{:?}:{state}", fault.point.kind())),
                logical_ticks: event.logical_tick,
                safety: InvariantVerdict::Satisfied,
                liveness: InvariantVerdict::Satisfied,
            })
        }
        fn state_sha256(&self, state: &Self::State) -> Result<String> {
            Ok(hash(&format!("state:{state}")))
        }
    }

    #[test]
    fn deterministic_replay_and_exact_fault_coverage() {
        let catalog = vec![
            FaultPoint::NetworkDrop {
                after_operation_id: "op.a".into(),
                operation_id: "op.b".into(),
            },
            FaultPoint::StorageFsyncLoss {
                after_operation_id: "op.a".into(),
                state_id: "ledger".into(),
            },
        ];
        let definition = ordered(definition(catalog));
        let first = build_replay_manifest(&definition).unwrap();
        let second = build_replay_manifest(&definition).unwrap();
        assert_eq!(first, second);
        verify_replay_manifest(&definition, &first).unwrap();
        assert_eq!(first.coverage.schedule_count, 3);
        assert_eq!(
            first
                .coverage
                .fault_occurrences
                .get(&FaultKind::NetworkDrop),
            Some(&1)
        );
        assert_eq!(
            first
                .coverage
                .fault_occurrences
                .get(&FaultKind::StorageFsyncLoss),
            Some(&1)
        );
        let report = run_replay(
            &definition,
            &first,
            &AdapterEvaluator::new(&DeterministicAdapter),
        )
        .unwrap();
        require_safe_and_live(&report).unwrap();
    }

    #[test]
    fn all_required_fault_families_generate_as_causal_schedules() {
        let catalog = vec![
            FaultPoint::NetworkReorder {
                after_operation_id: "op.a".into(),
                first_operation_id: "op.a".into(),
                second_operation_id: "op.b".into(),
            },
            FaultPoint::NetworkDrop {
                after_operation_id: "op.a".into(),
                operation_id: "op.b".into(),
            },
            FaultPoint::NetworkDuplicate {
                after_operation_id: "op.a".into(),
                operation_id: "op.b".into(),
            },
            FaultPoint::NetworkDelay {
                after_operation_id: "op.a".into(),
                operation_id: "op.b".into(),
                delay_ticks: 1,
            },
            FaultPoint::ProcessCrash {
                after_operation_id: "op.a".into(),
                actor_id: "alice".into(),
            },
            FaultPoint::ProcessRestart {
                after_operation_id: "op.a".into(),
                actor_id: "alice".into(),
            },
            FaultPoint::StorageTornWrite {
                after_operation_id: "op.a".into(),
                state_id: "ledger".into(),
                retained_bytes: 0,
            },
            FaultPoint::StorageFsyncLoss {
                after_operation_id: "op.a".into(),
                state_id: "ledger".into(),
            },
            FaultPoint::StorageCasConflict {
                after_operation_id: "op.a".into(),
                state_id: "ledger".into(),
                expected_generation: 0,
            },
            FaultPoint::StorageStaleRead {
                after_operation_id: "op.a".into(),
                state_id: "ledger".into(),
                observed_generation: 0,
            },
            FaultPoint::ClockJump {
                after_operation_id: "op.a".into(),
                actor_id: "alice".into(),
                offset_ticks: -1,
            },
        ];
        let mut definition = ordered(definition(catalog));
        definition.exploration.exhaustive_max_faults = 2;
        definition.budgets.max_schedules = 128;
        definition.mandatory_fault_kinds = vec![
            FaultKind::NetworkReorder,
            FaultKind::NetworkDrop,
            FaultKind::NetworkDuplicate,
            FaultKind::NetworkDelay,
            FaultKind::ProcessCrash,
            FaultKind::ProcessRestart,
            FaultKind::StorageTornWrite,
            FaultKind::StorageFsyncLoss,
            FaultKind::StorageCasConflict,
            FaultKind::StorageStaleRead,
            FaultKind::ClockJump,
        ];
        let manifest = build_replay_manifest(&definition).unwrap();
        for kind in &definition.mandatory_fault_kinds {
            assert!(
                manifest
                    .coverage
                    .fault_occurrences
                    .get(kind)
                    .copied()
                    .unwrap_or(0)
                    > 0,
                "{kind:?}"
            );
        }
        assert!(
            manifest
                .schedules
                .iter()
                .all(|schedule| validate_schedule(&definition, schedule).is_ok())
        );
    }

    #[test]
    fn rejects_causal_faults_and_crash_without_recovery() {
        let mut definition = ordered(definition(vec![FaultPoint::ProcessRestart {
            after_operation_id: "op.a".into(),
            actor_id: "alice".into(),
        }]));
        definition.mandatory_fault_kinds = vec![FaultKind::ProcessRestart];
        assert!(matches!(
            build_replay_manifest(&definition),
            Err(FaultError::CoverageIncomplete(_)) | Err(FaultError::InvalidSchedule(_))
        ));
        definition.operations[0].depends_on.push("op.c".into());
        assert!(matches!(
            validate_definition(&definition),
            Err(FaultError::InvalidDefinition(_))
        ));
    }

    #[test]
    fn crash_recovery_trace_is_causally_valid() {
        let catalog = vec![
            FaultPoint::ProcessCrash {
                after_operation_id: "op.a".into(),
                actor_id: "alice".into(),
            },
            FaultPoint::ProcessRestart {
                after_operation_id: "op.a".into(),
                actor_id: "alice".into(),
            },
        ];
        let mut definition = ordered(definition(catalog));
        definition.exploration.exhaustive_max_faults = 2;
        definition.mandatory_fault_kinds = vec![FaultKind::ProcessCrash, FaultKind::ProcessRestart];
        let manifest = build_replay_manifest(&definition).unwrap();
        let recovered = manifest
            .schedules
            .iter()
            .find(|schedule| schedule.faults.len() == 2)
            .unwrap();
        assert!(
            recovered
                .events
                .iter()
                .any(|event| matches!(event.kind, TimelineEventKind::Fault { .. }))
        );
        validate_schedule(&definition, recovered).unwrap();
    }

    struct FaultFailEvaluator;
    impl ScheduleEvaluator for FaultFailEvaluator {
        fn evaluate(
            &self,
            _: &FaultDefinition,
            schedule: &FaultSchedule,
        ) -> Result<ScheduleEvaluation> {
            let observations =
                schedule
                    .events
                    .iter()
                    .map(|event| {
                        bind_observation(
                            schedule,
                            event,
                            hash(&format!("state:{}", event.sequence)),
                            AdapterObservation {
                                observation_sha256: hash(&event.event_id),
                                logical_ticks: event.logical_tick,
                                safety: if schedule.faults.iter().any(|fault| {
                                    fault.point.kind() == FaultKind::StorageCasConflict
                                }) {
                                    InvariantVerdict::Violated
                                } else {
                                    InvariantVerdict::Satisfied
                                },
                                liveness: InvariantVerdict::Satisfied,
                            },
                        )
                    })
                    .collect::<Result<Vec<_>>>()?;
            build_evaluation(schedule, observations)
        }
    }

    #[test]
    fn shrinking_preserves_causality_and_reaches_one_minimal_fault_set() {
        let catalog = vec![
            FaultPoint::StorageCasConflict {
                after_operation_id: "op.a".into(),
                state_id: "ledger".into(),
                expected_generation: 0,
            },
            FaultPoint::NetworkDrop {
                after_operation_id: "op.a".into(),
                operation_id: "op.b".into(),
            },
        ];
        let mut definition = ordered(definition(catalog));
        definition.exploration.exhaustive_max_faults = 2;
        let manifest = build_replay_manifest(&definition).unwrap();
        let failing = manifest
            .schedules
            .iter()
            .find(|schedule| schedule.faults.len() == 2)
            .unwrap();
        let result = shrink_failing_schedule(&definition, failing, &FaultFailEvaluator).unwrap();
        assert!(result.one_minimal);
        assert_eq!(result.minimized_schedule.faults.len(), 1);
        assert_eq!(
            result.minimized_schedule.faults[0].point.kind(),
            FaultKind::StorageCasConflict
        );
        validate_schedule(&definition, &result.minimized_schedule).unwrap();
    }

    #[test]
    fn rejects_replay_drift_and_duplicate_schedule() {
        let definition = ordered(definition(vec![FaultPoint::NetworkDrop {
            after_operation_id: "op.a".into(),
            operation_id: "op.b".into(),
        }]));
        let mut manifest = build_replay_manifest(&definition).unwrap();
        manifest.schedules.push(manifest.schedules[0].clone());
        assert!(matches!(
            verify_replay_manifest(&definition, &manifest),
            Err(FaultError::Drift(_))
        ));
    }

    struct FlakyEvaluator(std::cell::Cell<u64>);
    impl ScheduleEvaluator for FlakyEvaluator {
        fn evaluate(
            &self,
            _: &FaultDefinition,
            schedule: &FaultSchedule,
        ) -> Result<ScheduleEvaluation> {
            let round = self.0.get();
            self.0.set(round + 1);
            let observations = schedule
                .events
                .iter()
                .map(|event| {
                    bind_observation(
                        schedule,
                        event,
                        hash(&format!("state:{}:{round}", event.sequence)),
                        AdapterObservation {
                            observation_sha256: hash(&format!("{}:{round}", event.event_id)),
                            logical_ticks: event.logical_tick,
                            safety: InvariantVerdict::Satisfied,
                            liveness: InvariantVerdict::Satisfied,
                        },
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            build_evaluation(schedule, observations)
        }
    }

    #[test]
    fn rejects_flaky_invariant_evidence_and_budget_exhaustion() {
        let definition = ordered(definition(vec![]));
        let manifest = build_replay_manifest(&definition).unwrap();
        assert!(matches!(
            run_replay(
                &definition,
                &manifest,
                &FlakyEvaluator(std::cell::Cell::new(0))
            ),
            Err(FaultError::Flaky(_))
        ));
        let mut constrained = definition.clone();
        constrained.budgets.max_evaluation_attempts = 1;
        assert!(matches!(
            run_replay(
                &constrained,
                &build_replay_manifest(&constrained).unwrap(),
                &AdapterEvaluator::new(&DeterministicAdapter)
            ),
            Err(FaultError::BudgetExhausted(_))
        ));
    }

    #[test]
    fn missing_observations_and_logical_timeouts_fail_closed() {
        let definition = ordered(definition(vec![]));
        let schedule = build_replay_manifest(&definition)
            .unwrap()
            .schedules
            .remove(0);
        let evaluator = AdapterEvaluator::new(&DeterministicAdapter);
        let mut evaluation = evaluator.evaluate(&definition, &schedule).unwrap();
        evaluation.observations.pop();
        evaluation.evaluation_sha256 = build_evaluation(&schedule, evaluation.observations.clone())
            .unwrap()
            .evaluation_sha256;
        assert!(matches!(
            verify_evaluation(&definition, &schedule, &evaluation),
            Err(FaultError::InvalidEvaluation(_))
        ));

        let mut evaluation = evaluator.evaluate(&definition, &schedule).unwrap();
        let event = &schedule.events[0];
        let original = &evaluation.observations[0];
        evaluation.observations[0] = bind_observation(
            &schedule,
            event,
            original.state_sha256.clone(),
            AdapterObservation {
                observation_sha256: original.observation_sha256.clone(),
                logical_ticks: definition.budgets.max_logical_ticks + 1,
                safety: original.safety,
                liveness: original.liveness,
            },
        )
        .unwrap();
        evaluation.evaluation_sha256 = build_evaluation(&schedule, evaluation.observations.clone())
            .unwrap()
            .evaluation_sha256;
        assert!(matches!(
            verify_evaluation(&definition, &schedule, &evaluation),
            Err(FaultError::Timeout(_))
        ));
    }
}
