//! Strict protocol-neutral process boundary for assurance components.
//!
//! Adapters receive one canonical request on standard input and return one
//! canonical response on standard output. Large inputs and outputs are
//! content-addressed blobs; secret input blobs are delivered out of band by the
//! sandbox and are never embedded in the request, environment, or argv.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const ADAPTER_PROTOCOL_V1: &str = "shieldkit-assurance-adapter/v1";

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum AdapterCapability {
    Describe,
    Canonicalize,
    Validate,
    #[serde(rename = "model.transition")]
    ModelTransition,
    #[serde(rename = "crypto.derive")]
    CryptoDerive,
    Prove,
    Verify,
    #[serde(rename = "transaction.assemble")]
    TransactionAssemble,
    #[serde(rename = "vm.evaluate")]
    VmEvaluate,
    #[serde(rename = "chain.observe")]
    ChainObserve,
    #[serde(rename = "store.step")]
    StoreStep,
    #[serde(rename = "store.recover")]
    StoreRecover,
    #[serde(rename = "privacy.observe")]
    PrivacyObserve,
    Measure,
}

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum BlobSecrecy {
    Public,
    Secret,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BlobReference {
    pub algorithm: String,
    pub digest: String,
    pub size: u64,
    pub media_type: String,
    pub secrecy: BlobSecrecy,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdapterRequest {
    pub protocol: String,
    pub request_id: String,
    pub case_id: String,
    pub capability: AdapterCapability,
    pub seed: String,
    pub public_input: Map<String, Value>,
    pub blobs: Vec<BlobReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdapterObservation {
    pub observation_type: String,
    pub public_value: Map<String, Value>,
    pub artifacts: Vec<BlobReference>,
    pub metrics: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdapterFailure {
    pub code: String,
    pub message: String,
}

/// A strict wire envelope. Validation requires exactly one success or failure
/// payload according to `ok`; optionality exists only because JSON Schema and
/// Serde cannot internally tag an enum with a Boolean literal.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdapterResponse {
    pub protocol: String,
    pub request_id: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observations: Option<Vec<AdapterObservation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<AdapterFailure>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AdapterProtocolError {
    #[error("unsupported adapter protocol: {0}")]
    UnsupportedProtocol(String),
    #[error("invalid {field}: {value}")]
    InvalidField { field: &'static str, value: String },
    #[error("duplicate blob reference: {0}")]
    DuplicateBlob(String),
    #[error("successful response must contain a nonempty observation list and no error")]
    InvalidSuccessShape,
    #[error("failed response must contain one error and no observations")]
    InvalidFailureShape,
    #[error("response request ID differs: expected {expected}, observed {observed}")]
    RequestIdMismatch { expected: String, observed: String },
    #[error("secret output artifacts are forbidden: {0}")]
    SecretOutput(String),
    #[error("canonical JSON encoding failed: {0}")]
    Canonical(String),
}

pub fn validate_request(request: &AdapterRequest) -> Result<(), AdapterProtocolError> {
    validate_protocol(&request.protocol)?;
    validate_id("requestId", &request.request_id)?;
    validate_id("caseId", &request.case_id)?;
    validate_sha256_identifier("seed", &request.seed)?;
    validate_json_object("publicInput", &request.public_input)?;
    validate_blobs(&request.blobs, true)?;
    Ok(())
}

pub fn validate_response(
    response: &AdapterResponse,
    expected_request_id: &str,
) -> Result<(), AdapterProtocolError> {
    validate_protocol(&response.protocol)?;
    validate_id("requestId", &response.request_id)?;
    if response.request_id != expected_request_id {
        return Err(AdapterProtocolError::RequestIdMismatch {
            expected: expected_request_id.into(),
            observed: response.request_id.clone(),
        });
    }
    match (response.ok, &response.observations, &response.error) {
        (true, Some(observations), None) if !observations.is_empty() => {
            let mut types = BTreeSet::new();
            for observation in observations {
                validate_id("observationType", &observation.observation_type)?;
                if !types.insert(observation.observation_type.as_str()) {
                    return Err(AdapterProtocolError::InvalidField {
                        field: "observationType",
                        value: observation.observation_type.clone(),
                    });
                }
                validate_json_object("publicValue", &observation.public_value)?;
                validate_blobs(&observation.artifacts, false)?;
                for artifact in &observation.artifacts {
                    if artifact.secrecy == BlobSecrecy::Secret {
                        return Err(AdapterProtocolError::SecretOutput(artifact.digest.clone()));
                    }
                }
                for (name, value) in &observation.metrics {
                    validate_id("metric", name)?;
                    if !value.is_finite() || *value < 0.0 {
                        return Err(AdapterProtocolError::InvalidField {
                            field: "metric",
                            value: name.clone(),
                        });
                    }
                }
            }
            Ok(())
        }
        (true, _, _) => Err(AdapterProtocolError::InvalidSuccessShape),
        (false, None, Some(error)) => {
            validate_id("error.code", &error.code)?;
            if error.message.trim().is_empty()
                || error.message.len() > 4096
                || error.message.chars().any(|character| character == '\0')
            {
                return Err(AdapterProtocolError::InvalidField {
                    field: "error.message",
                    value: "invalid message".into(),
                });
            }
            Ok(())
        }
        (false, _, _) => Err(AdapterProtocolError::InvalidFailureShape),
    }
}

pub fn canonical_request(request: &AdapterRequest) -> Result<Vec<u8>, AdapterProtocolError> {
    validate_request(request)?;
    serde_json_canonicalizer::to_vec(request)
        .map_err(|error| AdapterProtocolError::Canonical(error.to_string()))
}

pub fn canonical_response(
    response: &AdapterResponse,
    expected_request_id: &str,
) -> Result<Vec<u8>, AdapterProtocolError> {
    validate_response(response, expected_request_id)?;
    serde_json_canonicalizer::to_vec(response)
        .map_err(|error| AdapterProtocolError::Canonical(error.to_string()))
}

pub fn request_digest(request: &AdapterRequest) -> Result<String, AdapterProtocolError> {
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical_request(request)?))
    ))
}

pub fn response_digest(
    response: &AdapterResponse,
    expected_request_id: &str,
) -> Result<String, AdapterProtocolError> {
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical_response(
            response,
            expected_request_id
        )?))
    ))
}

fn validate_protocol(protocol: &str) -> Result<(), AdapterProtocolError> {
    if protocol == ADAPTER_PROTOCOL_V1 {
        Ok(())
    } else {
        Err(AdapterProtocolError::UnsupportedProtocol(protocol.into()))
    }
}

fn validate_id(field: &'static str, value: &str) -> Result<(), AdapterProtocolError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'/' | b'-'))
        });
    if valid {
        Ok(())
    } else {
        Err(AdapterProtocolError::InvalidField {
            field,
            value: value.into(),
        })
    }
}

fn validate_sha256_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), AdapterProtocolError> {
    let raw = value.strip_prefix("sha256:").unwrap_or_default();
    if raw.len() == 64
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(AdapterProtocolError::InvalidField {
            field,
            value: value.into(),
        })
    }
}

fn validate_json_object(
    field: &'static str,
    value: &Map<String, Value>,
) -> Result<(), AdapterProtocolError> {
    fn visit(value: &Value, depth: usize) -> bool {
        if depth > 64 {
            return false;
        }
        match value {
            Value::Null | Value::Bool(_) | Value::String(_) | Value::Number(_) => true,
            Value::Array(values) => values.iter().all(|value| visit(value, depth + 1)),
            Value::Object(values) => values.iter().all(|(key, value)| {
                !key.is_empty()
                    && key.len() <= 256
                    && !key.chars().any(|character| character == '\0')
                    && visit(value, depth + 1)
            }),
        }
    }
    if value.iter().all(|(key, value)| {
        !key.is_empty()
            && key.len() <= 256
            && !key.chars().any(|character| character == '\0')
            && visit(value, 1)
    }) {
        Ok(())
    } else {
        Err(AdapterProtocolError::InvalidField {
            field,
            value: "invalid JSON object".into(),
        })
    }
}

fn validate_blobs(blobs: &[BlobReference], allow_secret: bool) -> Result<(), AdapterProtocolError> {
    let mut digests = BTreeSet::new();
    for blob in blobs {
        if blob.algorithm != "sha256" {
            return Err(AdapterProtocolError::InvalidField {
                field: "blob.algorithm",
                value: blob.algorithm.clone(),
            });
        }
        validate_sha256_identifier("blob.digest", &format!("sha256:{}", blob.digest))?;
        if blob.media_type.is_empty()
            || blob.media_type.len() > 255
            || blob
                .media_type
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(AdapterProtocolError::InvalidField {
                field: "blob.mediaType",
                value: blob.media_type.clone(),
            });
        }
        if !allow_secret && blob.secrecy == BlobSecrecy::Secret {
            return Err(AdapterProtocolError::SecretOutput(blob.digest.clone()));
        }
        if !digests.insert(blob.digest.as_str()) {
            return Err(AdapterProtocolError::DuplicateBlob(blob.digest.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn request() -> AdapterRequest {
        AdapterRequest {
            protocol: ADAPTER_PROTOCOL_V1.into(),
            request_id: "request.one".into(),
            case_id: "case.one".into(),
            capability: AdapterCapability::Verify,
            seed: format!("sha256:{}", digest('a')),
            public_input: Map::from_iter([("value".into(), Value::from(1))]),
            blobs: vec![BlobReference {
                algorithm: "sha256".into(),
                digest: digest('b'),
                size: 3,
                media_type: "application/octet-stream".into(),
                secrecy: BlobSecrecy::Secret,
            }],
        }
    }

    fn success() -> AdapterResponse {
        AdapterResponse {
            protocol: ADAPTER_PROTOCOL_V1.into(),
            request_id: "request.one".into(),
            ok: true,
            observations: Some(vec![AdapterObservation {
                observation_type: "verify.result".into(),
                public_value: Map::from_iter([("accepted".into(), Value::Bool(true))]),
                artifacts: vec![BlobReference {
                    algorithm: "sha256".into(),
                    digest: digest('c'),
                    size: 4,
                    media_type: "application/octet-stream".into(),
                    secrecy: BlobSecrecy::Public,
                }],
                metrics: BTreeMap::from([("wall_ms".into(), 2.0)]),
            }]),
            error: None,
        }
    }

    #[test]
    fn request_and_response_are_strict_and_content_bound() {
        let request = request();
        validate_request(&request).unwrap();
        let response = success();
        validate_response(&response, &request.request_id).unwrap();
        assert_eq!(request_digest(&request).unwrap().len(), 71);
        assert_eq!(
            response_digest(&response, &request.request_id)
                .unwrap()
                .len(),
            71
        );
        let mut value = serde_json::to_value(&request).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), true.into());
        assert!(serde_json::from_value::<AdapterRequest>(value).is_err());
    }

    #[test]
    fn response_shape_and_request_binding_fail_closed() {
        let mut response = success();
        response.error = Some(AdapterFailure {
            code: "unexpected".into(),
            message: "both branches".into(),
        });
        assert_eq!(
            validate_response(&response, "request.one"),
            Err(AdapterProtocolError::InvalidSuccessShape)
        );
        let mut response = success();
        response.request_id = "request.two".into();
        assert!(matches!(
            validate_response(&response, "request.one"),
            Err(AdapterProtocolError::RequestIdMismatch { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_blobs_secret_outputs_and_invalid_metrics() {
        let mut request = request();
        request.blobs.push(request.blobs[0].clone());
        assert!(matches!(
            validate_request(&request),
            Err(AdapterProtocolError::DuplicateBlob(_))
        ));
        let mut response = success();
        response.as_success_mut().artifacts[0].secrecy = BlobSecrecy::Secret;
        assert!(matches!(
            validate_response(&response, "request.one"),
            Err(AdapterProtocolError::SecretOutput(_))
        ));
        let mut response = success();
        response
            .as_success_mut()
            .metrics
            .insert("negative".into(), -1.0);
        assert!(matches!(
            validate_response(&response, "request.one"),
            Err(AdapterProtocolError::InvalidField {
                field: "metric",
                ..
            })
        ));
    }

    #[test]
    fn rejects_malformed_seed_digest_and_excessive_json_depth() {
        let mut request = request();
        request.seed = "not-a-seed".into();
        assert!(validate_request(&request).is_err());
        let mut nested = Value::Null;
        for _ in 0..66 {
            nested = Value::Array(vec![nested]);
        }
        request.seed = format!("sha256:{}", digest('a'));
        request.public_input.insert("deep".into(), nested);
        assert!(validate_request(&request).is_err());
    }

    trait SuccessObservation {
        fn as_success_mut(&mut self) -> &mut AdapterObservation;
    }

    impl SuccessObservation for AdapterResponse {
        fn as_success_mut(&mut self) -> &mut AdapterObservation {
            self.observations
                .as_mut()
                .and_then(|observations| observations.first_mut())
                .expect("test success response")
        }
    }
}
