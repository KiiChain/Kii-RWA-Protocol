use cosmwasm_std::{StdError, Uint128};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized: {reason}")]
    Unauthorized { reason: String },

    #[error("Invalid address: {reason}")]
    InvalidAddress { reason: String },

    #[error("Invalid key type: {key_type}")]
    InvalidKeyType { key_type: String },

    #[error("Invalid key purpose")]
    InvalidKeyPurpose {},

    #[error("Invalid claim topic: {topic}")]
    InvalidClaimTopic { topic: String },

    #[error("Invalid issuer signature: {reason}")]
    InvalidIssuerSignature { reason: String },

    #[error("Error while serializing data: {reason}")]
    SerializationError { reason: String },

    #[error("Error while deserializing data: {reason}")]
    DeserializationError { reason: String },

    #[error("Key not found for type {key_type} and owner {owner}")]
    KeyNotFound { key_type: String, owner: String },

    #[error("No keys found for the given owner")]
    NoKeysFound {},

    #[error("Key already exists for type {key_type}")]
    KeyAlreadyExists { key_type: String },

    #[error("Invalid claim ID: {claim_id}")]
    InvalidClaimId { claim_id: String },

    #[error("Claim not found with ID: {claim_topic}")]
    ClaimNotFound { claim_topic: Uint128 },

    #[error("Claim already exists with ID: {claim_topic}")]
    ClaimAlreadyExists { claim_topic: Uint128 },

    #[error("Identity not found for owner: {owner}")]
    IdentityNotFound { owner: String },

    #[error("Identity already exists for owner: {owner}")]
    IdentityAlreadyExists { owner: String },

    #[error("Error loading {entity}: {reason}")]
    LoadError { entity: String, reason: String },

    #[error("Error saving {entity}: {reason}")]
    SaveError { entity: String, reason: String },

    #[error("Invalid signature: {reason}")]
    InvalidSignature { reason: String },

    #[error("Invalid contract version: {expected} != {actual}")]
    InvalidContract { expected: String, actual: String },

    #[error("Already migrated: {current_version} >= {new_version}")]
    AlreadyMigrated {
        current_version: String,
        new_version: String,
    },
}

impl From<ContractError> for StdError {
    fn from(error: ContractError) -> Self {
        StdError::generic_err(error.to_string())
    }
}
