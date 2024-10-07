use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Address is invalid")]
    InvalidAddress {},

    #[error("Invalid key purpose")]
    InvalidKeyPurpose {},

    #[error("Invalid claim topic")]
    InvalidClaimTopic {},

    #[error("Invalid issuer signature")]
    InvalidIssuerSignature {},

    #[error("Error while serializing data")]
    SerializationError {},

    #[error("Error while deserializing data")]
    DeserializationError {},

    #[error("Key not found")]
    KeyNotFound {},

    #[error("Key already exists")]
    KeyAlreadyExists,

    #[error("Invalid claim ID")]
    InvalidClaimId {},

    #[error("Claim not found")]
    ClaimNotFound {},

    #[error("Claim already exists")]
    ClaimAlreadyExists {},

    #[error("Identity not found")]
    IdentityNotFound {},
}


impl From<ContractError> for StdError {
    fn from(error: ContractError) -> Self {
        StdError::generic_err(error.to_string())
    }
}