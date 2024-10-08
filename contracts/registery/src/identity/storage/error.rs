use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Identity already exists")]
    IdentityAlreadyExists {},

    #[error("Identity not found")]
    IdentityNotFound {},

    #[error("Agent already exists")]
    AgentAlreadyExists {},

    #[error("Agent not found")]
    AgentNotFound {},
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.
}
