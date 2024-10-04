use cosmwasm_std::{DepsMut, MessageInfo, Response};

use crate::error::ContractError;

use crate::types::Claim;

use crate::state::CLAIMS;

pub fn add_claim(deps: DepsMut, info: MessageInfo, identity: String, claim: Claim) -> Result<Response, ContractError> {
    // Implementation
    unimplemented!()

}

pub fn remove_claim(deps: DepsMut, info: MessageInfo, identity: String, claim_id: Vec<u8>) -> Result<Response, ContractError> {
    // Implementation
    unimplemented!()

}
