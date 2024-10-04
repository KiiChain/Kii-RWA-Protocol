use cosmwasm_std::{DepsMut, MessageInfo, Response};
use crate::error::ContractError;


use crate::types::Identity;

use crate::state::IDENTITY;

pub fn create_identity(deps: DepsMut, info: MessageInfo, owner: String) -> Result<Response, ContractError> {
    // Implementation
    unimplemented!()
}