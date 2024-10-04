use cosmwasm_std::{DepsMut, MessageInfo, Response};
use crate::error::ContractError;

use crate::types::Key;

use crate::state::KEYS;

pub fn add_key(deps: DepsMut, info: MessageInfo, identity: String, key: Key) -> Result<Response, ContractError> {
    // Implementation
    unimplemented!()

}

pub fn remove_key(deps: DepsMut, info: MessageInfo, identity: String, key: Vec<u8>, purpose: u64) -> Result<Response, ContractError> {
    // Implementation
    unimplemented!()
}