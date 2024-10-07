use cosmwasm_std::{Addr, DepsMut};
use crate::error::ContractError;
use crate::state::{KEYS, KeyType};

pub fn check_key_authorization(deps: &DepsMut, sender: &Addr, required_key: KeyType) -> Result<(), ContractError> {
    // Load the Vec<Key> for the given sender address
    let keys = KEYS.load(deps.storage, sender)?;
    
    // Check if any of the sender's keys match the required key type
    if keys.iter().any(|key| key.key_type == required_key) {
        Ok(())
    } else {
        Err(ContractError::Unauthorized {})
    }
}