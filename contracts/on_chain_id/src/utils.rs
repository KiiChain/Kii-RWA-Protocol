use cosmwasm_std::{Addr, DepsMut};
use crate::error::ContractError;
use crate::state::{IDENTITY, KeyType};

pub fn check_key_authorization(deps: &DepsMut, sender: &Addr, required_key: KeyType) -> Result<(), ContractError> {
    let identity = IDENTITY.load(deps.storage, &sender)?;
    
    // Check if the sender is authorized (has the required key type)
    if !identity.keys.iter().any(|k| k.key_type == required_key) {
        return Err(ContractError::Unauthorized {});
    }
    Ok(())
}