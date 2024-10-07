use cosmwasm_std::{DepsMut, MessageInfo, Response};
use crate::error::ContractError;
use crate::state::{Key, KeyType, KEYS, OWNER};
use crate::utils::check_key_authorization;

pub fn execute_add_key(
    deps: DepsMut,
    info: MessageInfo,
    key_owner: String,
    key_type: String,
) -> Result<Response, ContractError> {
    // Check if the sender is authorized to add keys
    check_key_authorization(&deps, &info.sender, KeyType::ManagementKey)?;

    let addr_key_owner = deps.api.addr_validate(&key_owner)?;
    println!("HERE");

    let key_type = KeyType::from_str(&key_type)?;


    let new_key = Key {
        key_type: key_type.clone(),
        owner: addr_key_owner.clone(),
    };
    let owner = OWNER.load(deps.storage)?;
    // Load existing keys or create a new vector if none exist
    let mut keys = KEYS.load(deps.storage, &owner)?;

    // Check if the key already exists
    if keys.iter().any(|k| k.key_type == key_type && k.owner == addr_key_owner) {
        return Err(ContractError::KeyAlreadyExists {});
    }

    // Add the new key
    keys.push(new_key);

    // Save the updated keys
    KEYS.save(deps.storage, &owner, &keys)?;

    Ok(Response::new()
        .add_attribute("action", "add_key")
        .add_attribute("key_type", key_type.to_string())
        .add_attribute("key_owner", addr_key_owner))
}

pub fn execute_remove_key(
    deps: DepsMut,
    info: MessageInfo,
    key_owner: String,
    key_type: String,
) -> Result<Response, ContractError> {
    // Check if the sender is authorized to remove keys
    check_key_authorization(&deps, &info.sender, KeyType::ManagementKey)?;
    
    let addr_key_owner = deps.api.addr_validate(&key_owner)?;
    let key_type = KeyType::from_str(&key_type)?;

    let owner = OWNER.load(deps.storage)?;
    // Load existing keys
    let mut keys = KEYS.load(deps.storage, &owner)?;

    // Find and remove the key
    if let Some(index) = keys.iter().position(|k| k.key_type == key_type && k.owner == addr_key_owner) {
        keys.remove(index);
        // Save the updated keys
        KEYS.save(deps.storage, &owner, &keys)?;
    } else {
        return Err(ContractError::KeyNotFound {});
    }

    Ok(Response::new()
        .add_attribute("action", "remove_key")
        .add_attribute("key_owner", addr_key_owner)
        .add_attribute("key_type", key_type.to_string()))
}