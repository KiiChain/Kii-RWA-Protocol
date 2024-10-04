use cosmwasm_std::{DepsMut, MessageInfo, Response};
use crate::error::ContractError;
use crate::state::{Key, KeyType, IDENTITY};
use crate::utils::check_key_authorization;

pub fn add_key(
    deps: DepsMut,
    info: MessageInfo,
    key_owner: String,
    key_type: String,
) -> Result<Response, ContractError> {
    // Check if the sender is authorized to add keys
    check_key_authorization(&deps, &info.sender, KeyType::ManagementKey)?;

    let mut identity = IDENTITY.load(deps.storage, &info.sender)?;
    let addr_key_owner =  deps.api.addr_validate(&key_owner)?;

    let new_key = Key {
        key_type: KeyType::from_str(&key_type)?,
        owner: addr_key_owner.clone(),
    };

    // Check if the key already exists
    if identity.keys.iter().any(|k| k.owner == addr_key_owner && k.key_type == new_key.key_type) {
        return Err(ContractError::KeyAlreadyExists {});
    }

    identity.keys.push(new_key);
    IDENTITY.save(deps.storage, &info.sender, &identity)?;

    Ok(Response::new()
        .add_attribute("method", "add_key")
        .add_attribute("key_type", key_type)
        .add_attribute("key_owner", addr_key_owner))
}

pub fn remove_key(
    deps: DepsMut,
    info: MessageInfo,
    key_owner: String,
    key_type: String,
) -> Result<Response, ContractError> {
    // Check if the sender is authorized to remove keys
    check_key_authorization(&deps, &info.sender, KeyType::ManagementKey)?;
    
    let addr_key_owner =  deps.api.addr_validate(&key_owner)?;
    let mut identity = IDENTITY.load(deps.storage, &info.sender)?;
    let key_type = KeyType::from_str(&key_type)?;

    // Find and remove the key
    identity.keys.retain(|k| !(k.owner == addr_key_owner && k.key_type == key_type));

    IDENTITY.save(deps.storage, &info.sender, &identity)?;

    Ok(Response::new()
        .add_attribute("method", "remove_key")
        .add_attribute("key_owner", addr_key_owner)
        .add_attribute("key_type", key_type.to_string()))
}