use crate::error::ContractError;
use crate::state::{Key, KeyType, IDENTITIES};
use crate::utils::{check_identity_exists, check_key_authorization};
use cosmwasm_std::{DepsMut, MessageInfo, Response};
use std::str::FromStr;

pub fn execute_add_key(
    deps: DepsMut,
    info: MessageInfo,
    key_owner: String,
    key_type: String,
    identity_owner: String,
) -> Result<Response, ContractError> {
    if !check_identity_exists(&deps, &info.sender) {
        return Err(ContractError::IdentityNotFound {
            owner: info.sender.to_string(),
        });
    }

    let identity_owner_addr = deps.api.addr_validate(&identity_owner)?;

    // Check if the sender is authorized to add keys
    check_key_authorization(
        &deps,
        &info.sender,
        KeyType::ManagementKey,
        &identity_owner_addr,
    )
    .map_err(|e| ContractError::Unauthorized {
        reason: format!("Sender lacks ManagementKey: {e}"),
    })?;

    let addr_key_owner = deps.api.addr_validate(&key_owner)?;

    let key_type = KeyType::from_str(&key_type)?;

    let new_key = Key {
        key_type: key_type.clone(),
        owner: addr_key_owner.clone(),
    };

    // Load the identity
    let mut identity = IDENTITIES.load(deps.storage, identity_owner_addr.clone())?;

    // Check if the key already exists
    if identity
        .keys
        .iter()
        .any(|k| k.key_type == key_type && k.owner == addr_key_owner)
    {
        return Err(ContractError::KeyAlreadyExists {
            key_type: key_type.to_string(),
        });
    }

    // Add the new key
    identity.keys.push(new_key);

    // Save the updated identity
    IDENTITIES.save(deps.storage, identity_owner_addr.clone(), &identity)?;

    Ok(Response::new()
        .add_attribute("action", "add_key")
        .add_attribute("identity_owner", identity_owner)
        .add_attribute("key_type", key_type.to_string())
        .add_attribute("key_owner", addr_key_owner))
}

pub fn execute_remove_key(
    deps: DepsMut,
    info: MessageInfo,
    key_owner: String,
    key_type: String,
    identity_owner: String,
) -> Result<Response, ContractError> {
    if !check_identity_exists(&deps, &info.sender) {
        return Err(ContractError::IdentityNotFound {
            owner: info.sender.to_string(),
        });
    }

    let identity_owner_addr = deps.api.addr_validate(&identity_owner)?;

    // Check if the sender is authorized to remove keys
    check_key_authorization(
        &deps,
        &info.sender,
        KeyType::ManagementKey,
        &identity_owner_addr,
    )
    .map_err(|e| ContractError::Unauthorized {
        reason: format!("Sender lacks ManagementKey: {e}"),
    })?;

    let addr_key_owner = deps.api.addr_validate(&key_owner)?;

    let key_type = KeyType::from_str(&key_type)?;

    // Load the identity
    let mut identity = IDENTITIES.load(deps.storage, identity_owner_addr.clone())?;

    // Find and remove the key
    if let Some(index) = identity
        .keys
        .iter()
        .position(|k| k.key_type == key_type && k.owner == addr_key_owner)
    {
        identity.keys.remove(index);
        // Save the updated identity
        IDENTITIES.save(deps.storage, identity_owner_addr.clone(), &identity)?;
    } else {
        return Err(ContractError::KeyNotFound {
            key_type: key_type.to_string(),
            owner: addr_key_owner.to_string(),
        });
    }

    Ok(Response::new()
        .add_attribute("action", "remove_key")
        .add_attribute("identity_owner", identity_owner)
        .add_attribute("key_owner", addr_key_owner)
        .add_attribute("key_type", key_type.to_string()))
}
