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
    check_key_authorization(&deps, &info.sender, KeyType::ManagementKey)
        .map_err(|e| ContractError::Unauthorized { 
            reason: format!("Sender lacks ManagementKey: {}", e) 
        })?;

    let addr_key_owner = deps.api.addr_validate(&key_owner)
        .map_err(|e| ContractError::InvalidAddress { 
            reason: format!("Invalid key owner address '{}': {}", key_owner, e) 
        })?;

    let key_type = KeyType::from_str(&key_type)
        .map_err(|_| ContractError::InvalidKeyType { 
            key_type: key_type.clone() 
        })?;

    let new_key = Key {
        key_type: key_type.clone(),
        owner: addr_key_owner.clone(),
    };

    let owner = OWNER.load(deps.storage)
        .map_err(|e| ContractError::LoadError { 
            entity: "owner".to_string(), 
            reason: e.to_string() 
        })?;

    // Load existing keys or create a new vector if none exist
    let mut keys = KEYS.may_load(deps.storage, &owner)
        .map_err(|e| ContractError::LoadError { 
            entity: "keys".to_string(), 
            reason: e.to_string() 
        })?.unwrap_or_default();

    // Check if the key already exists
    if keys.iter().any(|k| k.key_type == key_type) {
        return Err(ContractError::KeyAlreadyExists { 
            key_type: key_type.to_string() 
        });
    }

    // Add the new key
    keys.push(new_key);

    // Save the updated keys
    KEYS.save(deps.storage, &owner, &keys)
        .map_err(|e| ContractError::SaveError { 
            entity: "keys".to_string(), 
            reason: e.to_string() 
        })?;

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
    check_key_authorization(&deps, &info.sender, KeyType::ManagementKey)
        .map_err(|e| ContractError::Unauthorized { 
            reason: format!("Sender lacks ManagementKey: {}", e) 
        })?;
    
    let addr_key_owner = deps.api.addr_validate(&key_owner)
        .map_err(|e| ContractError::InvalidAddress { 
            reason: format!("Invalid key owner address '{}': {}", key_owner, e) 
        })?;

    let key_type = KeyType::from_str(&key_type)
        .map_err(|_| ContractError::InvalidKeyType { 
            key_type: key_type.clone() 
        })?;

    let owner = OWNER.load(deps.storage)
        .map_err(|e| ContractError::LoadError { 
            entity: "owner".to_string(), 
            reason: e.to_string() 
        })?;

    // Load existing keys
    let mut keys = KEYS.load(deps.storage, &owner)
        .map_err(|e| ContractError::LoadError { 
            entity: "keys".to_string(), 
            reason: e.to_string() 
        })?;

    // Find and remove the key
    if let Some(index) = keys.iter().position(|k| k.key_type == key_type && k.owner == addr_key_owner) {
        keys.remove(index);
        // Save the updated keys
        KEYS.save(deps.storage, &owner, &keys)
            .map_err(|e| ContractError::SaveError { 
                entity: "keys".to_string(), 
                reason: e.to_string() 
            })?;
    } else {
        return Err(ContractError::KeyNotFound { 
            key_type: key_type.to_string(), 
            owner: addr_key_owner.to_string() 
        });
    }

    Ok(Response::new()
        .add_attribute("action", "remove_key")
        .add_attribute("key_owner", addr_key_owner)
        .add_attribute("key_type", key_type.to_string()))
}