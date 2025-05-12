use crate::error::ContractError;
use crate::state::{Identity, KeyType, IDENTITIES};
use crate::utils::{check_identity_exists, check_key_authorization};
use cosmwasm_std::{DepsMut, MessageInfo, Response};

pub fn execute_add_identity(
    deps: DepsMut,
    info: MessageInfo,
    country: String,
) -> Result<Response, ContractError> {
    // Check if the identity already exists
    if check_identity_exists(&deps, &info.sender) {
        return Err(ContractError::IdentityAlreadyExists {
            owner: info.sender.to_string(),
        });
    }

    let identity = Identity {
        owner: info.sender.clone(),
        country,
        keys: vec![],
        claims: vec![],
    };

    IDENTITIES.save(deps.storage, info.sender.clone(), &identity)?;

    Ok(Response::new()
        .add_attribute("action", "add_identity")
        .add_attribute("owner", info.sender))
}

pub fn execute_remove_identity(
    deps: DepsMut,
    info: MessageInfo,
    identity_owner: String,
) -> Result<Response, ContractError> {
    let identity_owner = deps.api.addr_validate(&identity_owner)?;

    // Check if the identity exists before attempting to remove it
    if !check_identity_exists(&deps, &identity_owner) {
        return Err(ContractError::IdentityNotFound {
            owner: identity_owner.to_string(),
        });
    }

    // Check if the sender has management key authorization
    check_key_authorization(&deps, &info.sender, KeyType::ManagementKey, &identity_owner)?;

    IDENTITIES.remove(deps.storage, identity_owner.clone());

    Ok(Response::new()
        .add_attribute("action", "remove_identity")
        .add_attribute("owner", identity_owner))
}

pub fn execute_update_country(
    deps: DepsMut,
    info: MessageInfo,
    new_country: String,
    identity_owner: String,
) -> Result<Response, ContractError> {
    let identity_owner = deps.api.addr_validate(&identity_owner)?;

    // Check if the identity exists
    if !check_identity_exists(&deps, &identity_owner) {
        return Err(ContractError::IdentityNotFound {
            owner: identity_owner.to_string(),
        });
    }

    // Check if the sender has management key authorization
    check_key_authorization(&deps, &info.sender, KeyType::ManagementKey, &identity_owner)?;

    let mut identity = IDENTITIES.load(deps.storage, identity_owner.clone())?;
    identity.country = new_country.clone();
    IDENTITIES.save(deps.storage, info.sender.clone(), &identity)?;

    Ok(Response::new()
        .add_attribute("action", "update_country")
        .add_attribute("owner", info.sender)
        .add_attribute("new_country", new_country))
}
