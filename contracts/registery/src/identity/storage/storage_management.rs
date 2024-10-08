use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};
use crate::identity::storage::state::IDENTITIES;
use crate::identity::storage::error::ContractError;
use crate::identity::storage::utils::is_authorized;

pub fn add_identity(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    owner: String,
    identity_address: String,
    country: String,
) -> Result<Response, ContractError> {
    let owner_addr = deps.api.addr_validate(&owner)?;
    let identity_addr = deps.api.addr_validate(&identity_address)?;

    // Check if the sender is authorized
    if !is_authorized(deps.as_ref(), &info.sender, &owner_addr)? {
        return Err(ContractError::Unauthorized {});
    }

    // Check if the identity already exists
    if IDENTITIES.has(deps.storage, owner_addr.clone()) {
        return Err(ContractError::IdentityAlreadyExists {});
    }

    // Store the new identity
    IDENTITIES.save(deps.storage, owner_addr.clone(), &(identity_addr, country.clone()))?;

    Ok(Response::new()
        .add_attribute("action", "add_identity")
        .add_attribute("owner", owner)
        .add_attribute("identity_address", identity_address)
        .add_attribute("country", country))
}

pub fn remove_identity(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    owner: String,
) -> Result<Response, ContractError> {
    let owner_addr = deps.api.addr_validate(&owner)?;

    // Check if the sender is authorized
    if !is_authorized(deps.as_ref(), &info.sender, &owner_addr)? {
        return Err(ContractError::Unauthorized {});
    }

    // Check if the identity exists
    if !IDENTITIES.has(deps.storage, owner_addr.clone()) {
        return Err(ContractError::IdentityNotFound {});
    }

    // Remove the identity
    IDENTITIES.remove(deps.storage, owner_addr.clone());

    Ok(Response::new()
        .add_attribute("action", "remove_identity")
        .add_attribute("owner", owner))
}

pub fn update_identity(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    owner: String,
    new_identity_address: String,
) -> Result<Response, ContractError> {
    let owner_addr = deps.api.addr_validate(&owner)?;
    let new_identity_addr = deps.api.addr_validate(&new_identity_address)?;

    // Check if the sender is authorized
    if !is_authorized(deps.as_ref(), &info.sender, &owner_addr)? {
        return Err(ContractError::Unauthorized {});
    }

    // Check if the identity exists
    let (_, country) = IDENTITIES.load(deps.storage, owner_addr.clone())?;

    // Update the identity address
    IDENTITIES.save(deps.storage, owner_addr.clone(), &(new_identity_addr.clone(), country))?;

    Ok(Response::new()
        .add_attribute("action", "update_identity")
        .add_attribute("owner", owner)
        .add_attribute("new_identity_address", new_identity_address))
}

pub fn update_country(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    owner: String,
    new_country: String,
) -> Result<Response, ContractError> {
    let owner_addr = deps.api.addr_validate(&owner)?;

    // Check if the sender is authorized
    if !is_authorized(deps.as_ref(), &info.sender, &owner_addr)? {
        return Err(ContractError::Unauthorized {});
    }

    // Check if the identity exists
    let (identity_addr, _) = IDENTITIES.load(deps.storage, owner_addr.clone())?;

    // Update the country
    IDENTITIES.save(deps.storage, owner_addr.clone(), &(identity_addr, new_country.clone()))?;

    Ok(Response::new()
        .add_attribute("action", "update_country")
        .add_attribute("owner", owner)
        .add_attribute("new_country", new_country))
}
