#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, to_json_binary};
use cw2::set_contract_version;

use crate::identity::storage::error::ContractError;
use crate::identity::storage::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::identity::storage::state::{OWNER, IDENTITIES, AGENTS};
use crate::identity::storage::storage_management::{add_identity, remove_identity, update_identity, update_country};
use crate::identity::storage::agents_management::{add_agent, remove_agent, update_agent};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:identity-storage";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    
    // Set the contract owner
    OWNER.save(deps.storage, &info.sender)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::AddIdentity { owner, identity_address, country } => {
            add_identity(deps, env, info, owner, identity_address, country)
        },
        ExecuteMsg::RemoveIdentity { owner } => {
            remove_identity(deps, env, info, owner)
        },
        ExecuteMsg::UpdateIdentity { owner, new_identity_address } => {
            update_identity(deps, env, info, owner, new_identity_address)
        },
        ExecuteMsg::UpdateCountry { owner, new_country } => {
            update_country(deps, env, info, owner, new_country)
        },
        ExecuteMsg::AddAgent { owner, agent_address } => {
            add_agent(deps, env, info, owner, agent_address)
        },
        ExecuteMsg::RemoveAgent { owner, agent_address } => {
            remove_agent(deps, env, info, owner, agent_address)
        },
        ExecuteMsg::UpdateAgent { owner, new_agent_address } => {
            update_agent(deps, env, info, owner, new_agent_address)
        },
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetIdentity { owner } => to_json_binary(&query_identity(deps, owner)?),
        QueryMsg::GetCountry { owner } => to_json_binary(&query_country(deps, owner)?),
        QueryMsg::GetIdentitiesByCountry { country } => to_json_binary(&query_identities_by_country(deps, country)?),
        QueryMsg::GetAgents { address } => to_json_binary(&query_agents(deps, address)?),
        QueryMsg::GetOwner {} => to_json_binary(&query_owner(deps)?),
    }
}

fn query_identity(deps: Deps, owner: String) -> StdResult<Option<String>> {
    let owner_addr = deps.api.addr_validate(&owner)?;
    let identity = IDENTITIES.may_load(deps.storage, owner_addr)?;
    Ok(identity.map(|(addr, _)| addr.to_string()))
}

fn query_country(deps: Deps, owner: String) -> StdResult<Option<String>> {
    let owner_addr = deps.api.addr_validate(&owner)?;
    let identity = IDENTITIES.may_load(deps.storage, owner_addr)?;
    Ok(identity.map(|(_, country)| country))
}

fn query_identities_by_country(deps: Deps, country: String) -> StdResult<Vec<String>> {
    let identities: StdResult<Vec<_>> = IDENTITIES
        .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
        .filter(|r| match r {
            Ok((_, (_, c))) => c == &country,
            Err(_) => false,
        })
        .map(|r| r.map(|(owner, _)| owner.to_string()))
        .collect();
    identities
}

fn query_agents(deps: Deps, address: String) -> StdResult<Vec<String>> {
    let agents = AGENTS.load(deps.storage, deps.api.addr_validate(&address)?)?;
    let agents_as_strings = agents.into_iter().map(|addr| addr.to_string()).collect();
    Ok(agents_as_strings)
}

fn query_owner(deps: Deps) -> StdResult<String> {
    let owner = OWNER.load(deps.storage)?;
    Ok(owner.to_string())
}

#[cfg(test)]
mod tests {}
