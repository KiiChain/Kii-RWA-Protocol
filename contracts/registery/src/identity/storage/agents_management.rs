use crate::identity::storage::error::ContractError;
use crate::identity::storage::state::AGENTS;
use crate::identity::storage::utils::is_authorized;
use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};

pub fn add_agent(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    owner: String,
    agent_address: String,
) -> Result<Response, ContractError> {
    let owner_addr = deps.api.addr_validate(&owner)?;
    let agent_addr = deps.api.addr_validate(&agent_address)?;

    // Check if the sender is authorized
    if !is_authorized(deps.as_ref(), &info.sender, &owner_addr)? {
        return Err(ContractError::Unauthorized {});
    }

    // Load or initialize the agents list
    let mut agents = AGENTS
        .may_load(deps.storage, owner_addr.clone())?
        .unwrap_or_default();

    // Check if the agent already exists
    if agents.contains(&agent_addr) {
        return Err(ContractError::AgentAlreadyExists {});
    }

    // Add the new agent
    agents.push(agent_addr.clone());
    AGENTS.save(deps.storage, owner_addr.clone(), &agents)?;

    Ok(Response::new()
        .add_attribute("action", "add_agent")
        .add_attribute("owner", owner)
        .add_attribute("agent_address", agent_address))
}

pub fn remove_agent(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    owner: String,
    agent_address: String,
) -> Result<Response, ContractError> {
    let owner_addr = deps.api.addr_validate(&owner)?;
    let agent_addr = deps.api.addr_validate(&agent_address)?;

    // Check if the sender is authorized
    if !is_authorized(deps.as_ref(), &info.sender, &owner_addr)? {
        return Err(ContractError::Unauthorized {});
    }

    // Load the agents list
    let mut agents = AGENTS
        .may_load(deps.storage, owner_addr.clone())?
        .ok_or(ContractError::AgentNotFound {})?;

    // Remove the agent
    agents.retain(|addr| addr != agent_addr);
    AGENTS.save(deps.storage, owner_addr.clone(), &agents)?;

    Ok(Response::new()
        .add_attribute("action", "remove_agent")
        .add_attribute("owner", owner)
        .add_attribute("agent_address", agent_address))
}

pub fn update_agent(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    owner: String,
    new_agent_address: String,
) -> Result<Response, ContractError> {
    let owner_addr = deps.api.addr_validate(&owner)?;
    let new_agent_addr = deps.api.addr_validate(&new_agent_address)?;

    // Check if the sender is authorized
    if !is_authorized(deps.as_ref(), &info.sender, &owner_addr)? {
        return Err(ContractError::Unauthorized {});
    }

    // Load the agents list
    let mut agents = AGENTS
        .may_load(deps.storage, owner_addr.clone())?
        .ok_or(ContractError::AgentNotFound {})?;

    // Check if the new agent already exists
    if agents.contains(&new_agent_addr) {
        return Err(ContractError::AgentAlreadyExists {});
    }

    // Replace the old agent with the new one
    // Note: This assumes that the sender's address is the one being updated
    if let Some(pos) = agents.iter().position(|addr| addr == info.sender) {
        agents[pos] = new_agent_addr.clone();
        AGENTS.save(deps.storage, owner_addr.clone(), &agents)?;
    } else {
        return Err(ContractError::AgentNotFound {});
    }

    Ok(Response::new()
        .add_attribute("action", "update_agent")
        .add_attribute("owner", owner)
        .add_attribute("new_agent_address", new_agent_address))
}
