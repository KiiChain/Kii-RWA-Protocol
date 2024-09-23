#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;
// use cw2::set_contract_version;

use crate::agent_role::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::agent_role::ContractError;

use super::state::OWNER;

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:agent-role";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Instantiate a new agent role contract
///
/// # Arguments
///
/// * `deps` - Mutable dependencies
/// * `_env` - The environment info (unused)
/// * `info` - Message info
/// * `msg` - Instantiate message containing the owner address
///
/// # Returns
///
/// * `Result<Response, ContractError>`
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    OWNER.save(deps.storage, &msg.owner)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
}

/// Execute function for the agent role contract
///
/// # Arguments
///
/// * `deps` - Mutable dependencies
/// * `_env` - The environment info (unused)
/// * `info` - Message info
/// * `msg` - Execute AddAgent or RemoveAgent
///
/// # Returns
///
/// * `Result<Response, ContractError>`
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::AddAgent { agent } => execute::add_agent(deps, info, agent),
        ExecuteMsg::RemoveAgent { agent } => execute::remove_agent(deps, info, agent),
    }
}

/// Query function for the agent role contract
///
/// # Arguments
///
/// * `deps` - Dependencies
/// * `_env` - The environment info (unused)
/// * `msg` - Query IsAgent
///
/// # Returns
///
/// * `StdResult<Binary>`
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::IsAgent { agent } => to_json_binary(&query::is_agent(deps, agent)?),
    }
}

pub mod execute {
    use super::*;
    use crate::agent_role::state::AGENT_ROLE;
    use cosmwasm_std::Addr;

    pub fn add_agent(
        deps: DepsMut,
        info: MessageInfo,
        agent: Addr,
    ) -> Result<Response, ContractError> {
        let owner = OWNER.load(deps.storage)?;
        if info.sender != owner {
            return Err(ContractError::Unauthorized {});
        }
        AGENT_ROLE.add_role(deps.storage, "agent".to_string(), agent.clone())?;
        Ok(Response::new()
            .add_attribute("action", "add_agent")
            .add_attribute("agent", agent))
    }

    pub fn remove_agent(
        deps: DepsMut,
        info: MessageInfo,
        agent: Addr,
    ) -> Result<Response, ContractError> {
        let owner = OWNER.load(deps.storage)?;
        if info.sender != owner {
            return Err(ContractError::Unauthorized {});
        }
        AGENT_ROLE.remove_role(deps.storage, "agent".to_string(), agent.clone())?;
        Ok(Response::new()
            .add_attribute("action", "remove_agent")
            .add_attribute("agent", agent))
    }
}

pub mod query {
    use super::*;
    use crate::agent_role::state::AGENT_ROLE;
    use cosmwasm_std::Addr;

    pub fn is_agent(deps: Deps, agent: Addr) -> StdResult<bool> {
        AGENT_ROLE.has_role(deps.storage, "agent".to_string(), agent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_json, Addr};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();
        let info = mock_info("creator", &[]);
        let msg = InstantiateMsg {
            owner: Addr::unchecked("owner"),
        };

        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Check if the owner is set correctly
        let owner = OWNER.load(&deps.storage).unwrap();
        assert_eq!(owner, Addr::unchecked("owner"));
    }

    #[test]
    fn add_agent() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add an agent
        let agent = Addr::unchecked("agent");
        let msg = ExecuteMsg::AddAgent {
            agent: agent.clone(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![("action", "add_agent"), ("agent", agent.as_str()),]
        );

        // Check if the agent was added correctly
        let msg = QueryMsg::IsAgent {
            agent: agent.clone(),
        };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let is_agent: bool = from_json(&res).unwrap();
        assert!(is_agent);
    }

    #[test]
    fn remove_agent() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        let _ = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add an agent
        let agent = Addr::unchecked("agent");
        let msg = ExecuteMsg::AddAgent {
            agent: agent.clone(),
        };
        let _ = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Remove the agent
        let msg = ExecuteMsg::RemoveAgent {
            agent: agent.clone(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![("action", "remove_agent"), ("agent", agent.as_str()),]
        );

        // Check if the agent was removed correctly
        let msg = QueryMsg::IsAgent { agent };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let is_agent: bool = from_json(&res).unwrap();
        assert!(!is_agent);
    }

    #[test]
    fn unauthorized_add_agent() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg { owner };
        let _ = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Try to add an agent with unauthorized sender
        let unauthorized_info = mock_info("unauthorized", &[]);
        let agent = Addr::unchecked("agent");
        let msg = ExecuteMsg::AddAgent { agent };
        let err = execute(deps.as_mut(), mock_env(), unauthorized_info, msg).unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized {}));
    }

    #[test]
    fn unauthorized_remove_agent() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg { owner };
        let _ = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Try to remove an agent with unauthorized sender
        let unauthorized_info = mock_info("unauthorized", &[]);
        let agent = Addr::unchecked("agent");
        let msg = ExecuteMsg::RemoveAgent { agent };
        let err = execute(deps.as_mut(), mock_env(), unauthorized_info, msg).unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized {}));
    }
}
