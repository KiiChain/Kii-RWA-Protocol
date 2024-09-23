#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;
// use cw2::set_contract_version;

use crate::agent_roles::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::agent_roles::ContractError;

use super::state::OWNER;

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:agent-roles";
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
/// * `msg` - Execute AddAgentRole or RemoveAgentRole
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
        ExecuteMsg::AddAgentRole { role, agent } => {
            execute::add_agent_role(deps, info, role, agent)
        }
        ExecuteMsg::RemoveAgentRole { role, agent } => {
            execute::remove_agent_role(deps, info, role, agent)
        }
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
        QueryMsg::IsAgent { role, agent } => to_json_binary(&query::is_agent(deps, role, agent)?),
    }
}

pub mod execute {
    use super::*;
    use crate::agent_roles::{msg::AgentRole, state::AGENT_ROLE};
    use cosmwasm_std::Addr;

    pub fn add_agent_role(
        deps: DepsMut,
        info: MessageInfo,
        role: AgentRole,
        agent: Addr,
    ) -> Result<Response, ContractError> {
        let owner = OWNER.load(deps.storage)?;
        if info.sender != owner {
            return Err(ContractError::Unauthorized {});
        }
        AGENT_ROLE.add_role(deps.storage, role.to_string(), agent.clone())?;
        Ok(Response::new()
            .add_attribute("action", "add_agent_role")
            .add_attribute("role", role.to_string())
            .add_attribute("agent", agent))
    }

    pub fn remove_agent_role(
        deps: DepsMut,
        info: MessageInfo,
        role: AgentRole,
        agent: Addr,
    ) -> Result<Response, ContractError> {
        let owner = OWNER.load(deps.storage)?;
        if info.sender != owner {
            return Err(ContractError::Unauthorized {});
        }
        AGENT_ROLE.remove_role(deps.storage, role.to_string(), agent.clone())?;
        Ok(Response::new()
            .add_attribute("action", "remove_agent_role")
            .add_attribute("role", role.to_string())
            .add_attribute("agent", agent))
    }
}

pub mod query {
    use super::*;
    use crate::agent_roles::{
        msg::{AgentRole, IsAgentResponse},
        state::AGENT_ROLE,
    };
    use cosmwasm_std::Addr;

    pub fn is_agent(deps: Deps, role: AgentRole, agent: Addr) -> StdResult<IsAgentResponse> {
        let is_agent = AGENT_ROLE.has_role(deps.storage, role.to_string(), agent)?;
        Ok(IsAgentResponse { is_agent, role })
    }
}

#[cfg(test)]
mod tests {
    use crate::agent_roles::msg::{AgentRole, IsAgentResponse};

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
    fn add_agent_role() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        let agent = Addr::unchecked("agent");
        let msg = ExecuteMsg::AddAgentRole {
            role: AgentRole::SupplyModifiers,
            agent: agent.clone(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![
                ("action", "add_agent_role"),
                ("role", "supplyModifiers"),
                ("agent", agent.as_str()),
            ]
        );

        let msg = QueryMsg::IsAgent {
            role: AgentRole::SupplyModifiers,
            agent: agent.clone(),
        };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let is_agent: IsAgentResponse = from_json(&res).unwrap();
        assert!(is_agent.is_agent);
        assert_eq!(is_agent.role, AgentRole::SupplyModifiers);
    }

    #[test]
    fn remove_agent_role() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        let agent = Addr::unchecked("agent");
        let msg = ExecuteMsg::AddAgentRole {
            role: AgentRole::Freezers,
            agent: agent.clone(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::RemoveAgentRole {
            role: AgentRole::Freezers,
            agent: agent.clone(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![
                ("action", "remove_agent_role"),
                ("role", "freezers"),
                ("agent", agent.as_str()),
            ]
        );

        let msg = QueryMsg::IsAgent {
            role: AgentRole::Freezers,
            agent,
        };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let is_agent: IsAgentResponse = from_json(&res).unwrap();
        assert!(!is_agent.is_agent);
        assert_eq!(is_agent.role, AgentRole::Freezers);
    }

    #[test]
    fn unauthorized_add_agent_role() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        let msg = InstantiateMsg { owner };
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        let unauthorized_info = mock_info("unauthorized", &[]);
        let agent = Addr::unchecked("agent");
        let msg = ExecuteMsg::AddAgentRole {
            role: AgentRole::TransferManager,
            agent,
        };
        let err = execute(deps.as_mut(), mock_env(), unauthorized_info, msg).unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized {}));
    }

    #[test]
    fn unauthorized_remove_agent_role() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        let msg = InstantiateMsg { owner };
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        let unauthorized_info = mock_info("unauthorized", &[]);
        let agent = Addr::unchecked("agent");
        let msg = ExecuteMsg::RemoveAgentRole {
            role: AgentRole::RecoveryAgents,
            agent,
        };
        let err = execute(deps.as_mut(), mock_env(), unauthorized_info, msg).unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized {}));
    }

    #[test]
    fn multiple_agent_roles() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add an agent with multiple roles
        let agent = Addr::unchecked("multi_role_agent");
        let roles = vec![
            AgentRole::SupplyModifiers,
            AgentRole::Freezers,
            AgentRole::TransferManager,
        ];

        for role in &roles {
            let msg = ExecuteMsg::AddAgentRole {
                role: role.clone(),
                agent: agent.clone(),
            };
            execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        }

        // Check if the agent has all the assigned roles
        for role in &roles {
            let msg = QueryMsg::IsAgent {
                role: role.clone(),
                agent: agent.clone(),
            };
            let res = query(deps.as_ref(), mock_env(), msg).unwrap();
            let is_agent: IsAgentResponse = from_json(&res).unwrap();
            assert!(is_agent.is_agent);
            assert_eq!(is_agent.role, *role);
        }

        // Check a role that wasn't assigned
        let msg = QueryMsg::IsAgent {
            role: AgentRole::ComplianceAgent,
            agent: agent.clone(),
        };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let is_agent: IsAgentResponse = from_json(&res).unwrap();
        assert!(!is_agent.is_agent);
        assert_eq!(is_agent.role, AgentRole::ComplianceAgent);

        // Remove one role
        let remove_role = AgentRole::Freezers;
        let msg = ExecuteMsg::RemoveAgentRole {
            role: remove_role.clone(),
            agent: agent.clone(),
        };
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Verify the removed role is gone but others remain
        for role in &roles {
            let msg = QueryMsg::IsAgent {
                role: role.clone(),
                agent: agent.clone(),
            };
            let res = query(deps.as_ref(), mock_env(), msg).unwrap();
            let is_agent: IsAgentResponse = from_json(&res).unwrap();

            if *role == remove_role {
                assert!(!is_agent.is_agent);
            } else {
                assert!(is_agent.is_agent);
            }
            assert_eq!(is_agent.role, *role);
        }
    }
}
