#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;
// use cw2::set_contract_version;

use crate::agent_roles::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::agent_roles::ContractError;

use super::state::{OWNER, TOKEN};

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
    TOKEN.save(deps.storage, &msg.token)?;

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
/// * `msg` - Execute agent functions
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
        ExecuteMsg::Burn { amount } => execute::burn(deps, info, amount),
        ExecuteMsg::BurnFrom { owner, amount } => execute::burn_from(deps, info, owner, amount),
        ExecuteMsg::Mint { recipient, amount } => execute::mint(deps, info, recipient, amount),
        ExecuteMsg::Transfer { recipient, amount } => {
            execute::transfer(deps, info, recipient, amount)
        }
        ExecuteMsg::TransferFrom {
            owner,
            recipient,
            amount,
        } => execute::transfer_from(deps, info, owner, recipient, amount),
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
    use crate::agent_roles::{
        helpers::{can_receive, can_transfer, is_transfer_allowed},
        msg::AgentRole,
        state::AGENT_ROLES,
    };
    use cosmwasm_std::{Addr, Uint128, WasmMsg};

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
        AGENT_ROLES.add_role(deps.storage, role.to_string(), agent.clone())?;
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
        AGENT_ROLES.remove_role(deps.storage, role.to_string(), agent.clone())?;
        Ok(Response::new()
            .add_attribute("action", "remove_agent_role")
            .add_attribute("role", role.to_string())
            .add_attribute("agent", agent))
    }
    pub fn burn(
        deps: DepsMut,
        info: MessageInfo,
        amount: Uint128,
    ) -> Result<Response, ContractError> {
        if !AGENT_ROLES.has_role(
            deps.storage,
            AgentRole::SupplyModifiers.to_string(),
            info.sender.clone(),
        )? {
            return Err(ContractError::Unauthorized {});
        }
        let token = TOKEN.load(deps.storage)?;
        let msg = WasmMsg::Execute {
            contract_addr: token.to_string(),
            msg: to_json_binary(&ExecuteMsg::Burn { amount })?,
            funds: vec![],
        };
        Ok(Response::new()
            .add_message(msg)
            .add_attribute("action", "burn")
            .add_attribute("token", token)
            .add_attribute("amount", amount))
    }

    pub fn burn_from(
        deps: DepsMut,
        info: MessageInfo,
        owner: String,
        amount: Uint128,
    ) -> Result<Response, ContractError> {
        if !AGENT_ROLES.has_role(
            deps.storage,
            AgentRole::SupplyModifiers.to_string(),
            info.sender.clone(),
        )? {
            return Err(ContractError::Unauthorized {});
        }
        let token = TOKEN.load(deps.storage)?;
        let msg = WasmMsg::Execute {
            contract_addr: token.to_string(),
            msg: to_json_binary(&ExecuteMsg::BurnFrom {
                owner: owner.clone(),
                amount,
            })?,
            funds: vec![],
        };
        Ok(Response::new()
            .add_message(msg)
            .add_attribute("action", "burn_from")
            .add_attribute("owner", owner)
            .add_attribute("amount", amount))
    }

    pub fn mint(
        deps: DepsMut,
        info: MessageInfo,
        recipient: String,
        amount: Uint128,
    ) -> Result<Response, ContractError> {
        if !AGENT_ROLES.has_role(
            deps.storage,
            AgentRole::SupplyModifiers.to_string(),
            info.sender.clone(),
        )? {
            return Err(ContractError::Unauthorized {});
        }
        let token = TOKEN.load(deps.storage)?;
        let msg = WasmMsg::Execute {
            contract_addr: token.to_string(),
            msg: to_json_binary(&ExecuteMsg::Mint {
                recipient: recipient.clone(),
                amount,
            })?,
            funds: vec![],
        };
        Ok(Response::new()
            .add_message(msg)
            .add_attribute("action", "mint")
            .add_attribute("recipient", recipient)
            .add_attribute("amount", amount))
    }

    pub fn transfer(
        deps: DepsMut,
        _info: MessageInfo,
        recipient: String,
        amount: Uint128,
    ) -> Result<Response, ContractError> {
        let token = TOKEN.load(deps.storage)?;

        // Check if transfers are currently allowed
        if !is_transfer_allowed(deps.as_ref())? {
            return Err(ContractError::TransfersDisabled {});
        }

        // Check if the recipient is allowed to receive transfers
        if !can_receive(deps.as_ref(), &recipient)? {
            return Err(ContractError::Unauthorized {});
        }
        let msg = WasmMsg::Execute {
            contract_addr: token.to_string(),
            msg: to_json_binary(&ExecuteMsg::Transfer {
                recipient: recipient.clone(),
                amount,
            })?,
            funds: vec![],
        };
        Ok(Response::new()
            .add_message(msg)
            .add_attribute("action", "transfer")
            .add_attribute("recipient", recipient)
            .add_attribute("amount", amount))
    }

    pub fn transfer_from(
        deps: DepsMut,
        info: MessageInfo,
        owner: String,
        recipient: String,
        amount: Uint128,
    ) -> Result<Response, ContractError> {
        if !AGENT_ROLES.has_role(
            deps.storage,
            AgentRole::TransferManager.to_string(),
            info.sender.clone(),
        )? {
            return Err(ContractError::Unauthorized {});
        }

        // Check if transfers are currently allowed
        if !is_transfer_allowed(deps.as_ref())? {
            return Err(ContractError::TransfersDisabled {});
        }

        // Check if the owner is allowed to transfer
        if !can_transfer(deps.as_ref(), &owner)? {
            return Err(ContractError::Unauthorized {});
        }

        // Check if the recipient is allowed to receive transfers
        if !can_receive(deps.as_ref(), &recipient)? {
            return Err(ContractError::Unauthorized {});
        }
        let token = TOKEN.load(deps.storage)?;
        let msg = WasmMsg::Execute {
            contract_addr: token.to_string(),
            msg: to_json_binary(&ExecuteMsg::TransferFrom {
                owner: owner.clone(),
                recipient: recipient.clone(),
                amount,
            })?,
            funds: vec![],
        };
        Ok(Response::new()
            .add_message(msg)
            .add_attribute("action", "transfer_from")
            .add_attribute("owner", owner)
            .add_attribute("recipient", recipient)
            .add_attribute("amount", amount))
    }
}

pub mod query {
    use super::*;
    use crate::agent_roles::{
        msg::{AgentRole, IsAgentResponse},
        state::AGENT_ROLES,
    };
    use cosmwasm_std::Addr;

    pub fn is_agent(deps: Deps, role: AgentRole, agent: Addr) -> StdResult<IsAgentResponse> {
        let is_agent = AGENT_ROLES.has_role(deps.storage, role.to_string(), agent)?;
        Ok(IsAgentResponse { is_agent, role })
    }
}

#[cfg(test)]
mod tests {
    use crate::agent_roles::msg::{AgentRole, IsAgentResponse};

    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_json, Addr, Uint128};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();
        let info = mock_info("creator", &[]);
        let msg = InstantiateMsg {
            owner: Addr::unchecked("owner"),
            token: Addr::unchecked("token"),
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
            token: Addr::unchecked("token"),
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
            token: Addr::unchecked("token"),
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

        let msg = InstantiateMsg {
            owner,
            token: Addr::unchecked("token"),
        };
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

        let msg = InstantiateMsg {
            owner,
            token: Addr::unchecked("token"),
        };
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
            token: Addr::unchecked("token"),
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

    #[test]
    fn test_burn() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let token = Addr::unchecked("token");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
            token: token.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add SupplyModifier role
        let supply_modifier = Addr::unchecked("supply_modifier");
        execute(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            ExecuteMsg::AddAgentRole {
                role: AgentRole::SupplyModifiers,
                agent: supply_modifier.clone(),
            },
        )
        .unwrap();

        // Test successful burn
        let burn_msg = ExecuteMsg::Burn {
            amount: Uint128::new(100),
        };
        let burn_info = mock_info(supply_modifier.as_str(), &[]);
        let res = execute(deps.as_mut(), mock_env(), burn_info, burn_msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![
                ("action", "burn"),
                ("token", token.as_str()),
                ("amount", "100"),
            ]
        );

        // Test unauthorized burn
        let unauthorized_info = mock_info("unauthorized", &[]);
        let unauthorized_burn_msg = ExecuteMsg::Burn {
            amount: Uint128::new(50),
        };
        let err = execute(
            deps.as_mut(),
            mock_env(),
            unauthorized_info,
            unauthorized_burn_msg,
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized {}));
    }

    #[test]
    fn test_mint() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let token = Addr::unchecked("token");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
            token: token.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add SupplyModifier role
        let supply_modifier = Addr::unchecked("supply_modifier");
        execute(
            deps.as_mut(),
            mock_env(),
            info,
            ExecuteMsg::AddAgentRole {
                role: AgentRole::SupplyModifiers,
                agent: supply_modifier.clone(),
            },
        )
        .unwrap();

        // Test successful mint
        let recipient = Addr::unchecked("recipient");
        let mint_msg = ExecuteMsg::Mint {
            recipient: recipient.to_string(),
            amount: Uint128::new(100),
        };
        let mint_info = mock_info(supply_modifier.as_str(), &[]);
        let res = execute(deps.as_mut(), mock_env(), mint_info, mint_msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![
                ("action", "mint"),
                ("recipient", recipient.as_str()),
                ("amount", "100"),
            ]
        );

        // Test unauthorized mint
        let unauthorized_info = mock_info("unauthorized", &[]);
        let unauthorized_mint_msg = ExecuteMsg::Mint {
            recipient: recipient.to_string(),
            amount: Uint128::new(50),
        };
        let err = execute(
            deps.as_mut(),
            mock_env(),
            unauthorized_info,
            unauthorized_mint_msg,
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized {}));
    }

    #[test]
    fn test_transfer() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let token = Addr::unchecked("token");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
            token: token.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Test successful transfer
        let sender = Addr::unchecked("sender");
        let recipient = Addr::unchecked("recipient");
        let transfer_msg = ExecuteMsg::Transfer {
            recipient: recipient.to_string(),
            amount: Uint128::new(100),
        };
        let transfer_info = mock_info(sender.as_str(), &[]);
        let res = execute(deps.as_mut(), mock_env(), transfer_info, transfer_msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![
                ("action", "transfer"),
                ("recipient", recipient.as_str()),
                ("amount", "100"),
            ]
        );
    }

    #[test]
    fn test_transfer_from() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let token = Addr::unchecked("token");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
            token: token.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add TransferManager role
        let transfer_manager = Addr::unchecked("transfer_manager");
        execute(
            deps.as_mut(),
            mock_env(),
            info,
            ExecuteMsg::AddAgentRole {
                role: AgentRole::TransferManager,
                agent: transfer_manager.clone(),
            },
        )
        .unwrap();

        // Test successful transfer_from
        let owner = Addr::unchecked("token_owner");
        let recipient = Addr::unchecked("recipient");
        let transfer_from_msg = ExecuteMsg::TransferFrom {
            owner: owner.to_string(),
            recipient: recipient.to_string(),
            amount: Uint128::new(100),
        };
        let transfer_from_info = mock_info(transfer_manager.as_str(), &[]);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            transfer_from_info,
            transfer_from_msg,
        )
        .unwrap();
        assert_eq!(
            res.attributes,
            vec![
                ("action", "transfer_from"),
                ("owner", owner.as_str()),
                ("recipient", recipient.as_str()),
                ("amount", "100"),
            ]
        );

        // Test unauthorized transfer_from
        let unauthorized_info = mock_info("unauthorized", &[]);
        let unauthorized_transfer_from_msg = ExecuteMsg::TransferFrom {
            owner: owner.to_string(),
            recipient: recipient.to_string(),
            amount: Uint128::new(50),
        };
        let err = execute(
            deps.as_mut(),
            mock_env(),
            unauthorized_info,
            unauthorized_transfer_from_msg,
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized {}));
    }
}
