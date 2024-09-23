#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;

use super::{state::OWNER, ContractError, ExecuteMsg, InstantiateMsg, QueryMsg};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:owner-roles";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Instantiate a new owner role contract
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

/// Execute function for the owner role contract
///
/// # Arguments
///
/// * `deps` - Mutable dependencies
/// * `_env` - The environment info (unused)
/// * `info` - Message info
/// * `msg` - Execute AddOwnerRole or RemoveOwnerRole
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
        ExecuteMsg::AddOwnerRole { role, owner } => {
            execute::add_owner_role(deps, info, role, owner)
        }
        ExecuteMsg::RemoveOwnerRole { role, owner } => {
            execute::remove_owner_role(deps, info, role, owner)
        }
    }
}

/// Query function for the owner role contract
///
/// # Arguments
///
/// * `deps` - Dependencies
/// * `_env` - The environment info (unused)
/// * `msg` - Query IsOwner
///
/// # Returns
///
/// * `StdResult<Binary>`
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::IsOwner { role, owner } => to_json_binary(&query::is_owner(deps, role, owner)?),
    }
}

pub mod execute {
    use super::*;
    use crate::owner_roles::{msg::OwnerRole, state::OWNER_ROLES};
    use cosmwasm_std::Addr;

    pub fn add_owner_role(
        deps: DepsMut,
        info: MessageInfo,
        role: OwnerRole,
        addr: Addr,
    ) -> Result<Response, ContractError> {
        let owner = OWNER.load(deps.storage)?;
        if info.sender != owner {
            return Err(ContractError::Unauthorized {});
        }
        OWNER_ROLES.add_role(deps.storage, role.to_string(), addr.clone())?;
        Ok(Response::new()
            .add_attribute("action", "add_owner")
            .add_attribute("role", role.to_string())
            .add_attribute("owner", addr))
    }

    pub fn remove_owner_role(
        deps: DepsMut,
        info: MessageInfo,
        role: OwnerRole,
        addr: Addr,
    ) -> Result<Response, ContractError> {
        let owner = OWNER.load(deps.storage)?;
        if info.sender != owner {
            return Err(ContractError::Unauthorized {});
        }
        OWNER_ROLES.remove_role(deps.storage, role.to_string(), addr.clone())?;
        Ok(Response::new()
            .add_attribute("action", "remove_owner")
            .add_attribute("role", role.to_string())
            .add_attribute("owner", addr))
    }
}

pub mod query {
    use super::*;
    use crate::owner_roles::{
        msg::{IsOwnerResponse, OwnerRole},
        state::OWNER_ROLES,
    };
    use cosmwasm_std::Addr;

    pub fn is_owner(deps: Deps, role: OwnerRole, owner: Addr) -> StdResult<IsOwnerResponse> {
        let is_owner = OWNER_ROLES.has_role(deps.storage, role.to_string(), owner)?;
        Ok(IsOwnerResponse { is_owner, role })
    }
}

#[cfg(test)]
mod tests {
    use crate::owner_roles::msg::{IsOwnerResponse, OwnerRole};

    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_json, Addr};

    /// Test proper contract initialization
    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();
        let info = mock_info("creator", &[]);
        let msg = InstantiateMsg {
            owner: Addr::unchecked("owner"),
        };

        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Check if the owner is set correctly
        let owner = OWNER.load(&deps.storage).unwrap();
        assert_eq!(owner, Addr::unchecked("owner"));
    }

    /// Test adding an owner
    #[test]
    fn add_owner() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add an owner_admin
        let new_owner = Addr::unchecked("new_owner");
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::OwnerAdmin,
            owner: new_owner.clone(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![
                ("action", "add_owner"),
                ("role", "owner_admin"),
                ("owner", new_owner.as_str()),
            ]
        );

        // Check if the owner was added correctly
        let msg = QueryMsg::IsOwner {
            role: OwnerRole::OwnerAdmin,
            owner: new_owner.clone(),
        };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();

        let is_owner: IsOwnerResponse = from_json(&res).unwrap();
        assert!(is_owner.is_owner);
        assert_eq!(is_owner.role, OwnerRole::OwnerAdmin);
    }

    #[test]
    fn remove_owner_role() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add an owner_admin
        let new_owner = Addr::unchecked("new_owner");
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::OwnerAdmin,
            owner: new_owner.clone(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Remove the owner_admin
        let msg = ExecuteMsg::RemoveOwnerRole {
            role: OwnerRole::OwnerAdmin,
            owner: new_owner.clone(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![
                ("action", "remove_owner"),
                ("role", "owner_admin"),
                ("owner", new_owner.as_str()),
            ]
        );

        // Check if the owner was removed correctly
        let msg = QueryMsg::IsOwner {
            role: OwnerRole::OwnerAdmin,
            owner: new_owner.clone(),
        };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let is_owner: IsOwnerResponse = from_json(&res).unwrap();
        assert!(!is_owner.is_owner);
    }

    #[test]
    fn unauthorized_add_owner_role() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Try to add an owner with unauthorized sender
        let unauthorized_info = mock_info("unauthorized", &[]);
        let new_owner = Addr::unchecked("new_owner");
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::OwnerAdmin,
            owner: new_owner,
        };
        let err = execute(deps.as_mut(), mock_env(), unauthorized_info, msg).unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized {}));
    }

    #[test]
    fn unauthorized_remove_owner_role() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add an owner_admin
        let new_owner = Addr::unchecked("new_owner");
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::OwnerAdmin,
            owner: new_owner.clone(),
        };
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Try to remove the owner with unauthorized sender
        let unauthorized_info = mock_info("unauthorized", &[]);
        let msg = ExecuteMsg::RemoveOwnerRole {
            role: OwnerRole::OwnerAdmin,
            owner: new_owner,
        };
        let err = execute(deps.as_mut(), mock_env(), unauthorized_info, msg).unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized {}));
    }

    #[test]
    fn multiple_owner_roles() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add multiple roles to the same owner
        let new_owner = Addr::unchecked("new_owner");
        let roles = vec![
            OwnerRole::OwnerAdmin,
            OwnerRole::ComplianceManager,
            OwnerRole::TokenInfoManager,
        ];

        for role in roles.iter() {
            let msg = ExecuteMsg::AddOwnerRole {
                role: role.clone(),
                owner: new_owner.clone(),
            };
            execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        }

        // Check if all roles were added correctly
        for role in roles.iter() {
            let msg = QueryMsg::IsOwner {
                role: role.clone(),
                owner: new_owner.clone(),
            };
            let res = query(deps.as_ref(), mock_env(), msg).unwrap();
            let is_owner: IsOwnerResponse = from_json(&res).unwrap();
            assert!(is_owner.is_owner);
            assert_eq!(is_owner.role, role.clone());
        }

        // Remove one role
        let msg = ExecuteMsg::RemoveOwnerRole {
            role: OwnerRole::ComplianceManager,
            owner: new_owner.clone(),
        };
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Check if the removed role is gone but others remain
        let msg = QueryMsg::IsOwner {
            role: OwnerRole::ComplianceManager,
            owner: new_owner.clone(),
        };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let is_owner: IsOwnerResponse = from_json(&res).unwrap();
        assert!(!is_owner.is_owner);

        let msg = QueryMsg::IsOwner {
            role: OwnerRole::OwnerAdmin,
            owner: new_owner.clone(),
        };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let is_owner: IsOwnerResponse = from_json(&res).unwrap();
        assert!(is_owner.is_owner);
        assert_eq!(is_owner.role, OwnerRole::OwnerAdmin);
    }
}
