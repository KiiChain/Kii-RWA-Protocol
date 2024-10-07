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
/// * `msg` - Execute functions
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
        ExecuteMsg::SetComplianceRegistry {
            compliance_registry,
        } => execute::set_compliance_registry(deps, info, compliance_registry),
        ExecuteMsg::SetClaimTopicsRegistry {
            claim_topic_registry,
        } => execute::set_claim_topic_registry(deps, info, claim_topic_registry),
        ExecuteMsg::SetTrustedIssuersRegistry {
            trusted_issuer_registry,
        } => execute::set_trusted_issuer_registry(deps, info, trusted_issuer_registry),
        ExecuteMsg::AddTrustedIssuer {
            issuer,
            claim_topics,
        } => execute::add_trusted_issuer(deps, info, issuer, claim_topics),
        ExecuteMsg::RemoveTrustedIssuer { issuer } => {
            execute::remove_trusted_issuer(deps, info, issuer)
        }
        ExecuteMsg::UpdateIssuerClaimTopics {
            issuer,
            claim_topics,
        } => execute::update_issuer_claim_topics(deps, info, issuer, claim_topics),
        ExecuteMsg::AddClaimTopic { claim_topic } => {
            execute::add_claim_topic(deps, info, claim_topic)
        }
        ExecuteMsg::RemoveClaimTopic { claim_topic } => {
            execute::remove_claim_topic(deps, info, claim_topic)
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
    use crate::owner_roles::{
        msg::OwnerRole,
        state::{
            CLAIM_TOPICS_REGISTRY, COMPLIANCE_REGISTRY, OWNER_ROLES, TRUSTED_ISSUERS_REGISTRY,
        },
    };
    use cosmwasm_std::{Addr, Uint128, WasmMsg};

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

    pub fn set_compliance_registry(
        deps: DepsMut,
        info: MessageInfo,
        compliance_registry: Addr,
    ) -> Result<Response, ContractError> {
        if !OWNER_ROLES.has_role(
            deps.storage,
            OwnerRole::RegistryAddressSetter.to_string(),
            info.sender.clone(),
        )? {
            return Err(ContractError::Unauthorized {});
        }

        COMPLIANCE_REGISTRY.save(deps.storage, &compliance_registry)?;

        Ok(Response::new()
            .add_attribute("action", "set_compliance_registry")
            .add_attribute("new_address", compliance_registry.to_string()))
    }

    pub fn set_claim_topic_registry(
        deps: DepsMut,
        info: MessageInfo,
        claim_topic_registry: Addr,
    ) -> Result<Response, ContractError> {
        if !OWNER_ROLES.has_role(
            deps.storage,
            OwnerRole::RegistryAddressSetter.to_string(),
            info.sender.clone(),
        )? {
            return Err(ContractError::Unauthorized {});
        }

        CLAIM_TOPICS_REGISTRY.save(deps.storage, &claim_topic_registry)?;

        Ok(Response::new()
            .add_attribute("action", "set_claim_topic_registry")
            .add_attribute("new_address", claim_topic_registry.to_string()))
    }

    pub fn set_trusted_issuer_registry(
        deps: DepsMut,
        info: MessageInfo,
        trusted_issuer_registry: Addr,
    ) -> Result<Response, ContractError> {
        if !OWNER_ROLES.has_role(
            deps.storage,
            OwnerRole::RegistryAddressSetter.to_string(),
            info.sender.clone(),
        )? {
            return Err(ContractError::Unauthorized {});
        }

        TRUSTED_ISSUERS_REGISTRY.save(deps.storage, &trusted_issuer_registry)?;

        Ok(Response::new()
            .add_attribute("action", "set_trusted_issuer_registry")
            .add_attribute("new_address", trusted_issuer_registry.to_string()))
    }

    pub fn add_trusted_issuer(
        deps: DepsMut,
        info: MessageInfo,
        issuer: Addr,
        claim_topics: Vec<Uint128>,
    ) -> Result<Response, ContractError> {
        if !OWNER_ROLES.has_role(
            deps.storage,
            OwnerRole::IssuersRegistryManager.to_string(),
            info.sender.clone(),
        )? {
            return Err(ContractError::Unauthorized {});
        }

        let trusted_issuers_registry = TRUSTED_ISSUERS_REGISTRY
            .load(deps.storage)
            .map_err(|_| ContractError::UninitializedAddress("trusted_issuers".to_string()))?;

        let msg = WasmMsg::Execute {
            contract_addr: trusted_issuers_registry.to_string(),
            msg: to_json_binary(&ExecuteMsg::AddTrustedIssuer {
                issuer: issuer.clone(),
                claim_topics: claim_topics.clone(),
            })?,
            funds: vec![],
        };

        Ok(Response::new()
            .add_message(msg)
            .add_attribute("action", "add_trusted_issuer")
            .add_attribute("issuer", issuer.to_string())
            .add_attribute("claim_topics", format!("{:?}", claim_topics)))
    }

    pub fn remove_trusted_issuer(
        deps: DepsMut,
        info: MessageInfo,
        issuer: Addr,
    ) -> Result<Response, ContractError> {
        if !OWNER_ROLES.has_role(
            deps.storage,
            OwnerRole::IssuersRegistryManager.to_string(),
            info.sender.clone(),
        )? {
            return Err(ContractError::Unauthorized {});
        }

        let trusted_issuers_registry = TRUSTED_ISSUERS_REGISTRY
            .load(deps.storage)
            .map_err(|_| ContractError::UninitializedAddress("trusted_issuers".to_string()))?;

        let msg = WasmMsg::Execute {
            contract_addr: trusted_issuers_registry.to_string(),
            msg: to_json_binary(&ExecuteMsg::RemoveTrustedIssuer {
                issuer: issuer.clone(),
            })?,
            funds: vec![],
        };

        Ok(Response::new()
            .add_message(msg)
            .add_attribute("action", "remove_trusted_issuer")
            .add_attribute("issuer", issuer.to_string()))
    }

    pub fn add_claim_topic(
        deps: DepsMut,
        info: MessageInfo,
        claim_topic: Uint128,
    ) -> Result<Response, ContractError> {
        if !OWNER_ROLES.has_role(
            deps.storage,
            OwnerRole::ClaimRegistryManager.to_string(),
            info.sender.clone(),
        )? {
            return Err(ContractError::Unauthorized {});
        }

        let claim_topics_registry = CLAIM_TOPICS_REGISTRY
            .load(deps.storage)
            .map_err(|_| ContractError::UninitializedAddress("claims_topics".to_string()))?;

        let msg = WasmMsg::Execute {
            contract_addr: claim_topics_registry.to_string(),
            msg: to_json_binary(&ExecuteMsg::AddClaimTopic { claim_topic })?,
            funds: vec![],
        };

        // Return a response with the execute message
        Ok(Response::new()
            .add_message(msg)
            .add_attribute("action", "add_claim_topic")
            .add_attribute("claim_topic", claim_topic.to_string()))
    }

    pub fn remove_claim_topic(
        deps: DepsMut,
        info: MessageInfo,
        claim_topic: Uint128,
    ) -> Result<Response, ContractError> {
        if !OWNER_ROLES.has_role(
            deps.storage,
            OwnerRole::ClaimRegistryManager.to_string(),
            info.sender.clone(),
        )? {
            return Err(ContractError::Unauthorized {});
        }

        let claim_topics_registry = CLAIM_TOPICS_REGISTRY
            .load(deps.storage)
            .map_err(|_| ContractError::UninitializedAddress("claims_topics".to_string()))?;

        let msg = WasmMsg::Execute {
            contract_addr: claim_topics_registry.to_string(),
            msg: to_json_binary(&ExecuteMsg::RemoveClaimTopic { claim_topic })?,
            funds: vec![],
        };

        Ok(Response::new()
            .add_message(msg)
            .add_attribute("action", "remove_claim_topic")
            .add_attribute("claim_topic", claim_topic.to_string()))
    }

    pub fn update_issuer_claim_topics(
        deps: DepsMut,
        info: MessageInfo,
        issuer: Addr,
        claim_topics: Vec<Uint128>,
    ) -> Result<Response, ContractError> {
        if !OWNER_ROLES.has_role(
            deps.storage,
            OwnerRole::IssuersRegistryManager.to_string(),
            info.sender.clone(),
        )? {
            return Err(ContractError::Unauthorized {});
        }

        let trusted_issuers_registry = TRUSTED_ISSUERS_REGISTRY
            .load(deps.storage)
            .map_err(|_| ContractError::UninitializedAddress("trusted_issuers".to_string()))?;

        let msg = WasmMsg::Execute {
            contract_addr: trusted_issuers_registry.to_string(),
            msg: to_json_binary(&ExecuteMsg::UpdateIssuerClaimTopics {
                issuer: issuer.clone(),
                claim_topics: claim_topics.clone(),
            })?,
            funds: vec![],
        };

        Ok(Response::new()
            .add_message(msg)
            .add_attribute("action", "update_issuer_claim_topics")
            .add_attribute("issuer", issuer.to_string())
            .add_attribute("claim_topics", format!("{:?}", claim_topics)))
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
    use cosmwasm_std::{attr, from_json, Addr, Uint128};

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

        let is_owner: IsOwnerResponse = from_json(res).unwrap();
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
        let is_owner: IsOwnerResponse = from_json(res).unwrap();
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
        let roles = [OwnerRole::OwnerAdmin,
            OwnerRole::ComplianceManager,
            OwnerRole::TokenInfoManager];

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
        let is_owner: IsOwnerResponse = from_json(res).unwrap();
        assert!(!is_owner.is_owner);

        let msg = QueryMsg::IsOwner {
            role: OwnerRole::OwnerAdmin,
            owner: new_owner.clone(),
        };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let is_owner: IsOwnerResponse = from_json(res).unwrap();
        assert!(is_owner.is_owner);
        assert_eq!(is_owner.role, OwnerRole::OwnerAdmin);
    }

    #[test]
    fn test_set_compliance_registry() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // add role
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::RegistryAddressSetter,
            owner: owner.clone(),
        };
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let new_registry = Addr::unchecked("new_compliance_registry");
        let msg = ExecuteMsg::SetComplianceRegistry {
            compliance_registry: new_registry.clone(),
        };

        // Test with authorized user
        let info = mock_info(owner.as_str(), &[]);
        let res = execute(deps.as_mut(), mock_env(), info, msg.clone()).unwrap();
        assert_eq!(
            res.attributes,
            vec![
                attr("action", "set_compliance_registry"),
                attr("new_address", new_registry.to_string()),
            ]
        );
    }

    #[test]
    fn test_set_claim_topics_registry() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add role
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::RegistryAddressSetter,
            owner: owner.clone(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        let new_registry = Addr::unchecked("new_claim_topics_registry");
        let msg = ExecuteMsg::SetClaimTopicsRegistry {
            claim_topic_registry: new_registry.clone(),
        };

        // Test with authorized user
        let res = execute(deps.as_mut(), mock_env(), info, msg.clone()).unwrap();

        // Check that the response contains the correct attributes
        assert_eq!(
            res.attributes,
            vec![
                attr("action", "set_claim_topic_registry"),
                attr("new_address", new_registry.to_string()),
            ]
        );
    }

    #[test]
    fn test_set_trusted_issuers_registry() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add role
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::RegistryAddressSetter,
            owner: owner.clone(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        let new_registry = Addr::unchecked("new_trusted_issuers_registry");
        let msg = ExecuteMsg::SetTrustedIssuersRegistry {
            trusted_issuer_registry: new_registry.clone(),
        };

        // Test with authorized user
        let res = execute(deps.as_mut(), mock_env(), info, msg.clone()).unwrap();

        // Check that the response contains the correct attributes
        assert_eq!(
            res.attributes,
            vec![
                attr("action", "set_trusted_issuer_registry"),
                attr("new_address", new_registry.to_string()),
            ]
        );
    }
    #[test]
    fn test_add_claim_topic() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let claim_manager = Addr::unchecked("claim_manager");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // add registryAddress role
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::RegistryAddressSetter,
            owner: owner.clone(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // set claim topics registry
        let new_registry = Addr::unchecked("new_claim_topics_registry");
        let msg = ExecuteMsg::SetClaimTopicsRegistry {
            claim_topic_registry: new_registry.clone(),
        };
        let _ = execute(deps.as_mut(), mock_env(), info.clone(), msg.clone()).unwrap();

        // Add ClaimRegistryManager role to claim_manager
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::ClaimRegistryManager,
            owner: claim_manager.clone(),
        };
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let claim_topic = Uint128::new(123);
        let msg = ExecuteMsg::AddClaimTopic { claim_topic };

        // Test with authorized user
        let info = mock_info(claim_manager.as_str(), &[]);
        let res = execute(deps.as_mut(), mock_env(), info, msg.clone()).unwrap();

        // Check that the response contains the correct attributes
        assert_eq!(
            res.attributes,
            vec![
                attr("action", "add_claim_topic"),
                attr("claim_topic", claim_topic.to_string()),
            ]
        );
    }

    #[test]
    fn test_remove_claim_topic() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let claim_manager = Addr::unchecked("claim_manager");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // add registryAddress role
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::RegistryAddressSetter,
            owner: owner.clone(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // set claim topics registry
        let new_registry = Addr::unchecked("new_claim_topics_registry");
        let msg = ExecuteMsg::SetClaimTopicsRegistry {
            claim_topic_registry: new_registry.clone(),
        };

        let _ = execute(deps.as_mut(), mock_env(), info.clone(), msg.clone()).unwrap();

        // Add ClaimRegistryManager role to claim_manager
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::ClaimRegistryManager,
            owner: claim_manager.clone(),
        };
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let claim_topic = Uint128::new(123);
        let msg = ExecuteMsg::RemoveClaimTopic { claim_topic };

        // Test with authorized user
        let info = mock_info(claim_manager.as_str(), &[]);
        let res = execute(deps.as_mut(), mock_env(), info, msg.clone()).unwrap();

        // Check that the response contains the correct attributes
        assert_eq!(
            res.attributes,
            vec![
                attr("action", "remove_claim_topic"),
                attr("claim_topic", claim_topic.to_string()),
            ]
        );
    }
    #[test]
    fn test_add_trusted_issuer() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let issuer_manager = Addr::unchecked("issuer_manager");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // add registryAddress role
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::RegistryAddressSetter,
            owner: owner.clone(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // set trusted issuer registry
        let new_registry = Addr::unchecked("new_trusted_issuer_registry");
        let msg = ExecuteMsg::SetTrustedIssuersRegistry {
            trusted_issuer_registry: new_registry,
        };

        let _ = execute(deps.as_mut(), mock_env(), info.clone(), msg.clone()).unwrap();

        // Add IssuersRegistryManager role to issuer_manager
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::IssuersRegistryManager,
            owner: issuer_manager.clone(),
        };
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let new_issuer = Addr::unchecked("new_issuer");
        let claim_topics = vec![Uint128::new(1), Uint128::new(2)];
        let msg = ExecuteMsg::AddTrustedIssuer {
            issuer: new_issuer.clone(),
            claim_topics: claim_topics.clone(),
        };

        // Test with authorized user
        let info = mock_info(issuer_manager.as_str(), &[]);
        let res = execute(deps.as_mut(), mock_env(), info, msg.clone()).unwrap();

        // Check that the response contains the correct attributes
        assert_eq!(
            res.attributes,
            vec![
                attr("action", "add_trusted_issuer"),
                attr("issuer", new_issuer.to_string()),
                attr("claim_topics", format!("{:?}", claim_topics)),
            ]
        );
    }

    #[test]
    fn test_remove_trusted_issuer() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let issuer_manager = Addr::unchecked("issuer_manager");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // add registryAddress role
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::RegistryAddressSetter,
            owner: owner.clone(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // set trusted issuer registry
        let new_registry = Addr::unchecked("new_trusted_issuer_registry");
        let msg = ExecuteMsg::SetTrustedIssuersRegistry {
            trusted_issuer_registry: new_registry,
        };

        let _ = execute(deps.as_mut(), mock_env(), info.clone(), msg.clone()).unwrap();

        // Add IssuersRegistryManager role to issuer_manager
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::IssuersRegistryManager,
            owner: issuer_manager.clone(),
        };
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let issuer_to_remove = Addr::unchecked("issuer_to_remove");
        let msg = ExecuteMsg::RemoveTrustedIssuer {
            issuer: issuer_to_remove.clone(),
        };

        // Test with authorized user
        let info = mock_info(issuer_manager.as_str(), &[]);
        let res = execute(deps.as_mut(), mock_env(), info, msg.clone()).unwrap();

        // Check that the response contains the correct attributes
        assert_eq!(
            res.attributes,
            vec![
                attr("action", "remove_trusted_issuer"),
                attr("issuer", issuer_to_remove.to_string()),
            ]
        );
    }

    #[test]
    fn test_update_issuer_claim_topics() {
        let mut deps = mock_dependencies();
        let owner = Addr::unchecked("owner");
        let issuer_manager = Addr::unchecked("issuer_manager");
        let info = mock_info(owner.as_str(), &[]);

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: owner.clone(),
        };
        instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // add registryAddress role
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::RegistryAddressSetter,
            owner: owner.clone(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // set trusted issuer registry
        let new_registry = Addr::unchecked("new_trusted_issuer_registry");
        let msg = ExecuteMsg::SetTrustedIssuersRegistry {
            trusted_issuer_registry: new_registry,
        };

        let _ = execute(deps.as_mut(), mock_env(), info.clone(), msg.clone()).unwrap();

        // Add IssuersRegistryManager role to issuer_manager
        let msg = ExecuteMsg::AddOwnerRole {
            role: OwnerRole::IssuersRegistryManager,
            owner: issuer_manager.clone(),
        };
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let issuer_to_update = Addr::unchecked("issuer_to_update");
        let new_claim_topics = vec![Uint128::new(3), Uint128::new(4)];
        let msg = ExecuteMsg::UpdateIssuerClaimTopics {
            issuer: issuer_to_update.clone(),
            claim_topics: new_claim_topics.clone(),
        };

        // Test with authorized user
        let info = mock_info(issuer_manager.as_str(), &[]);
        let res = execute(deps.as_mut(), mock_env(), info, msg.clone()).unwrap();

        // Check that the response contains the correct attributes
        assert_eq!(
            res.attributes,
            vec![
                attr("action", "update_issuer_claim_topics"),
                attr("issuer", issuer_to_update.to_string()),
                attr("claim_topics", format!("{:?}", new_claim_topics)),
            ]
        );
    }
}
