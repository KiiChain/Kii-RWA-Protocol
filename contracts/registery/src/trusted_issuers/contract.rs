#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;
use roles::owner_roles::msg::OwnerRole;
// use cw2::set_contract_version;

use crate::trusted_issuers::msg::{ExecuteMsg, InstantiateMsg};
use crate::trusted_issuers::ContractError;

use super::state::OWNER_ROLES_ADDRESS;
use super::QueryMsg;

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:trusted_issuers";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Instantiate a new trusted issuer role contract
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
    OWNER_ROLES_ADDRESS.save(deps.storage, &msg.owner_roles_address)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
}

/// Execute function for the trusted issuer contract
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
    // checking with the owner role contract to ensure only authorized personnel
    // with a role of IssuersRegistryManager are allowed to execute the functions
    execute::check_role(
        deps.as_ref(),
        info.sender,
        OwnerRole::IssuersRegistryManager,
    )?;
    match msg {
        ExecuteMsg::AddTrustedIssuer {
            issuer,
            claim_topics,
        } => execute::add_trusted_issuer(deps, issuer, claim_topics),
        ExecuteMsg::RemoveTrustedIssuer { issuer } => execute::remove_trusted_issuer(deps, issuer),
        ExecuteMsg::UpdateIssuerClaimTopics {
            issuer,
            claim_topics,
        } => execute::update_trusted_issuer(deps, issuer, claim_topics),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::IsTrustedIssuer { issuer } => {
            to_json_binary(&query::is_trusted_issuer(deps, issuer)?)
        }
        QueryMsg::GetIssuerClaimTopics { issuer } => {
            to_json_binary(&query::get_issuer_claim_topics(deps, issuer)?)
        }
    }
}

pub mod execute {
    use crate::trusted_issuers::{msg::TrustedIssuer, state::TRUSTED_ISSUERS};

    use super::*;
    use cosmwasm_std::{to_json_binary, Addr, QueryRequest, Uint128, WasmQuery};
    use roles::owner_roles::{msg::OwnerRole, QueryMsg};

    pub fn check_role(deps: Deps, owner: Addr, role: OwnerRole) -> Result<(), ContractError> {
        let owner_roles = OWNER_ROLES_ADDRESS.load(deps.storage)?;
        let msg = QueryMsg::IsOwner { role, owner };

        let query = QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: owner_roles.to_string(),
            msg: to_json_binary(&msg)?,
        });
        let has_role: bool = deps.querier.query(&query)?;
        if !has_role {
            return Err(ContractError::Unauthorized {});
        }
        Ok(())
    }

    pub fn add_trusted_issuer(
        deps: DepsMut,
        issuer: Addr,
        claim_topics: Vec<Uint128>,
    ) -> Result<Response, ContractError> {
        if TRUSTED_ISSUERS.has(deps.storage, issuer.clone()) {
            return Err(ContractError::IssuerAlreadyExists {});
        }
        TRUSTED_ISSUERS.save(
            deps.storage,
            issuer.clone(),
            &TrustedIssuer {
                claim_topics: claim_topics.clone(),
            },
        )?;
        Ok(Response::new()
            .add_attribute("action", "add_trusted_issuer")
            .add_attribute("issuer", issuer.to_string())
            .add_attribute("claim_topics", format!("{:?}", claim_topics)))
    }

    pub fn update_trusted_issuer(
        deps: DepsMut,
        issuer: Addr,
        claim_topics: Vec<Uint128>,
    ) -> Result<Response, ContractError> {
        if !TRUSTED_ISSUERS.has(deps.storage, issuer.clone()) {
            return Err(ContractError::IssuerNotFound {});
        }
        TRUSTED_ISSUERS.save(
            deps.storage,
            issuer.clone(),
            &TrustedIssuer {
                claim_topics: claim_topics.clone(),
            },
        )?;
        Ok(Response::new()
            .add_attribute("action", "updated_trusted_issuer")
            .add_attribute("issuer", issuer.to_string())
            .add_attribute("claim_topics", format!("{:?}", claim_topics)))
    }

    pub fn remove_trusted_issuer(deps: DepsMut, issuer: Addr) -> Result<Response, ContractError> {
        if !TRUSTED_ISSUERS.has(deps.storage, issuer.clone()) {
            return Err(ContractError::IssuerNotFound {});
        }
        TRUSTED_ISSUERS.remove(deps.storage, issuer.clone());
        Ok(Response::new()
            .add_attribute("action", "remove_trusted_issuer")
            .add_attribute("issuer", issuer.to_string()))
    }
}

pub mod query {
    use cosmwasm_std::{Deps, StdError};

    use crate::trusted_issuers::state::TRUSTED_ISSUERS;

    use super::*;
    use cosmwasm_std::{Addr, Uint128};

    pub fn is_trusted_issuer(deps: Deps, issuer: Addr) -> StdResult<bool> {
        Ok(TRUSTED_ISSUERS.has(deps.storage, issuer))
    }

    pub fn get_issuer_claim_topics(deps: Deps, issuer: Addr) -> StdResult<Vec<Uint128>> {
        TRUSTED_ISSUERS
            .load(deps.storage, issuer)
            .map(|trusted_issuer| trusted_issuer.claim_topics)
            .map_err(|_| StdError::generic_err("Issuer not found"))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_json, Addr, ContractResult, SystemResult, Uint128};
    use roles::owner_roles::msg::OwnerRole;

    fn setup_contract(deps: DepsMut) -> Addr {
        let owner_roles_address = Addr::unchecked("owner_roles_contract");
        let msg = InstantiateMsg {
            owner_roles_address: owner_roles_address.clone(),
        };
        let info = mock_info("creator", &[]);
        let _ = instantiate(deps, mock_env(), info, msg).unwrap();
        owner_roles_address
    }

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();
        let owner_roles_address = setup_contract(deps.as_mut());

        // Check if the owner_roles_address is set correctly
        let stored_address = OWNER_ROLES_ADDRESS.load(&deps.storage).unwrap();
        assert_eq!(stored_address, owner_roles_address);
    }

    #[test]
    fn add_trusted_issuer() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        // Mock the owner roles contract query
        deps.querier.update_wasm(|query| match query {
            cosmwasm_std::WasmQuery::Smart { msg, .. } => {
                let parsed: roles::owner_roles::QueryMsg = from_json(msg).unwrap();
                match parsed {
                    roles::owner_roles::QueryMsg::IsOwner { role, .. } => {
                        if role == OwnerRole::IssuersRegistryManager {
                            SystemResult::Ok(ContractResult::Ok(to_json_binary(&true).unwrap()))
                        } else {
                            panic!("Unexpected role query")
                        }
                    }
                }
            }
            _ => panic!("Unexpected query type"),
        });

        let info = mock_info("authorized_user", &[]);
        let issuer = Addr::unchecked("new_issuer");
        let claim_topics = vec![Uint128::new(1), Uint128::new(2)];

        let msg = ExecuteMsg::AddTrustedIssuer {
            issuer: issuer.clone(),
            claim_topics: claim_topics.clone(),
        };

        let _ = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Verify the issuer was added
        let msg = QueryMsg::IsTrustedIssuer {
            issuer: issuer.clone(),
        };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let is_trusted: bool = from_json(&res).unwrap();
        assert!(is_trusted);

        // Verify claim topics
        let msg = QueryMsg::GetIssuerClaimTopics { issuer };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let stored_claim_topics: Vec<Uint128> = from_json(&res).unwrap();
        assert_eq!(stored_claim_topics, claim_topics);
    }

    #[test]
    fn update_trusted_issuer() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        // Mock the owner roles contract query
        deps.querier.update_wasm(|query| match query {
            cosmwasm_std::WasmQuery::Smart { msg, .. } => {
                let parsed: roles::owner_roles::QueryMsg = from_json(msg).unwrap();
                match parsed {
                    roles::owner_roles::QueryMsg::IsOwner { role, .. } => {
                        if role == OwnerRole::IssuersRegistryManager {
                            SystemResult::Ok(ContractResult::Ok(to_json_binary(&true).unwrap()))
                        } else {
                            panic!("Unexpected role query")
                        }
                    }
                }
            }
            _ => panic!("Unexpected query type"),
        });

        let info = mock_info("authorized_user", &[]);
        let issuer = Addr::unchecked("existing_issuer");
        let initial_claim_topics = vec![Uint128::new(1), Uint128::new(2)];
        let updated_claim_topics = vec![Uint128::new(3), Uint128::new(4)];

        // First, add the issuer
        let msg = ExecuteMsg::AddTrustedIssuer {
            issuer: issuer.clone(),
            claim_topics: initial_claim_topics,
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Now update the issuer
        let msg = ExecuteMsg::UpdateIssuerClaimTopics {
            issuer: issuer.clone(),
            claim_topics: updated_claim_topics.clone(),
        };
        let _ = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Verify updated claim topics
        let msg = QueryMsg::GetIssuerClaimTopics { issuer };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let stored_claim_topics: Vec<Uint128> = from_json(&res).unwrap();
        assert_eq!(stored_claim_topics, updated_claim_topics);
    }

    #[test]
    fn remove_trusted_issuer() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        // Mock the owner roles contract query
        deps.querier.update_wasm(|query| match query {
            cosmwasm_std::WasmQuery::Smart { msg, .. } => {
                let parsed: roles::owner_roles::QueryMsg = from_json(msg).unwrap();
                match parsed {
                    roles::owner_roles::QueryMsg::IsOwner { role, .. } => {
                        if role == OwnerRole::IssuersRegistryManager {
                            SystemResult::Ok(ContractResult::Ok(to_json_binary(&true).unwrap()))
                        } else {
                            panic!("Unexpected role query")
                        }
                    }
                }
            }
            _ => panic!("Unexpected query type"),
        });

        let info = mock_info("authorized_user", &[]);
        let issuer = Addr::unchecked("existing_issuer");
        let claim_topics = vec![Uint128::new(1), Uint128::new(2)];

        // First, add the issuer
        let msg = ExecuteMsg::AddTrustedIssuer {
            issuer: issuer.clone(),
            claim_topics,
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Now remove the issuer
        let msg = ExecuteMsg::RemoveTrustedIssuer {
            issuer: issuer.clone(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![
                ("action", "remove_trusted_issuer"),
                ("issuer", issuer.as_str()),
            ]
        );

        // Verify the issuer was removed
        let msg = QueryMsg::IsTrustedIssuer { issuer };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let is_trusted: bool = from_json(&res).unwrap();
        assert!(!is_trusted);
    }
}
