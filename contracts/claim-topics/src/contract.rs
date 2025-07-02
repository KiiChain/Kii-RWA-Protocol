#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;
use utils::owner_roles::OwnerRole;
// use cw2::set_contract_version;

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::ContractError;

use super::state::OWNER_ROLES_ADDRESS;

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:claim_topics";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let owner_addr = deps
        .api
        .addr_validate(msg.owner_roles_address.as_ref())
        .map_err(|e| ContractError::InvalidAddress {
            reason: format!("Invalid owner address: {e}"),
        })?;

    OWNER_ROLES_ADDRESS.save(deps.storage, &owner_addr)?;
    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    // checking with the owner role contract to ensure only authorized personnel
    // with a role of ClaimRegistryManager are allowed to execute the functions
    execute::check_role(deps.as_ref(), info.sender, OwnerRole::ClaimRegistryManager)?;

    match msg {
        ExecuteMsg::AddClaimTopicForToken { token_addr, topic } => {
            execute::add_claim_topic(deps, token_addr, topic)
        }
        ExecuteMsg::RemoveClaimTopicForToken { token_addr, topic } => {
            execute::remove_claim_topic(deps, token_addr, topic)
        }
        ExecuteMsg::UpdateClaimTopicForToken {
            token_addr,
            topic,
            active,
        } => execute::update_claim_topic(deps, token_addr, topic, active),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetClaimsForToken { token_addr } => {
            to_json_binary(&query::get_claims_for_token(deps, token_addr)?)
        }
    }
}

pub mod execute {
    use crate::{msg::Claim, state::TOKEN_CLAIM_TOPICS};

    use super::*;
    use cosmwasm_std::{to_json_binary, Addr, QueryRequest, Uint128, WasmQuery};
    use utils::owner_roles::{IsOwnerResponse, OwnerRole, QueryMsg};

    pub fn check_role(deps: Deps, owner: Addr, role: OwnerRole) -> Result<(), ContractError> {
        let owner_roles = OWNER_ROLES_ADDRESS.load(deps.storage)?;
        let msg = QueryMsg::IsOwner { role, owner };

        let query = QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: owner_roles.to_string(),
            msg: to_json_binary(&msg)?,
        });

        let response: IsOwnerResponse = deps.querier.query(&query)?;
        if !response.is_owner {
            return Err(ContractError::Unauthorized {});
        }
        Ok(())
    }

    pub fn add_claim_topic(
        deps: DepsMut,
        token_addr: Addr,
        topic: Uint128,
    ) -> Result<Response, ContractError> {
        TOKEN_CLAIM_TOPICS.save(
            deps.storage,
            (token_addr.clone(), topic.into()),
            &Claim {
                topic,
                active: true,
            },
        )?;

        Ok(Response::new().add_attribute("action", "add_claim_topic"))
    }

    pub fn remove_claim_topic(
        deps: DepsMut,
        token_addr: Addr,
        claim_topic: Uint128,
    ) -> Result<Response, ContractError> {
        TOKEN_CLAIM_TOPICS.remove(deps.storage, (token_addr, claim_topic.into()));

        Ok(Response::new().add_attribute("action", "remove_claim_topic"))
    }

    pub fn update_claim_topic(
        deps: DepsMut,
        token_addr: Addr,
        claim_topic: Uint128,
        active: bool,
    ) -> Result<Response, ContractError> {
        TOKEN_CLAIM_TOPICS.update(
            deps.storage,
            (token_addr.clone(), claim_topic.into()),
            |module| -> Result<Claim, ContractError> {
                let mut module = module.ok_or(ContractError::ClaimTopicsNotFound {})?;
                module.active = active;
                Ok(module)
            },
        )?;

        Ok(Response::new()
            .add_attribute("action", "update_claim_topic")
            .add_attribute("token_address", token_addr.to_string())
            .add_attribute("claim_topic", claim_topic)
            .add_attribute("is_active", active.to_string()))
    }
}
pub mod query {
    use cosmwasm_std::{Addr, Uint128};

    use crate::state::TOKEN_CLAIM_TOPICS;

    use super::*;
    pub fn get_claims_for_token(deps: Deps, token_addr: Addr) -> StdResult<Vec<Uint128>> {
        let claims: Vec<Uint128> = TOKEN_CLAIM_TOPICS
            .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
            .filter_map(|item| {
                item.ok().and_then(|((token_address, _), module)| {
                    if token_addr == token_address && module.active {
                        Some(module.topic)
                    } else {
                        None
                    }
                })
            })
            .collect();
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage};
    use cosmwasm_std::{from_json, Addr, ContractResult, OwnedDeps, SystemResult, Uint128};
    use utils::owner_roles::{IsOwnerResponse, OwnerRole, QueryMsg as OwnerRolesQueryMsg};

    fn setup_contract(deps: DepsMut) -> Addr {
        let owner_roles_address = MockApi::default().addr_make("owner_roles_address");
        let msg = InstantiateMsg {
            owner_roles_address: owner_roles_address.clone(),
        };
        let info = MessageInfo {
            sender: Addr::unchecked("creator"),
            funds: vec![],
        };
        let _ = instantiate(deps, mock_env(), info, msg).unwrap();
        owner_roles_address
    }

    fn mock_owner_roles_query(deps: &mut OwnedDeps<MockStorage, MockApi, MockQuerier>) {
        deps.querier.update_wasm(|query| match query {
            cosmwasm_std::WasmQuery::Smart { msg, .. } => {
                let parsed: OwnerRolesQueryMsg = from_json(msg).unwrap();
                match parsed {
                    OwnerRolesQueryMsg::IsOwner { role, .. } => {
                        if role == OwnerRole::ClaimRegistryManager {
                            SystemResult::Ok(ContractResult::Ok(
                                to_json_binary(&IsOwnerResponse {
                                    is_owner: true,
                                    role: OwnerRole::ClaimRegistryManager,
                                })
                                .unwrap(),
                            ))
                        } else {
                            panic!("Unexpected role query")
                        }
                    }
                }
            }
            _ => panic!("Unexpected query type"),
        });
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
    fn add_claim_topic() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());
        let token_address = MockApi::default().addr_make("token_address");

        mock_owner_roles_query(&mut deps);

        let info = MessageInfo {
            sender: Addr::unchecked("authorized_user"),
            funds: vec![],
        };
        let msg = ExecuteMsg::AddClaimTopicForToken {
            topic: Uint128::new(1),
            token_addr: token_address.clone(),
        };

        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(res.attributes, vec![("action", "add_claim_topic")]);

        // Verify the topic was added
        let msg = QueryMsg::GetClaimsForToken {
            token_addr: token_address.clone(),
        };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let tokens: Vec<Uint128> = from_json(res).unwrap();
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn remove_claim_topic() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());
        let token_address = MockApi::default().addr_make("token_address");

        mock_owner_roles_query(&mut deps);

        let info = MessageInfo {
            sender: Addr::unchecked("authorized_user"),
            funds: vec![],
        };

        // First, add a claim topic
        let msg = ExecuteMsg::AddClaimTopicForToken {
            topic: Uint128::new(1),
            token_addr: token_address.clone(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Now remove the claim topic
        let msg = ExecuteMsg::RemoveClaimTopicForToken {
            topic: Uint128::new(1),
            token_addr: token_address.clone(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(res.attributes, vec![("action", "remove_claim_topic")]);

        // Verify the topic was removed
        let msg = QueryMsg::GetClaimsForToken {
            token_addr: token_address,
        };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let tokens: Vec<Uint128> = from_json(res).unwrap();
        assert!(tokens.is_empty());
    }

    #[test]
    fn update_claim_topic() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());
        let token_address = MockApi::default().addr_make("token_address");

        mock_owner_roles_query(&mut deps);

        let info = MessageInfo {
            sender: Addr::unchecked("authorized_user"),
            funds: vec![],
        };
        let msg = ExecuteMsg::AddClaimTopicForToken {
            topic: Uint128::new(1),
            token_addr: token_address.clone(),
        };

        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(res.attributes, vec![("action", "add_claim_topic")]);

        // Verify the topic was added
        let msg = QueryMsg::GetClaimsForToken {
            token_addr: token_address.clone(),
        };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let tokens: Vec<Uint128> = from_json(res).unwrap();
        assert_eq!(tokens.len(), 1);

        let info = MessageInfo {
            sender: Addr::unchecked("authorized_user"),
            funds: vec![],
        };
        let msg = ExecuteMsg::UpdateClaimTopicForToken {
            topic: Uint128::new(1),
            token_addr: token_address.clone(),
            active: false,
        };

        let _ = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        let msg = QueryMsg::GetClaimsForToken {
            token_addr: token_address.clone(),
        };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let tokens: Vec<Uint128> = from_json(res).unwrap();
        assert!(tokens.is_empty());
    }
}
