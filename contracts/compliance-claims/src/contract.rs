#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;
use utils::compliance::QueryMsg;

use crate::state::CLAIM_TOPICS_ADDRESS;
use crate::ContractError;
use crate::InstantiateMsg;

use super::state::{IDENTITY_ADDRESS, OWNER_ROLES_ADDRESS};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:compliance_modules:country_restriction";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Instantiate claims compliance check
///
/// # Arguments
///
/// * `deps` - Mutable dependencies
/// * `_env` - The environment info (unused)
/// * `info` - Message info
/// * `msg` - Instantiate message containing the owner roles and identity address
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
    IDENTITY_ADDRESS.save(deps.storage, &msg.identity_address)?;
    CLAIM_TOPICS_ADDRESS.save(deps.storage, &msg.claim_topics_address)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::CheckTokenCompliance {
            token_address,
            from,
            to,
            amount,
        } => to_json_binary(&query::check_compliance(
            deps,
            token_address,
            from,
            to,
            amount,
        )?),
    }
}

pub mod query {

    use crate::msg::Claim;

    use super::*;
    use cosmwasm_std::{Addr, QueryRequest, Uint128, WasmQuery};
    use serde_json::json;

    /// Check compliance to see if sender/receiver have claims associated with a token
    pub fn check_compliance(
        deps: Deps,
        token_address: Addr,
        from: Option<Addr>,
        to: Option<Addr>,
        _amount: Option<Uint128>,
    ) -> StdResult<bool> {
        let identity_address = IDENTITY_ADDRESS.load(deps.storage)?;
        let claims_topics_address = CLAIM_TOPICS_ADDRESS.load(deps.storage)?;

        // Query the claims required for the token
        let claims_for_token: Vec<Uint128> =
            query_claims_for_token(deps, &claims_topics_address, &token_address)?;

        // If there are no required claims for the token, compliance check passes
        if claims_for_token.is_empty() {
            return Ok(true);
        }

        // Check sender's claims if 'from' is provided
        if let Some(sender) = from {
            let sender_claims: Vec<Uint128> =
                query_claims_for_user(deps, &identity_address, &sender)?;
            if !has_all_required_claims(&claims_for_token, &sender_claims) {
                return Ok(false);
            }
        }

        // Check receiver's claims if 'to' is provided
        if let Some(receiver) = to {
            let receiver_claims: Vec<Uint128> =
                query_claims_for_user(deps, &identity_address, &receiver)?;
            if !has_all_required_claims(&claims_for_token, &receiver_claims) {
                return Ok(false);
            }
        }

        // all checks have passed
        Ok(true)
    }

    fn query_claims_for_token(
        deps: Deps,
        contract_addr: &Addr,
        token_addr: &Addr,
    ) -> StdResult<Vec<Uint128>> {
        let query_msg = json!({
            "get_claims_for_token": {
                "token_addr": token_addr
            }
        });
        let query = QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: contract_addr.to_string(),
            msg: to_json_binary(&query_msg)?,
        });
        deps.querier.query(&query)
    }

    fn query_claims_for_user(
        deps: Deps,
        contract_addr: &Addr,
        user: &Addr,
    ) -> StdResult<Vec<Uint128>> {
        let query_msg = json!({
            "get_validated_claims_for_user": {
                "identity_owner": user
            }
        });
        let query = QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: contract_addr.to_string(),
            msg: to_json_binary(&query_msg)?,
        });
        let claims: Vec<Claim> = deps.querier.query(&query)?;

        Ok(claims.into_iter().map(|claim| claim.topic).collect())
    }

    fn has_all_required_claims(required_claims: &[Uint128], user_claims: &[Uint128]) -> bool {
        required_claims
            .iter()
            .all(|claim| user_claims.contains(claim))
    }
}

#[cfg(test)]
mod tests {

    use crate::msg::Claim;

    use super::*;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{
        from_json, to_json_binary, Addr, ContractResult, SystemResult, Uint128, WasmQuery,
    };

    // Helper function to set up the test environment
    fn setup_test_case(deps: DepsMut) {
        let owner_roles_address = Addr::unchecked("owner_roles_contract");
        let identity_address = Addr::unchecked("identity_contract");
        let claims_topics_address = Addr::unchecked("claim_topics_contract");
        let msg = InstantiateMsg {
            owner_roles_address: owner_roles_address.clone(),
            identity_address: identity_address.clone(),
            claim_topics_address: claims_topics_address.clone(),
        };

        let info = message_info(&Addr::unchecked("owner"), &[]);
        let _ = instantiate(deps, mock_env(), info, msg).unwrap();
    }

    fn uint128_to_claim(topic: Uint128) -> Claim {
        Claim {
            topic,
            issuer: Addr::unchecked("mock_issuer"),
            data: Binary::from(b"mock_data"),
            uri: "https://example.com/mock_uri".to_string(),
        }
    }

    #[test]
    fn test_compliance_no_required_claims() {
        let mut deps = mock_dependencies();
        setup_test_case(deps.as_mut());

        let token_claims: Vec<Uint128> = vec![];
        let sender_claims: Vec<Claim> = vec![Uint128::new(1), Uint128::new(2)]
            .into_iter()
            .map(uint128_to_claim)
            .collect();
        let receiver_claims: Vec<Claim> = vec![Uint128::new(1), Uint128::new(2)]
            .into_iter()
            .map(uint128_to_claim)
            .collect();

        deps.querier.update_wasm(move |query| match query {
            WasmQuery::Smart { contract_addr, msg } => {
                let parsed: serde_json::Value = from_json(msg).unwrap();
                match contract_addr.as_str() {
                    "claim_topics_contract" => {
                        if parsed.get("get_claims_for_token").is_some() {
                            SystemResult::Ok(ContractResult::Ok(
                                to_json_binary(&token_claims).unwrap(),
                            ))
                        } else {
                            panic!("Unexpected query to claim_topics_contract");
                        }
                    }
                    "identity_contract" => {
                        if let Some(get_claims) = parsed.get("get_validated_claims_for_user") {
                            let identity_owner = get_claims
                                .get("identity_owner")
                                .and_then(|v| v.as_str())
                                .unwrap();
                            let claims = if identity_owner == "sender" {
                                &sender_claims
                            } else {
                                &receiver_claims
                            };
                            SystemResult::Ok(ContractResult::Ok(to_json_binary(claims).unwrap()))
                        } else {
                            panic!("Unexpected query to identity_contract");
                        }
                    }
                    _ => panic!("Unexpected contract call to {}", contract_addr),
                }
            }
            _ => panic!("Unexpected query type"),
        });

        let query_msg = QueryMsg::CheckTokenCompliance {
            token_address: Addr::unchecked("token"),
            from: Some(Addr::unchecked("sender")),
            to: Some(Addr::unchecked("receiver")),
            amount: None,
        };
        let res = query(deps.as_ref(), mock_env(), query_msg).unwrap();
        let compliance_valid: bool = from_json(res).unwrap();

        assert!(compliance_valid);
    }

    #[test]
    fn test_compliance_sender_fails_required_claims() {
        let mut deps = mock_dependencies();
        setup_test_case(deps.as_mut());

        let token_claims: Vec<Uint128> = vec![Uint128::new(3)];
        let sender_claims: Vec<Claim> = vec![Uint128::new(1), Uint128::new(2)]
            .into_iter()
            .map(uint128_to_claim)
            .collect();
        let receiver_claims: Vec<Claim> = vec![Uint128::new(1), Uint128::new(2)]
            .into_iter()
            .map(uint128_to_claim)
            .collect();

        deps.querier.update_wasm(move |query| match query {
            WasmQuery::Smart { contract_addr, msg } => {
                let parsed: serde_json::Value = from_json(msg).unwrap();
                match contract_addr.as_str() {
                    "claim_topics_contract" => {
                        if parsed.get("get_claims_for_token").is_some() {
                            SystemResult::Ok(ContractResult::Ok(
                                to_json_binary(&token_claims).unwrap(),
                            ))
                        } else {
                            panic!("Unexpected query to claim_topics_contract");
                        }
                    }
                    "identity_contract" => {
                        if let Some(get_claims) = parsed.get("get_validated_claims_for_user") {
                            let identity_owner = get_claims
                                .get("identity_owner")
                                .and_then(|v| v.as_str())
                                .unwrap();
                            let claims = if identity_owner == "sender" {
                                &sender_claims
                            } else {
                                &receiver_claims
                            };
                            SystemResult::Ok(ContractResult::Ok(to_json_binary(claims).unwrap()))
                        } else {
                            panic!("Unexpected query to identity_contract");
                        }
                    }
                    _ => panic!("Unexpected contract call to {}", contract_addr),
                }
            }
            _ => panic!("Unexpected query type"),
        });

        let query_msg = QueryMsg::CheckTokenCompliance {
            token_address: Addr::unchecked("token"),
            from: Some(Addr::unchecked("sender")),
            to: Some(Addr::unchecked("receiver")),
            amount: None,
        };
        let res = query(deps.as_ref(), mock_env(), query_msg).unwrap();
        let compliance_valid: bool = from_json(res).unwrap();

        assert!(!compliance_valid);
    }
    #[test]
    fn test_compliance_receiver_fails_required_claims() {
        let mut deps = mock_dependencies();
        setup_test_case(deps.as_mut());

        let token_claims: Vec<Uint128> = vec![Uint128::new(3)];

        let sender_claims: Vec<Claim> = vec![Uint128::new(3), Uint128::new(2)]
            .into_iter()
            .map(uint128_to_claim)
            .collect();
        let receiver_claims: Vec<Claim> = vec![Uint128::new(1), Uint128::new(2)]
            .into_iter()
            .map(uint128_to_claim)
            .collect();

        deps.querier.update_wasm(move |query| match query {
            WasmQuery::Smart { contract_addr, msg } => {
                let parsed: serde_json::Value = from_json(msg).unwrap();
                match contract_addr.as_str() {
                    "claim_topics_contract" => {
                        if parsed.get("get_claims_for_token").is_some() {
                            SystemResult::Ok(ContractResult::Ok(
                                to_json_binary(&token_claims).unwrap(),
                            ))
                        } else {
                            panic!("Unexpected query to claim_topics_contract");
                        }
                    }
                    "identity_contract" => {
                        if let Some(get_claims) = parsed.get("get_validated_claims_for_user") {
                            let identity_owner = get_claims
                                .get("identity_owner")
                                .and_then(|v| v.as_str())
                                .unwrap();
                            let claims = if identity_owner == "sender" {
                                &sender_claims
                            } else {
                                &receiver_claims
                            };
                            SystemResult::Ok(ContractResult::Ok(to_json_binary(claims).unwrap()))
                        } else {
                            panic!("Unexpected query to identity_contract");
                        }
                    }
                    _ => panic!("Unexpected contract call to {}", contract_addr),
                }
            }
            _ => panic!("Unexpected query type"),
        });

        let query_msg = QueryMsg::CheckTokenCompliance {
            token_address: Addr::unchecked("token"),
            from: Some(Addr::unchecked("sender")),
            to: Some(Addr::unchecked("receiver")),
            amount: None,
        };
        let res = query(deps.as_ref(), mock_env(), query_msg).unwrap();
        let compliance_valid: bool = from_json(res).unwrap();

        assert!(!compliance_valid);
    }
}
