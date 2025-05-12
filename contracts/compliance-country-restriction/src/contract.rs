#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;
use utils::compliance::QueryMsg;
use utils::owner_roles::OwnerRole;
// use cw2::set_contract_version;

use crate::ContractError;
use crate::{ExecuteMsg, InstantiateMsg};

use super::state::{IDENTITY_ADDRESS, OWNER_ROLES_ADDRESS};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:compliance_modules:country_restriction";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Instantiate country restriction contract
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
    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
}

/// Execute function for the country restriction contract
///
/// # Arguments
///
/// * `deps` - Mutable dependencies
/// * `_env` - The environment info (unused)
/// * `info` - Message info
/// * `msg` - Execute message
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
    // with a role of ComplianceManager are allowed to execute the functions
    execute::check_role(deps.as_ref(), info.sender, OwnerRole::ComplianceManager)?;

    match msg {
        ExecuteMsg::AddCountryRestriction {
            token_address,
            country,
        } => execute::add_country_restriction(deps, token_address, country),
        ExecuteMsg::RemoveCountryRestriction {
            token_address,
            country,
        } => execute::remove_country_restriction(deps, token_address, country),
        ExecuteMsg::UpdateCountryRestriction {
            token_address,
            country,
            active,
        } => execute::update_country_restriction(deps, token_address, country, active),
    }
}

pub mod execute {
    use crate::{msg::RestrictedCountry, state::RESTRICTED_COUNTRY};

    use super::*;
    use cosmwasm_std::{to_json_binary, Addr, QueryRequest, WasmQuery};
    use utils::owner_roles::{IsOwnerResponse, QueryMsg};

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

    /// Add country restriction for a token
    pub fn add_country_restriction(
        deps: DepsMut,
        token_address: Addr,
        country: String,
    ) -> Result<Response, ContractError> {
        RESTRICTED_COUNTRY.save(
            deps.storage,
            (token_address.clone(), country.clone()),
            &RestrictedCountry {
                country: country.clone(),
                active: true,
            },
        )?;

        Ok(Response::new()
            .add_attribute("action", "add_country_restriction")
            .add_attribute("token_address", token_address.to_string())
            .add_attribute("country", country.to_string()))
    }

    /// Remove country restriction for a token
    pub fn remove_country_restriction(
        deps: DepsMut,
        token_address: Addr,
        country: String,
    ) -> Result<Response, ContractError> {
        RESTRICTED_COUNTRY.remove(deps.storage, (token_address.clone(), country.clone()));

        Ok(Response::new()
            .add_attribute("action", "remove_country_restriction")
            .add_attribute("token_address", token_address.to_string())
            .add_attribute("country", country.to_string()))
    }

    /// Update the country restriction active status for a token
    pub fn update_country_restriction(
        deps: DepsMut,
        token_address: Addr,
        country: String,
        active: bool,
    ) -> Result<Response, ContractError> {
        RESTRICTED_COUNTRY.update(
            deps.storage,
            (token_address.clone(), country.clone()),
            |module| -> Result<RestrictedCountry, ContractError> {
                let mut module = module.ok_or(ContractError::CountryNotFound {})?;
                module.active = active;
                Ok(module)
            },
        )?;

        Ok(Response::new()
            .add_attribute("action", "update_country_restriction")
            .add_attribute("token_address", token_address.to_string())
            .add_attribute("country", country.to_string())
            .add_attribute("is_active", active.to_string()))
    }
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
    use crate::{msg::RestrictedCountry, state::RESTRICTED_COUNTRY};

    use super::*;
    use cosmwasm_std::{Addr, QueryRequest, Uint128, WasmQuery};
    use serde_json::json;

    /// Check compliance for a token transfer
    pub fn check_compliance(
        deps: Deps,
        token_address: Addr,
        from: Option<Addr>,
        to: Option<Addr>,
        _amount: Option<Uint128>,
    ) -> StdResult<bool> {
        let identity_address = IDENTITY_ADDRESS.load(deps.storage)?;

        // Get all active restricted countries for the token
        let restricted_countries: Vec<RestrictedCountry> = RESTRICTED_COUNTRY
            .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
            .filter_map(|item| {
                item.ok().and_then(|((token_addr, _), module)| {
                    if token_addr == token_address && module.active {
                        Some(module)
                    } else {
                        None
                    }
                })
            })
            .collect();

        // Query sender's country if 'from' is provided
        let sender_country = if let Some(sender) = from {
            match query_country_for_identity(deps, &identity_address, &sender) {
                Ok(country) => Some(country),
                Err(_) => return Ok(false), // If we can't get the sender's country, fail the compliance check
            }
        } else {
            None
        };

        // Query receiver's country if 'to' is provided
        let receiver_country = if let Some(receiver) = to {
            match query_country_for_identity(deps, &identity_address, &receiver) {
                Ok(country) => Some(country),
                Err(_) => return Ok(false), // If we can't get the receiver's country, fail the compliance check
            }
        } else {
            None
        };

        // Check if sender or receiver is in a restricted country
        for restricted_country in restricted_countries {
            if let Some(sender_country) = &sender_country {
                if sender_country == &restricted_country.country {
                    return Ok(false); // Sender is in a restricted country
                }
            }
            if let Some(receiver_country) = &receiver_country {
                if receiver_country == &restricted_country.country {
                    return Ok(false); // Receiver is in a restricted country
                }
            }
        }

        // If we've made it this far, the compliance check passes
        Ok(true)
    }

    fn query_country_for_identity(
        deps: Deps,
        contract_addr: &Addr,
        user: &Addr,
    ) -> StdResult<String> {
        let query_msg = json!({
            "get_country_for_identity": {
                "identity_owner": user
            }
        });
        let query = QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: contract_addr.to_string(),
            msg: to_json_binary(&query_msg)?,
        });
        deps.querier.query(&query)
    }
}

#[cfg(test)]
mod tests {
    use crate::msg::RestrictedCountry;
    use crate::state::RESTRICTED_COUNTRY;

    use super::*;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{from_json, Addr, ContractResult, SystemResult};
    use utils::owner_roles::{IsOwnerResponse, OwnerRole};

    fn setup_contract(deps: DepsMut) -> (Addr, Addr) {
        let owner_roles_address = Addr::unchecked("owner_roles_contract");
        let identity_address = Addr::unchecked("identity_contract");
        let msg = InstantiateMsg {
            owner_roles_address: owner_roles_address.clone(),
            identity_address: identity_address.clone(),
        };
        let info = message_info(&Addr::unchecked("creator"), &[]);
        let _ = instantiate(deps, mock_env(), info, msg).unwrap();
        (owner_roles_address, identity_address)
    }

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();
        let (owner_roles_address, identity_address) = setup_contract(deps.as_mut());

        // Check if the owner_roles_address is set correctly
        let stored_owner_roles = OWNER_ROLES_ADDRESS.load(&deps.storage).unwrap();
        assert_eq!(stored_owner_roles, owner_roles_address);

        // Check if the identity_address is set correctly
        let stored_identity = IDENTITY_ADDRESS.load(&deps.storage).unwrap();
        assert_eq!(stored_identity, identity_address);
    }

    #[test]
    fn add_country_restriction() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        // Mock the owner roles contract query
        deps.querier.update_wasm(|query| match query {
            cosmwasm_std::WasmQuery::Smart { msg, .. } => {
                let parsed: utils::owner_roles::QueryMsg = from_json(msg).unwrap();
                match parsed {
                    utils::owner_roles::QueryMsg::IsOwner { role, .. } => {
                        if role == OwnerRole::ComplianceManager {
                            SystemResult::Ok(ContractResult::Ok(
                                to_json_binary(&IsOwnerResponse {
                                    is_owner: true,
                                    role: OwnerRole::ComplianceManager,
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

        let info = message_info(&Addr::unchecked("authorized_user"), &[]);
        let token_address = Addr::unchecked("token_address");
        let country = "US".to_string();

        let msg = ExecuteMsg::AddCountryRestriction {
            token_address: token_address.clone(),
            country: country.clone(),
        };

        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![
                ("action", "add_country_restriction"),
                ("token_address", token_address.as_str()),
                ("country", &country),
            ]
        );

        // Verify the country restriction was added
        let restriction = RESTRICTED_COUNTRY
            .load(&deps.storage, (token_address, country))
            .unwrap();
        assert!(restriction.active);
    }

    #[test]
    fn remove_country_restriction() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        // Mock the owner roles contract query
        deps.querier.update_wasm(|query| match query {
            cosmwasm_std::WasmQuery::Smart { msg, .. } => {
                let parsed: utils::owner_roles::QueryMsg = from_json(msg).unwrap();
                match parsed {
                    utils::owner_roles::QueryMsg::IsOwner { role, .. } => {
                        if role == OwnerRole::ComplianceManager {
                            SystemResult::Ok(ContractResult::Ok(
                                to_json_binary(&IsOwnerResponse {
                                    is_owner: true,
                                    role: OwnerRole::ComplianceManager,
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

        let info = message_info(&Addr::unchecked("authorized_user"), &[]);
        let token_address = Addr::unchecked("token_address");
        let country = "US".to_string();

        // First, add a country restriction
        let add_msg = ExecuteMsg::AddCountryRestriction {
            token_address: token_address.clone(),
            country: country.clone(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), add_msg).unwrap();

        // Now remove the country restriction
        let remove_msg = ExecuteMsg::RemoveCountryRestriction {
            token_address: token_address.clone(),
            country: country.clone(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, remove_msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![
                ("action", "remove_country_restriction"),
                ("token_address", token_address.as_str()),
                ("country", &country),
            ]
        );

        // Verify the country restriction was removed
        let restriction = RESTRICTED_COUNTRY
            .may_load(&deps.storage, (token_address, country))
            .unwrap();
        assert!(restriction.is_none());
    }

    #[test]
    fn update_country_restriction() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        // Mock the owner roles contract query
        deps.querier.update_wasm(|query| match query {
            cosmwasm_std::WasmQuery::Smart { msg, .. } => {
                let parsed: utils::owner_roles::QueryMsg = from_json(msg).unwrap();
                match parsed {
                    utils::owner_roles::QueryMsg::IsOwner { role, .. } => {
                        if role == OwnerRole::ComplianceManager {
                            SystemResult::Ok(ContractResult::Ok(
                                to_json_binary(&IsOwnerResponse {
                                    is_owner: true,
                                    role: OwnerRole::ComplianceManager,
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

        let info = message_info(&Addr::unchecked("authorized_user"), &[]);
        let token_address = Addr::unchecked("token_address");
        let country = "US".to_string();

        // First, add a country restriction
        let add_msg = ExecuteMsg::AddCountryRestriction {
            token_address: token_address.clone(),
            country: country.clone(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), add_msg).unwrap();

        // Now update the country restriction
        let update_msg = ExecuteMsg::UpdateCountryRestriction {
            token_address: token_address.clone(),
            country: country.clone(),
            active: false,
        };
        let res = execute(deps.as_mut(), mock_env(), info, update_msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![
                ("action", "update_country_restriction"),
                ("token_address", token_address.as_str()),
                ("country", &country),
                ("is_active", "false"),
            ]
        );

        // Verify the country restriction was updated
        let restriction = RESTRICTED_COUNTRY
            .load(&deps.storage, (token_address, country))
            .unwrap();
        assert!(!restriction.active);
    }

    #[test]
    fn test_check_compliance() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        let token_address = Addr::unchecked("token_address");
        let sender = Addr::unchecked("sender");
        let receiver = Addr::unchecked("receiver");

        // Add a restricted country
        RESTRICTED_COUNTRY
            .save(
                deps.as_mut().storage,
                (token_address.clone(), "US".to_string()),
                &RestrictedCountry {
                    country: "US".to_string(),
                    active: true,
                },
            )
            .unwrap();

        // Mock the identity contract query
        deps.querier.update_wasm(|query| match query {
            cosmwasm_std::WasmQuery::Smart { contract_addr, msg } => {
                let parsed: serde_json::Value = from_json(msg).unwrap();
                if contract_addr == "identity_contract" {
                    if let Some(get_country) = parsed.get("get_country_for_identity") {
                        let identity_owner = get_country["identity_owner"].as_str().unwrap();
                        let country = match identity_owner {
                            "sender" => "CA",
                            "receiver" => "US",
                            _ => panic!("Unexpected identity owner"),
                        };
                        SystemResult::Ok(ContractResult::Ok(to_json_binary(&country).unwrap()))
                    } else {
                        panic!("Unexpected query to identity contract");
                    }
                } else {
                    panic!("Unexpected contract call");
                }
            }
            _ => panic!("Unexpected query type"),
        });

        // Test case 1: Sender is not in a restricted country, but receiver is
        let res = query::check_compliance(
            deps.as_ref(),
            token_address.clone(),
            Some(sender.clone()),
            Some(receiver.clone()),
            None,
        )
        .unwrap();
        assert!(!res);

        // Test case 2: Both sender and receiver are not in restricted countries
        deps.querier.update_wasm(|query| match query {
            cosmwasm_std::WasmQuery::Smart { contract_addr, msg } => {
                let parsed: serde_json::Value = from_json(msg).unwrap();
                if contract_addr == "identity_contract" {
                    if let Some(get_country) = parsed.get("get_country_for_identity") {
                        let identity_owner = get_country["identity_owner"].as_str().unwrap();
                        let country = match identity_owner {
                            "sender" => "CA",
                            "receiver" => "CA",
                            _ => panic!("Unexpected identity owner"),
                        };
                        SystemResult::Ok(ContractResult::Ok(to_json_binary(&country).unwrap()))
                    } else {
                        panic!("Unexpected query to identity contract");
                    }
                } else {
                    panic!("Unexpected contract call");
                }
            }
            _ => panic!("Unexpected query type"),
        });

        let res = query::check_compliance(
            deps.as_ref(),
            token_address.clone(),
            Some(sender.clone()),
            Some(receiver.clone()),
            None,
        )
        .unwrap();
        assert!(res);

        // Test case 3: Only check sender (e.g., for burning tokens)
        let res = query::check_compliance(
            deps.as_ref(),
            token_address.clone(),
            Some(sender.clone()),
            None,
            None,
        )
        .unwrap();
        assert!(res);

        // Test case 4: Only check receiver (e.g., for minting tokens)
        deps.querier.update_wasm(|query| match query {
            cosmwasm_std::WasmQuery::Smart { contract_addr, msg } => {
                let parsed: serde_json::Value = from_json(msg).unwrap();
                if contract_addr == "identity_contract" {
                    if let Some(get_country) = parsed.get("get_country_for_identity") {
                        let identity_owner = get_country["identity_owner"].as_str().unwrap();
                        let country = match identity_owner {
                            "receiver" => "US",
                            _ => panic!("Unexpected identity owner"),
                        };
                        SystemResult::Ok(ContractResult::Ok(to_json_binary(&country).unwrap()))
                    } else {
                        panic!("Unexpected query to identity contract");
                    }
                } else {
                    panic!("Unexpected contract call");
                }
            }
            _ => panic!("Unexpected query type"),
        });

        let res = query::check_compliance(deps.as_ref(), token_address, None, Some(receiver), None)
            .unwrap();
        assert!(!res);
    }
}
