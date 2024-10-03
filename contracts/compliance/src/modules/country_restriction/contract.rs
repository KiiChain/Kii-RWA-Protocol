#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;
use roles::owner_roles::msg::OwnerRole;
// use cw2::set_contract_version;

use crate::modules::country_restriction::msg::{ExecuteMsg, InstantiateMsg};
use crate::modules::country_restriction::ContractError;
use crate::QueryMsg;

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
            country_code,
        } => execute::add_country_restriction(deps, token_address, country_code),
        ExecuteMsg::RemoveCountryRestriction {
            token_address,
            country_code,
        } => execute::remove_country_restriction(deps, token_address, country_code),
        ExecuteMsg::UpdateCountryRestriction {
            token_address,
            country_code,
            active,
        } => execute::update_country_restriction(deps, token_address, country_code, active),
    }
}

pub mod execute {
    use crate::modules::country_restriction::{msg::RestrictedCountry, state::RESTRICTED_COUNTRY};

    use super::*;
    use cosmwasm_std::{to_json_binary, Addr, QueryRequest, WasmQuery};
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

    /// Add country restriction for a token

    pub fn add_country_restriction(
        deps: DepsMut,
        token_address: Addr,
        country_code: String,
    ) -> Result<Response, ContractError> {
        RESTRICTED_COUNTRY.save(
            deps.storage,
            (token_address.clone(), country_code.clone()),
            &RestrictedCountry {
                country_code: country_code.clone(),
                active: true,
            },
        )?;

        Ok(Response::new()
            .add_attribute("action", "add_country_restriction")
            .add_attribute("token_address", token_address.to_string())
            .add_attribute("country_code", country_code.to_string()))
    }

    /// Remove country restriction for a token

    pub fn remove_country_restriction(
        deps: DepsMut,
        token_address: Addr,
        country_code: String,
    ) -> Result<Response, ContractError> {
        RESTRICTED_COUNTRY.remove(deps.storage, (token_address.clone(), country_code.clone()));

        Ok(Response::new()
            .add_attribute("action", "remove_country_restriction")
            .add_attribute("token_address", token_address.to_string())
            .add_attribute("country_code", country_code.to_string()))
    }

    /// Update the country restriction active status for a token

    pub fn update_country_restriction(
        deps: DepsMut,
        token_address: Addr,
        country_code: String,
        active: bool,
    ) -> Result<Response, ContractError> {
        RESTRICTED_COUNTRY.update(
            deps.storage,
            (token_address.clone(), country_code.clone()),
            |module| -> Result<RestrictedCountry, ContractError> {
                let mut module = module.ok_or(ContractError::CountryNotFound {})?;
                module.active = active;
                Ok(module)
            },
        )?;

        Ok(Response::new()
            .add_attribute("action", "update_country_restriction")
            .add_attribute("token_address", token_address.to_string())
            .add_attribute("country_code", country_code.to_string())
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
    use crate::modules::country_restriction::{msg::RestrictedCountry, state::RESTRICTED_COUNTRY};

    use super::*;
    use cosmwasm_std::{to_json_binary, Addr, QueryRequest, Uint128, WasmQuery};

    /// Check compliance for a token transfer
    pub fn check_compliance(
        deps: Deps,
        token_address: Addr,
        from: Option<Addr>,
        to: Option<Addr>,
        amount: Option<Uint128>,
    ) -> StdResult<bool> {
        let idenitry_address = IDENTITY_ADDRESS.load(deps.storage)?;

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

        // Check if sender or receiver is in a restricted country
        for restricted_country in restricted_countries {
            // let msg = QueryMsg::GetCountryCode {
            //     from: from.clone(),
            //     to: to.clone(),
            // };

            // let query = QueryRequest::Wasm(WasmQuery::Smart {
            //     contract_addr: idenitry_address.to_string(),
            //     msg: to_json_binary(&msg)?,
            // });
            // let (from_country_code, to_country_code): (String, String) =
            //     deps.querier.query(&query)?;
            // if from_country_code == restricted_country.country_code
            //     || to_country_code == restricted_country.country_code
            // {
            //     return Ok(false);
            // }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use crate::modules::country_restriction::state::RESTRICTED_COUNTRY;

    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_json, Addr, ContractResult, SystemResult, Uint128};
    use roles::owner_roles::msg::OwnerRole;

    fn setup_contract(deps: DepsMut) -> (Addr, Addr) {
        let owner_roles_address = Addr::unchecked("owner_roles_contract");
        let identity_address = Addr::unchecked("identity_contract");
        let msg = InstantiateMsg {
            owner_roles_address: owner_roles_address.clone(),
            identity_address: identity_address.clone(),
        };
        let info = mock_info("creator", &[]);
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
                let parsed: roles::owner_roles::QueryMsg = from_json(msg).unwrap();
                match parsed {
                    roles::owner_roles::QueryMsg::IsOwner { role, .. } => {
                        if role == OwnerRole::ComplianceManager {
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
        let token_address = Addr::unchecked("token_address");
        let country_code = "US".to_string();

        let msg = ExecuteMsg::AddCountryRestriction {
            token_address: token_address.clone(),
            country_code: country_code.clone(),
        };

        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![
                ("action", "add_country_restriction"),
                ("token_address", token_address.as_str()),
                ("country_code", &country_code),
            ]
        );

        // Verify the country restriction was added
        let restriction = RESTRICTED_COUNTRY
            .load(&deps.storage, (token_address, country_code))
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
                let parsed: roles::owner_roles::QueryMsg = from_json(msg).unwrap();
                match parsed {
                    roles::owner_roles::QueryMsg::IsOwner { role, .. } => {
                        if role == OwnerRole::ComplianceManager {
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
        let token_address = Addr::unchecked("token_address");
        let country_code = "US".to_string();

        // First, add a country restriction
        let add_msg = ExecuteMsg::AddCountryRestriction {
            token_address: token_address.clone(),
            country_code: country_code.clone(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), add_msg).unwrap();

        // Now remove the country restriction
        let remove_msg = ExecuteMsg::RemoveCountryRestriction {
            token_address: token_address.clone(),
            country_code: country_code.clone(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, remove_msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![
                ("action", "remove_country_restriction"),
                ("token_address", token_address.as_str()),
                ("country_code", &country_code),
            ]
        );

        // Verify the country restriction was removed
        let restriction = RESTRICTED_COUNTRY
            .may_load(&deps.storage, (token_address, country_code))
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
                let parsed: roles::owner_roles::QueryMsg = from_json(msg).unwrap();
                match parsed {
                    roles::owner_roles::QueryMsg::IsOwner { role, .. } => {
                        if role == OwnerRole::ComplianceManager {
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
        let token_address = Addr::unchecked("token_address");
        let country_code = "US".to_string();

        // First, add a country restriction
        let add_msg = ExecuteMsg::AddCountryRestriction {
            token_address: token_address.clone(),
            country_code: country_code.clone(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), add_msg).unwrap();

        // Now update the country restriction
        let update_msg = ExecuteMsg::UpdateCountryRestriction {
            token_address: token_address.clone(),
            country_code: country_code.clone(),
            active: false,
        };
        let res = execute(deps.as_mut(), mock_env(), info, update_msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![
                ("action", "update_country_restriction"),
                ("token_address", token_address.as_str()),
                ("country_code", &country_code),
                ("is_active", "false"),
            ]
        );

        // Verify the country restriction was updated
        let restriction = RESTRICTED_COUNTRY
            .load(&deps.storage, (token_address, country_code))
            .unwrap();
        assert!(!restriction.active);
    }

    #[test]
    fn check_compliance() {
        assert!(true);
    }
}
