#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};
use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg};
use crate::state::{COMPLIANCE_MODULE_ADDRESS, OWNER_ROLES_ADDRESS, WHITELISTED_ADDRESSES};
use utils::owner_roles::OwnerRole;

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:compliance";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Instantiate a new compliance contract
///
/// # Arguments
///
/// * `deps` - Mutable dependencies
/// * `_env` - The environment info (unused)
/// * `info` - Message info
/// * `msg` - Instantiate message containing the owner roles address and compliance module address
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
    COMPLIANCE_MODULE_ADDRESS.save(deps.storage, &msg.module_address)?;
    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
}

/// Execute function for the compliance contract
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
        ExecuteMsg::ChangeComplianceModule { module_address } => {
            execute::change_compliance_module(deps, module_address)
        }
        ExecuteMsg::AddAddressToWhitelist { address } => {
            execute::add_address_to_whitelist(deps, address)
        }
        ExecuteMsg::RemoveAddressFromWhitelist { address } => {
            execute::remove_address_from_whitelist(deps, address)
        }
    }
}

pub mod execute {
    use crate::state::WHITELISTED_ADDRESSES;

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

    /// change_compliance_module changes the compliance module address utilized
    pub fn change_compliance_module(
        deps: DepsMut,
        module_address: Addr,
    ) -> Result<Response, ContractError> {
        COMPLIANCE_MODULE_ADDRESS.save(deps.storage, &module_address)?;

        Ok(Response::new()
            .add_attribute("action", "change_compliance_module")
            .add_attribute("module_address", module_address.to_string()))
    }

    pub fn add_address_to_whitelist(
        deps: DepsMut,
        address: Addr,
    ) -> Result<Response, ContractError> {
        WHITELISTED_ADDRESSES.save(deps.storage, address.clone(), &true)?;
        Ok(Response::new().add_attribute("action", "add_address_to_whitelist"))
    }

    pub fn remove_address_from_whitelist(
        deps: DepsMut,
        address: Addr,
    ) -> Result<Response, ContractError> {
        WHITELISTED_ADDRESSES.remove(deps.storage, address);
        Ok(Response::new().add_attribute("action", "remove_address_from_whitelist"))
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: utils::compliance::QueryMsg) -> StdResult<Binary> {
    match msg {
        utils::compliance::QueryMsg::CheckTokenCompliance {
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

fn is_whitelisted(deps: Deps, address: Option<Addr>) -> bool {
    match address {
        None => true,
        Some(addr) => WHITELISTED_ADDRESSES.load(deps.storage, addr).is_ok(),
    }
}

pub mod query {
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
        // Get compliance module and whitelisted addresses
        let module_address = COMPLIANCE_MODULE_ADDRESS.load(deps.storage)?;

        // Replace whitelisted addrs with None
        let from = if is_whitelisted(deps, from.clone()) {
            None
        } else {
            from
        };
        let to = if is_whitelisted(deps, to.clone()) {
            None
        } else {
            to
        };

        // Check compliance with wrapped module
        let msg = utils::compliance::QueryMsg::CheckTokenCompliance {
            token_address: token_address.clone(),
            from: if is_whitelisted(deps, from.clone()) {
                None
            } else {
                from
            },
            to: to.clone(),
            amount,
        };

        let query = QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: module_address.to_string(),
            msg: to_json_binary(&msg)?,
        });
        let is_compliant: bool = deps.querier.query(&query)?;
        if !is_compliant {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{from_json, Addr, ContractResult, SystemResult, Uint128};
    use utils::owner_roles::{IsOwnerResponse, OwnerRole};

    // Helper function to instantiate the contract
    fn setup_contract(deps: DepsMut) {
        let msg = InstantiateMsg {
            owner_roles_address: Addr::unchecked("owner_roles"),
            module_address: Addr::unchecked("compliance_module"),
        };
        let info = message_info(&Addr::unchecked("creator"), &[]);
        let res = instantiate(deps, mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();
        setup_contract(deps.as_mut());

        // Check that the owner_roles_address was properly set
        let owner_roles = OWNER_ROLES_ADDRESS.load(deps.as_ref().storage).unwrap();
        assert_eq!(owner_roles, Addr::unchecked("owner_roles"));

        // Check that the module_address was properly set
        let compliance_module = COMPLIANCE_MODULE_ADDRESS
            .load(deps.as_ref().storage)
            .unwrap();
        assert_eq!(compliance_module, Addr::unchecked("compliance_module"));
    }

    #[test]
    fn add_compliance_module() {
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
        let info = message_info(&Addr::unchecked("admin"), &[]);
        let msg = ExecuteMsg::ChangeComplianceModule {
            module_address: Addr::unchecked("module"),
        };

        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(2, res.attributes.len());
    }

    #[test]
    fn add_and_remove_from_whitelist() {
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

        let info = message_info(&Addr::unchecked("admin"), &[]);
        let add_msg = ExecuteMsg::AddAddressToWhitelist {
            address: Addr::unchecked("address"),
        };
        let res = execute(deps.as_mut(), mock_env(), info.clone(), add_msg).unwrap();
        assert_eq!(1, res.attributes.len());

        // Now remove the module
        let remove_msg = ExecuteMsg::RemoveAddressFromWhitelist {
            address: Addr::unchecked("address"),
        };
        let res = execute(deps.as_mut(), mock_env(), info, remove_msg).unwrap();
        assert_eq!(1, res.attributes.len());
    }

    #[test]
    fn check_compliance() {
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

        // Mock the module query
        deps.querier.update_wasm(|query| match query {
            cosmwasm_std::WasmQuery::Smart { msg, .. } => {
                let parsed: utils::compliance::QueryMsg = from_json(msg).unwrap();
                match parsed {
                    utils::compliance::QueryMsg::CheckTokenCompliance {
                        token_address: _,
                        from: _,
                        to: _,
                        amount: _,
                    } => SystemResult::Ok(ContractResult::Ok(to_json_binary(&true).unwrap())),
                }
            }
            _ => panic!("Unexpected query type"),
        });

        // Check compliance
        let msg = utils::compliance::QueryMsg::CheckTokenCompliance {
            token_address: Addr::unchecked("token"),
            from: Some(Addr::unchecked("sender")),
            to: Some(Addr::unchecked("receiver")),
            amount: Some(Uint128::new(100)),
        };

        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let is_compliant: bool = from_json(res).unwrap();
        assert!(is_compliant);
    }
}
