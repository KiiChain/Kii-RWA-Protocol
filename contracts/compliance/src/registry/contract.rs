#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;
use roles::owner_roles::msg::OwnerRole;

use crate::registry::error::ContractError;
use crate::registry::msg::{ExecuteMsg, InstantiateMsg};
use crate::registry::state::OWNER_ROLES_ADDRESS;
use utils::QueryMsg;

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
/// * `msg` - Instantiate message containing the owner roles address
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
        ExecuteMsg::AddComplianceModule {
            token_address,
            module_address,
            module_name,
        } => execute::add_compliance_module(deps, token_address, module_address, module_name),
        ExecuteMsg::RemoveComplianceModule {
            token_address,
            module_address,
        } => execute::remove_compliance_module(deps, token_address, module_address),
        ExecuteMsg::UpdateComplianceModule {
            token_address,
            module_address,
            active,
        } => execute::update_compliance_module(deps, token_address, module_address, active),
    }
}

pub mod execute {
    use crate::registry::{msg::ComplianceModule, state::TOKEN_COMPLIANCE_MODULES};

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

    /// Add a new compliance module for a token

    pub fn add_compliance_module(
        deps: DepsMut,
        token_address: Addr,
        module_address: Addr,
        module_name: String,
    ) -> Result<Response, ContractError> {
        TOKEN_COMPLIANCE_MODULES.save(
            deps.storage,
            (token_address.clone(), module_address.clone()),
            &ComplianceModule {
                name: module_name.clone(),
                active: true,
                address: module_address.clone(),
            },
        )?;

        Ok(Response::new()
            .add_attribute("action", "add_compliance_module")
            .add_attribute("token_address", token_address.to_string())
            .add_attribute("module_address", module_address.to_string())
            .add_attribute("module_name", module_name))
    }

    /// Remove a compliance module for a token

    pub fn remove_compliance_module(
        deps: DepsMut,
        token_address: Addr,
        module_address: Addr,
    ) -> Result<Response, ContractError> {
        TOKEN_COMPLIANCE_MODULES.remove(
            deps.storage,
            (token_address.clone(), module_address.clone()),
        );

        Ok(Response::new()
            .add_attribute("action", "remove_compliance_module")
            .add_attribute("token_address", token_address.to_string())
            .add_attribute("module_address", module_address.to_string()))
    }

    /// Update the active status of a compliance module

    pub fn update_compliance_module(
        deps: DepsMut,
        token_address: Addr,
        module_address: Addr,
        active: bool,
    ) -> Result<Response, ContractError> {
        TOKEN_COMPLIANCE_MODULES.update(
            deps.storage,
            (token_address.clone(), module_address.clone()),
            |module| -> Result<ComplianceModule, ContractError> {
                let mut module = module.ok_or(ContractError::ComplianceNotFound {})?;
                module.active = active;
                Ok(module)
            },
        )?;

        Ok(Response::new()
            .add_attribute("action", "update_compliance_module")
            .add_attribute("token_address", token_address.to_string())
            .add_attribute("module_address", module_address.to_string())
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
    use crate::registry::{msg::ComplianceModule, state::TOKEN_COMPLIANCE_MODULES};

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
        // Get all active compliance modules for the token
        let valid_modules: Vec<ComplianceModule> = TOKEN_COMPLIANCE_MODULES
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

        // Check compliance with each module
        for module in valid_modules {
            let msg = QueryMsg::CheckTokenCompliance {
                token_address: token_address.clone(),
                from: from.clone(),
                to: to.clone(),
                amount,
            };

            let query = QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: module.address.to_string(),
                msg: to_json_binary(&msg)?,
            });
            let is_compliant: bool = deps.querier.query(&query)?;
            if !is_compliant {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{from_json, Addr, ContractResult, SystemResult, Uint128};

    // Helper function to instantiate the contract
    fn setup_contract(deps: DepsMut) {
        let msg = InstantiateMsg {
            owner_roles_address: Addr::unchecked("owner_roles"),
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
    }

    #[test]
    fn add_compliance_module() {
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
        let info = message_info(&Addr::unchecked("admin"), &[]);
        let msg = ExecuteMsg::AddComplianceModule {
            token_address: Addr::unchecked("token"),
            module_address: Addr::unchecked("module"),
            module_name: "Test Module".to_string(),
        };

        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(4, res.attributes.len());
    }

    #[test]
    fn remove_compliance_module() {
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

        let info = message_info(&Addr::unchecked("admin"), &[]);
        let add_msg = ExecuteMsg::AddComplianceModule {
            token_address: Addr::unchecked("token"),
            module_address: Addr::unchecked("module"),
            module_name: "Test Module".to_string(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), add_msg).unwrap();

        // Now remove the module
        let remove_msg = ExecuteMsg::RemoveComplianceModule {
            token_address: Addr::unchecked("token"),
            module_address: Addr::unchecked("module"),
        };
        let res = execute(deps.as_mut(), mock_env(), info, remove_msg).unwrap();
        assert_eq!(3, res.attributes.len());
    }

    #[test]
    fn update_compliance_module() {
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

        let info = message_info(&Addr::unchecked("admin"), &[]);
        let add_msg = ExecuteMsg::AddComplianceModule {
            token_address: Addr::unchecked("token"),
            module_address: Addr::unchecked("module"),
            module_name: "Test Module".to_string(),
        };
        execute(deps.as_mut(), mock_env(), info.clone(), add_msg).unwrap();

        // Now update the module
        let update_msg = ExecuteMsg::UpdateComplianceModule {
            token_address: Addr::unchecked("token"),
            module_address: Addr::unchecked("module"),
            active: false,
        };
        let res = execute(deps.as_mut(), mock_env(), info, update_msg).unwrap();
        assert_eq!(4, res.attributes.len());
    }

    #[test]
    fn check_compliance() {
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

        let info = message_info(&Addr::unchecked("admin"), &[]);
        let add_msg = ExecuteMsg::AddComplianceModule {
            token_address: Addr::unchecked("token"),
            module_address: Addr::unchecked("module"),
            module_name: "Test Module".to_string(),
        };
        execute(deps.as_mut(), mock_env(), info, add_msg).unwrap();

        // Mock the module query
        deps.querier.update_wasm(|query| match query {
            cosmwasm_std::WasmQuery::Smart { msg, .. } => {
                let parsed: utils::QueryMsg = from_json(msg).unwrap();
                match parsed {
                    QueryMsg::CheckTokenCompliance {
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
        let msg = QueryMsg::CheckTokenCompliance {
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
