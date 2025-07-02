#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
    Uint128,
};
use cw2::set_contract_version;
use std::str::FromStr;

use crate::claim_management::{execute_add_claim, execute_remove_claim};
use crate::error::ContractError;
use crate::identity_management::{
    execute_add_identity, execute_remove_identity, execute_update_country,
};
use crate::key_management::{execute_add_key, execute_remove_key};
use crate::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};
use crate::state::{Claim, Identity, Key, KeyType, IDENTITIES, OWNER, TRUSTED_ISSUERS_ADDR};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:onchainid";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION).map_err(|e| {
        ContractError::Std(StdError::generic_err(format!("Failed to set contract version: {e}")))
    })?;

    let owner = deps
        .api
        .addr_validate(&msg.owner)
        .map_err(|e| ContractError::InvalidAddress {
            reason: format!("Invalid owner address: {e}"),
        })?;

    // Save the owner
    OWNER
        .save(deps.storage, &owner)
        .map_err(|e| ContractError::SaveError {
            entity: "owner".to_string(),
            reason: e.to_string(),
        })?;

    let trusted_issuer_addr = deps
        .api
        .addr_validate(&msg.trusted_issuer_addr)
        .map_err(|e| ContractError::InvalidAddress {
            reason: format!("Invalid trusted issuer address: {e}"),
        })?;

    // Save the trusted issuers address
    TRUSTED_ISSUERS_ADDR
        .save(deps.storage, &trusted_issuer_addr)
        .map_err(|e| ContractError::SaveError {
            entity: "trusted_issuer".to_string(),
            reason: e.to_string(),
        })?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::AddIdentity { country } => execute_add_identity(deps, info, country),
        ExecuteMsg::RemoveIdentity { identity_owner } => {
            execute_remove_identity(deps, info, identity_owner)
        }
        ExecuteMsg::UpdateCountry {
            new_country,
            identity_owner,
        } => execute_update_country(deps, info, new_country, identity_owner),
        ExecuteMsg::AddKey {
            key_owner,
            key_type,
            identity_owner,
        } => execute_add_key(deps, info, key_owner, key_type, identity_owner),
        ExecuteMsg::RevokeKey {
            key_owner,
            key_type,
            identity_owner,
        } => execute_remove_key(deps, info, key_owner, key_type, identity_owner),
        ExecuteMsg::AddClaim {
            claim,
            identity_owner,
        } => execute_add_claim(deps, info, claim, identity_owner),
        ExecuteMsg::RemoveClaim {
            claim_topic,
            identity_owner,
        } => execute_remove_claim(deps, info, claim_topic, identity_owner),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetKey {
            key_owner,
            key_type,
            identity_owner,
        } => to_json_binary(&query_key(deps, key_owner, key_type, identity_owner)?),
        QueryMsg::GetValidatedClaimsForUser { identity_owner } => {
            to_json_binary(&get_validated_claims_for_user(deps, identity_owner)?)
        }
        QueryMsg::VerifyClaim {
            claim_id,
            identity_owner,
        } => to_json_binary(&verify_claim(deps, claim_id, identity_owner)?),
        QueryMsg::GetOwner {} => to_json_binary(&query_owner(deps)?),
        QueryMsg::GetIdentity { identity_owner } => {
            to_json_binary(&query_identity(deps, identity_owner)?)
        }
        QueryMsg::GetAllKeysForIdentity { identity_owner } => {
            to_json_binary(&query_all_keys_for_identity(deps, identity_owner)?)
        }
        QueryMsg::GetAllClaimsForIdentity { identity_owner } => {
            to_json_binary(&query_all_claims_for_identity(deps, identity_owner)?)
        }
        QueryMsg::GetCountryForIdentity { identity_owner } => {
            to_json_binary(&query_country_for_identity(deps, identity_owner)?)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    let current_version = cw2::get_contract_version(deps.storage)?;

    if current_version.contract != CONTRACT_NAME {
        return Err(ContractError::InvalidContract {
            expected: CONTRACT_NAME.to_string(),
            actual: current_version.contract,
        });
    }

    let new_version = CONTRACT_VERSION.parse::<semver::Version>().unwrap();
    let stored_version = current_version.version.parse::<semver::Version>().unwrap();

    if stored_version >= new_version {
        return Err(ContractError::AlreadyMigrated {
            current_version: stored_version.to_string(),
            new_version: new_version.to_string(),
        });
    }

    // Perform any necessary state migrations here

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::new()
        .add_attribute("action", "migrate")
        .add_attribute("from_version", current_version.version)
        .add_attribute("to_version", CONTRACT_VERSION))
}

fn query_key(
    deps: Deps,
    key_owner: String,
    key_type: String,
    identity_owner: String,
) -> StdResult<Key> {
    let key_owner = deps.api.addr_validate(&key_owner)?;
    let identity_owner = deps.api.addr_validate(&identity_owner)?;
    let key_type =
        KeyType::from_str(&key_type).map_err(|e| StdError::generic_err(e.to_string()))?;

    let identity = IDENTITIES.load(deps.storage, identity_owner.clone())?;

    identity
        .keys
        .iter()
        .find(|key| key.key_type == key_type && key.owner == key_owner)
        .cloned()
        .ok_or_else(|| {
            StdError::not_found(format!(
                "Key not found for owner {key_owner} and type {key_type:?} in identity {identity_owner}"
            ))
        })
}

fn get_validated_claims_for_user(deps: Deps, identity_owner: String) -> StdResult<Vec<Claim>> {
    let identity_owner = deps.api.addr_validate(&identity_owner)?;
    let identity = IDENTITIES.load(deps.storage, identity_owner)?;
    Ok(identity.claims)
}

fn verify_claim(deps: Deps, claim_id: Uint128, identity_owner: String) -> StdResult<bool> {
    let identity_owner = deps.api.addr_validate(&identity_owner)?;
    let identity = IDENTITIES.load(deps.storage, identity_owner)?;
    Ok(identity.claims.iter().any(|claim| claim.topic == claim_id))
}

fn query_owner(deps: Deps) -> StdResult<Addr> {
    OWNER.load(deps.storage)
}

fn query_identity(deps: Deps, identity_owner: String) -> StdResult<Identity> {
    let identity_owner = deps.api.addr_validate(&identity_owner)?;
    IDENTITIES.load(deps.storage, identity_owner)
}

fn query_all_keys_for_identity(deps: Deps, identity_owner: String) -> StdResult<Vec<Key>> {
    let identity_owner = deps.api.addr_validate(&identity_owner)?;
    let identity = IDENTITIES.load(deps.storage, identity_owner)?;
    Ok(identity.keys)
}

fn query_all_claims_for_identity(deps: Deps, identity_owner: String) -> StdResult<Vec<Claim>> {
    let identity_owner = deps.api.addr_validate(&identity_owner)?;
    let identity = IDENTITIES.load(deps.storage, identity_owner)?;
    Ok(identity.claims)
}

fn query_country_for_identity(deps: Deps, identity_owner: String) -> StdResult<String> {
    let identity_owner = deps.api.addr_validate(&identity_owner)?;
    let identity = IDENTITIES.load(deps.storage, identity_owner)?;
    Ok(identity.country)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{
        from_json,
        testing::{message_info, mock_dependencies, mock_env, MockApi},
        Addr, Binary, ContractResult, SystemResult, WasmQuery,
    };
    use cw_multi_test::{App, ContractWrapper, Executor};

    fn instantiate_contract(app: &mut App, owner: Addr, trusted_issuer_addr: Addr) -> Addr {
        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        app.instantiate_contract(
            code_id,
            owner.clone(),
            &InstantiateMsg {
                owner: owner.to_string(),
                trusted_issuer_addr: trusted_issuer_addr.to_string(),
            },
            &[],
            "On-chain ID Contract",
            Some(owner.to_string()),
        )
        .unwrap()
    }

    #[test]
    fn proper_initialization() {
        let mut app = App::default();
        let owner = app.api().addr_make("owner");
        let trusted_issuers_addr = app.api().addr_make("trusted_issers_addr");

        let contract_addr =
            instantiate_contract(&mut app, owner.clone(), trusted_issuers_addr.clone());

        // Test query_owner
        let res: Addr = app
            .wrap()
            .query_wasm_smart(contract_addr, &QueryMsg::GetOwner {})
            .unwrap();
        assert_eq!(res, owner);
    }

    #[test]
    fn add_and_remove_key() {
        let mut app = App::default();
        let owner = app.api().addr_make("owner");
        let trusted_issuers_addr = app.api().addr_make("trusted_issers_addr");
        let contract_addr =
            instantiate_contract(&mut app, owner.clone(), trusted_issuers_addr.clone());

        // Add identity first
        let msg = ExecuteMsg::AddIdentity {
            country: "US".to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        let key_owner = app.api().addr_make("new_key_owner");

        // Test adding a key
        let msg = ExecuteMsg::AddKey {
            key_owner: key_owner.to_string(),
            key_type: "ExecutionKey".to_string(),
            identity_owner: owner.to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Test querying the added key
        let res: Key = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetKey {
                    key_owner: key_owner.to_string(),
                    key_type: "ExecutionKey".to_string(),
                    identity_owner: owner.to_string(),
                },
            )
            .unwrap();
        assert_eq!(res.owner, key_owner);
        assert_eq!(res.key_type, KeyType::ExecutionKey);

        // Test removing the key
        let msg = ExecuteMsg::RevokeKey {
            key_owner: key_owner.to_string(),
            key_type: "ExecutionKey".to_string(),
            identity_owner: owner.to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Verify the key is removed
        let res: Result<Key, _> = app.wrap().query_wasm_smart(
            contract_addr,
            &QueryMsg::GetKey {
                key_owner: key_owner.to_string(),
                key_type: "ExecutionKey".to_string(),
                identity_owner: owner.to_string(),
            },
        );
        assert!(res.is_err());
    }

    #[test]
    fn add_and_remove_claim() {
        let mut deps = mock_dependencies();
        // mock_querier(&mut deps);
        deps.querier.update_wasm(|query| match query {
            WasmQuery::Smart {
                contract_addr: _,
                msg,
            } => {
                let parsed: serde_json::Value = from_json(msg).unwrap();
                if parsed.get("is_trusted_issuer").is_some() {
                    SystemResult::Ok(ContractResult::Ok(to_json_binary(&true).unwrap()))
                } else {
                    panic!("Unexpected query: {:?}", msg)
                }
            }
            _ => panic!("Unexpected query type"),
        });

        let env = mock_env();
        let owner_addr = MockApi::default().addr_make("owner");
        let identity_owner = MockApi::default().addr_make("identity_owner");

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: MockApi::default().addr_make("owner").into_string(),
            trusted_issuer_addr: MockApi::default()
                .addr_make("trusted_issuer_addr")
                .into_string(),
        };
        let info = message_info(&owner_addr, &[]);
        let _ = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        // Add identity
        let msg = ExecuteMsg::AddIdentity {
            country: "US".to_string(),
        };
        let info = message_info(&identity_owner, &[]);
        let _ = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // Add a claim signer key
        let msg = ExecuteMsg::AddKey {
            key_owner: owner_addr.to_string(),
            key_type: "ClaimSignerKey".to_string(),
            identity_owner: identity_owner.to_string(),
        };
        let info = message_info(&identity_owner, &[]);
        let _ = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // Create and add a claim
        let claim = Claim {
            topic: Uint128::one(),
            issuer: owner_addr.clone(),
            data: Binary::from(vec![4, 5, 6]),
            uri: "https://example.com".to_string(),
        };
        let msg = ExecuteMsg::AddClaim {
            claim: claim.clone(),
            identity_owner: identity_owner.to_string(),
        };
        let info = message_info(&owner_addr, &[]);
        let _ = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // Query to verify the claim was added
        let msg = QueryMsg::VerifyClaim {
            claim_id: Uint128::one(),
            identity_owner: identity_owner.to_string(),
        };
        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let claim_added: bool = from_json(res).unwrap();
        assert!(claim_added);

        // Remove the claim
        let msg = ExecuteMsg::RemoveClaim {
            claim_topic: Uint128::one(),
            identity_owner: identity_owner.to_string(),
        };
        let info = message_info(&owner_addr, &[]);
        let _ = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // Query to verify the claim was removed
        let msg = QueryMsg::VerifyClaim {
            claim_id: Uint128::one(),
            identity_owner: identity_owner.to_string(),
        };

        let res = query(deps.as_ref(), mock_env(), msg).unwrap();
        let res: bool = from_json(res).unwrap();
        assert!(!res);
    }

    #[test]
    fn unauthorized_add_claim() {
        let mut deps = mock_dependencies();
        // mock_querier(&mut deps);
        deps.querier.update_wasm(|query| match query {
            WasmQuery::Smart {
                contract_addr: _,
                msg,
            } => {
                let parsed: serde_json::Value = from_json(msg).unwrap();
                if parsed.get("is_trusted_issuer").is_some() {
                    SystemResult::Ok(ContractResult::Ok(to_json_binary(&false).unwrap()))
                } else {
                    panic!("Unexpected query: {:?}", msg)
                }
            }
            _ => panic!("Unexpected query type"),
        });

        let env = mock_env();
        let owner_addr = MockApi::default().addr_make("owner");
        let identity_owner = MockApi::default().addr_make("identity_owner");

        // Instantiate the contract
        let msg = InstantiateMsg {
            owner: MockApi::default().addr_make("owner").into_string(),
            trusted_issuer_addr: MockApi::default()
                .addr_make("trusted_issuer_addr")
                .into_string(),
        };
        let info = message_info(&owner_addr, &[]);
        let _ = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        // Add identity
        let msg = ExecuteMsg::AddIdentity {
            country: "US".to_string(),
        };
        let info = message_info(&identity_owner, &[]);
        let _ = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // Add a claim signer key
        let msg = ExecuteMsg::AddKey {
            key_owner: owner_addr.to_string(),
            key_type: "ClaimSignerKey".to_string(),
            identity_owner: identity_owner.to_string(),
        };
        let info = message_info(&identity_owner, &[]);
        let _ = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // Create and add a claim
        let claim = Claim {
            topic: Uint128::one(),
            issuer: owner_addr.clone(),
            data: Binary::from(vec![4, 5, 6]),
            uri: "https://example.com".to_string(),
        };
        let msg = ExecuteMsg::AddClaim {
            claim: claim.clone(),
            identity_owner: identity_owner.to_string(),
        };
        let info = message_info(&owner_addr, &[]);
        let res = execute(deps.as_mut(), env.clone(), info, msg);
        assert!(res.is_err());
    }

    #[test]
    fn add_and_remove_identity() {
        let mut app = App::default();
        let owner = app.api().addr_make("owner");
        let trusted_issuers_addr = app.api().addr_make("trusted_issers_addr");

        let contract_addr =
            instantiate_contract(&mut app, owner.clone(), trusted_issuers_addr.clone());

        // Add identity
        let msg = ExecuteMsg::AddIdentity {
            country: "US".to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Verify identity exists (indirectly by adding a key)
        let msg = ExecuteMsg::AddKey {
            key_owner: owner.to_string(),
            key_type: "ExecutionKey".to_string(),
            identity_owner: owner.to_string(),
        };
        let res = app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[]);
        assert!(res.is_ok());

        // Remove identity
        let msg = ExecuteMsg::RemoveIdentity {
            identity_owner: owner.to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Verify identity doesn't exist (indirectly by trying to add a key)
        let msg = ExecuteMsg::AddKey {
            key_owner: owner.to_string(),
            key_type: "ExecutionKey".to_string(),
            identity_owner: owner.to_string(),
        };
        let res = app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[]);
        assert!(res.is_err());
    }

    #[test]
    fn update_country() {
        let mut app = App::default();
        let owner = app.api().addr_make("owner");
        let trusted_issuers_addr = app.api().addr_make("trusted_issers_addr");
        let contract_addr =
            instantiate_contract(&mut app, owner.clone(), trusted_issuers_addr.clone());

        // Add identity
        let msg = ExecuteMsg::AddIdentity {
            country: "US".to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Update country
        let msg = ExecuteMsg::UpdateCountry {
            new_country: "CA".to_string(),
            identity_owner: owner.to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Verify country update (indirectly by checking if the identity still exists)
        let msg = ExecuteMsg::AddKey {
            key_owner: owner.to_string(),
            key_type: "ExecutionKey".to_string(),
            identity_owner: owner.to_string(),
        };
        let res = app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[]);
        assert!(res.is_ok());
    }

    #[test]
    fn test_query_key() {
        let mut app = App::default();
        let owner = app.api().addr_make("owner");
        let trusted_issuers_addr = app.api().addr_make("trusted_issers_addr");

        let contract_addr =
            instantiate_contract(&mut app, owner.clone(), trusted_issuers_addr.clone());

        // Add identity
        let msg = ExecuteMsg::AddIdentity {
            country: "US".to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Add a key for an external wallet
        let external_wallet = app.api().addr_make("external_wallet");
        let msg = ExecuteMsg::AddKey {
            key_owner: external_wallet.to_string(),
            key_type: "ExecutionKey".to_string(),
            identity_owner: owner.to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Query the key
        let res: Key = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetKey {
                    key_owner: external_wallet.to_string(),
                    key_type: "ExecutionKey".to_string(),
                    identity_owner: owner.to_string(),
                },
            )
            .unwrap();

        assert_eq!(res.owner, external_wallet);
        assert_eq!(res.key_type, KeyType::ExecutionKey);

        // Try to query the key with incorrect identity_owner (should fail)
        let incorrect_query: StdResult<Key> = app.wrap().query_wasm_smart(
            contract_addr.clone(),
            &QueryMsg::GetKey {
                key_owner: external_wallet.to_string(),
                key_type: "ExecutionKey".to_string(),
                identity_owner: external_wallet.to_string(), // Incorrect identity owner
            },
        );

        assert!(incorrect_query.is_err());
    }

    #[test]
    fn test_query_identity() {
        let mut app = App::default();
        let owner = app.api().addr_make("owner");
        let trusted_issuers_addr = app.api().addr_make("trusted_issers_addr");
        let contract_addr =
            instantiate_contract(&mut app, owner.clone(), trusted_issuers_addr.clone());

        // Add identity
        let msg = ExecuteMsg::AddIdentity {
            country: "US".to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Query the identity
        let res: Identity = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetIdentity {
                    identity_owner: owner.to_string(),
                },
            )
            .unwrap();

        assert_eq!(res.owner, owner);
        assert_eq!(res.country, "US");
        assert!(res.keys.is_empty());
        assert!(res.claims.is_empty());
    }

    #[test]
    fn test_query_all_keys_for_identity() {
        let mut app = App::default();
        let owner = app.api().addr_make("owner");
        let trusted_issuers_addr = app.api().addr_make("trusted_issers_addr");
        let contract_addr =
            instantiate_contract(&mut app, owner.clone(), trusted_issuers_addr.clone());

        // Add identity
        let msg = ExecuteMsg::AddIdentity {
            country: "US".to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Add two keys
        let external_wallet1 = app.api().addr_make("external_wallet1");
        let external_wallet2 = app.api().addr_make("external_wallet2");

        for wallet in [external_wallet1.clone(), external_wallet2.clone()] {
            let msg = ExecuteMsg::AddKey {
                key_owner: wallet.to_string(),
                key_type: "ExecutionKey".to_string(),
                identity_owner: owner.to_string(),
            };
            app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
                .unwrap();
        }

        // Query all keys
        let res: Vec<Key> = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetAllKeysForIdentity {
                    identity_owner: owner.to_string(),
                },
            )
            .unwrap();

        assert_eq!(res.len(), 2);
        assert_eq!(res[0].owner, external_wallet1);
        assert_eq!(res[0].key_type, KeyType::ExecutionKey);
        assert_eq!(res[1].owner, external_wallet2);
        assert_eq!(res[1].key_type, KeyType::ExecutionKey);
    }
}
