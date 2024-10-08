#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;

use crate::identity::storage::error::ContractError;
use crate::identity::storage::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::identity::storage::state::{IDENTITIES, OWNER};
use crate::identity::storage::storage_management::{
    add_identity, remove_identity, update_country, update_identity,
};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:identity-storage";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    // Set the contract owner
    OWNER.save(deps.storage, &info.sender)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::AddIdentity {
            owner,
            identity_address,
            country,
        } => add_identity(deps, env, info, owner, identity_address, country),
        ExecuteMsg::RemoveIdentity { owner } => remove_identity(deps, env, info, owner),
        ExecuteMsg::UpdateIdentity {
            owner,
            new_identity_address,
        } => update_identity(deps, env, info, owner, new_identity_address),
        ExecuteMsg::UpdateCountry { owner, new_country } => {
            update_country(deps, env, info, owner, new_country)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetIdentity { owner } => to_json_binary(&query_identity(deps, owner)?),
        QueryMsg::GetCountry { owner } => to_json_binary(&query_country(deps, owner)?),
        QueryMsg::GetIdentitiesByCountry { country } => {
            to_json_binary(&query_identities_by_country(deps, country)?)
        }
        QueryMsg::GetOwner {} => to_json_binary(&query_owner(deps)?),
    }
}

fn query_identity(deps: Deps, owner: String) -> StdResult<Option<String>> {
    let owner_addr = deps.api.addr_validate(&owner)?;
    let identity = IDENTITIES.may_load(deps.storage, owner_addr)?;
    Ok(identity.map(|(addr, _)| addr.to_string()))
}

fn query_country(deps: Deps, owner: String) -> StdResult<Option<String>> {
    let owner_addr = deps.api.addr_validate(&owner)?;
    let identity = IDENTITIES.may_load(deps.storage, owner_addr)?;
    Ok(identity.map(|(_, country)| country))
}

fn query_identities_by_country(deps: Deps, country: String) -> StdResult<Vec<String>> {
    let identities: StdResult<Vec<_>> = IDENTITIES
        .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
        .filter(|r| match r {
            Ok((_, (_, c))) => c == &country,
            Err(_) => false,
        })
        .map(|r| r.map(|(owner, _)| owner.to_string()))
        .collect();
    identities
}

fn query_owner(deps: Deps) -> StdResult<String> {
    let owner = OWNER.load(deps.storage)?;
    Ok(owner.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::Addr;
    use cw_multi_test::{App, ContractWrapper, Executor};

    fn instantiate_contract(app: &mut App, owner: Addr) -> Addr {
        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        app.instantiate_contract(
            code_id,
            owner.clone(),
            &InstantiateMsg {},
            &[],
            "Identity Storage",
            None,
        )
        .unwrap()
    }

    #[test]
    fn proper_initialization() {
        let mut app = App::default();
        let owner = app.api().addr_make("owner");
        let contract_addr = instantiate_contract(&mut app, owner.clone());

        // Check if the owner is set correctly
        let res: String = app
            .wrap()
            .query_wasm_smart(contract_addr, &QueryMsg::GetOwner {})
            .unwrap();
        assert_eq!(owner.to_string(), res);
    }

    #[test]
    fn add_and_query_identity() {
        let mut app = App::default();
        let owner = app.api().addr_make("owner");
        let contract_addr = instantiate_contract(&mut app, owner.clone());

        let alice = app.api().addr_make("alice");
        let alice_identity = app.api().addr_make("alice_identity");

        // Add identity
        let msg = ExecuteMsg::AddIdentity {
            owner: alice.to_string(),
            identity_address: alice_identity.to_string(),
            country: "Wonderland".to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Query identity
        let res: Option<String> = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetIdentity {
                    owner: alice.to_string(),
                },
            )
            .unwrap();
        assert_eq!(Some(alice_identity.to_string()), res);

        // Query country
        let res: Option<String> = app
            .wrap()
            .query_wasm_smart(
                contract_addr,
                &QueryMsg::GetCountry {
                    owner: alice.to_string(),
                },
            )
            .unwrap();
        assert_eq!(Some("Wonderland".to_string()), res);
    }

    #[test]
    fn update_identity_and_country() {
        let mut app = App::default();
        let owner = app.api().addr_make("owner");
        let contract_addr = instantiate_contract(&mut app, owner.clone());

        let bob = app.api().addr_make("bob");
        let bob_identity = app.api().addr_make("bob_identity");
        let new_bob_identity = app.api().addr_make("new_bob_identity");

        // Add identity
        let msg = ExecuteMsg::AddIdentity {
            owner: bob.to_string(),
            identity_address: bob_identity.to_string(),
            country: "Neverland".to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Update identity
        let msg = ExecuteMsg::UpdateIdentity {
            owner: bob.to_string(),
            new_identity_address: new_bob_identity.to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Update country
        let msg = ExecuteMsg::UpdateCountry {
            owner: bob.to_string(),
            new_country: "Wonderland".to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Query updated identity
        let res: Option<String> = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetIdentity {
                    owner: bob.to_string(),
                },
            )
            .unwrap();
        assert_eq!(Some(new_bob_identity.to_string()), res);

        // Query updated country
        let res: Option<String> = app
            .wrap()
            .query_wasm_smart(
                contract_addr,
                &QueryMsg::GetCountry {
                    owner: bob.to_string(),
                },
            )
            .unwrap();
        assert_eq!(Some("Wonderland".to_string()), res);
    }

    #[test]
    fn remove_identity() {
        let mut app = App::default();
        let owner = app.api().addr_make("owner");
        let contract_addr = instantiate_contract(&mut app, owner.clone());

        let charlie = app.api().addr_make("charlie");
        let charlie_identity = app.api().addr_make("charlie_identity");

        // Add identity
        let msg = ExecuteMsg::AddIdentity {
            owner: charlie.to_string(),
            identity_address: charlie_identity.to_string(),
            country: "Dreamland".to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Remove identity
        let msg = ExecuteMsg::RemoveIdentity {
            owner: charlie.to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Query removed identity
        let res: Option<String> = app
            .wrap()
            .query_wasm_smart(
                contract_addr,
                &QueryMsg::GetIdentity {
                    owner: charlie.to_string(),
                },
            )
            .unwrap();
        assert_eq!(None, res);
    }

    #[test]
    fn query_identities_by_country() {
        let mut app = App::default();
        let owner = app.api().addr_make("owner");
        let contract_addr = instantiate_contract(&mut app, owner.clone());

        let alice = app.api().addr_make("alice");
        let bob = app.api().addr_make("bob");
        let charlie = app.api().addr_make("charlie");

        // Add identities
        let msg = ExecuteMsg::AddIdentity {
            owner: alice.to_string(),
            identity_address: app.api().addr_make("alice_identity").to_string(),
            country: "Wonderland".to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        let msg = ExecuteMsg::AddIdentity {
            owner: bob.to_string(),
            identity_address: app.api().addr_make("bob_identity").to_string(),
            country: "Wonderland".to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        let msg = ExecuteMsg::AddIdentity {
            owner: charlie.to_string(),
            identity_address: app.api().addr_make("charlie_identity").to_string(),
            country: "Neverland".to_string(),
        };
        app.execute_contract(owner.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Query identities by country
        let res: Vec<String> = app
            .wrap()
            .query_wasm_smart(
                contract_addr,
                &QueryMsg::GetIdentitiesByCountry {
                    country: "Wonderland".to_string(),
                },
            )
            .unwrap();
        assert_eq!(vec![alice.to_string(), bob.to_string()], res);
    }
}
