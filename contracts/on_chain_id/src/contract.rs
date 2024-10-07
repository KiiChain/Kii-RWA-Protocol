#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, Deps, DepsMut, Env, MessageInfo, Response, StdResult, to_json_binary, Binary, Addr, StdError,
};

use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::key_management::{execute_add_key, execute_remove_key};
use crate::claim_management::{execute_add_claim, execute_remove_claim};
use crate::state::{Key, KeyType, Claim, ClaimTopic, KEYS, OWNER, CLAIMS};

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
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    
    let owner = deps.api.addr_validate(&msg.owner)?;

    // Create and save the management key for the owner
    let key = Key {
        key_type: KeyType::ManagementKey,
        owner: owner.clone(),
    };
    KEYS.save(deps.storage, &owner, &vec![key])?;

    // Save the owner
    OWNER.save(deps.storage, &owner)?;

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
        ExecuteMsg::AddKey { key_owner, key_type } => execute_add_key(deps, info, key_owner, key_type),
        ExecuteMsg::RevokeKey { key_owner, key_type } => execute_remove_key(deps, info, key_owner, key_type),
        ExecuteMsg::AddClaim { claim, issuer_signature } => execute_add_claim(deps, info, claim, issuer_signature),
        ExecuteMsg::RemoveClaim { claim_id } => execute_remove_claim(deps, info, claim_id),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetKey { key_owner, key_type } => to_json_binary(&query_key(deps, key_owner, key_type)?),
        QueryMsg::GetClaim { claim_id } => to_json_binary(&query_claim(deps, claim_id)?),
        QueryMsg::GetClaimIdsByTopic { topic } => to_json_binary(&query_claim_ids_by_topic(deps, topic)?),
        QueryMsg::GetClaimsByIssuer { issuer } => to_json_binary(&query_claims_by_issuer(deps, issuer)?),
        QueryMsg::VerifyClaim { claim_id, trusted_issuers_registry } => 
            to_json_binary(&verify_claim(deps, claim_id, trusted_issuers_registry)?),
        QueryMsg::GetOwner {} => to_json_binary(&query_owner(deps)?),
    }
}

fn query_key(deps: Deps, key_owner: String, key_type: String) -> StdResult<Key> {
    let key_owner = deps.api.addr_validate(&key_owner)?;
    let key_type = KeyType::from_str(&key_type).map_err(|_| StdError::generic_err("Invalid key type"))?;
    
    let keys = KEYS.load(deps.storage, &key_owner)?;
    keys.iter()
        .find(|key| key.key_type == key_type)
        .cloned()
        .ok_or_else(|| StdError::not_found("Key not found"))
}

fn query_claim(deps: Deps, claim_id: String) -> StdResult<Claim> {
    let owner = OWNER.load(deps.storage)?;
    let claims = CLAIMS.load(deps.storage, &owner)?;
    claims.iter()
        .find(|claim| claim.id == Some(claim_id.clone()))
        .cloned()
        .ok_or_else(|| StdError::not_found("Claim not found"))
}

fn query_claim_ids_by_topic(deps: Deps, topic: String) -> StdResult<Vec<String>> {
    let topic = ClaimTopic::from_str(&topic).map_err(|_| StdError::parse_err("ClaimTopic", "Invalid topic"))?;
    let owner = OWNER.load(deps.storage)?;
    let claims = CLAIMS.load(deps.storage, &owner)?;
    let claim_ids: Vec<String> = claims
        .iter()
        .filter_map(|claim| {
            if claim.topic == topic {
                claim.id.clone()
            } else {
                None
            }
        })
        .collect();
    Ok(claim_ids)
}

fn query_claims_by_issuer(deps: Deps, issuer: String) -> StdResult<Vec<Claim>> {
    let issuer_addr = deps.api.addr_validate(&issuer)?;
    let owner = OWNER.load(deps.storage)?;
    let claims = CLAIMS.load(deps.storage, &owner)?;
    let filtered_claims: Vec<Claim> = claims
        .into_iter()
        .filter(|claim| claim.issuer == issuer_addr)
        .collect();
    Ok(filtered_claims)
}

fn verify_claim(deps: Deps, claim_id: String, trusted_issuers_registry: String) -> StdResult<bool> {
    let claim = query_claim(deps, claim_id)?;
    
    // Here you would typically check if the claim issuer is in the trusted issuers registry
    // For this example, we'll just check if the issuer matches the provided registry
    // In a real implementation, you'd want to query an actual registry contract
    
    Ok(claim.issuer == deps.api.addr_validate(&trusted_issuers_registry)?)
}

fn query_owner(deps: Deps) -> StdResult<Addr> {
    OWNER.load(deps.storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{Addr, Binary};
    use cw_multi_test::{App, ContractWrapper, Executor};

    fn instantiate_contract(app: &mut App, owner: &str) -> Addr {
        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let owner_addr = app.api().addr_make(owner);

        app.instantiate_contract(
            code_id,
            owner_addr.clone(),
            &InstantiateMsg {
                owner: owner_addr.to_string(),
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
        let owner = "owner";
        
        let contract_addr = instantiate_contract(&mut app, owner);

        // Test query_owner
        let res: Addr = app
            .wrap()
            .query_wasm_smart(contract_addr, &QueryMsg::GetOwner {})
            .unwrap();
        assert_eq!(res, app.api().addr_make(owner));
    }

    #[test]
    fn add_and_remove_key() {
        let mut app = App::default();
        let owner = "owner";
        let contract_addr = instantiate_contract(&mut app, owner);

        let key_owner = "new_key_owner";
        
        // Test adding a key
        let msg = ExecuteMsg::AddKey {
            key_owner: key_owner.to_string(),
            key_type: "ManagementKey".to_string(),
        };
        app.execute_contract(Addr::unchecked(owner), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Test querying the added key
        let res: Key = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetKey {
                    key_owner: key_owner.to_string(),
                    key_type: "ManagementKey".to_string(),
                },
            )
            .unwrap();
        assert_eq!(res.owner, Addr::unchecked(key_owner));
        assert_eq!(res.key_type, KeyType::ManagementKey);

        // Test removing the key
        let msg = ExecuteMsg::RevokeKey {
            key_owner: key_owner.to_string(),
            key_type: "ManagementKey".to_string(),
        };
        app.execute_contract(Addr::unchecked(owner), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Verify the key is removed
        let res: Result<Key, _> = app.wrap().query_wasm_smart(
            contract_addr,
            &QueryMsg::GetKey {
                key_owner: key_owner.to_string(),
                key_type: "ManagementKey".to_string(),
            },
        );
        assert!(res.is_err());
    }

    #[test]
    fn add_and_remove_claim() {
        let mut app = App::default();
        let owner = "owner";
        let contract_addr = instantiate_contract(&mut app, owner);

        // Add a claim signer key first
        let msg = ExecuteMsg::AddKey {
            key_owner: "owner".to_string(),
            key_type: "ClaimSignerKey".to_string(),
        };
        app.execute_contract(Addr::unchecked(owner), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Test adding a claim
        let claim = Claim {
            id: None,
            topic: ClaimTopic::BiometricTopic,
            issuer: app.api().addr_make("owner"),
            signature: Binary::from(vec![1, 2, 3]),
            data: Binary::from(vec![4, 5, 6]),
            uri: "https://example.com".to_string(),
        };
        let msg = ExecuteMsg::AddClaim {
            claim: claim.clone(),
            issuer_signature: Binary::from(vec![7, 8, 9]),
        };
        let res = app.execute_contract(Addr::unchecked(owner), contract_addr.clone(), &msg, &[])
            .unwrap();
        let claim_id = res.events
            .iter()
            .find(|e| e.ty == "wasm")
            .and_then(|e| e.attributes.iter().find(|attr| attr.key == "claim_id"))
            .map(|attr| attr.value.clone())
            .unwrap();

        // Test querying the added claim
        let res: Claim = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetClaim { claim_id: claim_id.clone() },
            )
            .unwrap();
        assert_eq!(res.topic, ClaimTopic::BiometricTopic);

        // Test removing the claim
        let msg = ExecuteMsg::RemoveClaim { claim_id: claim_id.clone() };
        app.execute_contract(Addr::unchecked(owner), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Verify the claim is removed
        let res: Result<Claim, _> = app
            .wrap()
            .query_wasm_smart(
                contract_addr,
                &QueryMsg::GetClaim { claim_id },
            );
        assert!(res.is_err());
    }
}