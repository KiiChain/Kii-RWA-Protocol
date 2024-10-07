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
use crate::utils::hash_claim_without_signature;

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
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)
        .map_err(|e| ContractError::Std(StdError::generic_err(format!("Failed to set contract version: {}", e))))?;
    
    let owner = deps.api.addr_validate(&msg.owner)
        .map_err(|e| ContractError::InvalidAddress { reason: format!("Invalid owner address: {}", e) })?;

    // Create and save the management key for the owner
    let key = Key {
        key_type: KeyType::ManagementKey,
        owner: owner.clone(),
    };
    KEYS.save(deps.storage, &owner, &vec![key])
        .map_err(|e| ContractError::SaveError { entity: "keys".to_string(), reason: e.to_string() })?;

    // Save the owner
    OWNER.save(deps.storage, &owner)
        .map_err(|e| ContractError::SaveError { entity: "owner".to_string(), reason: e.to_string() })?;

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
    let key_owner = deps.api.addr_validate(&key_owner)
        .map_err(|e| StdError::generic_err(format!("Invalid key owner address: {}", e)))?;
    let key_type = KeyType::from_str(&key_type)
        .map_err(|_| StdError::generic_err(format!("Invalid key type: {}", key_type)))?;
    let owner = OWNER.load(deps.storage)
        .map_err(|e| StdError::generic_err(format!("Failed to load owner: {}", e)))?;
    let keys = KEYS.load(deps.storage, &owner)
        .map_err(|e| StdError::generic_err(format!("Failed to load keys for owner {}: {}", owner, e)))?;
    keys.iter()
        .find(|key| key.key_type == key_type && key.owner == key_owner)
        .cloned()
        .ok_or_else(|| StdError::not_found(format!("Key not found for owner {} and type {:?}", key_owner, key_type)))
}

fn query_claim(deps: Deps, claim_id: String) -> StdResult<Claim> {
    let owner = OWNER.load(deps.storage)
        .map_err(|e| StdError::generic_err(format!("Failed to load owner: {}", e)))?;
    let claims = CLAIMS.load(deps.storage, &owner)
        .map_err(|e| StdError::generic_err(format!("Failed to load claims for owner {}: {}", owner, e)))?;
    claims.iter()
        .find(|claim| claim.id == Some(claim_id.clone()))
        .cloned()
        .ok_or_else(|| StdError::not_found(format!("Claim not found with id: {}", claim_id)))
}

fn query_claim_ids_by_topic(deps: Deps, topic: String) -> StdResult<Vec<String>> {
    let topic = ClaimTopic::from_str(&topic)
        .map_err(|_| StdError::parse_err("ClaimTopic", format!("Invalid topic: {}", topic)))?;
    let owner = OWNER.load(deps.storage)
        .map_err(|e| StdError::generic_err(format!("Failed to load owner: {}", e)))?;
    let claims = CLAIMS.load(deps.storage, &owner)
        .map_err(|e| StdError::generic_err(format!("Failed to load claims for owner {}: {}", owner, e)))?;
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
    let issuer_addr = deps.api.addr_validate(&issuer)
        .map_err(|e| StdError::generic_err(format!("Invalid issuer address: {}", e)))?;
    let owner = OWNER.load(deps.storage)
        .map_err(|e| StdError::generic_err(format!("Failed to load owner: {}", e)))?;
    let claims = CLAIMS.load(deps.storage, &owner)
        .map_err(|e| StdError::generic_err(format!("Failed to load claims for owner {}: {}", owner, e)))?;
    let filtered_claims: Vec<Claim> = claims
        .into_iter()
        .filter(|claim| claim.issuer == issuer_addr)
        .collect();
    Ok(filtered_claims)
}

fn verify_claim(deps: Deps, claim_id: String, trusted_issuers_registry: String) -> StdResult<bool> {
    let claim = query_claim(deps, claim_id.clone())
        .map_err(|e| StdError::generic_err(format!("Failed to query claim {}: {}", claim_id, e)))?;
    
    // Here you would typically check if the claim issuer is in the trusted issuers registry
    // For this example, we'll just check if the issuer matches the provided registry
    // In a real implementation, you'd want to query an actual registry contract
    
    let registry_addr = deps.api.addr_validate(&trusted_issuers_registry)
        .map_err(|e| StdError::generic_err(format!("Invalid trusted issuers registry address: {}", e)))?;
    
    Ok(claim.issuer == registry_addr)
}

fn query_owner(deps: Deps) -> StdResult<Addr> {
    OWNER.load(deps.storage)
        .map_err(|e| StdError::generic_err(format!("Failed to load owner: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{Addr, Binary};
    use cw_multi_test::{App, ContractWrapper, Executor};
    use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
    use crate::utils::hash_claim_without_signature;

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
        let owner_addr = app.api().addr_make(owner);

        let key_owner = app.api().addr_make("new_key_owner");
        
        // Test adding a key
        let msg = ExecuteMsg::AddKey {
            key_owner: key_owner.to_string(),
            key_type: "ExecutionKey".to_string(),
        };
        app.execute_contract(owner_addr.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();
        // Test querying the added key
        let res: Key = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetKey {
                    key_owner: key_owner.to_string().clone(),
                    key_type: "ExecutionKey".to_string(),
                },
            )
            .unwrap();
        assert_eq!(res.owner, Addr::unchecked(key_owner.clone()));
        assert_eq!(res.key_type, KeyType::ExecutionKey);

        // Test removing the key
        let msg = ExecuteMsg::RevokeKey {
            key_owner: key_owner.to_string(),
            key_type: "ExecutionKey".to_string(),
        };
        app.execute_contract(owner_addr, contract_addr.clone(), &msg, &[])
            .unwrap();

        // Verify the key is removed
        let res: Result<Key, _> = app.wrap().query_wasm_smart(
            contract_addr,
            &QueryMsg::GetKey {
                key_owner: key_owner.to_string(),
                key_type: "ExecutionKey".to_string(),
            },
        );
        assert!(res.is_err());
    }

    #[test]
    fn add_and_remove_claim() {
        let mut app = App::default();
        let owner = "owner";
        let contract_addr = instantiate_contract(&mut app, owner);
        let owner_addr = app.api().addr_make(owner);

        // Generate a keypair for signing
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        // Add a claim signer key first
        let msg = ExecuteMsg::AddKey {
            key_owner: owner_addr.to_string(),
            key_type: "ClaimSignerKey".to_string(),
        };
        app.execute_contract(owner_addr.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Create a claim
        let claim = Claim {
            id: None,
            topic: ClaimTopic::BiometricTopic,
            issuer: owner_addr.clone(),
            signature: Binary::from(vec![]), // This will be filled later
            data: Binary::from(vec![4, 5, 6]),
            uri: "https://example.com".to_string(),
        };

        // Hash the claim data (excluding signature)
        let message_hash = hash_claim_without_signature(&claim);

        // Sign the hash
        let message = Message::from_slice(&message_hash).unwrap();
        let signature = secp.sign_ecdsa(&message, &secret_key);

        // Create the final claim with the signature
        let signed_claim = Claim {
            signature: Binary::from(signature.serialize_compact()),
            ..claim
        };

        // Test adding the claim
        let msg = ExecuteMsg::AddClaim {
            claim: signed_claim.clone(),
            issuer_signature: Binary::from(public_key.serialize()),
        };
        let res = app.execute_contract(owner_addr.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();
        
        // Correctly retrieve the claim_id from the attributes
        let claim_id = res.events
            .iter()
            .find(|e| e.ty == "wasm")
            .and_then(|e| e.attributes.iter().find(|attr| attr.key == "claim_id"))
            .map(|attr| attr.value.clone())
            .expect("Claim ID not found in response");

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
        app.execute_contract(owner_addr.clone(), contract_addr.clone(), &msg, &[])
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

    #[test]
    fn add_different_key_types() {
        let mut app = App::default();
        let owner = "owner";
        let contract_addr = instantiate_contract(&mut app, owner);
        let owner_addr = app.api().addr_make(owner);

        let key_types = vec!["ExecutionKey", "ClaimSignerKey", "EncryptionKey"];

        // Add keys one at a time
        for key_type in &key_types {
            let msg = ExecuteMsg::AddKey {
                key_owner: owner_addr.to_string(),
                key_type: key_type.to_string(),
            };
            app.execute_contract(owner_addr.clone(), contract_addr.clone(), &msg, &[])
                .unwrap();

            // Query and verify the added key
            let res: Key = app
                .wrap()
                .query_wasm_smart(
                    contract_addr.clone(),
                    &QueryMsg::GetKey {
                        key_owner: owner_addr.to_string(),
                        key_type: key_type.to_string(),
                    },
                )
                .unwrap();
            assert_eq!(res.owner, owner_addr);
            assert_eq!(res.key_type, KeyType::from_str(key_type).unwrap());
        }

        // Attempt to add a duplicate key
        let msg = ExecuteMsg::AddKey {
            key_owner: owner_addr.to_string(),
            key_type: "ManagementKey".to_string(),
        };
        let err = app.execute_contract(owner_addr.clone(), contract_addr.clone(), &msg, &[])
            .unwrap_err();
        assert!(err.to_string().contains("Error"));
    }


    #[test]
    fn add_and_query_claims() {
        let mut app = App::default();
        let owner = "owner";
        let contract_addr = instantiate_contract(&mut app, owner);
        let owner_addr = app.api().addr_make(owner);

        // Generate a keypair for signing
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        // Add a claim signer key
        let msg = ExecuteMsg::AddKey {
            key_owner: owner_addr.to_string(),
            key_type: "ClaimSignerKey".to_string(),
        };
        app.execute_contract(owner_addr.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        let claim_topics = vec![ClaimTopic::BiometricTopic, ClaimTopic::ResidenceTopic, ClaimTopic::RegistryTopic];
        let mut claim_ids = Vec::new();

        // Add claims one at a time
        for topic in &claim_topics {
            let claim = Claim {
                id: None,
                topic: topic.clone(),
                issuer: owner_addr.clone(),
                signature: Binary::from(vec![]),
                data: Binary::from(vec![1, 2, 3]),
                uri: "https://example.com".to_string(),
            };

            let message_hash = hash_claim_without_signature(&claim);
            let message = Message::from_slice(&message_hash).unwrap();
            let signature = secp.sign_ecdsa(&message, &secret_key);

            let signed_claim = Claim {
                signature: Binary::from(signature.serialize_compact()),
                ..claim
            };

            let msg = ExecuteMsg::AddClaim {
                claim: signed_claim,
                issuer_signature: Binary::from(public_key.serialize()),
            };
            let res = app.execute_contract(owner_addr.clone(), contract_addr.clone(), &msg, &[])
                .unwrap();
            
            let claim_id = res.events
                .iter()
                .find(|e| e.ty == "wasm")
                .and_then(|e| e.attributes.iter().find(|attr| attr.key == "claim_id"))
                .map(|attr| attr.value.clone())
                .expect("Claim ID not found in response");
            
            claim_ids.push(claim_id);
        }

        // Query and verify each claim
        for (i, topic) in claim_topics.iter().enumerate() {
            let res: Claim = app
                .wrap()
                .query_wasm_smart(
                    contract_addr.clone(),
                    &QueryMsg::GetClaim { claim_id: claim_ids[i].clone() },
                )
                .unwrap();
            assert_eq!(res.topic, *topic);
        }

        // Test GetClaimIdsByTopic
        for topic in &claim_topics {
            let res: Vec<String> = app
                .wrap()
                .query_wasm_smart(
                    contract_addr.clone(),
                    &QueryMsg::GetClaimIdsByTopic { topic: topic.to_string() },
                )
                .unwrap();
            assert_eq!(res.len(), 1);
        }

        // Test GetClaimsByIssuer
        let res: Vec<Claim> = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetClaimsByIssuer { issuer: owner_addr.to_string() },
            )
            .unwrap();
        assert_eq!(res.len(), claim_topics.len());
        // Attempt to add a duplicate claim
        let duplicate_claim = Claim {
            id: Some(claim_ids[0].clone()),
            topic: claim_topics[0].clone(),
            issuer: owner_addr.clone(),
            signature: Binary::from(vec![]),
            data: Binary::from(vec![1, 2, 3]),
            uri: "https://example.com".to_string(),
        };
        let message_hash = hash_claim_without_signature(&duplicate_claim);
        let message = Message::from_slice(&message_hash).unwrap();
        let signature = secp.sign_ecdsa(&message, &secret_key);
        let signed_duplicate_claim = Claim {
            signature: Binary::from(signature.serialize_compact()),
            ..duplicate_claim
        };
        let msg = ExecuteMsg::AddClaim {
            claim: signed_duplicate_claim,
            issuer_signature: Binary::from(public_key.serialize()),
        };
        let err = app.execute_contract(owner_addr.clone(), contract_addr.clone(), &msg, &[])
            .unwrap_err();
        assert!(err.to_string().contains("Error"));
    }

    #[test]
    fn add_key_to_different_wallet() {
        let mut app = App::default();
        let owner = "owner";
        let contract_addr = instantiate_contract(&mut app, owner);
        let owner_addr = app.api().addr_make(owner);

        // Create a different wallet address
        let different_wallet = "different_wallet";
        let different_wallet_addr = app.api().addr_make(different_wallet);

        // Add a key for the different wallet
        let msg = ExecuteMsg::AddKey {
            key_owner: different_wallet_addr.to_string(),
            key_type: "ExecutionKey".to_string(),
        };
        app.execute_contract(owner_addr.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Query the added key
        let res: Key = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetKey {
                    key_owner: different_wallet_addr.to_string(),
                    key_type: "ExecutionKey".to_string(),
                },
            )
            .unwrap();

        // Verify the key details
        assert_eq!(res.owner, different_wallet_addr);
        assert_eq!(res.key_type, KeyType::ExecutionKey);

        // Attempt to add another key with the different wallet (should fail)
        let msg = ExecuteMsg::AddKey {
            key_owner: owner_addr.to_string(),
            key_type: "ManagementKey".to_string(),
        };
        let err = app.execute_contract(different_wallet_addr.clone(), contract_addr.clone(), &msg, &[])
            .unwrap_err();
        assert!(err.to_string().contains("Error"));

        // The owner should still be able to add keys
        let msg = ExecuteMsg::AddKey {
            key_owner: owner_addr.to_string(),
            key_type: "EncryptionKey".to_string(),
        };
        app.execute_contract(owner_addr.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // Verify both keys exist
        let res: Key = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetKey {
                    key_owner: different_wallet_addr.to_string(),
                    key_type: "ExecutionKey".to_string(),
                },
            )
            .unwrap();
        assert_eq!(res.owner, different_wallet_addr);
        assert_eq!(res.key_type, KeyType::ExecutionKey);

        let res: Key = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetKey {
                    key_owner: owner_addr.to_string(),
                    key_type: "EncryptionKey".to_string(),
                },
            )
            .unwrap();
        assert_eq!(res.owner, owner_addr);
        assert_eq!(res.key_type, KeyType::EncryptionKey);
    }

}