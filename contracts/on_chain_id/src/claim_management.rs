use crate::error::ContractError;
use crate::state::{Claim, KeyType, IDENTITIES, TRUSTED_ISSUERS_ADDR};
use crate::utils::{check_identity_exists, check_key_authorization};
use cosmwasm_std::{
    to_json_binary, Deps, DepsMut, MessageInfo, QueryRequest, Response, StdResult, Uint128,
    WasmQuery,
};
use serde_json::json;

pub fn execute_add_claim(
    deps: DepsMut,
    info: MessageInfo,
    claim: Claim,
    identity_owner: String,
) -> Result<Response, ContractError> {
    // Check if the identity exists
    let identity_owner_addr = deps.api.addr_validate(&identity_owner)?;

    if !check_identity_exists(&deps, &identity_owner_addr) {
        return Err(ContractError::IdentityNotFound {
            owner: identity_owner_addr.to_string(),
        });
    }

    //Check that the sender is an authorized issuer
    let is_trusted = query_is_trusted_issuer(deps.as_ref(), info.sender.to_string())?;

    if !is_trusted {
        return Err(ContractError::Unauthorized {
            reason: "Sender does not have permission to add claim".to_string(),
        });
    }

    // Check if the sender is authorized to add claims (must have a CLAIM_SIGNER_KEY)
    check_key_authorization(
        &deps,
        &info.sender,
        KeyType::ClaimSignerKey,
        &identity_owner_addr,
    )?;

    // Load the identity
    let mut identity = IDENTITIES.load(deps.storage, identity_owner_addr.clone())?;

    // Check if the claim already exists
    if identity.claims.iter().any(|c| c.topic == claim.topic) {
        return Err(ContractError::ClaimAlreadyExists {
            claim_topic: claim.topic,
        });
    }

    // Add the new claim
    identity.claims.push(claim.clone());

    // Save the updated identity
    IDENTITIES.save(deps.storage, identity_owner_addr.clone(), &identity)?;

    Ok(Response::new()
        .add_attribute("action", "add_claim")
        .add_attribute("identity_owner", identity_owner)
        .add_attribute("claim_topic", claim.topic.to_string()))
}

fn query_is_trusted_issuer(deps: Deps, issuer: String) -> StdResult<bool> {
    let trusted_issuer_addr = TRUSTED_ISSUERS_ADDR.load(deps.storage)?;
    let query_msg = json!({
        "is_trusted_issuer": {
            "issuer": issuer
        }
    });

    let query = QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: trusted_issuer_addr.to_string(),
        msg: to_json_binary(&query_msg)?,
    });

    let result: bool = deps.querier.query(&query)?;
    Ok(result)
}

pub fn execute_remove_claim(
    deps: DepsMut,
    info: MessageInfo,
    claim_topic: Uint128,
    identity_owner: String,
) -> Result<Response, ContractError> {
    let identity_owner_addr = deps.api.addr_validate(&identity_owner)?;

    // Check if the identity exists
    if !check_identity_exists(&deps, &identity_owner_addr) {
        return Err(ContractError::IdentityNotFound {
            owner: identity_owner_addr.to_string(),
        });
    }

    //Check that the sender is an authorized issuer
    let is_trusted = query_is_trusted_issuer(deps.as_ref(), info.sender.to_string())?;

    if !is_trusted {
        return Err(ContractError::Unauthorized {
            reason: "Sender does not have persmission to add claim".to_string(),
        });
    }

    // Check if the sender is authorized to remove claims (must have a CLAIM_SIGNER_KEY)
    check_key_authorization(
        &deps,
        &info.sender,
        KeyType::ClaimSignerKey,
        &identity_owner_addr,
    )?;

    // Load the identity
    let mut identity = IDENTITIES.load(deps.storage, identity_owner_addr.clone())?;

    // Find the claim and check authorization
    if let Some(index) = identity.claims.iter().position(|c| c.topic == claim_topic) {
        let claim = &identity.claims[index];

        // Check if the sender is the issuer or the owner
        if info.sender != claim.issuer && info.sender != identity.owner {
            return Err(ContractError::Unauthorized {
                reason: "Only the claim issuer or the identity owner can remove a claim"
                    .to_string(),
            });
        }

        // Remove the claim
        identity.claims.remove(index);

        // Save the updated identity
        IDENTITIES.save(deps.storage, identity_owner_addr.clone(), &identity)?;
    } else {
        return Err(ContractError::ClaimNotFound { claim_topic });
    }

    Ok(Response::new()
        .add_attribute("action", "remove_claim")
        .add_attribute("identity_owner", identity_owner)
        .add_attribute("claim_topic", claim_topic.to_string()))
}
