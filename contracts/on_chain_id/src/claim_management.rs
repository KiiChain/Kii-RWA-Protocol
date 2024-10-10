use crate::error::ContractError;
use crate::state::{Claim, KeyType, CLAIMS, OWNER};
use crate::utils::{check_key_authorization, verify_claim_signature};
use cosmwasm_std::{Addr, Binary, DepsMut, MessageInfo, Response, Uint128};

pub fn execute_add_claim(
    deps: DepsMut,
    info: MessageInfo,
    claim: Claim,
    public_key: Binary,
    user_addr: Addr,
) -> Result<Response, ContractError> {
    // Check sender is authorized

    // Check if the sender is authorized to add claims (must have a CLAIM_SIGNER_KEY)
    check_key_authorization(&deps, &info.sender, KeyType::ClaimSignerKey).map_err(|e| {
        ContractError::Unauthorized {
            reason: format!("Sender lacks CLAIM_SIGNER_KEY: {}", e),
        }
    })?;

    // Verify the issuer's signature (must be signed by a CLAIM_SIGNER_KEY)
    verify_claim_signature(&deps, &claim, public_key).map_err(|e| {
        ContractError::InvalidSignature {
            reason: format!("Failed to verify claim signature: {}", e),
        }
    })?;

    // Generate and set the claim ID
    // generate_claim_id(&mut claim);

    // Load existing claims or create a new vector if none exist
    let mut claims = CLAIMS
        .may_load(deps.storage, &user_addr)
        .map_err(|e| ContractError::LoadError {
            entity: "claims".to_string(),
            reason: e.to_string(),
        })?
        .unwrap_or_default();
    // Check if the claim already exists
    if claims.iter().any(|c| c.topic == claim.topic) {
        return Err(ContractError::ClaimAlreadyExists {
            claim_topic: claim.topic,
        });
    }

    // Add the new claim
    claims.push(claim.clone());

    // Save the updated claims
    CLAIMS
        .save(deps.storage, &user_addr, &claims)
        .map_err(|e| ContractError::SaveError {
            entity: "claims".to_string(),
            reason: e.to_string(),
        })?;

    Ok(Response::new()
        .add_attribute("action", "add_claim")
        .add_attribute("claim_topic", claim.topic))
}

pub fn execute_remove_claim(
    deps: DepsMut,
    info: MessageInfo,
    claim_topic: Uint128,
    user_addr: Addr,
) -> Result<Response, ContractError> {
    // Check if the sender is authorized to remove claims (must have a CLAIM_SIGNER_KEY)
    check_key_authorization(&deps, &info.sender, KeyType::ClaimSignerKey).map_err(|e| {
        ContractError::Unauthorized {
            reason: format!("Sender lacks CLAIM_SIGNER_KEY: {}", e),
        }
    })?;

    // Get the owner of the identity
    let owner = OWNER
        .load(deps.storage)
        .map_err(|e| ContractError::LoadError {
            entity: "owner".to_string(),
            reason: e.to_string(),
        })?;

    // Load existing claims
    let mut claims =
        CLAIMS
            .load(deps.storage, &user_addr)
            .map_err(|e| ContractError::LoadError {
                entity: "claims".to_string(),
                reason: e.to_string(),
            })?;

    // Find the claim and check authorization
    if let Some(index) = claims.iter().position(|c| c.topic == claim_topic) {
        let claim = &claims[index];

        // Check if the sender is the issuer or the owner
        if info.sender != claim.issuer && info.sender != owner {
            return Err(ContractError::Unauthorized {
                reason: "Only the claim issuer or the identity owner can remove a claim"
                    .to_string(),
            });
        }

        // Remove the claim
        claims.remove(index);

        // Save the updated claims
        CLAIMS
            .save(deps.storage, &user_addr, &claims)
            .map_err(|e| ContractError::SaveError {
                entity: "claims".to_string(),
                reason: e.to_string(),
            })?;
    } else {
        return Err(ContractError::ClaimNotFound { claim_topic });
    }

    Ok(Response::new()
        .add_attribute("action", "remove_claim")
        .add_attribute("claim_topic", claim_topic))
}
