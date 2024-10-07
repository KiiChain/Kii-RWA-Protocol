use cosmwasm_std::{DepsMut, MessageInfo, Response, Binary};
use crate::error::ContractError;
use crate::state::{Claim, KeyType, CLAIMS, OWNER};
use crate::utils::{check_key_authorization, verify_claim_signature, generate_claim_id};

pub fn execute_add_claim(
    deps: DepsMut,
    info: MessageInfo,
    mut claim: Claim,
    public_key: Binary,
) -> Result<Response, ContractError> {
    // Check if the sender is authorized to add claims (must have a MANAGEMENT_KEY)
    check_key_authorization(&deps, &info.sender, KeyType::ManagementKey)
        .map_err(|e| ContractError::Unauthorized { reason: format!("Sender lacks MANAGEMENT_KEY: {}", e) })?;

    // Verify the issuer's signature (must be signed by a CLAIM_SIGNER_KEY)
    verify_claim_signature(&deps, &claim, public_key)
        .map_err(|e| ContractError::InvalidSignature { reason: format!("Failed to verify claim signature: {}", e) })?;
    
    // Generate and set the claim ID
    generate_claim_id(&mut claim);
    
    // Get the owner of the identity
    let owner = OWNER.load(deps.storage)
        .map_err(|e| ContractError::LoadError { entity: "owner".to_string(), reason: e.to_string() })?;
    
    // Load existing claims or create a new vector if none exist
    let mut claims = CLAIMS.may_load(deps.storage, &owner)
        .map_err(|e| ContractError::LoadError { entity: "claims".to_string(), reason: e.to_string() })?
        .unwrap_or_default();
    // Check if the claim already exists
    if claims.iter().any(|c| c.id == claim.id) {
        return Err(ContractError::ClaimAlreadyExists { 
            claim_id: claim.id.clone().unwrap_or_default() 
        });
    }

    // Add the new claim
    claims.push(claim.clone());

    // Save the updated claims
    CLAIMS.save(deps.storage, &owner, &claims)
        .map_err(|e| ContractError::SaveError { entity: "claims".to_string(), reason: e.to_string() })?;

    Ok(Response::new()
        .add_attribute("action", "add_claim")
        .add_attribute("claim_id", claim.id.unwrap_or_default()))
}

pub fn execute_remove_claim(
    deps: DepsMut,
    info: MessageInfo,
    claim_id: String,
) -> Result<Response, ContractError> {
    // Check if the sender is authorized to remove claims (must have a MANAGEMENT_KEY)
    check_key_authorization(&deps, &info.sender, KeyType::ManagementKey)
        .map_err(|e| ContractError::Unauthorized { reason: format!("Sender lacks MANAGEMENT_KEY: {}", e) })?;

    // Get the owner of the identity
    let owner = OWNER.load(deps.storage)
        .map_err(|e| ContractError::LoadError { entity: "owner".to_string(), reason: e.to_string() })?;
    
    // Load existing claims
    let mut claims = CLAIMS.load(deps.storage, &owner)
        .map_err(|e| ContractError::LoadError { entity: "claims".to_string(), reason: e.to_string() })?;

    // Find and remove the claim
    if let Some(index) = claims.iter().position(|c| c.id == Some(claim_id.clone())) {
        claims.remove(index);
        // Save the updated claims
        CLAIMS.save(deps.storage, &owner, &claims)
            .map_err(|e| ContractError::SaveError { entity: "claims".to_string(), reason: e.to_string() })?;
    } else {
        return Err(ContractError::ClaimNotFound { claim_id });
    }

    Ok(Response::new()
        .add_attribute("action", "remove_claim")
        .add_attribute("claim_id", claim_id))
}

