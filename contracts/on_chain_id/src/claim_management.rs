use cosmwasm_std::{DepsMut, MessageInfo, Response, Binary, Deps, Addr};
use crate::error::ContractError;
use crate::state::{Claim, ClaimTopic, KeyType, CLAIMS, KEYS, OWNER};
use crate::utils::check_key_authorization;
use sha2::{Sha256, Digest};

pub fn execute_add_claim(
    deps: DepsMut,
    info: MessageInfo,
    mut claim: Claim,
    issuer_signature: Binary,
) -> Result<Response, ContractError> {
    // Check if the sender is authorized to add claims (must have a MANAGEMENT_KEY)
    check_key_authorization(&deps, &info.sender, KeyType::ManagementKey)?;

    // Verify the issuer's signature (must be signed by a CLAIM_SIGNER_KEY)
    //verify_claim_signature(&deps, &claim, &issuer_signature)?;
    
    // Generate and set the claim ID
    generate_claim_id(&mut claim);
    
    // Get the owner of the identity
    let owner = OWNER.load(deps.storage)?;
    
    // Load existing claims or create a new vector if none exist
    let mut claims = CLAIMS.may_load(deps.storage, &owner)?.unwrap_or_default();
    
    // Check if the claim already exists
    if claims.iter().any(|c| c.id == claim.id) {
        return Err(ContractError::ClaimAlreadyExists {});
    }

    // Add the new claim
    claims.push(claim.clone());

    // Save the updated claims
    CLAIMS.save(deps.storage, &owner, &claims)?;

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
    check_key_authorization(&deps, &info.sender, KeyType::ManagementKey)?;

    // Get the owner of the identity
    let owner = OWNER.load(deps.storage)?;
    
    // Load existing claims
    let mut claims = CLAIMS.load(deps.storage, &owner)?;

    // Find and remove the claim
    if let Some(index) = claims.iter().position(|c| c.id == Some(claim_id.clone())) {
        claims.remove(index);
        // Save the updated claims
        CLAIMS.save(deps.storage, &owner, &claims)?;
    } else {
        return Err(ContractError::ClaimNotFound {});
    }

    Ok(Response::new()
        .add_attribute("action", "remove_claim")
        .add_attribute("claim_id", claim_id))
}

// fn verify_claim_signature(deps: &DepsMut, claim: &Claim, signature: &Binary) -> Result<(), ContractError> {
//     let issuer_keys = KEYS.load(deps.storage, &claim.issuer)?;
    
//     // Check if the issuer has a CLAIM_SIGNER_KEY
//     let claim_signer_key = issuer_keys.iter().find(|key| key.key_type == KeyType::ClaimSignerKey)
//         .ok_or(ContractError::Unauthorized {})?;

//     // Serialize the claim data
//     let claim_data = serde_json::to_vec(claim).map_err(|_| ContractError::SerializationError {})?;

//     // Hash the claim data
//     let message_hash = Sha256::digest(&claim_data);

//     // Verify the signature using the CLAIM_SIGNER_KEY
//     let public_key = claim_signer_key.owner.as_bytes();
//     let signature = signature.as_slice();

//     // Use cosmwasm_std::secp256k1_verify for signature verification
//     let valid = deps.api.secp256k1_verify(message_hash.as_slice(), signature, public_key)
//         .map_err(|_| ContractError::InvalidIssuerSignature {})?;

//     if !valid {
//         return Err(ContractError::InvalidIssuerSignature {});
//     }

//     Ok(())
// }

// pub fn verify_claim(
//     deps: Deps,
//     identity: Addr,
//     claim_topic: ClaimTopic,
// ) -> Result<bool, ContractError> {
//     // Load claims for the given identity
//     let claims = CLAIMS.load(deps.storage, &identity)?;
    
//     // Check if any claim matches the given topic
//     Ok(claims.iter().any(|claim| claim.topic == claim_topic))
// }

// Helper function to generate a unique claim ID and set it in the claim
fn generate_claim_id(claim: &mut Claim) {
    let mut hasher = Sha256::new();
    hasher.update(claim.topic.to_string().as_bytes());
    hasher.update(&claim.issuer.as_bytes());
    hasher.update(&claim.signature);
    hasher.update(&claim.data);
    hasher.update(&claim.uri.to_string().as_bytes());
    let claim_id = hex::encode(hasher.finalize());
    claim.id = Some(claim_id);
}
