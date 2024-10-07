use cosmwasm_std::{Addr, DepsMut, Binary, Deps};
use crate::error::ContractError;
use crate::state::{KEYS, KeyType, OWNER, Claim, CLAIMS, ClaimTopic};
use sha2::{Sha256, Digest};

pub fn check_key_authorization(deps: &DepsMut, sender: &Addr, required_key: KeyType) -> Result<(), ContractError> {
    // Load the owner of the identity
    let owner = OWNER.load(deps.storage)
        .map_err(|e| ContractError::LoadError { 
            entity: "owner".to_string(), 
            reason: e.to_string() 
        })?;

    // Load the Vec<Key> for the owner address
    let keys = KEYS.load(deps.storage, &owner)
        .map_err(|e| ContractError::LoadError { 
            entity: "keys".to_string(), 
            reason: e.to_string() 
        })?;
    
    // Check if the sender is the owner and has the required key type
    if owner == *sender {
        if keys.iter().any(|key| key.key_type == required_key) {
            Ok(())
        } else {
            Err(ContractError::Unauthorized { 
                reason: format!("Sender lacks required key type: {:?}", required_key) 
            })
        }
    } else {
        Err(ContractError::Unauthorized { 
            reason: "Sender is not the owner of the identity".to_string() 
        })
    }
}

pub fn generate_claim_id(claim: &Claim) -> String {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(claim.topic.to_string().as_bytes());
    hasher.update(&claim.issuer.as_bytes());
    hasher.update(&claim.signature);
    hasher.update(&claim.data);
    hasher.update(&claim.uri.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn verify_claim_signature(deps: &DepsMut, claim: &Claim, signature: &Binary) -> Result<(), ContractError> {
    let issuer_keys = KEYS.load(deps.storage, &claim.issuer)
        .map_err(|e| ContractError::LoadError { entity: "issuer keys".to_string(), reason: e.to_string() })?;
    
    // Check if the issuer has a CLAIM_SIGNER_KEY
    let claim_signer_key = issuer_keys.iter().find(|key| key.key_type == KeyType::ClaimSignerKey)
        .ok_or(ContractError::Unauthorized { reason: "Issuer lacks CLAIM_SIGNER_KEY".to_string() })?;

    // Serialize the claim data
    let claim_data = serde_json::to_vec(claim)
        .map_err(|e| ContractError::SerializationError { reason: e.to_string() })?;

    // Hash the claim data
    let message_hash = Sha256::digest(&claim_data);

    // Verify the signature using the CLAIM_SIGNER_KEY
    let public_key = claim_signer_key.owner.as_bytes();
    let signature = signature.as_slice();

    // Use cosmwasm_std::secp256k1_verify for signature verification
    let valid = deps.api.secp256k1_verify(message_hash.as_slice(), signature, public_key)
        .map_err(|e| ContractError::InvalidIssuerSignature { reason: e.to_string() })?;

    if !valid {
        return Err(ContractError::InvalidIssuerSignature { 
            reason: "Signature verification failed".to_string() 
        });
    }

    Ok(())
}

pub fn verify_claim(
    deps: Deps,
    identity: Addr,
    claim_topic: ClaimTopic,
) -> Result<bool, ContractError> {
    // Load claims for the given identity
    let claims = CLAIMS.load(deps.storage, &identity)
        .map_err(|e| ContractError::LoadError { entity: "claims".to_string(), reason: e.to_string() })?;
    
    // Check if any claim matches the given topic
    Ok(claims.iter().any(|claim| claim.topic == claim_topic))
}