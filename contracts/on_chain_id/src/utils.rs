use crate::error::ContractError;
use crate::state::{Claim, KeyType, KEYS, OWNER};
use cosmwasm_std::{Addr, Binary, DepsMut};
use sha2::{Digest, Sha256};

pub fn check_key_authorization(
    deps: &DepsMut,
    sender: &Addr,
    required_key: KeyType,
) -> Result<(), ContractError> {
    // Load the owner of the identity
    let owner = OWNER
        .load(deps.storage)
        .map_err(|e| ContractError::LoadError {
            entity: "owner".to_string(),
            reason: e.to_string(),
        })?;

    // Load the Vec<Key> for the owner address
    let keys = KEYS
        .load(deps.storage, &owner)
        .map_err(|e| ContractError::LoadError {
            entity: "keys".to_string(),
            reason: e.to_string(),
        })?;

    // Check if the sender is the owner and has the required key type

    if keys
        .iter()
        .any(|key| key.key_type == required_key && key.owner == *sender)
    {
        Ok(())
    } else {
        Err(ContractError::Unauthorized {
            reason: format!("Sender lacks required key type: {:?}", required_key),
        })
    }
}

pub fn generate_claim_id(claim: &mut Claim) {
    let mut hasher = Sha256::new();

    hasher.update(claim.topic.to_string().as_bytes());
    hasher.update(claim.issuer.as_bytes());
    hasher.update(&claim.data);
    hasher.update(claim.uri.as_bytes());
    // let id = hex::encode(hasher.finalize());
    // claim.id = Some(id);
}

pub fn verify_claim_signature(
    deps: &DepsMut,
    claim: &Claim,
    public_key: Binary,
) -> Result<(), ContractError> {
    // Hash the claim data (excluding signature)
    let message_hash = hash_claim_without_signature(claim);

    // Retrieve the signature from the claim
    let signature = claim.signature.as_slice();

    // Use cosmwasm_std::secp256k1_verify for signature verification
    let valid = deps
        .api
        .secp256k1_verify(message_hash.as_slice(), signature, public_key.as_slice())
        .map_err(|e| ContractError::InvalidIssuerSignature {
            reason: e.to_string(),
        })?;

    if !valid {
        return Err(ContractError::InvalidIssuerSignature {
            reason: "Signature verification failed".to_string(),
        });
    }

    Ok(())
}

pub fn hash_claim_without_signature(claim: &Claim) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(claim.topic.to_string().as_bytes());
    hasher.update(claim.issuer.as_bytes());
    hasher.update(&claim.data);
    hasher.update(claim.uri.as_bytes());
    hasher.finalize().into()
}
