use crate::error::ContractError;
use crate::state::{KeyType, IDENTITIES};
use cosmwasm_std::{Addr, DepsMut};

pub fn check_key_authorization(
    deps: &DepsMut,
    sender: &Addr,
    required_key: KeyType,
    identity_owner: &Addr,
) -> Result<(), ContractError> {
    // Check if the identity exists
    if !check_identity_exists(deps, identity_owner) {
        return Err(ContractError::IdentityNotFound {
            owner: identity_owner.to_string(),
        });
    }

    // Load the identity for the sender
    let identity = IDENTITIES.load(deps.storage, identity_owner.clone())?;

    if sender == identity_owner {
        return Ok(());
    }

    // Check if the sender has the required key type
    if identity
        .keys
        .iter()
        .any(|key| key.key_type == required_key && key.owner == *sender)
    {
        Ok(())
    } else {
        Err(ContractError::Unauthorized {
            reason: format!("Sender lacks required key type: {required_key:?}"),
        })
    }
}

pub fn check_identity_exists(deps: &DepsMut, addr: &Addr) -> bool {
    IDENTITIES.has(deps.storage, addr.clone())
}
