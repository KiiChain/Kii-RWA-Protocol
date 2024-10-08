use crate::identity::storage::state::OWNER;
use cosmwasm_std::{Addr, Deps, StdResult};

pub fn is_authorized(deps: Deps, sender: &Addr) -> StdResult<bool> {
    let contract_owner = OWNER.load(deps.storage)?;
    if sender == contract_owner {
        return Ok(true);
    }
    Ok(false)
}
