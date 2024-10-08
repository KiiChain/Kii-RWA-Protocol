use crate::identity::state::OWNER;
use cosmwasm_std::{Addr, Deps, StdResult};

pub fn is_authorized(deps: Deps, sender: &Addr, contract_to_add: &Addr) -> StdResult<bool> {
    let contract_owner = OWNER.load(deps.storage)?;
    if sender == contract_owner || sender == contract_to_add {
        return Ok(true);
    }
    Ok(false)
}
