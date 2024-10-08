use crate::identity::storage::state::{AGENTS, OWNER};
use cosmwasm_std::{Addr, Deps, StdResult};

pub fn is_authorized(deps: Deps, sender: &Addr, owner: &Addr) -> StdResult<bool> {
    let contract_owner = OWNER.load(deps.storage)?;
    if sender == contract_owner {
        return Ok(true);
    }

    let agents = AGENTS.may_load(deps.storage, owner.clone())?;
    match agents {
        Some(agent_list) => Ok(agent_list.contains(sender)),
        None => Ok(false),
    }
}
