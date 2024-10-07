use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{to_json_binary, Addr, CosmosMsg, Deps, StdResult, WasmMsg};

use crate::agent_roles::msg::ExecuteMsg;

/// CwTemplateContract is a wrapper around Addr that provides a lot of helpers
/// for working with this.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct CwTemplateContract(pub Addr);

impl CwTemplateContract {
    pub fn addr(&self) -> Addr {
        self.0.clone()
    }

    pub fn call<T: Into<ExecuteMsg>>(&self, msg: T) -> StdResult<CosmosMsg> {
        let msg = to_json_binary(&msg.into())?;
        Ok(WasmMsg::Execute {
            contract_addr: self.addr().into(),
            msg,
            funds: vec![],
        }
        .into())
    }
}

pub fn is_transfer_allowed(_deps: Deps) -> StdResult<bool> {
    // Check if transfers are globally enabled
    // This could be a flag in your contract's state
    Ok(true) // Placeholder implementation
}

pub fn can_transfer(_deps: Deps, _address: &str) -> StdResult<bool> {
    // Check if the address is allowed to send transfers
    // This could involve checking the address against a whitelist,
    // checking for a specific role, or other criteria
    Ok(true) // Placeholder implementation
}

pub fn can_receive(_deps: Deps, _address: &str) -> StdResult<bool> {
    // Check if the address is allowed to receive transfers
    // Similar to can_transfer, but for recipients
    Ok(true) // Placeholder implementation
}
