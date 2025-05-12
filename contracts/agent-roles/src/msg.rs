use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint128};
use utils::agent_roles::AgentRole;

#[cw_serde]
pub struct InstantiateMsg {
    pub owner: Addr,
}

#[cw_serde]
pub enum ExecuteMsg {
    AddAgentRole {
        role: AgentRole,
        agent: Addr,
    },
    RemoveAgentRole {
        role: AgentRole,
        agent: Addr,
    },

    SetTokenRegistry {
        token_registry: Addr,
    },
    Burn {
        amount: Uint128,
    },
    BurnFrom {
        owner: String,
        amount: Uint128,
    },
    Mint {
        recipient: String,
        amount: Uint128,
    },

    Transfer {
        recipient: String,
        amount: Uint128,
    },
    TransferFrom {
        owner: String,
        recipient: String,
        amount: Uint128,
    },
}
