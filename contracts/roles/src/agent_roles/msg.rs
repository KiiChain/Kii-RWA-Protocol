use std::fmt;

use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};

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

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(IsAgentResponse)]
    IsAgent { role: AgentRole, agent: Addr },
}

#[cw_serde]
pub struct IsAgentResponse {
    pub is_agent: bool,
    pub role: AgentRole,
}

#[cw_serde]
pub enum AgentRole {
    SupplyModifiers,
    Freezers,
    TransferManager,
    RecoveryAgents,
    ComplianceAgent,
    WhiteListManages,
    AgentAdmin,
}

impl fmt::Display for AgentRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentRole::SupplyModifiers => write!(f, "supplyModifiers"),
            AgentRole::Freezers => write!(f, "freezers"),
            AgentRole::TransferManager => write!(f, "transferManager"),
            AgentRole::RecoveryAgents => write!(f, "recoveryAgents"),
            AgentRole::ComplianceAgent => write!(f, "complianceAgent"),
            AgentRole::WhiteListManages => write!(f, "whiteListManages"),
            AgentRole::AgentAdmin => write!(f, "agentAdmin"),
        }
    }
}
