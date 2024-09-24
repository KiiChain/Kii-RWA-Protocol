use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};

#[cw_serde]
pub struct InstantiateMsg {
    pub owner: Addr,
    pub token: Addr,
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

impl ToString for AgentRole {
    fn to_string(&self) -> String {
        match self {
            AgentRole::SupplyModifiers => "supplyModifiers",
            AgentRole::Freezers => "freezers",
            AgentRole::TransferManager => "transferManager",
            AgentRole::RecoveryAgents => "recoveryAgents",
            AgentRole::ComplianceAgent => "complianceAgent",
            AgentRole::WhiteListManages => "whiteListManages",
            AgentRole::AgentAdmin => "agentAdmin",
        }
        .into()
    }
}
