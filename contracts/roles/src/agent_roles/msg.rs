use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;

#[cw_serde]
pub struct InstantiateMsg {
    pub owner: Addr,
}

#[cw_serde]
pub enum ExecuteMsg {
    AddAgentRole { role: AgentRole, agent: Addr },
    RemoveAgentRole { role: AgentRole, agent: Addr },
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
