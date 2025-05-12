use std::fmt;

use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;

pub mod agent_roles {
    use super::*;

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
}

pub mod owner_roles {
    use super::*;

    #[cw_serde]
    #[derive(QueryResponses)]
    pub enum QueryMsg {
        #[returns(IsOwnerResponse)]
        IsOwner { role: OwnerRole, owner: Addr },
    }

    #[cw_serde]
    pub struct IsOwnerResponse {
        pub is_owner: bool,
        pub role: OwnerRole,
    }

    #[cw_serde]
    pub enum OwnerRole {
        OwnerAdmin,
        RegistryAddressSetter,
        ComplianceSetter,
        ComplianceManager,
        ClaimRegistryManager,
        IssuersRegistryManager,
        TokenInfoManager,
    }

    impl fmt::Display for OwnerRole {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                OwnerRole::OwnerAdmin => write!(f, "owner_admin"),
                OwnerRole::RegistryAddressSetter => write!(f, "registry_address_setter"),
                OwnerRole::ComplianceSetter => write!(f, "compliance_setter"),
                OwnerRole::ComplianceManager => write!(f, "compliance_manager"),
                OwnerRole::ClaimRegistryManager => write!(f, "claim_registry_manager"),
                OwnerRole::IssuersRegistryManager => write!(f, "issuers_registry_manager"),
                OwnerRole::TokenInfoManager => write!(f, "token_info_manager"),
            }
        }
    }
}
