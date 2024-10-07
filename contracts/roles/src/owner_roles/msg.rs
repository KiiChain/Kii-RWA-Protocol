use std::fmt;

use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};

#[cw_serde]
pub struct InstantiateMsg {
    pub owner: Addr,
}

#[cw_serde]
pub enum ExecuteMsg {
    AddOwnerRole {
        role: OwnerRole,
        owner: Addr,
    },
    RemoveOwnerRole {
        role: OwnerRole,
        owner: Addr,
    },
    SetComplianceRegistry {
        compliance_registry: Addr,
    },
    SetClaimTopicsRegistry {
        claim_topic_registry: Addr,
    },
    SetTrustedIssuersRegistry {
        trusted_issuer_registry: Addr,
    },
    AddTrustedIssuer {
        issuer: Addr,
        claim_topics: Vec<Uint128>,
    },
    RemoveTrustedIssuer {
        issuer: Addr,
    },
    UpdateIssuerClaimTopics {
        issuer: Addr,
        claim_topics: Vec<Uint128>,
    },
    AddClaimTopic {
        claim_topic: Uint128,
    },
    RemoveClaimTopic {
        claim_topic: Uint128,
    },
}

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
