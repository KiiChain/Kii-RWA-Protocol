use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint128};
use utils::owner_roles::OwnerRole;

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
