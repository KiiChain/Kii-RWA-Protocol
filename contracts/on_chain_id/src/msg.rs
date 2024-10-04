use cosmwasm_schema::{cw_serde, QueryResponses, Binary};
use crate::types::{Identity, Key, Claim};


#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    AddKey {
        key_type: String,
        key: String,
    },
    RevokeKey {
        key: String,
    },
    AddClaim {
        claim: Claim,
        issuer_signature: Binary,
    },
    RemoveClaim {
        claim_id: String,
    },
    ChangeOwner {
        new_owner: String,
    },
    Execute {
        to: String,
        msg: Binary,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    GetKey {
        key_type: String,
    },
    GetKeysByType {
        key_type: String,
    },
    GetClaim {
        claim_id: String,
    },
    GetClaimIdsByTopic {
        topic: String,
    },
    GetClaimsByIssuer {
        issuer: String,
    },
    VerifyClaim {
        claim_id: String,
        trusted_issuers_registry: String,
    },
    GetOwner {},
}
