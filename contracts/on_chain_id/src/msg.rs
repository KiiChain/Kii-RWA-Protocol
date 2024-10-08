use crate::state::{Claim, Key};
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

#[cw_serde]
pub struct InstantiateMsg {
    pub owner: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    AddKey { key_owner: String, key_type: String },
    RevokeKey { key_owner: String, key_type: String },
    AddClaim { claim: Claim, public_key: Binary },
    RemoveClaim { claim_id: String },
}

#[cw_serde]
pub struct MigrateMsg {}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Key)]
    GetKey { key_owner: String, key_type: String },
    #[returns(Claim)]
    GetClaim { claim_id: String },
    #[returns(Vec<String>)]
    GetClaimIdsByTopic { topic: String },
    #[returns(Vec<Claim>)]
    GetClaimsByIssuer { issuer: String },
    #[returns(bool)]
    VerifyClaim {
        claim_id: String,
        trusted_issuers_registry: String,
    },
    #[returns(String)]
    GetOwner {},
}
