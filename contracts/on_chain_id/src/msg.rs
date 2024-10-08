use crate::state::{Claim, Key};
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Binary, Uint128};

#[cw_serde]
pub struct InstantiateMsg {
    pub owner: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    AddKey {
        key_owner: String,
        key_type: String,
    },
    RevokeKey {
        key_owner: String,
        key_type: String,
    },
    AddClaim {
        claim: Claim,
        public_key: Binary,
        user_addr: Addr,
    },
    RemoveClaim {
        claim_topic: Uint128,
        user_addr: Addr,
    },
}

#[cw_serde]
pub struct MigrateMsg {}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Key)]
    GetKey { key_owner: String, key_type: String },

    #[returns(Vec<Claim>)]
    GetValidatedClaimsForUser { user_addr: Addr },

    #[returns(bool)]
    VerifyClaim { claim_id: Uint128, user_addr: Addr },

    #[returns(String)]
    GetOwner {},
}
