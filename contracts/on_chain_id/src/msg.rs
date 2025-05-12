use crate::state::{Claim, Identity, Key};
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};

#[cw_serde]
pub struct InstantiateMsg {
    pub owner: String,
    pub trusted_issuer_addr: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    AddIdentity {
        country: String,
    },
    RemoveIdentity {
        identity_owner: String,
    },
    UpdateCountry {
        new_country: String,
        identity_owner: String,
    },
    AddKey {
        key_owner: String,
        key_type: String,
        identity_owner: String,
    },
    RevokeKey {
        key_owner: String,
        key_type: String,
        identity_owner: String,
    },
    AddClaim {
        claim: Claim,
        identity_owner: String,
    },
    RemoveClaim {
        claim_topic: Uint128,
        identity_owner: String,
    },
}

#[cw_serde]
pub struct MigrateMsg {}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Key)]
    GetKey {
        key_owner: String,
        key_type: String,
        identity_owner: String,
    },

    #[returns(Vec<Claim>)]
    GetValidatedClaimsForUser { identity_owner: String },

    #[returns(bool)]
    VerifyClaim {
        claim_id: Uint128,
        identity_owner: String,
    },

    #[returns(Addr)]
    GetOwner {},

    #[returns(Identity)]
    GetIdentity { identity_owner: String },

    #[returns(Vec<Key>)]
    GetAllKeysForIdentity { identity_owner: String },

    #[returns(Vec<Claim>)]
    GetAllClaimsForIdentity { identity_owner: String },

    #[returns(String)]
    GetCountryForIdentity { identity_owner: String },
}
