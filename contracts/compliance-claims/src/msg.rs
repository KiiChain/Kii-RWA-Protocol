use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary, Uint128};

#[cw_serde]
pub struct InstantiateMsg {
    pub identity_address: Addr,
    pub owner_roles_address: Addr,
    pub claim_topics_address: Addr,
}

#[cw_serde]
pub struct Claim {
    pub topic: Uint128,
    pub issuer: Addr,
    pub data: Binary,
    pub uri: String,
}
