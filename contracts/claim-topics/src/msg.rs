use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};

#[cw_serde]
pub struct InstantiateMsg {
    pub owner_roles_address: Addr,
}

#[cw_serde]
pub enum ExecuteMsg {
    AddClaimTopicForToken {
        token_addr: Addr,
        topic: Uint128,
    },
    RemoveClaimTopicForToken {
        token_addr: Addr,
        topic: Uint128,
    },
    UpdateClaimTopicForToken {
        token_addr: Addr,
        topic: Uint128,
        active: bool,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Vec<Uint128>)]
    GetClaimsForToken { token_addr: Addr },
}

#[cw_serde]
pub struct Claim {
    pub topic: Uint128,
    pub active: bool,
}
