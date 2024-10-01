use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};

#[cw_serde]
pub struct InstantiateMsg {
    pub owner_roles_address: Addr,
}

#[cw_serde]
pub enum ExecuteMsg {
    AddClaimTopic { topic: Uint128 },
    RemoveClaimTopic { topic: Uint128 },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(IsClaimTopicValidResponse)]
    IsClaimTopicValid { topic: Uint128 },
}

#[cw_serde]
pub struct IsClaimTopicValidResponse(bool);
