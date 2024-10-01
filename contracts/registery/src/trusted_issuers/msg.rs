use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};

#[cw_serde]
pub struct InstantiateMsg {
    pub owner_roles_address: Addr,
}

#[cw_serde]
pub enum ExecuteMsg {
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
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(IsTrustedIssuerResponse)]
    IsTrustedIssuer { issuer: Addr },
    #[returns(GetIssuerClaimTopicsResponse)]
    GetIssuerClaimTopics { issuer: Addr },
}

#[cw_serde]
pub struct IsTrustedIssuerResponse(bool);

#[cw_serde]
pub struct GetIssuerClaimTopicsResponse(Vec<Uint128>);

#[cw_serde]
pub struct TrustedIssuer {
    pub claim_topics: Vec<Uint128>,
}
