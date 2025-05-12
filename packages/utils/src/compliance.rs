use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(CheckTokenComplianceResponse)]
    CheckTokenCompliance {
        token_address: Addr,
        from: Option<Addr>,
        to: Option<Addr>,
        amount: Option<Uint128>,
    },
}

#[cw_serde]
pub struct CheckTokenComplianceResponse(bool);
