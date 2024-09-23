use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;

#[cw_serde]
pub struct InstantiateMsg {
    pub owner: Addr,
}

#[cw_serde]
pub enum ExecuteMsg {
    AddAgent { agent: Addr },
    RemoveAgent { agent: Addr },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(IsAgentResponse)]
    IsAgent { agent: Addr },
}

#[cw_serde]
pub struct IsAgentResponse {
    pub is_agent: bool,
}
