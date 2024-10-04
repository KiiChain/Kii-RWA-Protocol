use cosmwasm_schema::{cw_serde, QueryResponses};
use crate::types::{Identity, Key, Claim};


#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
   
}
