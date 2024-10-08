use cosmwasm_schema::{cw_serde, QueryResponses};

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    AddIdentity {
        owner: String,
        identity_address: String,
        country: String,
    },
    RemoveIdentity {
        owner: String,
    },
    UpdateIdentity {
        owner: String,
        new_identity_address: String,
    },
    UpdateCountry {
        owner: String,
        new_country: String,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(String)]
    GetIdentity { owner: String },
    #[returns(String)]
    GetCountry { owner: String },
    #[returns(Vec<String>)]
    GetIdentitiesByCountry { country: String },
    #[returns(String)]
    GetOwner {},
}
