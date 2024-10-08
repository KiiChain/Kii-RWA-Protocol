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
    AddAgent {
        owner: String,
        agent_address: String,
    },
    RemoveAgent {
        owner: String,
        agent_address: String,
    },
    UpdateAgent {
        owner: String,
        new_agent_address: String,
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
    #[returns(Vec<String>)]
    GetAgents { address: String },
    #[returns(String)]
    GetOwner {},
}
