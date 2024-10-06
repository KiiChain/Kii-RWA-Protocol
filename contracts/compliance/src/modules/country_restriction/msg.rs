use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;

#[cw_serde]
pub struct InstantiateMsg {
    pub identity_address: Addr,
    pub owner_roles_address: Addr,
}

#[cw_serde]
pub enum ExecuteMsg {
    AddCountryRestriction {
        token_address: Addr,
        country_code: String,
    },
    RemoveCountryRestriction {
        token_address: Addr,
        country_code: String,
    },
    UpdateCountryRestriction {
        token_address: Addr,
        country_code: String,
        active: bool,
    },
}

#[cw_serde]
pub struct RestrictedCountry {
    pub active: bool,
    pub country_code: String,
}
