use cosmwasm_schema::cw_serde;
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
        country: String,
    },
    RemoveCountryRestriction {
        token_address: Addr,
        country: String,
    },
    UpdateCountryRestriction {
        token_address: Addr,
        country: String,
        active: bool,
    },
}

#[cw_serde]
pub struct RestrictedCountry {
    pub active: bool,
    pub country: String,
}
