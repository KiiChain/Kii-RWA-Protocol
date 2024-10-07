use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;

#[cw_serde]
pub struct InstantiateMsg {
    pub owner_roles_address: Addr,
}

#[cw_serde]
pub enum ExecuteMsg {
    AddComplianceModule {
        token_address: Addr,
        module_address: Addr,
        module_name: String,
    },
    RemoveComplianceModule {
        token_address: Addr,
        module_address: Addr,
    },

    UpdateComplianceModule {
        token_address: Addr,
        module_address: Addr,
        active: bool,
    },
}

#[cw_serde]
pub struct ComplianceModule {
    pub active: bool,
    pub name: String,
    pub address: Addr,
}
