use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;

#[cw_serde]
pub struct InstantiateMsg {
    pub owner_roles_address: Addr,
    pub module_address: Addr,
}

#[cw_serde]
pub enum ExecuteMsg {
    ChangeComplianceModule { module_address: Addr },
    AddAddressToWhitelist { address: Addr },
    RemoveAddressFromWhitelist { address: Addr },
}
