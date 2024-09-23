use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;

#[cw_serde]
pub struct InstantiateMsg {
    pub owner: Addr,
}

#[cw_serde]
pub enum ExecuteMsg {
    AddOwnerRole { role: OwnerRole, owner: Addr },
    RemoveOwnerRole { role: OwnerRole, owner: Addr },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(IsOwnerResponse)]
    IsOwner { role: OwnerRole, owner: Addr },
}

#[cw_serde]
pub struct IsOwnerResponse {
    pub is_owner: bool,
    pub role: OwnerRole,
}

#[cw_serde]
pub enum OwnerRole {
    OwnerAdmin,
    RegistryAddressSetter,
    ComplianceSetter,
    ComplianceManager,
    ClaimRegistryManager,
    IssuersRegistryManager,
    TokenInfoManager,
}

impl ToString for OwnerRole {
    fn to_string(&self) -> String {
        match self {
            OwnerRole::OwnerAdmin => "owner_admin",
            OwnerRole::RegistryAddressSetter => "registry_address_setter",
            OwnerRole::ComplianceSetter => "compliance_setter",
            OwnerRole::ComplianceManager => "compliance_manager",
            OwnerRole::ClaimRegistryManager => "claim_registry_manager",
            OwnerRole::IssuersRegistryManager => "issuers_registry_manager",
            OwnerRole::TokenInfoManager => "token_info_manager",
        }
        .into()
    }
}
