use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

use crate::msg::ComplianceModule;

pub const OWNER_ROLES_ADDRESS: Item<Addr> = Item::new("owner_role_contract_address");
pub const TOKEN_COMPLIANCE_MODULES: Map<(Addr, Addr), ComplianceModule> =
    Map::new("token_compliance_modules");
