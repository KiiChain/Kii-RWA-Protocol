use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

pub const OWNER_ROLES_ADDRESS: Item<Addr> = Item::new("owner_role_contract_address");
pub const COMPLIANCE_MODULE_ADDRESS: Item<Addr> = Item::new("compliance_module_address");
pub const WHITELISTED_ADDRESSES: Map<Addr, bool> = Map::new("whitelisted_addresses");
